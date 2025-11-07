// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Package distsign runs a NonceDKG and signs the supplied hash.
//
// This is a simplified implementation.
// Later the DKG part can be run in advance, while waiting for transactions.
//
// The general workflow is the following:
//
//  1. Start it upon activation of a step (last stateOutput is approved).
//  2. Exchange the underlying messages until:
//     2.1. ACSS Intermediate output is received.
//  3. Then wait for the ACS and then the VM to complete:
//     3.1. pass the ACS result to the nonce-dkg (to complete the nonces).
//     3.2. pass the VM output as a message to sign (its hash).
//  4. Exchange messages until the signature is produced.
//  5. Output the signature.
//
// TODO: Make sure no two signatures are ever produced by the nonce-dkg for the same
//
//	base TX. That would reveal the permanent private key of the committee.
package distsign

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/dss"
	"go.dedis.ch/kyber/v3/suites"

	"github.com/samber/lo"

	"github.com/iotaledger/hive.go/ds/shrinkingmap"
	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/gpa/asyncdistkeygen/nonce"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

type Output struct {
	ProposedIndexes []int  // Intermediate output.
	Signature       []byte // Final output.
}

const (
	subsystemDistributedKeyGeneration byte = iota
)

type DistributedSignature struct {
	out                             gpa.OutBuffer
	suite                           suites.Suite
	me                              gpa.NodeID
	mySK                            kyber.Scalar
	nodeIDs                         []gpa.NodeID
	nodePKs                         map[gpa.NodeID]kyber.Point
	f                               int
	longTermSecretShare             tcrypto.SecretShare
	distributedKeyGen               *nonce.NonceDKG
	distKeyGenOutIndexes            []int                // Intermediate DKG output.
	distKeyGenDecidedIndexProposals map[gpa.NodeID][]int // ACS decision.
	distKeyGenOutNonce              dss.DistKeyShare     // Final DKG output.
	messageToSign                   []byte
	distSignPartialSigBuffer        *shrinkingmap.ShrinkingMap[gpa.NodeID, *dss.PartialSig] // Accumulate early partial signatures
	distributedSignatureSigner      *dss.DSS
	signature                       []byte // The output.
	msgWrapper                      *gpa.MsgWrapper
	log                             log.Logger
}

var _ gpa.GPA = &DistributedSignature{}

func New(
	suite suites.Suite,
	nodeIDs []gpa.NodeID,
	nodePKs map[gpa.NodeID]kyber.Point,
	f int,
	me gpa.NodeID,
	mySK kyber.Scalar,
	longTermSecretShare tcrypto.SecretShare,
	log log.Logger,
) *DistributedSignature {
	d := &DistributedSignature{
		suite:                           suite,
		me:                              me,
		mySK:                            mySK,
		nodeIDs:                         nodeIDs,
		nodePKs:                         nodePKs,
		f:                               f,
		longTermSecretShare:             longTermSecretShare,
		distributedKeyGen:               nonce.New(suite, nodeIDs, nodePKs, f, me, mySK, log),
		distKeyGenOutIndexes:            nil, // To be decided.
		distKeyGenDecidedIndexProposals: nil, // To be received.
		distKeyGenOutNonce:              nil, // To be decided.
		messageToSign:                   nil, // Will be received later.
		distSignPartialSigBuffer:        shrinkingmap.New[gpa.NodeID, *dss.PartialSig](),
		distributedSignatureSigner:      nil, // Will be created when indexProposals and message to sign will be created.
		log:                             log,
	}
	d.msgWrapper = gpa.NewMsgWrapper(msgTypeWrapped, d.msgWrapperFunc)
	return d
}

func (d *DistributedSignature) SwapOutBuffer() []gpa.MessageOut {
	return d.out.Swap()
}

func (d *DistributedSignature) Start() {
	d.distributedKeyGen.Start()
	d.tryHandleDistributedKeyGenerationOutput()
}

// Message handles the messages.
func (d *DistributedSignature) Message(msg gpa.MessageIn) {
	switch msgT := msg.Payload.(type) {
	case *msgPartialSig:
		d.log.LogDebugf("Message %+v", msg)
		d.handlePartialSig(gpa.AsTypedMessageIn[*msgPartialSig](msg))
	case *gpa.WrappingMsg:
		if msgT.Subsystem() == subsystemDistributedKeyGeneration && msgT.Index() == 0 {
			d.distributedKeyGen.Message(msgT.WrappedIn(msg.Sender))
			d.tryHandleDistributedKeyGenerationOutput()
		}
		d.log.LogWarnf("unknown wrapped message %T: %+v", msgT, msgT)
		return
	default:
		panic(fmt.Errorf("unknown message %T: %v", msg, msg))
	}
}

// Output provides the output, if any.
func (d *DistributedSignature) Output() *Output {
	if d.distKeyGenOutIndexes == nil && d.signature == nil {
		return nil
	}
	return &Output{
		ProposedIndexes: d.distKeyGenOutIndexes,
		Signature:       d.signature,
	}
}

func (d *DistributedSignature) tryHandleDistributedKeyGenerationOutput() {
	d.out.PutAll(lo.Must(d.msgWrapper.WrapMessagesOut(subsystemDistributedKeyGeneration, 0)))
	distKeyGenOut := d.distributedKeyGen.Output()
	if d.distKeyGenOutIndexes == nil && distKeyGenOut != nil && distKeyGenOut.Indexes != nil {
		d.distKeyGenOutIndexes = distKeyGenOut.Indexes
	}
	if d.distKeyGenOutNonce == nil && distKeyGenOut != nil && distKeyGenOut.PriShare != nil {
		d.distKeyGenOutNonce = tcrypto.NewDistKeyShare(
			distKeyGenOut.PriShare,
			distKeyGenOut.Commits,
			len(d.nodeIDs),
			distKeyGenOut.Threshold,
		)
		//
		// Create a partial signature.
		dssSigner, err := dss.NewDSS(d.suite, d.mySK, d.nodePKArray(), d.longTermSecretShare, d.distKeyGenOutNonce, d.messageToSign, d.longTermSecretShare.Threshold())
		if err != nil {
			d.log.LogError("Failed to create DSS Signer: %v", err)
			return
		}
		d.distributedSignatureSigner = dssSigner
		partialSig, err := d.distributedSignatureSigner.PartialSig()
		if err != nil {
			d.log.LogErrorf("cannot create a partial signature: %v", err)
			return
		}
		//
		// Process early sent partial signatures, if any.
		if d.distSignPartialSigBuffer.Size() > 0 {
			d.distSignPartialSigBuffer.ForEach(func(nid gpa.NodeID, ps *dss.PartialSig) bool {
				err := d.distributedSignatureSigner.ProcessPartialSig(ps)
				if err != nil {
					d.log.LogErrorf("Failed to process a buffered partial signature: %v", err)
				}
				d.distSignPartialSigBuffer.Delete(nid)
				return true
			})
		}
		//
		// Broadcast it (except the current node).
		for i := range d.nodeIDs {
			if d.nodeIDs[i] == d.me {
				continue
			}
			d.out.Put(gpa.NewMessageOut(d.nodeIDs[i], &msgPartialSig{
				suite:      d.suite,
				partialSig: partialSig,
			}))
		}
		//
		// Maybe we have everything for the signature already?
		if d.distributedSignatureSigner.EnoughPartialSig() {
			sig, err := d.distributedSignatureSigner.Signature()
			if err != nil {
				d.log.LogErrorf("unable to aggregate the signature: %v", err)
				return
			}
			d.signature = sig
		}
	}
}

func (d *DistributedSignature) handlePartialSig(msg gpa.TypedMessageIn[*msgPartialSig]) {
	if d.signature != nil {
		// Signature already aggregated, ignore the remaining shares.
		return
	}
	if d.distributedSignatureSigner == nil {
		if d.distSignPartialSigBuffer.Has(msg.Sender) {
			d.log.LogWarn("duplicate partial signature from %v", msg.Sender)
			return
		}

		d.distSignPartialSigBuffer.Set(msg.Sender, msg.Payload.partialSig)
		return
	}
	//
	// Then process the one received with the current message.
	err := d.distributedSignatureSigner.ProcessPartialSig(msg.Payload.partialSig)
	if err != nil {
		d.log.LogWarnf("Failed to process a partial signature: %v", err)
		return
	}
	if !d.distributedSignatureSigner.EnoughPartialSig() {
		return
	}

	sig, err := d.distributedSignatureSigner.Signature()
	if err != nil {
		d.log.LogErrorf("unable to aggregate the signature: %v", err)
		return
	}
	d.signature = sig
}

func (d *DistributedSignature) InputDecided(decidedIndexProposals map[gpa.NodeID][]int, messageToSign []byte) {
	if d.distKeyGenDecidedIndexProposals != nil {
		d.log.LogWarn("Duplicate will be dropped: DecidedIndexes=%+v", decidedIndexProposals)
		return
	}
	d.distKeyGenDecidedIndexProposals = decidedIndexProposals
	d.messageToSign = messageToSign

	d.distributedKeyGen.AgreementResult(decidedIndexProposals)
	d.tryHandleDistributedKeyGenerationOutput()
}

func (d *DistributedSignature) nodePKArray() []kyber.Point {
	res := make([]kyber.Point, len(d.nodeIDs))
	for i := range res {
		res[i] = d.nodePKs[d.nodeIDs[i]]
	}
	return res
}

func (d *DistributedSignature) StatusString() string {
	return fmt.Sprintf("{DSS, dkg=%v}", d.distributedKeyGen.StatusString())
}
