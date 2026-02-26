package actors

import (
	"context"
	"fmt"

	"github.com/samber/lo"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/dss"
	"go.dedis.ch/kyber/v3/suites"

	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

// DistSign runs a NonceDKG and signs the supplied hash.
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
type DistSign struct {
	Actor
	OutputProposedIndexes *Output[[]int]  // Intermediate output
	OutputSignature       *Output[[]byte] // Final output
	f                     int
	suite                 suites.Suite
	peerPKs               map[NodeID]kyber.Point
	mySK                  kyber.Scalar
	longTermSecretShare   tcrypto.SecretShare
	chInputDecided        chan inputDecided
}

type (
	msgDistSignPartialSig struct {
		sig *dss.PartialSig `bcs:"export"`
	}
)

func (m *msgDistSignPartialSig) MsgType() MessageType { return 0 }
func (m *msgDistSignPartialSig) String() string {
	return fmt.Sprintf("PartialSig(%q)", lo.Ellipsis(string(m.sig.Signature), 16))
}

type inputDecided struct {
	decidedProposals map[NodeID][]int
	messageToSign    []byte
}

func NewDistSign(
	endpoint *Endpoint,
	f int,
	suite suites.Suite,
	peerPKs map[NodeID]kyber.Point,
	mySK kyber.Scalar,
	longTermSecretShare tcrypto.SecretShare,
) *DistSign {
	return &DistSign{
		Actor:                 NewActor(endpoint),
		OutputProposedIndexes: NewOutput[[]int](endpoint.Context()),
		OutputSignature:       NewOutput[[]byte](endpoint.Context()),
		f:                     f,
		suite:                 suite,
		peerPKs:               peerPKs,
		mySK:                  mySK,
		longTermSecretShare:   longTermSecretShare,
		chInputDecided:        make(chan inputDecided, 1),
	}
}

// Start starts the distributed signing process. A child NonceDKG instance is started, and when its intermediate output is received,
// OutputProposedIndexes is set. Then the process waits until InputDecided is called with the ACS decision.
func (d *DistSign) Start() {
	d.Go(func() {
		dkg := NewNonceDKG(d.Endpoint().Sub("dkg"), d.f, d.suite, d.peerPKs, d.mySK)
		dkg.Start()
		dkgIntermediateOutput := dkg.IntermediateOutput.ValueChan()
		dkgFinalOutput := dkg.FinalOutput.ValueChan()

		var messageToSign []byte
		var signer *dss.DSS

		partialSigsBuffer := map[NodeID]*dss.PartialSig{}

		processPartialSig := func(partialSig *dss.PartialSig) {
			if d.OutputSignature.IsReady() {
				return
			}
			if partialSig != nil {
				lo.Must0(signer.ProcessPartialSig(partialSig))
			}
			if signer.EnoughPartialSig() {
				sig := lo.Must(signer.Signature())
				d.OutputSignature.Set(sig)
			}
		}

		for {
			select {
			case <-d.Context().Done():
				return

			case <-d.Endpoint().Status():
				d.Log().Info("status", "proposedIndexes", d.OutputProposedIndexes.String(), "signature", d.OutputSignature.String())

			case proposedIndexes := <-dkgIntermediateOutput:
				d.OutputProposedIndexes.Set(proposedIndexes)

			case input := <-d.chInputDecided:
				dkg.AgreementResult(input.decidedProposals)
				messageToSign = input.messageToSign

			case dkgOutput := <-dkgFinalOutput:
				dkgOutNonce := tcrypto.NewDistKeyShare(
					dkgOutput.PriShare,
					dkgOutput.Commits,
					d.Endpoint().N(),
					dkgOutput.Threshold,
				)

				// Create a partial signature.
				signer = lo.Must(dss.NewDSS(d.suite, d.mySK, d.nodePKArray(), d.longTermSecretShare, dkgOutNonce, messageToSign, d.longTermSecretShare.Threshold()))
				partialSig, err := signer.PartialSig()
				if err != nil {
					panic(fmt.Sprintf("cannot create a partial signature: %v", err))
				}

				// Process own partial signature.
				processPartialSig(nil)

				// Broadcast it to other nodes
				d.Endpoint().SendToAllButMe(&msgDistSignPartialSig{
					sig: partialSig,
				})

				// process early sent partial signatures, if any.
				for nid, ps := range partialSigsBuffer {
					processPartialSig(ps)
					delete(partialSigsBuffer, nid)
				}

			case m, ok := <-d.Endpoint().In():
				if !ok {
					panic(context.Canceled)
				}
				payload, ok := m.Payload.(*msgDistSignPartialSig)
				if !ok {
					d.Log().Warn("unexpected message type", "type", fmt.Sprintf("%T", m.Payload))
					continue
				}

				if d.OutputSignature.IsReady() {
					// Signature already aggregated, ignore the remaining shares.
					continue
				}
				if signer == nil {
					// store incoming partial signatures until we have the signer ready.
					if partialSigsBuffer[m.Sender] != nil {
						d.Log().Warn("duplicate partial signature", "sender", m.Sender.ShortString())
						return
					}
					partialSigsBuffer[m.Sender] = payload.sig
				} else {
					processPartialSig(payload.sig)
				}
			}
		}
	})
}

func (d *DistSign) nodePKArray() []kyber.Point {
	return lo.Map(d.Endpoint().Router.Peers, func(nid NodeID, _ int) kyber.Point {
		return d.peerPKs[nid]
	})
}

// InputDecided is called with the ACS decision (the indexes of the proposals that were decided), and the
// message to sign (the hash of the VM output). Then the process continues until the signature is produced, which is set in OutputSignature.
func (d *DistSign) InputDecided(decidedProposals map[NodeID][]int, messageToSign []byte) {
	d.chInputDecided <- inputDecided{
		decidedProposals: decidedProposals,
		messageToSign:    messageToSign,
	}
}
