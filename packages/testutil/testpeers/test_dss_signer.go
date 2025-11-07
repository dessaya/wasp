// Package testpeers provides utilities for testing peer-related functionality
package testpeers

import (
	"fmt"

	"github.com/minio/blake2b-simd"
	"github.com/samber/lo"
	"go.dedis.ch/kyber/v3"

	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotasigner"
	"github.com/iotaledger/wasp/v2/packages/chain/distsign"
	"github.com/iotaledger/wasp/v2/packages/cryptolib"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/registry"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

type testDssSigner struct {
	dkShares []tcrypto.DKShare
	nodeIDs  []gpa.NodeID
	nodeKeys []*cryptolib.KeyPair
	log      log.Logger
}

func NewTestDistributedSignatureSigner(
	addr *cryptolib.Address,
	reg []registry.DKShareRegistry,
	nodeIDs []gpa.NodeID,
	nodeKeys []*cryptolib.KeyPair,
	log log.Logger,
) cryptolib.Signer {
	dkShares := lo.Map(reg, func(prov registry.DKShareRegistry, index int) tcrypto.DKShare {
		return lo.Must(prov.LoadDKShare(addr))
	})

	return &testDssSigner{
		dkShares: dkShares,
		nodeIDs:  nodeIDs,
		nodeKeys: nodeKeys,
		log:      log,
	}
}

func (sig *testDssSigner) Address() *cryptolib.Address {
	return sig.dkShares[0].GetSharedPublic().AsAddress()
}

func (sig *testDssSigner) Sign(messageToSign []byte) (*cryptolib.Signature, error) {
	n := len(sig.nodeIDs)
	f := n - sig.dkShares[0].DSS().Threshold()
	edSuite := tcrypto.DefaultEd25519Suite()

	nodePKs := map[gpa.NodeID]kyber.Point{}
	for i, pk := range sig.dkShares[0].GetNodePubKeys() {
		nodePKs[sig.nodeIDs[i]] = lo.Must(pk.AsKyberPoint())
	}

	//
	// Setup nodes.
	distributedSignatures := map[gpa.NodeID]*distsign.DistributedSignature{}
	for idx, nid := range sig.nodeIDs {
		dks := sig.dkShares[idx]
		privKey := lo.Must(sig.nodeKeys[idx].GetPrivateKey().AsKyberKeyPair()).Private
		distributedSignatures[nid] = distsign.New(edSuite, sig.nodeIDs, nodePKs, f, nid, privKey, dks.DSS(), sig.log)
	}
	tc := gpa.NewTestContext(distributedSignatures)
	//
	// Run the DKG
	for _, nid := range sig.nodeIDs {
		distributedSignatures[nid].Start()
	}
	tc.RunUntil(func() bool {
		// at least n - f nodes have non-nil output
		return lo.CountBy(
			lo.Values(distributedSignatures),
			func(n *distsign.DistributedSignature) bool { return n.Output() != nil },
		) >= n-f
	})

	//
	// Check the INTERMEDIATE result.
	intermediateOutputs := map[gpa.NodeID]*distsign.Output{}
	for nid := range distributedSignatures {
		intermediateOutput := distributedSignatures[nid].Output()
		if intermediateOutput != nil {
			intermediateOutputs[nid] = intermediateOutput
		}
	}
	//
	// Emulate the agreement on index proposals (ACS).
	decidedProposals := map[gpa.NodeID][]int{}
	for nid := range intermediateOutputs {
		decidedProposals[nid] = intermediateOutputs[nid].ProposedIndexes
	}
	for nid := range distributedSignatures {
		distributedSignatures[nid].InputDecided(decidedProposals, messageToSign)
	}
	//
	// Run the ADKG with agreement already decided.
	tc.RunUntil(tc.OutOfMessagesPredicate())
	//
	// Check the FINAL result.
	for _, n := range distributedSignatures {
		o := n.Output()
		if o != nil {
			signatureBytes := o.Signature
			signature := cryptolib.NewSignature(sig.dkShares[0].GetSharedPublic(), signatureBytes)
			if !signature.Validate(messageToSign) {
				return nil, fmt.Errorf("produced an invalid signature")
			}
			return signature, nil
		}
	}
	return nil, fmt.Errorf("no node generated a signature")
}

func (sig *testDssSigner) SignTransactionBlock(txnBytes []byte, intent iotasigner.Intent) (*cryptolib.Signature, error) {
	data := iotasigner.MessageWithIntent(intent, txnBytes)
	hash := blake2b.Sum256(data)
	return sig.Sign(hash[:])
}
