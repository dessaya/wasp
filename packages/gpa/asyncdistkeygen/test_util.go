// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Package asyncdistkeygen implements Asynchronous Distributed Key Generation algorithms
package asyncdistkeygen

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/dss"
	"go.dedis.ch/kyber/v3/suites"

	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/gpa/asyncdistkeygen/nonce"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

// MakeTestDistributedKey is for tests only.
func MakeTestDistributedKey(
	t *testing.T,
	suite suites.Suite,
	nodeIDs []gpa.NodeID,
	nodeSKs map[gpa.NodeID]kyber.Scalar,
	nodePKs map[gpa.NodeID]kyber.Point,
	f int,
	log log.Logger,
) (kyber.Point, map[gpa.NodeID]tcrypto.SecretShare) {
	n := len(nodeIDs)
	threshold := n - f
	if n == 1 {
		// We don't need to make secret sharing for a single node.
		require.Equal(t, 0, f)
		sk := suite.Scalar().Pick(suite.RandomStream())
		pk := suite.Point().Mul(sk, nil)
		dkss := map[gpa.NodeID]tcrypto.SecretShare{
			nodeIDs[0]: tcrypto.NewDistKeyShare(&share.PriShare{I: 0, V: sk}, []kyber.Point{pk}, n, threshold),
		}
		return pk, dkss
	}
	//
	// Setup nodes.
	nodes := map[gpa.NodeID]*nonce.NonceDKG{}
	for _, nid := range nodeIDs {
		nodes[nid] = nonce.New(suite, nodeIDs, nodePKs, f, nid, nodeSKs[nid], log)
		nodes[nid].Start()
	}
	tc := gpa.NewTestContext(nodes)
	tc.RunUntil(func() bool {
		numOuts := lo.CountBy(lo.Values(nodes), func(n *nonce.NonceDKG) bool {
			return n.Output() != nil
		})
		return numOuts >= threshold
	})
	//
	// Check the INTERMEDIATE result.
	intermediateOutputs := map[gpa.NodeID]*nonce.Output{}
	for nid, node := range nodes {
		intermediateOutput := node.Output()
		if intermediateOutput == nil {
			continue
		}
		require.NotNil(t, intermediateOutput)
		require.NotNil(t, intermediateOutput.Indexes)
		require.Len(t, intermediateOutput.Indexes, threshold)
		require.Nil(t, intermediateOutput.PriShare)
		intermediateOutputs[nid] = intermediateOutput
	}
	require.Len(t, intermediateOutputs, threshold)
	//
	// Emulate the agreement.
	decidedProposals := map[gpa.NodeID][]int{}
	for nid := range intermediateOutputs {
		decidedProposals[nid] = intermediateOutputs[nid].Indexes
	}
	//
	// Run the ADKG with agreement already decided.
	for _, nid := range nodeIDs {
		nodes[nid].AgreementResult(decidedProposals)
	}
	tc.RunUntil(tc.OutOfMessagesPredicate())
	//
	// Check the FINAL result.
	var pubKey kyber.Point
	dkss := map[gpa.NodeID]tcrypto.SecretShare{}
	for nid, node := range nodes {
		o := node.Output()
		require.NotNil(t, o)
		require.NotNil(t, o.PubKey)
		require.NotNil(t, o.PriShare)
		require.NotNil(t, o.Commits)
		require.Equal(t, threshold, o.Threshold)
		dkss[nid] = tcrypto.NewDistKeyShare(o.PriShare, o.Commits, n, threshold)
		if pubKey == nil {
			pubKey = o.Commits[0]
		}
	}
	return pubKey, dkss
}

// VerifyPriShares is for tests only.
func VerifyPriShares(
	t *testing.T,
	suite suites.Suite,
	nodeIDs []gpa.NodeID,
	nodePKs map[gpa.NodeID]kyber.Point,
	nodeSKs map[gpa.NodeID]kyber.Scalar,
	longPubKey kyber.Point,
	priShares map[gpa.NodeID]*share.PriShare,
	commits []kyber.Point,
	f int,
) {
	n := len(nodeIDs)
	messageToSign := []byte{112, 117, 116, 105, 110, 32, 99, 104, 117, 105, 108, 111}
	signers := make([]*dss.DSS, n)
	partSigs := make([]*dss.PartialSig, n)
	for i := range nodeIDs {
		nodePKArray := make([]kyber.Point, n)
		for j := range nodePKArray {
			nodePKArray[j] = nodePKs[nodeIDs[j]]
		}
		threshold := n - f
		long := tcrypto.NewDistKeyShare(priShares[nodeIDs[i]], commits, n, threshold) // We use long key for nonce as well. Insecure, but OK for this test.
		signer, err := dss.NewDSS(suite, nodeSKs[nodeIDs[i]], nodePKArray, long, long, messageToSign, threshold)
		require.NoError(t, err)
		signers[i] = signer
		partSigs[i], err = signer.PartialSig()
		require.NoError(t, err)
	}
	for i := range nodeIDs {
		for j := range nodeIDs {
			if i == j {
				continue
			}
			if !signers[i].EnoughPartialSig() {
				require.NoError(t, signers[i].ProcessPartialSig(partSigs[j]))
			}
		}
		require.True(t, signers[i].EnoughPartialSig())
		sig, err := signers[i].Signature()
		require.NoError(t, err)
		require.NoError(t, dss.Verify(longPubKey, messageToSign, sig))
	}
}
