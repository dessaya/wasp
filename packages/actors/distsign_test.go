package actors_test

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/eddsa"
	"go.dedis.ch/kyber/v3/suites"

	"github.com/iotaledger/wasp/v2/packages/actors"
	"github.com/iotaledger/wasp/v2/packages/actors/actorstest"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

func TestDistSign(t *testing.T) {
	for _, tc := range []struct {
		n int
		f int
	}{
		{1, 0},
		{2, 0},
		{3, 0},
		{4, 1},
		{10, 3},
		{31, 10},
	} {
		t.Run(fmt.Sprintf("N=%d,F=%d", tc.n, tc.f), func(t *testing.T) {
			testDistSign(t, tc.n, tc.f)
		})
	}
}

func testDistSign(t *testing.T, n int, f int) {
	// Setup keys and node names.
	ctx, stop, nodeIDs, routers := actorstest.MakeRouters(t, n, true)
	defer stop()

	nodeSKs := map[actors.NodeID]kyber.Scalar{}
	nodePKs := map[actors.NodeID]kyber.Point{}
	suite := tcrypto.DefaultEd25519Suite()
	for i := range nodeIDs {
		nodeSKs[nodeIDs[i]] = suite.Scalar().Pick(suite.RandomStream())
		nodePKs[nodeIDs[i]] = suite.Point().Mul(nodeSKs[nodeIDs[i]], nil)
	}

	longTermPK, longTermSecretShares := makeTestDistributedKey(t, suite, nodeIDs, nodeSKs, nodePKs, f, slog.Default())

	// Setup nodes
	distributedSignatures := map[actors.NodeID]*actors.DistSign{}
	proposedIndexesOuts := map[actors.NodeID]*actors.Output[[]int]{}
	const path = "ds"
	for _, nid := range nodeIDs {
		endpoint := routers[nid].GetEndpoint(path)
		ds := actors.NewDistSign(endpoint, f, suite, nodePKs, nodeSKs[nid], longTermSecretShares[nid], slog.Default())
		distributedSignatures[nid] = ds
		proposedIndexesOuts[nid] = ds.OutputProposedIndexes
		ds.Start()
	}

	actorstest.Start(t, ctx, routers)

	// wait until n-f intermediate outputs are ready
	ch := actors.OutputsReadyChan(ctx, proposedIndexesOuts)
	for range n - f {
		<-ch
	}

	// Check the INTERMEDIATE result.
	decidedProposals := map[actors.NodeID][]int{}
	for nid, o := range proposedIndexesOuts {
		if !o.IsReady() {
			continue
		}
		proposedIndexes := o.MustGet()
		require.NotNil(t, proposedIndexes)
		decidedProposals[nid] = proposedIndexes
	}
	require.GreaterOrEqual(t, len(decidedProposals), n-f)

	messageToSign := []byte{112, 117, 116, 105, 110, 32, 99, 104, 117, 105, 108, 111}
	for nid := range distributedSignatures {
		distributedSignatures[nid].InputDecided(decidedProposals, messageToSign)
	}

	// Check the FINAL result.
	var signature []byte
	for _, ds := range distributedSignatures {
		sig := ds.OutputSignature.Wait()
		require.NotNil(t, sig)
		if signature == nil {
			signature = sig
		}
		require.Equal(t, signature, sig)
	}
	require.NoError(t, eddsa.Verify(longTermPK, messageToSign, signature))
}

func makeTestDistributedKey(
	t *testing.T,
	suite suites.Suite,
	nodeIDs []actors.NodeID,
	nodeSKs map[actors.NodeID]kyber.Scalar,
	nodePKs map[actors.NodeID]kyber.Point,
	f int,
	log *slog.Logger,
) (kyber.Point, map[actors.NodeID]tcrypto.SecretShare) {
	n := len(nodeIDs)
	threshold := n - f
	if n == 1 {
		// We don't need to make secret sharing for a single node.
		require.Equal(t, 0, f)
		sk := suite.Scalar().Pick(suite.RandomStream())
		pk := suite.Point().Mul(sk, nil)
		dkss := map[actors.NodeID]tcrypto.SecretShare{
			nodeIDs[0]: tcrypto.NewDistKeyShare(&share.PriShare{I: 0, V: sk}, []kyber.Point{pk}, n, threshold),
		}
		return pk, dkss
	}

	ctx, stop, nodeIDs, routers := actorstest.MakeRouters(t, n, false)
	defer stop()

	nodes := map[actors.NodeID]*actors.NonceDKG{}
	intermediateOutputs := map[actors.NodeID]*actors.Output[[]int]{}
	const path = "dkg"
	for _, nid := range nodeIDs {
		endpoint := routers[nid].GetEndpoint(path)
		nodes[nid] = actors.NewNonceDKG(endpoint, f, suite, nodePKs, nodeSKs[nid], log)
		nodes[nid].Start()
		intermediateOutputs[nid] = nodes[nid].IntermediateOutput
	}

	actorstest.Start(t, ctx, routers)

	// Check the INTERMEDIATE result.
	ch := actors.OutputsReadyChan(ctx, intermediateOutputs)
	decidedProposals := map[actors.NodeID][]int{}
	for range threshold {
		nid := <-ch
		decidedProposals[nid] = intermediateOutputs[nid].MustGet()
	}

	// Run the ADKG with agreement already decided.
	for _, nid := range nodeIDs {
		nodes[nid].AgreementResult(decidedProposals)
	}

	var pubKey kyber.Point
	dkss := map[actors.NodeID]tcrypto.SecretShare{}
	for nid, node := range nodes {
		o := node.FinalOutput.Wait()
		dkss[nid] = tcrypto.NewDistKeyShare(o.PriShare, o.Commits, n, threshold)
		if pubKey == nil {
			pubKey = o.Commits[0]
		}
	}
	return pubKey, dkss
}
