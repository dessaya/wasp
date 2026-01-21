package actors_test

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/dss"
	"go.dedis.ch/kyber/v3/suites"

	"github.com/iotaledger/wasp/v2/packages/actors"
	"github.com/iotaledger/wasp/v2/packages/actors/actorstest"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

func TestNonceDKG(t *testing.T) {
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
			testNonceDKG(t, tc.n, tc.f)
		})
	}
}

func testNonceDKG(t *testing.T, n int, f int) {
	ctx, stop, peers, routers := actorstest.MakeRouters(t, n)
	defer stop()

	suite := tcrypto.DefaultEd25519Suite()

	nodeSKs := map[actors.NodeID]kyber.Scalar{}
	nodePKs := map[actors.NodeID]kyber.Point{}
	for _, nodeID := range peers {
		nodeSKs[nodeID] = suite.Scalar().Pick(suite.RandomStream())
		nodePKs[nodeID] = suite.Point().Mul(nodeSKs[nodeID], nil)
	}

	const path = "dkg"

	dkgs := map[actors.NodeID]*actors.NonceDKG{}
	for _, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(path)
		dkg := actors.NewNonceDKG(
			endpoint,
			f,
			suite,
			nodePKs,
			nodeSKs[nodeID],
			slog.Default(),
		)
		dkgs[nodeID] = dkg
		dkg.Start()
	}

	actorstest.Start(t, ctx, routers)

	// Check the INTERMEDIATE result.
	decidedProposals := map[actors.NodeID][]int{}
	for nid, dkg := range dkgs {
		indexes := dkg.IntermediateOutput.Wait()
		require.NotNil(t, indexes)
		require.NotNil(t, indexes)
		require.Len(t, indexes, n-f)
		// Emulate the agreement.
		decidedProposals[nid] = dkg.IntermediateOutput.MustGet()
		if len(decidedProposals) == n-f {
			break
		}
	}

	// Run the ADKG with agreement already decided.
	for _, nid := range peers {
		dkgs[nid].AgreementResult(decidedProposals)
	}

	// Check the FINAL result.
	priShares := map[actors.NodeID]*share.PriShare{}
	var pubKey kyber.Point
	var commits []kyber.Point
	for nid, n := range dkgs {
		o := n.FinalOutput.Wait()
		require.NotNil(t, o.PubKey)
		require.NotNil(t, o.PriShare)
		require.NotNil(t, o.Commits)
		priShares[nid] = o.PriShare
		if pubKey == nil && commits == nil {
			pubKey = o.PubKey
			commits = o.Commits
		}
	}
	verifyPriShares(t, suite, peers, nodePKs, nodeSKs, pubKey, priShares, commits, f)
}

func verifyPriShares(
	t *testing.T,
	suite suites.Suite,
	nodeIDs []actors.NodeID,
	nodePKs map[actors.NodeID]kyber.Point,
	nodeSKs map[actors.NodeID]kyber.Scalar,
	longPubKey kyber.Point,
	priShares map[actors.NodeID]*share.PriShare,
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
