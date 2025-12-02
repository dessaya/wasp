package actors_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"

	"github.com/iotaledger/wasp/v2/packages/actors"
	"github.com/iotaledger/wasp/v2/packages/actors/actorstest"
	"github.com/iotaledger/wasp/v2/packages/actors/future"
	"github.com/iotaledger/wasp/v2/packages/gpa/acss/crypto"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

func TestACSS(t *testing.T) {
	cases := []struct {
		n           int
		f           int
		silent      int // Number of actually faulty nodes (by not responding to anything).
		faultyDeals int // How many faulty deals the dealer produces?
	}{
		{1, 0, 0, 0},
		{2, 0, 0, 0},
		{3, 0, 0, 0},
		{4, 1, 0, 0},
		{10, 3, 0, 0},
		{31, 10, 0, 0},
		{4, 1, 1, 0},
		{10, 3, 3, 0},
		{31, 10, 10, 0},
		// TODO: test with faulty dealer
		{4, 1, 0, 1},
		{10, 3, 2, 1},
		{31, 10, 5, 5},
		{31, 10, 0, 10},
	}

	for _, tc := range cases {
		t.Run(
			fmt.Sprintf("n=%d,f=%d,F=%d,D=%d", tc.n, tc.f, tc.silent, tc.faultyDeals),
			func(tt *testing.T) { runACSSTest(tt, tc.n, tc.f, tc.silent, tc.faultyDeals) },
		)
	}
}

func runACSSTest(t *testing.T, n, f int, silent int, faultyDeals int) {
	if f >= n {
		panic("f must be < n")
	}
	if silent+faultyDeals > f {
		panic("silent + faultyDeals must be <= f")
	}
	suite := tcrypto.DefaultEd25519Suite()
	secret := suite.Scalar().Pick(suite.RandomStream())

	peers, routers := actorstest.MakeRouters(t, n)
	pubKeys := make(map[actors.NodeID]kyber.Point)
	sks := make(map[actors.NodeID]kyber.Scalar)

	for _, nid := range peers {
		sks[nid] = suite.Scalar().Pick(suite.RandomStream())
		pubKeys[nid] = suite.Point().Mul(sks[nid], nil)
	}

	validRange := n - silent
	isValidNode := func(i int) bool { return i < validRange }

	dealer := peers[rand.Intn(validRange)]
	outputs := make([]*future.Future[*actors.ACSSOutput], validRange)

	for i, nid := range peers {
		endpoint := routers[nid].GetEndpoint(actors.Path("acss"))
		if isValidNode(i) {
			acssActor := actors.NewACSS(endpoint, f, suite, pubKeys, sks[nid], slog.Default().With("nodeID", nid.ShortString()))
			go func() {
				var err error
				if nid == dealer {
					deal := acssActor.MakeDealFromSecret(secret)
					for range faultyDeals {
						// corrupt deal
						deal.Shares[i][0]++
					}
					err = acssActor.ShareDeal(t.Context(), deal)
				} else {
					err = acssActor.Receive(t.Context(), dealer)
				}
				if errors.Is(err, context.Canceled) {
					return
				}
				require.NoError(t, err)
			}()
			outputs[i] = acssActor.Output()
		} else {
			// silent nodes do nothing
			silentActor := actorstest.NewSilent(endpoint)
			go func() {
				_ = silentActor.Run(t.Context())
			}()
		}
	}

	outputsReady := make(chan struct{})
	go func() {
		err := future.WaitAll(t.Context(), outputs)
		require.NoError(t, err, "waiting for outputs failed")
		close(outputsReady)
	}()

	stats, err := actorstest.ExecuteUntil(t, routers, outputsReady)
	t.Logf("Delivered %d messages", stats.Delivered)
	require.NoError(t, err, "message execution failed")

	var priShares []*share.PriShare
	for i := range validRange {
		o, err := outputs[i].Get(t.Context())
		require.NoError(t, err)
		require.NotNil(t, o)
		require.NotNil(t, o.PriShare)
		require.NotNil(t, o.Commits)
		priShares = append(priShares, o.PriShare)
	}

	// Reconstruct secret
	recovered, err := share.RecoverSecret(suite, priShares, f+1, n)
	require.NoError(t, err)
	require.True(t, recovered.Equal(secret), "reconstructed secret mismatch")
}

// --- Minimal sanity test for implicate mechanics (optional / simple) ---

// TestImplicateProofFormat ensures implicate proofs have the expected length & basic verification.
func TestImplicateProofFormat(t *testing.T) {
	t.Parallel()
	suite := tcrypto.DefaultEd25519Suite()
	skDealer := suite.Scalar().Pick(suite.RandomStream())
	pkDealer := suite.Point().Mul(skDealer, nil)
	skPeer := suite.Scalar().Pick(suite.RandomStream())
	pkPeer := suite.Point().Mul(skPeer, nil)

	imp := crypto.Implicate(suite, pkDealer, skPeer)
	require.Equal(t, crypto.ImplicateLen(suite), len(imp), "implicate length mismatch")

	secret, err := crypto.CheckImplicate(suite, pkDealer, pkPeer, imp)
	require.NoError(t, err)
	// Secret should match DH(skPeer, pkDealer)
	expected := crypto.Secret(suite, pkDealer, skPeer)
	require.Equal(t, expected, secret)
}
