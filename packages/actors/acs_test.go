package actors_test

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/wasp/v2/packages/actors"
	"github.com/iotaledger/wasp/v2/packages/actors/actorstest"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
	"github.com/iotaledger/wasp/v2/packages/testutil/testpeers"
)

func TestACS(t *testing.T) {
	for _, tc := range []struct {
		n int // total nodes
		f int // tolerated faulty nodes
		s int // silent nodes
	}{
		// Basic tests (no silent nodes)
		{n: 1, f: 0, s: 0},
		{n: 2, f: 0, s: 0},
		{n: 3, f: 0, s: 0},
		{n: 4, f: 1, s: 0},
		{n: 10, f: 3, s: 0},
		{n: 31, f: 10, s: 0},
		// With silent nodes
		{n: 4, f: 1, s: 1},
		{n: 10, f: 3, s: 3},
		{n: 31, f: 10, s: 10},
	} {
		t.Run(fmt.Sprintf("N=%d,F=%d,S=%d", tc.n, tc.f, tc.s), func(t *testing.T) {
			testACSCase(t, tc.n, tc.f, tc.s)
		})
	}
}

func testACSCase(t *testing.T, n, f, silent int) {
	ccThreshold := f + 1

	// Set up routers / endpoints.
	ctx, stop, peers, routers := actorstest.MakeRouters(t, n)
	defer stop()

	const path = "acs"

	// BLSSig setup for the common coin instances.
	suite := tcrypto.DefaultBLSSuite()
	_, pubPoly, priShares := testpeers.MakeSharedSecret(suite, n, ccThreshold)

	active := n - silent

	outputs := make(map[actors.NodeID]*actors.Output[map[actors.NodeID][]byte])
	for i, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(path)
		if i < active {
			// Honest node with ACS.
			makeCC := func(endpoint *actors.Endpoint, sid string) *actors.CommonCoinBLSSig {
				// Derive a per-round session ID to avoid cross-round interference.
				return actors.NewCommonCoinBLSSig(
					endpoint,
					ccThreshold,
					suite,
					pubPoly,
					priShares[i],
					[]byte(sid),
					slog.Default(),
				)
			}
			acs := actors.NewACS(endpoint, f, makeCC, slog.Default().With("nodeID", nodeID.ShortString()))
			outputs[nodeID] = acs.Output
			// Each node receives a deterministic, node-specific input:
			vi := fmt.Appendf(nil, "%v-input", nodeID)
			acs.Run(vi)
		} else {
			actorstest.NewSilent(endpoint).Run()
		}
	}

	actorstest.Start(t, ctx, routers)

	// Collect outputs from active nodes.
	done := actors.OutputsReadyChan(ctx, outputs)
	results := make(map[actors.NodeID]map[actors.NodeID][]byte)
	for range active {
		nodeID := <-done
		results[nodeID] = outputs[nodeID].MustGet()
	}

	ref := results[peers[0]]

	// Sanity: all values should be some node's input.
	for nid, v := range ref {
		require.NotEmptyf(t, v, "value for node %s is empty", nid.ShortString())
		require.Containsf(
			t,
			string(v),
			"-input",
			"value for node %s does not look like an input string: %q",
			nid.ShortString(),
			string(v),
		)
	}

	// Verify all honest nodes decided on the same subset and that at least one value is included.
	// We compare the maps structurally.
	for nodeID, r := range results {
		require.Equalf(
			t,
			ref,
			r,
			"ACS outputs differ between nodes %s and %s",
			peers[0].ShortString(),
			nodeID.ShortString(),
		)
	}
}
