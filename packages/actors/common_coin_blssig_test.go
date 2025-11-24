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

func TestCommonCoinBLSSig(t *testing.T) {
	for _, tc := range []struct {
		n int // total nodes
		t int // threshold
		s int // silent nodes
	}{
		// Basic / single node
		{n: 1, t: 1, s: 0},
		// No silent nodes
		{n: 4, t: 3, s: 0}, // high threshold (N - F with F=1)
		{n: 4, t: 2, s: 0}, // low threshold (F+1 with F=1)
		{n: 10, t: 7, s: 0},
		{n: 10, t: 4, s: 0},
		// With silent nodes (s <= n - t to still allow completion)
		{n: 4, t: 3, s: 1},
		{n: 4, t: 2, s: 1},
		{n: 10, t: 7, s: 3},
		{n: 10, t: 4, s: 3},
	} {
		t.Run(fmt.Sprintf("n=%d,t=%d,s=%d", tc.n, tc.t, tc.s), func(t *testing.T) {
			testCommonCoinCase(t, tc.n, tc.t, tc.s)
		})
	}
}

func testCommonCoinCase(t *testing.T, n, threshold, silent int) {
	peers, routers := actorstest.MakeRouters(t, n)
	const path = "cc"
	suite := tcrypto.DefaultBLSSuite()
	_, pubPoly, priShares := testpeers.MakeSharedSecret(suite, n, threshold)
	sid := []byte{0xA, 0xB, 0xC, 0xD} // session identifier for signing
	active := n - silent
	nodes := make(map[actors.NodeID]*actors.CommonCoinBLSSig, active)
	outCh := make(chan bool, active)

	for i, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(path)
		if i < active {
			// fair node
			node := actors.NewCommonCoinBLSSig(endpoint, threshold, suite, pubPoly, priShares[i], sid, slog.Default())
			nodes[nodeID] = node
			go func(nodeID actors.NodeID, node *actors.CommonCoinBLSSig) {
				coin, err := node.Run(t.Context())
				require.NoError(t, err, "node %s failed to decide coin", nodeID.ShortString())
				outCh <- coin
			}(nodeID, node)
		} else {
			// silent node
			s := actorstest.NewSilent(endpoint)
			go func() {
				_ = s.Run(t.Context())
			}()
		}
	}

	// Execute message delivery until all endpoints are closed.
	stats, err := actorstest.Execute(t, routers)
	require.NoError(t, err)
	t.Logf("delivered %d messages", stats.Delivered)

	// verify results
	var coins []bool
	for range active {
		coins = append(coins, <-outCh)
	}
	require.Equal(t, active, len(coins), "not all active nodes decided")
	firstCoin := coins[0]
	for i, coin := range coins {
		require.Equalf(t, firstCoin, coin, "node %d decided differently", i)
	}
}
