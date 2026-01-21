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
	ctx, stop, peers, routers := actorstest.MakeRouters(t, n)
	defer stop()

	const path = "cc"
	suite := tcrypto.DefaultBLSSuite()
	_, pubPoly, priShares := testpeers.MakeSharedSecret(suite, n, threshold)
	sid := []byte{0xA, 0xB, 0xC, 0xD} // session identifier for signing
	active := n - silent
	outputs := make(map[actors.NodeID]*actors.Output[bool])

	for i, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(path)
		if i < active {
			// fair node
			node := actors.NewCommonCoinBLSSig(endpoint, threshold, suite, pubPoly, priShares[i], sid, slog.Default())
			outputs[nodeID] = node.Output
			node.Run()
		} else {
			// silent node
			actorstest.NewSilent(endpoint).Run()
		}
	}

	actorstest.Start(t, ctx, routers)

	done := actors.OutputsReadyChan(ctx, outputs)
	var coins []bool
	for range active {
		nodeID := <-done
		coins = append(coins, outputs[nodeID].MustGet())
	}
	firstCoin := coins[0]
	for i, coin := range coins {
		require.Equalf(t, firstCoin, coin, "node %d decided differently", i)
	}
}
