package actors_test

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/wasp/v2/packages/actors"
	"github.com/iotaledger/wasp/v2/packages/actors/actorstest"
)

func TestBracha(t *testing.T) {
	for _, testcase := range []struct {
		n int
		f int
		s int // "silent" nodes
	}{
		// all nodes are fair:
		{1, 0, 0},
		{2, 0, 0},
		{3, 0, 0},
		{4, 1, 0},
		{10, 3, 0},
		{31, 10, 0},
		// f nodes are silent:
		{4, 1, 1},
		{10, 3, 3},
		{31, 10, 10},
	} {
		t.Run(fmt.Sprintf("n=%d,f=%d,s=%d", testcase.n, testcase.f, testcase.s), func(t *testing.T) {
			testBracha(t, testcase.n, testcase.f, testcase.s)
		})
	}
}

func testBracha(t *testing.T, n, f, s int) {
	if s > f {
		t.Fatalf("number of silent nodes s=%d cannot be greater than f=%d", s, f)
	}
	const path = "bracha"
	peers, routers := actorstest.MakeRouters(t, n)
	nodes := map[actors.NodeID]*actors.ReliableBroadcast{}
	broadcaster := peers[0]

	ctx := t.Context()
	m := []byte("hello")
	r := make(chan []byte, n-s) // expecting n-s responses

	for i, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(path)
		if i < n-s {
			// fair node
			rbc := actors.NewReliableBroadcast(endpoint, f, broadcaster, slog.Default())
			nodes[nodeID] = rbc
			go func() {
				var out []byte
				var err error
				if i == 0 {
					// broadcaster broadcasts "hello"
					out, err = rbc.Broadcast(ctx, m)
				} else {
					// other nodes receive "hello"
					out, err = rbc.Receive(ctx)
				}
				require.NoError(t, err)
				r <- out
			}()
		} else {
			// silent node
			s := actorstest.NewSilent(endpoint)
			go func() {
				_ = s.Run(ctx)
			}()
		}
	}

	// execute runs until all transports are closed
	stats, err := actorstest.Execute(t, routers)
	require.NoError(t, err)
	t.Logf("delivered %d messages", stats.Delivered)

	// check that all nodes received the correct message
	for range n - s {
		out := <-r
		require.Equal(t, m, out)
	}
}
