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
	rbcs := map[actors.NodeID]*actors.ReliableBroadcast{}
	broadcaster := peers[0]

	m := []byte("hello")

	for i, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(path)
		if i < n-s {
			// fair node
			rbc := actors.NewReliableBroadcast(endpoint, f, broadcaster, slog.Default())
			rbcs[nodeID] = rbc
			go func() {
				if i == 0 {
					// broadcaster broadcasts "hello"
					rbc.Broadcast(t.Context(), m)
				} else {
					// other nodes receive "hello"
					rbc.Receive(t.Context())
				}
			}()
		} else {
			// silent node
			s := actorstest.NewSilent(endpoint)
			go func() {
				_ = s.Run(t.Context())
			}()
		}
	}

	done := actorstest.ExecuteAndTrack(t, routers, rbcs)

	// check that all nodes received the correct message
	for range n - s {
		nodeID := <-done
		require.Equal(t, m, rbcs[nodeID].Output().MustGet())
	}
}
