package actorstest

import (
	"testing"

	"github.com/iotaledger/wasp/v2/packages/actors"
)

func TrackActors[T any, ActorT actors.Actor[T]](ctx *actors.Context, nodes map[actors.NodeID]ActorT) <-chan actors.NodeID {
	done := make(chan actors.NodeID)
	for nodeID, node := range nodes {
		ctx.Wg.Go(func() {
			select {
			case <-ctx.Done():
				return
			case <-node.Output().ReadyChan():
				done <- nodeID
			}
		})
	}
	return done
}

func ExecuteAndTrack[T any, ActorT actors.Actor[T]](t *testing.T, ctx *actors.Context, routers map[actors.NodeID]*actors.Router, nodes map[actors.NodeID]ActorT) <-chan actors.NodeID {
	done := TrackActors(ctx, nodes)
	ctx.Wg.Go(func() {
		stats := Execute(t, ctx, routers)
		t.Logf("delivered %d messages", stats.Delivered)
	})
	return done
}
