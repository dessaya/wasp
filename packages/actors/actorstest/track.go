package actorstest

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/wasp/v2/packages/actors"
)

func TrackActors[T any, ActorT actors.Actor[T]](t *testing.T, nodes map[actors.NodeID]ActorT) <-chan actors.NodeID {
	done := make(chan actors.NodeID)
	for nodeID, node := range nodes {
		go func() {
			select {
			case <-t.Context().Done():
				return
			case <-node.Output().ReadyChan():
				done <- nodeID
			case err := <-node.Errors():
				require.NoError(t, err)
			}
		}()
	}
	return done
}

func ExecuteAndTrack[T any, ActorT actors.Actor[T]](t *testing.T, routers map[actors.NodeID]*actors.Router, nodes map[actors.NodeID]ActorT) <-chan actors.NodeID {
	done := TrackActors(t, nodes)
	go func() {
		stats, err := Execute(t, routers)
		if errors.Is(err, context.Canceled) {
			return
		}
		if err != nil {
			require.NoError(t, err, context.Canceled)
		} else {
			t.Logf("delivered %d messages", stats.Delivered)
		}
	}()
	return done
}
