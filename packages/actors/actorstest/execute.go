package actorstest

import (
	"encoding/binary"
	"fmt"
	"runtime/debug"
	"testing"

	"fortio.org/safecast"
	"go.uber.org/goleak"

	"github.com/iotaledger/wasp/v2/packages/actors"
)

func MakeNodeIDFromIndex(index int) actors.NodeID {
	nodeID := actors.NodeID{}

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, safecast.MustConvert[uint32](index))
	copy(nodeID[:4], indexBytes)

	return nodeID
}

func MakeRouters(t *testing.T, n int, verifyGoroutineLeaks bool) (*actors.Context, func(), []actors.NodeID, map[actors.NodeID]*actors.Router) {
	ctx := actors.NewContext(t.Context(), func(r any) {
		t.Errorf("goroutine panicked: %v\n%s", r, debug.Stack())
	})

	var peers []actors.NodeID
	for i := range n {
		peers = append(peers, MakeNodeIDFromIndex(i))
	}
	routers := make(map[actors.NodeID]*actors.Router)
	for i := range n {
		nodeID := MakeNodeIDFromIndex(i)
		router := actors.NewRouter(ctx, nodeID, peers)
		routers[nodeID] = router
	}

	stop := func() {
		ctx.Cancel()
		ctx.Wg.Wait()
		if verifyGoroutineLeaks {
			goleak.VerifyNone(t)
		}
	}

	return ctx, stop, peers, routers
}

type messageInTransit struct {
	recipient actors.NodeID
	path      actors.Path
	msg       actors.MessageIn
}

func (m *messageInTransit) String() string {
	return fmt.Sprintf("%s -> %s [path=%q] %v", m.msg.Sender.ShortString(), m.recipient.ShortString(), m.path, m.msg.Payload)
}

func Start(t *testing.T, ctx *actors.Context, routers map[actors.NodeID]*actors.Router) {
	ctx.Wg.Go(func() { execute(t, ctx, routers) })
}

// execute delivers messages between actors until all Endpoints are closed or the test context is done
func execute(t *testing.T, ctx *actors.Context, routers map[actors.NodeID]*actors.Router) {
	delivered := 0
	bus := combine(ctx, routers)

	for {
		select {
		case <-ctx.Done():
			t.Logf("Execute done (context canceled) -- delivered %d messages", delivered)
			return
		case msg := <-bus:
			router, nodeExists := routers[msg.recipient]
			if !nodeExists {
				t.Logf("dropping message to non-existing node %s: %s", msg.recipient, msg)
				continue
			}
			// t.Logf("delivering %s", msg)
			select {
			case router.GetEndpoint(msg.path).In() <- msg.msg:
			default:
				t.Logf("dropping message to %s [%s]: channel full [%s]", msg.recipient.ShortString(), msg.path, msg)
			}
			delivered++
			// case <-time.After(1 * time.Second):
			// 	for _, r := range routers {
			// 		r.LogStatus()
			// 	}
		}
	}
}

// combine combines all out channels into one
func combine(ctx *actors.Context, routers map[actors.NodeID]*actors.Router) chan *messageInTransit {
	bus := make(chan *messageInTransit)
	for sender, senderRouter := range routers {
		ctx.Wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case msg := <-senderRouter.Out():
					select {
					case <-ctx.Done():
						return
					case bus <- &messageInTransit{
						recipient: msg.Recipient,
						path:      msg.Path,
						msg:       actors.NewMessageIn(sender, msg.Payload),
					}:
					}
				}
			}
		})
	}
	return bus
}
