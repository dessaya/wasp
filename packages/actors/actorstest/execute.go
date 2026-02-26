package actorstest

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime/debug"
	"runtime/pprof"
	"testing"
	"time"

	"fortio.org/safecast"
	"github.com/samber/lo/mutable"
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
	var peers []actors.NodeID
	for i := range n {
		peers = append(peers, MakeNodeIDFromIndex(i))
	}
	return MakeRoutersWithNodeIDs(t, peers, verifyGoroutineLeaks)
}

func MakeRoutersWithNodeIDs(t *testing.T, peers []actors.NodeID, verifyGoroutineLeaks bool) (*actors.Context, func(), []actors.NodeID, map[actors.NodeID]*actors.Router) {
	ctx := actors.NewContext(t.Context(), func(r any) {
		t.Errorf("goroutine panicked: %v\n%s", r, debug.Stack())
	}, slog.Default())

	routers := make(map[actors.NodeID]*actors.Router)
	for _, nodeID := range peers {
		router := actors.NewRouter(ctx, nodeID, peers)
		routers[nodeID] = router
	}

	stop := func() {
		ctx.Cancel()
		ctx.Wg.Wait()
		if verifyGoroutineLeaks {
			goleak.VerifyNone(
				t,
				goleak.IgnoreAnyFunction("github.com/iotaledger/hive.go/runtime/workerpool.(*WorkerPool).dispatcher"),
				goleak.IgnoreAnyFunction("github.com/iotaledger/hive.go/runtime/workerpool.(*WorkerPool).worker"),
			)
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

func Start(t *testing.T, ctx *actors.Context, routers map[actors.NodeID]*actors.Router, shuffle bool) {
	ctx.Wg.Go(func() { execute(t, ctx, routers, shuffle) })
}

// execute delivers messages between actors until all Endpoints are closed or the test context is done
func execute(t *testing.T, ctx *actors.Context, routers map[actors.NodeID]*actors.Router, shuffle bool) {
	delivered := 0
	bus := combine(ctx, routers)
	var pending []*messageInTransit

	deliver := func(msg *messageInTransit) {
		router, nodeExists := routers[msg.recipient]
		if !nodeExists {
			t.Logf("dropping message to non-existing node %s: %s", msg.recipient, msg)
			return
		}
		// t.Logf("delivering %s", msg)
		select {
		case router.GetEndpoint(msg.path).In() <- msg.msg:
		default:
			t.Logf("dropping message to %s [%s]: channel full [%s]", msg.recipient.ShortString(), msg.path, msg)
		}
		delivered++
	}

	var shuffleChan <-chan time.Time
	if shuffle {
		shuffleTicker := time.NewTicker(100 * time.Millisecond)
		shuffleChan = shuffleTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			t.Logf("Execute done (context canceled) -- delivered %d messages", delivered)
			return
		case msg := <-bus:
			if shuffle {
				pending = append(pending, msg)
				mutable.Shuffle(pending)
				if rand.Intn(10) == 0 {
					deliver(pending[len(pending)-1])
					pending = pending[:len(pending)-1]
				}
			} else {
				deliver(msg)
			}
		case <-shuffleChan:
			for _, msg := range pending {
				deliver(msg)
			}
			pending = pending[:0]
		case <-time.After(5 * time.Second):
			t.Log("timeout: no messages delivered for 1 second")
			pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
			for _, r := range routers {
				r.LogStatus()
			}
			time.Sleep(1 * time.Second) // give some time for actors to process the status updates
			ctx.Cancel()
			t.Fatal("timeout: possible deadlock")
			return
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
