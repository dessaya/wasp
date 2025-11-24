package actorstest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"

	"fortio.org/safecast"

	"github.com/iotaledger/wasp/v2/packages/actors"
)

func MakeNodeIDFromIndex(index int) actors.NodeID {
	nodeID := actors.NodeID{}

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, safecast.MustConvert[uint32](index))
	copy(nodeID[:4], indexBytes)

	return nodeID
}

func MakeRouters(t *testing.T, n int) ([]actors.NodeID, map[actors.NodeID]*actors.Router) {
	var peers []actors.NodeID
	for i := range n {
		peers = append(peers, MakeNodeIDFromIndex(i))
	}
	routers := make(map[actors.NodeID]*actors.Router)
	for i := range n {
		nodeID := MakeNodeIDFromIndex(i)
		router := actors.NewRouter(t.Context(), nodeID, peers)
		routers[nodeID] = router
	}
	return peers, routers
}

type messageInTransit struct {
	recipient actors.NodeID
	path      actors.Path
	msg       actors.MessageIn
}

func (m *messageInTransit) String() string {
	return fmt.Sprintf("%s -> %s [path=%q] %v", m.msg.Sender.ShortString(), m.recipient.ShortString(), m.path, m.msg.Payload)
}

type Stats struct {
	Delivered int
}

// Execute delivers messages between actors until all Endpoints are closed or the test context is done
func Execute(t *testing.T, routers map[actors.NodeID]*actors.Router) (Stats, error) {
	var stats Stats
	bus := combine(t, routers)
	for {
		select {
		case <-t.Context().Done():
			return stats, t.Context().Err()
		case msg, ok := <-bus:
			if !ok {
				// all endpoints are closed
				return stats, nil
			}
			router, nodeExists := routers[msg.recipient]
			if !nodeExists {
				t.Logf("dropping message to non-existing node %s: %s", msg.recipient, msg)
				continue
			}
			// t.Logf("delivering %s", msg)
			select {
			case router.GetEndpoint(msg.path).In() <- msg.msg:
				stats.Delivered++
			case <-t.Context().Done():
				return stats, t.Context().Err()
			default:
				return stats, errors.New("cannot deliver message: `in` channel full")
			}
		}
	}
}

// combine combines all out channels into one
func combine(t *testing.T, routers map[actors.NodeID]*actors.Router) chan *messageInTransit {
	bus := make(chan *messageInTransit)
	var wg sync.WaitGroup

	for sender, senderRouter := range routers {
		wg.Add(1)
		go func() {
			for msg := range senderRouter.Out() {
				bus <- &messageInTransit{
					recipient: msg.Recipient,
					path:      msg.Path,
					msg:       actors.NewMessageIn(sender, msg.Payload),
				}
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(bus)
	}()

	return bus
}
