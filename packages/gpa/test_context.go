// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package gpa

import (
	"bytes"
	"math/rand"
	"sort"
	"sync"

	"github.com/samber/lo"
)

type PendingMessage = struct {
	recipient NodeID
	msg       MessageIn
}

// TestContext imitates a cluster of nodes and the medium performing the message exchange.
// Inputs are processes in-order for each node individually.
type TestContext[T GPA] struct {
	nodes           map[NodeID]T     // Nodes to test.
	msgDeliveryProb float64          // A probability to deliver a message (to not discard/loose it).
	msgSerialize    bool             // Use serialization/deserialization when delivering the messages?
	msgs            []PendingMessage // Not yet delivered messages.
	msgsSent        int              // Stats.
	msgsRecv        int              // Stats.
	bytesRecv       int
	loopHandler     func()
	mu              sync.Mutex
}

func NewTestContext[T GPA](nodes map[NodeID]T) *TestContext[T] {
	tc := TestContext[T]{
		msgSerialize:    true,
		nodes:           nodes,
		msgDeliveryProb: 1.0,
		msgs:            []PendingMessage{},
	}
	return &tc
}

func (tc *TestContext[T]) WithLoopHandler(f func()) *TestContext[T] {
	tc.loopHandler = f
	return tc
}

func (tc *TestContext[T]) WithoutSerialization() *TestContext[T] {
	tc.msgSerialize = false
	return tc
}

func (tc *TestContext[T]) MsgCounts() (int, int) {
	return tc.msgsSent, tc.msgsRecv
}

func (tc *TestContext[T]) WithMessageDeliveryProbability(msgDeliveryProb float64) *TestContext[T] {
	tc.msgDeliveryProb = msgDeliveryProb
	return tc
}

func (tc *TestContext[T]) WithMessages(recipient NodeID, msgs []MessageIn) *TestContext[T] {
	tc.addMessages(lo.Map(msgs, func(m MessageIn, _ int) PendingMessage {
		return PendingMessage{recipient: recipient, msg: m}
	}))
	return tc
}

func (tc *TestContext[T]) addMessages(msgs []PendingMessage) {
	tc.msgsSent += len(msgs)
	tc.msgs = append(tc.msgs, msgs...)
}

func (tc *TestContext[T]) WithMessage(recipient NodeID, msg MessageIn) *TestContext[T] {
	tc.msgsSent++
	tc.msgs = append(tc.msgs, PendingMessage{recipient: recipient, msg: msg})
	return tc
}

func (tc *TestContext[T]) RunUntil(predicate func() bool) {
	// prevent reentrant call
	ok := tc.mu.TryLock()
	if !ok {
		panic("TestContext: reentrant call")
	}
	defer tc.mu.Unlock()

	for {
		if predicate() {
			return
		}

		for nid, node := range tc.nodes {
			msgs := node.SwapOutBuffer()
			tc.addMessages(lo.Map(msgs, func(m MessageOut, _ int) PendingMessage {
				return PendingMessage{recipient: m.Recipient, msg: NewMessageIn(nid, m.Payload)}
			}))
		}

		if len(tc.msgs) == 0 {
			return
		}
		tc.tryProcessMessage()
		if tc.loopHandler != nil {
			tc.loopHandler()
		}
	}
}

func (tc *TestContext[T]) tryProcessMessage() {
	// select a random message, swap it with the last one and decrease the slice length
	rnd := rand.Intn(len(tc.msgs))
	pendingMsg := tc.msgs[rnd]
	tc.msgs[rnd] = tc.msgs[len(tc.msgs)-1]
	tc.msgs = tc.msgs[:len(tc.msgs)-1]

	tc.msgsRecv++
	if rand.Float64() > tc.msgDeliveryProb {
		// message dropped
		return
	}

	// deliver message
	nid := pendingMsg.recipient
	msg := pendingMsg.msg
	if tc.msgSerialize {
		msgBytes := lo.Must(MarshalPayload(msg.Payload))
		tc.bytesRecv += len(msgBytes)
		m, err := tc.nodes[nid].UnmarshalPayload(msgBytes)
		if err != nil {
			// E.g. silent node cannot decode messages.
			return
		}
		msg = NewMessageIn(msg.Sender, m)
	}
	// fmt.Printf("%s -> %s :: %s (count: %d / %d bytes)\n", msg.Sender.ShortString(), nid.ShortString(), msg.Payload, tc.msgsRecv, tc.bytesRecv)
	tc.nodes[nid].Message(msg)
}

func (tc *TestContext[T]) RunAll() {
	tc.RunUntil(tc.OutOfMessagesPredicate())
}

// OutOfMessagesPredicate runs until all the messages will be processed.
func (tc *TestContext[T]) OutOfMessagesPredicate() func() bool {
	return func() bool { return false }
}

func (tc *TestContext[T]) PrintAllStatusStrings(prefix string, logFunc func(format string, args ...any)) {
	logFunc("TC[%p] Status, |msgs|=%v", tc, len(tc.msgs))
	keys := []NodeID{}
	for nid := range tc.nodes {
		keys = append(keys, nid)
	}
	// Print them sorted.
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})
	for _, nidStr := range keys {
		logFunc("TC[%p] %v [node=%v]: %v", tc, prefix, nidStr, tc.nodes[nidStr].StatusString())
	}
}
