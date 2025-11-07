// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package gpa

import (
	"fmt"
	"time"

	"fortio.org/safecast"
	"github.com/samber/lo"

	bcs "github.com/iotaledger/bcs-go"
	"github.com/iotaledger/hive.go/ds/shrinkingmap"
)

const (
	msgTypeAckHandlerReset MessageType = iota
	msgTypeAckHandlerBatch
)

// The purpose of this wrapper is to handle unreliable network by implementing
// a RELIABLE CHANNEL abstraction. This is done by resending messages until an
// acknowledgement is received. To make this more efficient, acknowledgements
// are piggy-backed on other messages (or sent stand-alone, if there is no
// messages to piggy-back the acknowledgements).
type ackHandler[NestedGPA GPA] struct {
	me           NodeID
	out          OutBuffer
	nested       NestedGPA
	resendPeriod time.Duration
	initialized  *shrinkingmap.ShrinkingMap[NodeID, bool]
	initPending  *shrinkingmap.ShrinkingMap[NodeID, []MessagePayload]
	counters     *shrinkingmap.ShrinkingMap[NodeID, int] // For numbering the outgoing messages.
	sentUnacked  *shrinkingmap.ShrinkingMap[NodeID, *shrinkingmap.ShrinkingMap[int, *ackHandlerBatch]]
	recvAcksIn   *shrinkingmap.ShrinkingMap[NodeID, map[int]*int]
}

type AckHandler[NestedGPA GPA] interface {
	GPA
	Tick(timestamp time.Time)
	DismissPeer(peerID NodeID) // To avoid resending messages to dead peers.
	Nested() NestedGPA
}

func NewAckHandler[NestedGPA GPA](me NodeID, nested NestedGPA, resendPeriod time.Duration) AckHandler[NestedGPA] {
	return &ackHandler[NestedGPA]{
		me:           me,
		nested:       nested,
		resendPeriod: resendPeriod,
		initialized:  shrinkingmap.New[NodeID, bool](),
		initPending:  shrinkingmap.New[NodeID, []MessagePayload](),
		counters:     shrinkingmap.New[NodeID, int](),
		sentUnacked:  shrinkingmap.New[NodeID, *shrinkingmap.ShrinkingMap[int, *ackHandlerBatch]](),
		recvAcksIn:   shrinkingmap.New[NodeID, map[int]*int](),
	}
}

func (a *ackHandler[NestedGPA]) DismissPeer(peerID NodeID) {
	a.initialized.Delete(peerID)
	a.initPending.Delete(peerID)
	a.counters.Delete(peerID)
	a.sentUnacked.Delete(peerID)
	a.recvAcksIn.Delete(peerID)
}

func (a *ackHandler[NestedGPA]) Nested() NestedGPA {
	return a.nested
}

func (a *ackHandler[NestedGPA]) SwapOutBuffer() []MessageOut {
	return a.out.Swap()
}

func (a *ackHandler[NestedGPA]) Message(msg MessageIn) {
	defer a.makeBatches()

	switch msg.Payload.(type) {
	case *ackHandlerReset:
		a.handleResetMsg(AsTypedMessageIn[*ackHandlerReset](msg))
	case *ackHandlerBatch:
		a.handleBatchMsg(AsTypedMessageIn[*ackHandlerBatch](msg))
	default:
		panic(fmt.Errorf("unexpected message type: %+v", msg))
	}
}

func (a *ackHandler[NestedGPA]) StatusString() string {
	return fmt.Sprintf("{ACK:%s}", a.nested.StatusString())
}

func (a *ackHandler[NestedGPA]) UnmarshalPayload(data []byte) (MessagePayload, error) {
	msg, err := UnmarshalPayload(data, PayloadAllocator{
		msgTypeAckHandlerReset: func() MessagePayload { return &ackHandlerReset{} },
		msgTypeAckHandlerBatch: func() MessagePayload { return &ackHandlerBatch{nestedGPA: a.nested} },
	})
	if err != nil {
		fmt.Printf("ack, err=%v\n", err) // TODO: Clean this up.
	}
	return msg, err
}

func (a *ackHandler[NestedGPA]) Tick(timestamp time.Time) {
	defer a.makeBatches()

	resendOlderThan := timestamp.Add(-a.resendPeriod)
	a.sentUnacked.ForEach(func(nodeID NodeID, nodeSentUnacked *shrinkingmap.ShrinkingMap[int, *ackHandlerBatch]) bool {
		nodeSentUnacked.ForEach(func(batchID int, batch *ackHandlerBatch) bool {
			if batch.sent.IsZero() {
				// Don't resend, just mark the current timestamp.
				// We have sent it after the previous tick.
				batch.sent = timestamp
			} else if batch.sent.Before(resendOlderThan) {
				// Resend it, timeout is already passed.
				batch.sent = timestamp
				a.out.Put(NewMessageOut(nodeID, batch))
			}
			return true
		})
		return true
	})

	a.initPending.ForEachKey(func(nodeID NodeID) bool {
		a.out.Put(NewMessageOut(nodeID, &ackHandlerReset{
			response: false,
			latestID: 0,
		}))
		return true
	})
}

func (a *ackHandler[NestedGPA]) handleResetMsg(msg TypedMessageIn[*ackHandlerReset]) {
	from := msg.Sender
	if !msg.Payload.response {
		maxID := 0
		if recvAcksIn, exists := a.recvAcksIn.Get(msg.Sender); exists {
			for id := range recvAcksIn {
				if id > maxID {
					maxID = id
				}
			}
		}
		a.out.Put(NewMessageOut(msg.Sender, &ackHandlerReset{
			response: true,
			latestID: maxID,
		}))
		return
	}
	if ini, exists := a.initialized.Get(from); exists && ini {
		return
	}
	a.counters.Set(msg.Sender, msg.Payload.latestID+1)
	a.initialized.Set(msg.Sender, true)
}

func (a *ackHandler[NestedGPA]) handleBatchMsg(msgBatch TypedMessageIn[*ackHandlerBatch]) {
	//
	// Process the received acknowledgements.
	// Drop all the outgoing batches, that are now acknowledged.
	for _, ackedBatchID := range msgBatch.Payload.acks {
		if unacked, exists := a.sentUnacked.Get(msgBatch.Sender); exists {
			unacked.Delete(ackedBatchID)
		}
	}
	//
	// Was that ack-only message?
	if msgBatch.Payload.id == nil {
		// That was ack-only batch, nothing more to do with it.
		return
	}

	peerRecvAcksIn, _ := a.recvAcksIn.GetOrCreate(msgBatch.Sender, func() map[int]*int { return make(map[int]*int) })

	batchAckedIn, exists := peerRecvAcksIn[*msgBatch.Payload.id]
	if exists {
		// Was received already before.
		if batchAckedIn == nil {
			// Not acknowledged yet, just send an ack-only message for now.
			// The sender has already re-sent the message, so it waits for the ack.
			a.out.Put(NewMessageOut(msgBatch.Sender, &ackHandlerBatch{
				id:   nil,                         // That's ack-only.
				msgs: nil,                         // No payload.
				acks: []int{*msgBatch.Payload.id}, // Ack single message.
				sent: time.Time{},                 // We will not track this message, it has no payload.
			}))
			return
		}
		//
		// We have acked it already. If we have the batch with an ack, we
		// resent it. Otherwise the ack was already acked and this message
		// is outdated and can be ignored.
		peerSentUnacked, exists := a.sentUnacked.Get(msgBatch.Sender)
		if !exists {
			return
		}
		ackedBatch, exists := peerSentUnacked.Get(*batchAckedIn)
		if !exists {
			return
		}
		ackedBatch.sent = time.Now()
		a.out.Put(NewMessageOut(msgBatch.Sender, ackedBatch))
		return
	}
	//
	// That's a new batch, we have to process it.
	for _, p := range msgBatch.Payload.msgs {
		a.nested.Message(NewMessageIn(msgBatch.Sender, p))
	}

	sender, _ := a.recvAcksIn.GetOrCreate(msgBatch.Sender, func() map[int]*int { return make(map[int]*int) })
	sender[*msgBatch.Payload.id] = nil
}

func (a *ackHandler[NestedGPA]) makeBatches() {
	msgs := a.nested.SwapOutBuffer()
	groupedMsgs := lo.MapEntries(
		lo.GroupBy(msgs, func(msg MessageOut) NodeID { return msg.Recipient }),
		func(nodeID NodeID, msgsForNode []MessageOut) (NodeID, []MessagePayload) {
			return nodeID, lo.Map(msgsForNode, func(msg MessageOut, _ int) MessagePayload {
				return msg.Payload
			})
		},
	)

	// send back messages going to self
	for _, msg := range groupedMsgs[a.me] {
		a.nested.Message(NewMessageIn(a.me, msg))
	}
	delete(groupedMsgs, a.me)

	a.initPending.ForEach(func(nodeID NodeID, pending []MessagePayload) bool {
		if gr, ok := groupedMsgs[nodeID]; ok {
			groupedMsgs[nodeID] = append(gr, pending...)
		} else {
			groupedMsgs[nodeID] = pending
		}
		return true
	})
	a.initPending.Clear()

	for nodeID, batchMsgs := range groupedMsgs {
		if initialized, exists := a.initialized.Get(nodeID); !exists || !initialized {
			pending, _ := a.initPending.GetOrCreate(nodeID, func() []MessagePayload { return make([]MessagePayload, 0, 1) })
			a.initPending.Set(nodeID, append(pending, batchMsgs...))
			a.out.Put(NewMessageOut(nodeID, &ackHandlerReset{
				response: false,
				latestID: 0,
			}))
			continue
		}
		//
		// Assign batch ID.
		batchID, _ := a.counters.GetOrCreate(nodeID, func() int { return 0 })
		a.counters.Set(nodeID, batchID+1)

		//
		// Collect batches to be acknowledged and mark them as acknowledged.
		acks := []int{}
		if nodeRecvAcksIn, exists := a.recvAcksIn.Get(nodeID); exists {
			for recvBatchID, ackedIn := range nodeRecvAcksIn {
				if ackedIn == nil {
					acks = append(acks, recvBatchID)
					nodeRecvAcksIn[recvBatchID] = &batchID
				}
			}
		}
		//
		// Produce the batch and register it as unacked.
		batch := &ackHandlerBatch{
			id:   &batchID,
			acks: acks,
			msgs: batchMsgs,
			sent: time.Time{}, // Will be set after first resend, to avoid resend too early.
		}
		unackedMap, _ := a.sentUnacked.GetOrCreate(nodeID, func() *shrinkingmap.ShrinkingMap[int, *ackHandlerBatch] {
			return shrinkingmap.New[int, *ackHandlerBatch]()
		})
		unackedMap.Set(*batch.id, batch)
		a.out.Put(NewMessageOut(nodeID, batch))
	}
}

////////////////////////////////////////////////////////////////////////////////
// ackHandlerReset

type ackHandlerReset struct {
	response bool `bcs:"export"`
	latestID int  `bcs:"export"`
}

var _ MessagePayload = new(ackHandlerReset)

func (msg *ackHandlerReset) MsgType() MessageType {
	return msgTypeAckHandlerReset
}

func (msg *ackHandlerReset) String() string {
	return fmt.Sprintf("{ackHandlerReset response=%v latestID=%d}", msg.response, msg.latestID)
}

////////////////////////////////////////////////////////////////////////////////
// ackHandlerBatch

// Message conveying the message batches and acknowledgements.
type ackHandlerBatch struct {
	id        *int             // That's ACK only, if nil.
	msgs      []MessagePayload // Messages in the batch.
	acks      []int            // Acknowledged batches.
	sent      time.Time        // Transient, only used for outgoing messages, not sent to the outside.
	nestedGPA GPA              // Transient, for un-marshaling only.
}

var _ MessagePayload = new(ackHandlerBatch)

func (msg *ackHandlerBatch) MsgType() MessageType {
	return msgTypeAckHandlerBatch
}

func (msg *ackHandlerBatch) MarshalBCS(e *bcs.Encoder) error {
	e.EncodeOptional(msg.id)

	n, err := safecast.Convert[uint16](len(msg.msgs))
	if err != nil {
		return fmt.Errorf("too many nested messages to marshal: %w", err)
	}
	e.Encode(n)
	for _, p := range msg.msgs {
		msgBytes, err := MarshalPayload(p)
		if err != nil {
			return fmt.Errorf("marshaling nested payload: %w", err)
		}
		e.Encode(msgBytes)
	}

	e.Encode(msg.acks)
	return nil
}

func (msg *ackHandlerBatch) UnmarshalBCS(d *bcs.Decoder) error {
	msg.id = nil
	d.DecodeOptional(&msg.id)

	var n uint16
	d.Decode(&n)
	msg.msgs = make([]MessagePayload, n)
	for i := uint16(0); i < n; i++ {
		msgBytes := bcs.Decode[[]byte](d)
		payload, err := msg.nestedGPA.UnmarshalPayload(msgBytes)
		if err != nil {
			return fmt.Errorf("msgs[%d]: %w", i, err)
		}
		msg.msgs[i] = payload
	}

	msg.acks = bcs.Decode[[]int](d)

	return nil
}

func (msg *ackHandlerBatch) String() string {
	return fmt.Sprintf("{ackHandlerBatch id=%v msgs=%d acks=%v}", msg.id, len(msg.msgs), msg.acks)
}
