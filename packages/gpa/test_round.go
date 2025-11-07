// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package gpa

import (
	"errors"
	"fmt"
)

const (
	msgTypeTestRound MessageType = iota
)

// A protocol for testing infrastructure.
// A peer outputs true when it receives a message from each peer.
type TestRound struct {
	me       NodeID
	out      OutBuffer
	nodeIDs  []NodeID
	received map[NodeID]bool
}

var _ GPA = &TestRound{}

func NewTestRound(nodeIDs []NodeID, me NodeID) *TestRound {
	return &TestRound{me: me, nodeIDs: nodeIDs, received: map[NodeID]bool{}}
}

func (tr *TestRound) SwapOutBuffer() []MessageOut {
	return tr.out.Swap()
}

func (tr *TestRound) MakeRound() {
	for _, nid := range tr.nodeIDs {
		tr.out.Put(NewMessageOut(nid, &testRoundMsg{}))
	}
}

func (tr *TestRound) Message(msg MessageIn) {
	from := msg.Sender
	if tr.received[from] {
		panic(errors.New("duplicate message"))
	}
	tr.received[from] = true
}

func (tr *TestRound) Output() bool {
	return len(tr.received) == len(tr.nodeIDs)
}

func (tr *TestRound) StatusString() string {
	return fmt.Sprintf("{TestRound, received=%v}", tr.received)
}

func (tr *TestRound) UnmarshalPayload(data []byte) (MessagePayload, error) {
	return UnmarshalPayload(data, PayloadAllocator{
		msgTypeTestRound: func() MessagePayload { return &testRoundMsg{} },
	})
}

type testRoundMsg struct{}

var _ MessagePayload = new(testRoundMsg)

func (msg *testRoundMsg) MsgType() MessageType {
	return msgTypeTestRound
}

func (msg *testRoundMsg) String() string {
	return "{testRoundMsg}"
}
