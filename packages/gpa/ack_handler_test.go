// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package gpa

import (
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	bcs "github.com/iotaledger/bcs-go"
)

func TestAckHandler(t *testing.T) {
	t.Parallel()
	n := 10
	nodeIDs := MakeTestNodeIDs(n)
	nodes := map[NodeID]AckHandler[*TestRound]{}
	for _, nid := range nodeIDs {
		nodes[nid] = NewAckHandler(nid, NewTestRound(nodeIDs, nid), 10*time.Millisecond)
	}
	tc := NewTestContext(nodes).
		WithMessageDeliveryProbability(0.5) // NOTE: The AckHandler has to compensate this.
	tc.RunAll()
	//
	// Tick the timer until all the messages are delivered.

	for _, nid := range nodeIDs {
		nodes[nid].Nested().MakeRound()
	}
	for {
		allCompleted := lo.EveryBy(lo.Values(nodes), func(node AckHandler[*TestRound]) bool {
			return node.Nested().Output()
		})
		if allCompleted {
			break
		}

		timestamp := time.Now()
		for _, nid := range nodeIDs {
			nodes[nid].Tick(timestamp)
		}

		tc.RunAll()
	}
}

func TestAckHandlerBatchCodec(t *testing.T) {
	testMsgs := []ackHandlerBatch{
		{
			id: lo.ToPtr(42),
			msgs: []MessagePayload{
				&TestMessage{ID: 50},
				&TestMessage{ID: 100},
			},
			acks:      []int{1, 2, 3},
			nestedGPA: &testGPA{},
		},
		{
			id:        lo.ToPtr(42),
			msgs:      []MessagePayload{},
			acks:      []int{1, 2, 3},
			nestedGPA: &testGPA{},
		},
		{
			id:        lo.ToPtr(42),
			msgs:      nil,
			acks:      []int{1, 2, 3},
			nestedGPA: &testGPA{},
		},
	}

	for _, v := range testMsgs {
		vEnc := bcs.MustMarshal(&v)
		vDec := bcs.MustUnmarshalInto(vEnc, &ackHandlerBatch{nestedGPA: &testGPA{}})
		if len(v.msgs) == 0 {
			require.Len(t, vDec.msgs, 0)
			vDec.msgs = v.msgs
		}
		require.Equal(t, v, *vDec, vEnc)

		v.id = nil
		vEnc = bcs.MustMarshal(&v)
		vDec = bcs.MustUnmarshalInto(vEnc, &ackHandlerBatch{nestedGPA: &testGPA{}})
		if len(v.msgs) == 0 {
			require.Len(t, vDec.msgs, 0)
			vDec.msgs = v.msgs
		}
		require.Equal(t, v, *vDec, vEnc)
	}
}

type testGPA struct {
	GPA
}

var _ GPA = &testGPA{}

func (g *testGPA) UnmarshalPayload(data []byte) (MessagePayload, error) {
	return UnmarshalPayload(data, PayloadAllocator{
		msgTypeTest: func() MessagePayload { return &TestMessage{} },
	}, nil)
}

func TestAckHandlerResetCodec(t *testing.T) {
	bcs.TestCodecAndHash(t, ackHandlerReset{
		response: true,
		latestID: 123,
	}, "85add3e79841")
}
