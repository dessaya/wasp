// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package actors

import (
	"fmt"

	"github.com/samber/lo"

	"github.com/iotaledger/wasp/v2/packages/hashing"
)

// ReliableBroadcast implements Bracha's Reliable Broadcast.
// The original version of this RBC can be found here (see "FIG. 1. The broadcast primitive"):
//
//	Gabriel Bracha. 1987. Asynchronous byzantine agreement protocols. Inf. Comput.
//	75, 2 (November 1, 1987), 130–143. DOI:https://doi.org/10.1016/0890-5401(87)90054-X
//
// Here we follow the algorithm presentation from (see "Algorithm 2 Bracha’s RBC [14]"):
//
//	Sourav Das, Zhuolun Xiang, and Ling Ren. 2021. Asynchronous Data Dissemination
//	and its Applications. In Proceedings of the 2021 ACM SIGSAC Conference on Computer
//	and Communications Security (CCS '21). Association for Computing Machinery,
//	New York, NY, USA, 2705–2721. DOI:https://doi.org/10.1145/3460120.3484808
//
// The algorithms differs a bit. The latter supports predicates and also it don't
// imply sending ECHO messages upon receiving F+1 READY messages. The pseudo-code
// from the Das et al.:
//
//	01: // only broadcaster node
//	02: input 𝑀
//	03: send ⟨PROPOSE, 𝑀⟩ to all
//	04: // all nodes
//	05: input 𝑃(·) // predicate 𝑃(·) returns true unless otherwise specified.
//	06: upon receiving ⟨PROPOSE, 𝑀⟩ from the broadcaster do
//	07:     if 𝑃(𝑀) then
//	08:         send ⟨ECHO, 𝑀⟩ to all
//	09: upon receiving 2𝑡 + 1 ⟨ECHO, 𝑀⟩ messages and not having sent a READY message do
//	10:     send ⟨READY, 𝑀⟩ to all
//	11: upon receiving 𝑡 + 1 ⟨READY, 𝑀⟩ messages and not having sent a READY message do
//	12:     send ⟨READY, 𝑀⟩ to all
//	13: upon receiving 2𝑡 + 1 ⟨READY, 𝑀⟩ messages do
//	14:     output 𝑀
//
// In the above 𝑡 is "Given a network of 𝑛 nodes, of which up to 𝑡 could be malicious",
// thus that's the parameter F in the specification below.
type ReliableBroadcast struct {
	Actor
	Output      *Output[[]byte]
	f           int
	broadcaster NodeID
}

type (
	msgPropose struct {
		m []byte `bcs:"export"`
	}
	msgEcho struct {
		m []byte `bcs:"export"`
	}
	msgReady struct {
		m []byte `bcs:"export"`
	}
)

func (m *msgPropose) MsgType() MessageType { return 0 }
func (m *msgPropose) String() string       { return fmt.Sprintf("PROPOSE(%q)", lo.Ellipsis(string(m.m), 16)) }
func (m *msgEcho) MsgType() MessageType    { return 1 }
func (m *msgEcho) String() string          { return fmt.Sprintf("ECHO(%q)", lo.Ellipsis(string(m.m), 16)) }
func (m *msgReady) MsgType() MessageType   { return 2 }
func (m *msgReady) String() string         { return fmt.Sprintf("READY(%q)", lo.Ellipsis(string(m.m), 16)) }

func NewReliableBroadcast(
	endpoint *Endpoint,
	f int,
	broadcaster NodeID,
) *ReliableBroadcast {
	return &ReliableBroadcast{
		Actor:       NewActor(endpoint),
		Output:      NewOutput[[]byte](endpoint.Context()),
		f:           f,
		broadcaster: broadcaster,
	}
}

// Broadcast implements the reliable broadcast algorithm from the broadcaster's side.
func (r *ReliableBroadcast) Broadcast(m []byte) {
	if r.Endpoint().Me() != r.broadcaster {
		panic("only broadcaster can call Broadcast")
	}
	r.Go(func() {
		//	01: // only broadcaster node
		//	02: input 𝑀
		//	03: send ⟨PROPOSE, 𝑀⟩ to all
		r.Endpoint().SendToAll(&msgPropose{m: m})
		r.receive()
	})
}

// Receive implements the reliable broadcast algorithm for all nodes.
func (r *ReliableBroadcast) Receive() {
	r.Go(func() {
		r.receive()
	})
}

func (r *ReliableBroadcast) receive() {
	readySent := false
	sendReady := func(m []byte) {
		if !readySent {
			r.Endpoint().SendToAll(&msgReady{m: m})
			readySent = true
		}
	}

	echoCounters := make(map[hashing.HashValue]map[NodeID]bool)
	readyCounters := make(map[hashing.HashValue]map[NodeID]bool)
	counter := func(m map[hashing.HashValue]map[NodeID]bool, v []byte) map[NodeID]bool {
		hash := hashing.HashData(v)
		c := m[hash]
		if c == nil {
			c = make(map[NodeID]bool)
			m[hash] = c
		}
		return c
	}

	for {
		msg := r.Endpoint().Receive(func() {
			r.Log().Info("status",
				"readySent", readySent,
				"echoCounters", len(echoCounters),
				"readyCounters", len(readyCounters),
				"output", r.Output.IsReady(),
			)
		})

		switch payload := msg.Payload.(type) {
		//	06: upon receiving ⟨PROPOSE, 𝑀⟩ from the broadcaster do
		//	07:     if 𝑃(𝑀) then // (ignoring predicate in this implementation)
		//	08:         send ⟨ECHO, 𝑀⟩ to all
		case *msgPropose:
			if msg.Sender != r.broadcaster {
				r.Log().Warn("RBC: ignoring PROPOSE from non-broadcaster", "sender", msg.Sender.String())
				continue
			}
			r.Endpoint().SendToAll(&msgEcho{m: payload.m})

		//	09: upon receiving 2𝑡 + 1 ⟨ECHO, 𝑀⟩ messages and not having sent a READY message do
		//	10:     send ⟨READY, 𝑀⟩ to all
		case *msgEcho:
			echoReceived := counter(echoCounters, payload.m)
			if !echoReceived[msg.Sender] {
				echoReceived[msg.Sender] = true
				if len(echoReceived) == 2*r.f+1 {
					sendReady(payload.m)
				}
			}

		//	11: upon receiving 𝑡 + 1 ⟨READY, 𝑀⟩ messages and not having sent a READY message do
		//	12:     send ⟨READY, 𝑀⟩ to all
		//	13: upon receiving 2𝑡 + 1 ⟨READY, 𝑀⟩ messages do
		//	14:     output 𝑀
		case *msgReady:
			readyReceived := counter(readyCounters, payload.m)
			if !readyReceived[msg.Sender] {
				readyReceived[msg.Sender] = true
				switch len(readyReceived) {
				case 2*r.f + 1:
					r.Output.Set(payload.m)
				case r.f + 1:
					sendReady(payload.m)
				}
			}

		default:
			r.Log().Warn("ReliableBroadcast: unexpected message", "type", msg.Payload.MsgType(), "sender", msg.Sender.String())
		}
	}
}
