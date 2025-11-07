// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package mostefaoui

import (
	"fmt"

	"github.com/iotaledger/wasp/v2/packages/gpa"
)

// Represents the `binValues` variable and sends/handles the BVAL messages.
// This type implements the following logic from the algorithm:
//
// >     – multicast BVAL_r(est_r)
// >     – bin_values_r := {}
// >     – upon receiving BVAL_r(b) messages from f + 1 nodes, if
// >       BVAL_r(b) has not been sent, multicast BVAL_r(b)
// >     – upon receiving BVAL_r(b) messages from 2f + 1 nodes,
// >       bin_values_r := bin_values_r ∪ {b}
// >     – wait until bin_values_r != {}, then
type varBinVals struct {
	aba       *ABA
	round     int
	est       bool
	recvT     map[gpa.NodeID]bool
	recvF     map[gpa.NodeID]bool
	sentT     bool
	sentF     bool
	binValues []bool
}

func newBinVals(aba *ABA) *varBinVals {
	return &varBinVals{aba: aba}
}

// >     – multicast BVAL_r(est_r)
// >     – bin_values_r := {}
func (v *varBinVals) startRound(round int, est bool) {
	v.round = round
	v.est = est
	v.recvT = map[gpa.NodeID]bool{}
	v.recvF = map[gpa.NodeID]bool{}
	v.sentT = false
	v.sentF = false
	v.binValues = []bool{}
	v.multicast(v.est)
}

// >     – upon receiving BVAL_r(b) messages from f + 1 nodes, if
// >       BVAL_r(b) has not been sent, multicast BVAL_r(b)
// >     – upon receiving BVAL_r(b) messages from 2f + 1 nodes,
// >       bin_values_r := bin_values_r ∪ {b}
// >     – wait until bin_values_r != {}, then
func (v *varBinVals) msgVoteBVALReceived(msg gpa.TypedMessageIn[*msgVote]) {
	recv := v.recv(msg.Payload.value) // NOTE: A reference to a field.

	if ok := recv[msg.Sender]; ok {
		return // Duplicate.
	}
	recv[msg.Sender] = true

	if len(recv) == v.aba.f+1 {
		v.multicast(msg.Payload.value) // This checks, if already sent.
	}

	if len(recv) == 2*v.aba.f+1 {
		v.binValues = append(v.binValues, msg.Payload.value)
		v.aba.uponBinValuesUpdated(v.binValues)
	}
	return
}

// Misc helpers.

func (v *varBinVals) sent(value bool) *bool {
	if value {
		return &v.sentT
	}
	return &v.sentF
}

func (v *varBinVals) recv(value bool) map[gpa.NodeID]bool {
	if value {
		return v.recvT
	}
	return v.recvF
}

func (v *varBinVals) multicast(value bool) {
	sent := v.sent(value)
	if *sent {
		return
	}
	*sent = true
	v.aba.out.PutAll(multicastMsgVote(v.aba.nodeIDs, v.round, BVAL, value))
}

func (v *varBinVals) statusString() string {
	return fmt.Sprintf("BIN(N=%v,T=%v,F=%v)", v.aba.n, len(v.recvT), len(v.recvF))
}
