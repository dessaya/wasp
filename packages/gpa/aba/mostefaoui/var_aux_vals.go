// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package mostefaoui

import (
	"fmt"

	"github.com/iotaledger/wasp/v2/packages/gpa"
)

// Here we implement the derivation of the `vals` (auxVals) variable in the following:
//
// >         ∗ wait until at least (N − f) AUX_r messages have been
// >           received, such that the set of values carried by these
// >           messages, vals are a subset of bin_values_r (note that
// >           bin_values_r may continue to change as BVAL_r messages
// >           are received, thus this condition may be triggered upon
// >           arrival of either an AUX_r or a BVAL_r message)
//
// For this we have to get updates to the binValues variable and exchange the AUX messages.
type varAuxVals struct {
	aba       *ABA
	recv      map[gpa.NodeID]bool
	ready     bool
	round     int
	sent      bool
	binValues []bool
}

func newAuxVals(aba *ABA) *varAuxVals {
	return &varAuxVals{
		aba:       aba,
		recv:      map[gpa.NodeID]bool{},
		ready:     false,
		round:     -1,
		sent:      false,
		binValues: nil,
	}
}

func (v *varAuxVals) startRound(round int) {
	v.recv = map[gpa.NodeID]bool{}
	v.ready = false
	v.round = round
	v.sent = false
	v.binValues = nil
}

// >     – wait until bin_values_r != {}, then
// >         ∗ multicast AUX_r(w) where w ∈ bin_values_r
// ...
// >                                                       (note that
// >           bin_values_r may continue to change as BVAL_r messages
// >           are received, thus this condition may be triggered upon
// >           arrival of either an AUX_r or a BVAL_r message)
func (v *varAuxVals) binValuesUpdated(binValues []bool) {
	if len(binValues) == 1 {
		v.multicast(binValues[0])
	}
	v.binValues = binValues
	v.tryOutput()
}

// >         ∗ wait until at least (N − f) AUX_r messages have been
// >           received, such that the set of values carried by these
// >           messages, vals are a subset of bin_values_r ...
func (v *varAuxVals) msgVoteAUXReceived(msg gpa.TypedMessageIn[*msgVote]) {
	if _, ok := v.recv[msg.Sender]; ok {
		return // Duplicate.
	}
	v.recv[msg.Sender] = msg.Payload.value
	v.tryOutput()
}

// >         ∗ wait until at least (N − f) AUX_r messages have been
// >           received, such that the set of values carried by these
// >           messages, vals are a subset of bin_values_r (note that
// >           bin_values_r may continue to change as BVAL_r messages
// >           are received, thus this condition may be triggered upon
// >           arrival of either an AUX_r or a BVAL_r message)
func (v *varAuxVals) tryOutput() {
	if v.ready || len(v.recv) < v.aba.n-v.aba.f || v.binValues == nil {
		return
	}
	hasBinValsT := false
	hasBinValsF := false
	for _, b := range v.binValues {
		if b {
			hasBinValsT = true
		} else {
			hasBinValsF = true
		}
	}
	count := 0
	hasAuxValsT := false
	hasAuxValsF := false
	for _, vote := range v.recv {
		if vote && hasBinValsT {
			count++
			hasAuxValsT = true
			continue
		}
		if !vote && hasBinValsF {
			hasAuxValsF = true
			count++
		}
	}
	if count >= v.aba.n-v.aba.f {
		auxVals := make([]bool, 0, 2)
		if hasAuxValsT {
			auxVals = append(auxVals, true)
		}
		if hasAuxValsF {
			auxVals = append(auxVals, false)
		}
		v.ready = true
		v.aba.uponAuxValsReady(auxVals)
	}
}

func (v *varAuxVals) multicast(value bool) {
	if v.sent {
		return
	}
	v.sent = true
	v.aba.out.PutAll(multicastMsgVote(v.aba.nodeIDs, v.round, AUX, value))
}

func (v *varAuxVals) statusString() string {
	return fmt.Sprintf("AUX(N=%v,recv=%v)", v.aba.n, len(v.recv))
}
