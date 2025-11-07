// Copyright 2020 IOTA Stiftung

// Package mostefaoui implements the Mostefaoui ABA consensus algorithm
// SPDX-License-Identifier: Apache-2.0
//
// Here we implement the Asynchronous Byzantine Binary Agreement by
// Mostefaoui et al., as described in the HBBFT paper:
//
// > Miller, A., Xia, Y., Croman, K., Shi, E., and Song, D. (2016). The Honey Badger of
// > BFT Protocols. In Proceedings of the 2016 ACM SIGSAC Conference on Computer
// > and Communications Security, CCS ’16, page 31–42, New York, NY, USA.
// > Association for Computing Machinery.
//
// The original paper by Mostefaoui is:
//
// > A. Mostefaoui, H. Moumen, and M. Raynal. Signature-free
// > asynchronous byzantine consensus with t< n/3 and o (n 2)
// > messages. In Proceedings of the 2014 ACM symposium on
// > Principles of distributed computing, pages 2–9. ACM, 2014.
//
// The HBBFT paper presents the algorithm as follows:
//
// > • upon receiving input b_input, set est_0 := b_input and proceed as
// >   follows in consecutive epochs, with increasing labels r:
// >     – multicast BVAL_r(est_r)
// >     – bin_values_r := {}
// >     – upon receiving BVAL_r(b) messages from f + 1 nodes, if
// >       BVAL_r(b) has not been sent, multicast BVAL_r(b)
// >     – upon receiving BVAL_r(b) messages from 2f + 1 nodes,
// >       bin_values_r := bin_values_r ∪ {b}
// >     – wait until bin_values_r != {}, then
// >         ∗ multicast AUX_r(w) where w ∈ bin_values_r
// >         ∗ wait until at least (N − f) AUX_r messages have been
// >           received, such that the set of values carried by these
// >           messages, vals are a subset of bin_values_r (note that
// >           bin_values_r may continue to change as BVAL_r messages
// >           are received, thus this condition may be triggered upon
// >           arrival of either an AUX_r or a BVAL_r message)
// >         ∗ s ← Coin_r.GetCoin()
// >         ∗ if vals = {b}, then
// >             · est_r+1 := b
// >             · if (b = s%2) then output b
// >         ∗ else est_r+1 := s%2
// > • continue looping until both a value b is output in some round r,
// >   and the value Coin_r' = b for some round r' > r.
//
// Additionally we add the STOP messages to make this algorithm terminating.
// The STOP messages are discussed in the original paper by Mostefaoui.
//
// This implementation is split to several parts to handle various rance
// conditions easier.
//
//   - varBinVals -- maintains the binValues variable and handles the BVAL messages.
//   - varAuxVals -- maintains the `vars` variable and handles the AUX messages.
//   - varDone -- tracks the termination condition for the algorithm.
//   - uponDecisionInputs -- a predicate waiting for the CC and AuxVals to be ready.
//
// All these parts are independent of each-other and are wired-up in this file.
// With these parts defined, the overall algorithm can be rephrased as follows:
//
// > • upon receiving input b_input, set est_0 := b_input and proceed as
// >   follows in consecutive epochs, with increasing labels r:
// >     - start the round r (for varBinVals, CC and others).
// >     - on each varBinVals update pass it to varAuxVals.
// >     - wait until varAuxVals != {} and s ← Coin_r.GetCoin()
// >         ∗ if vals = {b}, then
// >             · est_r+1 := b
// >             · if (b = s%2) then output b
// >         ∗ else est_r+1 := s%2
// > • continue looping varDone is true.
package mostefaoui

import (
	"fmt"

	"github.com/iotaledger/hive.go/log"

	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/gpa/cc"
)

// Output is the structure provided as an output of the algorithm.
// If the value is undecided, untyped nil is returned.
// The Terminate field indicates, if this algorithm can be
// dropped (no other peers need any messages from this node).
type Output struct {
	Value      bool
	Terminated bool
}

// ABA is the public API for this protocol.
const (
	subsystemCC byte = iota
)

type ABA struct {
	out                gpa.OutBuffer
	nodeIDs            []gpa.NodeID                   // Nodes in the consensus.
	me                 gpa.NodeID                     // this node
	n                  int                            // len(nodeIDs)
	f                  int                            // maximum faulty nodes
	nodeIdx            map[gpa.NodeID]bool            // For a fast check, if peer is known.
	round              int                            // The current round.
	varBinVals         *varBinVals                    // The `binValues` variable (based on BVAL msgs).
	varAuxVals         *varAuxVals                    // The `vals` variable (based on AUX msgs).
	varDone            *varDone                       // Termination condition.
	uponDecisionInputs *uponDecisionInputs            // Decision condition.
	ccInsts            []cc.CommonCoin                // Common coin instances for all the rounds.
	ccCreateFun        func(round int) cc.CommonCoin  // Function to create CC instances.
	output             *Output                        // The current output of the algorithm.
	postponedMsgs      []gpa.TypedMessageIn[*msgVote] // Buffer for future round messages.
	msgWrapper         *gpa.MsgWrapper                // Helper to wrap messages for sub-components.
	log                log.Logger                     // A logger.
}

var _ gpa.GPA = &ABA{}

// New creates a single node for a consensus.
//
// Here `ccCreateFun` is used as a factory function to create Common Coin instances for each round.
// This way this implementation is made independent of particular CC instance. The created CC
// is expected to take `nil` inputs and produce `*bool` outputs.
func New(nodeIDs []gpa.NodeID, me gpa.NodeID, f int, ccCreateFun func(round int) cc.CommonCoin, log log.Logger) *ABA {
	nodeIdx := map[gpa.NodeID]bool{}
	for _, n := range nodeIDs {
		nodeIdx[n] = true
	}
	a := &ABA{
		nodeIDs:       nodeIDs,
		me:            me,
		n:             len(nodeIDs),
		f:             f,
		nodeIdx:       nodeIdx,
		round:         -1,
		ccInsts:       []cc.CommonCoin{},
		ccCreateFun:   ccCreateFun,
		output:        nil,
		postponedMsgs: []gpa.TypedMessageIn[*msgVote]{},
		log:           log,
	}
	a.varBinVals = newBinVals(a)
	a.varAuxVals = newAuxVals(a)
	a.varDone = newVarDone(a, log)
	a.uponDecisionInputs = newUponDecisionInputs(a)
	a.msgWrapper = gpa.NewMsgWrapper(msgTypeWrapped, a.selectSubsystem)
	return a
}

func (a *ABA) SwapOutBuffer() []gpa.MessageOut {
	return a.out.Swap()
}

// Helper for routing messages to sub-protocols (i.e. CC instances).
func (a *ABA) selectSubsystem(subsystem byte, index int) (gpa.GPA, error) {
	if subsystem == subsystemCC {
		if index > a.round+10 {
			return nil, fmt.Errorf("cc round=%v to far in future, our round=%v", index, a.round)
		}
		return a.ccInst(index), nil
	}
	return nil, fmt.Errorf("unexpected subsystem=%v, index=%v", subsystem, index)
}

// Creates and returns a CC instance for a particular round.
// CC instances are not cleaned up, as the algorithm is supposed to terminate in few rounds.
func (a *ABA) ccInst(round int) cc.CommonCoin {
	if round >= len(a.ccInsts) {
		add := make([]cc.CommonCoin, round-len(a.ccInsts)+1)
		a.ccInsts = append(a.ccInsts, add...)
	}
	if a.ccInsts[round] == nil {
		a.ccInsts[round] = a.ccCreateFun(round)
	}
	return a.ccInsts[round]
}

// > • upon receiving input b_input, set est_0 := b_input and proceed as
// >   follows in consecutive epochs, with increasing labels r:
func (a *ABA) Input(v bool) {
	if a.round != -1 {
		panic(fmt.Errorf("duplicate input to ABA: %v", v))
	}
	a.startRound(0, v)
}

// Advances the algorithm to the next round.
//
// >     – multicast BVAL_r(est_r)
// >     – bin_values_r := {}
func (a *ABA) startRound(round int, est bool) {
	if a.output != nil && a.output.Terminated {
		// Don't start the next round if the algorithm is already terminated.
		return
	}
	if round != a.round+1 {
		panic(fmt.Errorf("non-sequential rounds %v->%v", a.round, round))
	}
	a.round = round
	a.varAuxVals.startRound(a.round)
	a.varDone.startRound(round)
	a.uponDecisionInputs.startRound()
	a.varBinVals.startRound(a.round, est)
	//
	// Start the CC.
	ccInst := a.ccInst(round)
	ccInst.Input()
	subMsgs, err := a.msgWrapper.WrapMessagesOut(subsystemCC, round)
	if err != nil {
		panic(fmt.Errorf("wrapping CC messages for round %v: %w", round, err))
	}
	a.out.PutAll(subMsgs)
	if out := ccInst.Output(); out != nil {
		a.uponDecisionInputs.ccOutputReceived(*out)
	}
	//
	// Resend postponed messages, if any.
	if len(a.postponedMsgs) > 0 {
		oldPostponedMsgs := a.postponedMsgs
		a.postponedMsgs = []gpa.TypedMessageIn[*msgVote]{}
		for _, m := range oldPostponedMsgs {
			a.handleMsgVote(m)
		}
	}
}

// Message implements the gpa.GPA interface.
// Here we only route the messages to appropriate objects.
func (a *ABA) Message(msg gpa.MessageIn) {
	switch msg.Payload.(type) {
	case *msgVote: // The BVAL and AUX messages.
		a.handleMsgVote(gpa.AsTypedMessageIn[*msgVote](msg))
	case *msgDone: // The DONE messages for the termination.
		a.handleMsgDone(gpa.AsTypedMessageIn[*msgDone](msg))
	case *gpa.WrappingMsg: // The CC messages.
		a.handleMsgWrapped(gpa.AsTypedMessageIn[*gpa.WrappingMsg](msg))
	}
	a.log.LogWarnf("unexpected message of type %T: %+v", msg, msg)
}

func (a *ABA) handleMsgVote(msgT gpa.TypedMessageIn[*msgVote]) {
	if _, ok := a.nodeIdx[msgT.Sender]; !ok {
		a.log.LogWarnf("unknown sender: %+v", msgT)
		return // Unknown sender.
	}
	if msgT.Payload.round < a.round || (a.output != nil && a.output.Terminated) {
		return // Outdated message.
	}
	if msgT.Payload.round > a.round {
		a.postponedMsgs = append(a.postponedMsgs, msgT)
		return // Will be processed later.
	}
	switch msgT.Payload.voteType {
	case BVAL:
		a.varBinVals.msgVoteBVALReceived(msgT)
	case AUX:
		a.varAuxVals.msgVoteAUXReceived(msgT)
	}
	a.log.LogWarnf("unexpected msgVote message: %+v", msgT)
}

func (a *ABA) handleMsgDone(msgT gpa.TypedMessageIn[*msgDone]) {
	if _, ok := a.nodeIdx[msgT.Sender]; !ok {
		return // Unknown sender.
	}
	a.varDone.msgDoneReceived(msgT)
}

func (a *ABA) handleMsgWrapped(msgT gpa.TypedMessageIn[*gpa.WrappingMsg]) {
	err := a.msgWrapper.DelegateMessageIn(msgT)
	if err != nil {
		a.log.LogWarnf("cannot select subsystem: %v", err)
		return
	}

	subMsgs, err := a.msgWrapper.WrapMessagesOut(msgT.Payload.Subsystem(), msgT.Payload.Index())
	if err != nil {
		a.log.LogWarnf("wrapping messages out for subsystem %v index %v: %v", msgT.Payload.Subsystem(), msgT.Payload.Index(), err)
		return
	}
	a.out.PutAll(subMsgs)

	if msgT.Payload.Subsystem() == subsystemCC && msgT.Payload.Index() == a.round && !a.uponDecisionInputs.haveCC() {
		ccOut := a.ccInst(a.round).Output()
		if ccOut != nil {
			a.uponDecisionInputs.ccOutputReceived(*ccOut)
		}
	}
}

// >     – wait until bin_values_r != {}, then
// >         ∗ multicast AUX_r(w) where w ∈ bin_values_r
// >         ∗ wait until at least (N − f) AUX_r messages have been
// >           received, such that the set of values carried by these
// >           messages, vals are a subset of bin_values_r (note that
// >           bin_values_r may continue to change as BVAL_r messages
// >           are received, thus this condition may be triggered upon
// >           arrival of either an AUX_r or a BVAL_r message)
func (a *ABA) uponBinValuesUpdated(binValues []bool) {
	a.varAuxVals.binValuesUpdated(binValues)
}

// >         ∗ wait until at least (N − f) AUX_r messages have been
// >           received, such that the set of values carried by these
// >           messages, vals are a subset of bin_values_r (note that
// >           bin_values_r may continue to change as BVAL_r messages
// >           are received, thus this condition may be triggered upon
// >           arrival of either an AUX_r or a BVAL_r message)
func (a *ABA) uponAuxValsReady(auxVals []bool) {
	a.uponDecisionInputs.auxValsReady(auxVals)
}

// >         ∗ if vals = {b}, then
// >             · est_r+1 := b
// >             · if (b = s%2) then output b
// >         ∗ else est_r+1 := s%2
func (a *ABA) uponDecisionInputsReceived(cc bool, auxVals []bool) {
	if len(auxVals) == 1 {
		nextEst := auxVals[0]
		if nextEst == cc {
			if a.output == nil {
				a.output = &Output{Value: nextEst, Terminated: a.varDone.isDone()}
			}
			a.varDone.outputProduced()
			a.startRound(a.round+1, nextEst)
		} else {
			a.startRound(a.round+1, nextEst)
		}
	} else {
		a.startRound(a.round+1, cc)
	}
}

// Here we get notification from `varDone` on the termination.
func (a *ABA) uponTerminationCondition() {
	if a.output != nil {
		a.output.Terminated = true
	}
}

// Output implements the gpa.GPA interface.
func (a *ABA) Output() *Output {
	return a.output
}

// StatusString implements the gpa.GPA interface.
func (a *ABA) StatusString() string {
	return fmt.Sprintf(
		"{ABA:Mostefaoui, R=%v, %v, %v, %v, %v, out=%+v}",
		a.round,
		a.varBinVals.statusString(),
		a.varAuxVals.statusString(),
		a.uponDecisionInputs.statusString(),
		a.varDone.statusString(),
		a.output,
	)
}
