// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Package acs implements the Asynchronous Common Subset algorithm
// from the HBBFT paper:
//
// > Miller, A., Xia, Y., Croman, K., Shi, E., and Song, D. (2016). The Honey Badger of
// > BFT Protocols. In Proceedings of the 2016 ACM SIGSAC Conference on Computer
// > and Communications Security, CCS ’16, page 31–42, New York, NY, USA.
// > Association for Computing Machinery.
//
// The HBBFT paper presents the algorithm as follows:
//
// > Let {RBC_i}_N refer to N instances of the reliable broadcast protocol,
// > where P_i is the sender of RBC_i. Let {BA_i}_N refer to N instances
// > of the binary byzantine agreement protocol.
// >   • upon receiving input v_i, input v_i to RBC_i
// >   • upon delivery of v_j from RBC_j, if input has not yet been
// >     provided to BA_j, then provide input 1 to BA_j.
// >   • upon delivery of value 1 from at least N − f instances of BA,
// >     provide input 0 to each instance of BA that has not yet been
// >     provided input.
// >   • once all instances of BA have completed, let C ⊂ [1..N] be the
// >     indexes of each BA that delivered 1. Wait for the output v_j for
// >     each RBC_j such that j ∈ C. Finally output ∪_{j∈C} v_j.
//
// TODO: Erasure coding in RBC.
package acs

import (
	"fmt"
	"math"

	"github.com/iotaledger/hive.go/log"

	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/gpa/aba/mostefaoui"
	"github.com/iotaledger/wasp/v2/packages/gpa/cc"
	"github.com/iotaledger/wasp/v2/packages/gpa/rbc/bracha"
)

type Output struct {
	Values     map[gpa.NodeID][]byte
	Terminated bool
}

const (
	subsystemRBC byte = iota
	subsystemABA
)

type ACS struct {
	out     gpa.OutBuffer
	nodeIDs []gpa.NodeID       // Nodes in the consensus.
	nodeIdx map[gpa.NodeID]int // For a fast check, if peer is known.
	me      gpa.NodeID         // Our ID.
	n       int                // Number of nodes in the cluster.
	f       int                // Max number of tolerated faulty nodes.

	rbcInsts   map[gpa.NodeID]*bracha.RBC // RBC instances.
	rbcInput   bool                       // Have we provided our input?
	rbcOutputs map[gpa.NodeID][]byte      // Outputs received from the RBC.

	abaInsts   map[gpa.NodeID]*mostefaoui.ABA // ABA Instances.
	abaInputs  map[gpa.NodeID]bool            // Inputs already provided to ABAs.
	abaOutputs map[gpa.NodeID]bool            // Outputs already received from ABAs.

	output     *Output            // Output we produced.
	termCond   *uponTermCondition // Tracks the termination condition.
	msgWrapper *gpa.MsgWrapper    // Helper to wrap messages for sub-components.
	log        log.Logger         // A logger.
}

var _ gpa.GPA = &ACS{}

// New creates a new instance of the ACS protocol.
// > Let {RBC_i}_N refer to N instances of the reliable broadcast protocol,
// > where P_i is the sender of RBC_i. Let {BA_i}_N refer to N instances
// > of the binary byzantine agreement protocol.
func New(nodeIDs []gpa.NodeID, me gpa.NodeID, f int, ccCreateFun func(node gpa.NodeID, round int) cc.CommonCoin, log log.Logger) *ACS {
	nodeIdx := map[gpa.NodeID]int{}
	rbcInsts := map[gpa.NodeID]*bracha.RBC{}
	abaInsts := map[gpa.NodeID]*mostefaoui.ABA{}
	for i, nid := range nodeIDs {
		nidCopy := nid
		ccCreateFunForNode := func(round int) cc.CommonCoin {
			return ccCreateFun(nidCopy, round)
		}
		nodeIdx[nid] = i
		rbcInsts[nid] = bracha.New(nodeIDs, f, me, nid, math.MaxInt, func(b []byte) bool { return true }, log) // TODO: MaxInt.
		abaInsts[nid] = mostefaoui.New(nodeIDs, me, f, ccCreateFunForNode, log)
	}

	n := len(nodeIDs)
	a := &ACS{
		nodeIDs:    nodeIDs,
		nodeIdx:    nodeIdx,
		me:         me,
		n:          n,
		f:          f,
		rbcInsts:   rbcInsts,
		rbcInput:   false,
		rbcOutputs: map[gpa.NodeID][]byte{},
		abaInsts:   abaInsts,
		abaInputs:  map[gpa.NodeID]bool{},
		abaOutputs: map[gpa.NodeID]bool{},
		output:     nil,
		log:        log,
	}
	a.termCond = newUponTermCondition(a)
	a.msgWrapper = gpa.NewMsgWrapper(msgTypeWrapped, a.selectSubsystem)
	return a
}

func (a *ACS) SwapOutBuffer() []gpa.MessageOut {
	return a.out.Swap()
}

// Helper for routing messages to sub-protocols (i.e. RBC and ABA instances).
func (a *ACS) selectSubsystem(subsystem byte, index int) (gpa.GPA, error) {
	if index < 0 || index >= a.n {
		return nil, fmt.Errorf("unexpected index=%v for subsystem", index)
	}
	nid := a.nodeIDs[index]
	switch subsystem {
	case subsystemRBC:
		return a.rbcInsts[nid], nil
	case subsystemABA:
		return a.abaInsts[nid], nil
	}
	return nil, fmt.Errorf("unexpected subsystem=%v, index=%v", subsystem, index)
}

// Input implements the gpa.GPA interface:
// >   • upon receiving input v_i, input v_i to RBC_i
func (a *ACS) Input(v []byte) {
	if a.rbcInput {
		return // Duplicate input.
	}

	a.rbcInput = true
	rbc := a.rbcInsts[a.me]
	rbc.Input(v)
	a.tryHandleRBCOutput(a.me, rbc)
}

func (a *ACS) Message(msg gpa.MessageIn) {
	msgT, ok := msg.Payload.(*gpa.WrappingMsg)
	if !ok {
		a.log.LogWarnf("unexpected message of type %T: %+v", msg, msg)
		return
	}
	err := a.msgWrapper.DelegateMessageIn(gpa.AsTypedMessageIn[*gpa.WrappingMsg](msg))
	if err != nil {
		a.log.LogWarnf("cannot delegate a message: %v", err)
		return
	}
	nid := a.nodeIDs[msgT.Index()]
	switch msgT.Subsystem() {
	case subsystemRBC:
		sub := a.rbcInsts[nid]
		a.tryHandleRBCOutput(nid, sub)
	case subsystemABA:
		sub := a.abaInsts[nid]
		a.tryHandleABAOutput(nid, sub)
	default:
		a.log.LogWarnf("unexpected subsystem: %v", msgT.Subsystem())
		return
	}
}

// >   • upon delivery of v_j from RBC_j, if input has not yet been
// >     provided to BA_j, then provide input 1 to BA_j.
func (a *ACS) tryHandleRBCOutput(nodeID gpa.NodeID, rbcInst *bracha.RBC) {
	subMsgs, err := a.msgWrapper.WrapMessagesOut(subsystemRBC, a.nodeIdx[nodeID])
	if err != nil {
		panic(fmt.Errorf("cannot wrap RBC messages: %w", err))
	}
	a.out.PutAll(subMsgs)

	out := rbcInst.Output()
	if out == nil {
		return // Output not ready yet.
	}
	if _, ok := a.rbcOutputs[nodeID]; ok {
		return // Already handled.
	}
	a.rbcOutputs[nodeID] = out
	a.tryOutput()

	if _, ok := a.abaInputs[nodeID]; ok {
		return // We already provided an input to the ABA.
	}
	a.abaInputs[nodeID] = true
	aba := a.abaInsts[nodeID]
	aba.Input(true)
	a.tryHandleABAOutput(nodeID, aba)
}

// >   • upon delivery of value 1 from at least N − f instances of BA,
// >     provide input 0 to each instance of BA that has not yet been
// >     provided input.
func (a *ACS) tryHandleABAOutput(nodeID gpa.NodeID, abaInst *mostefaoui.ABA) {
	subMsgs, err := a.msgWrapper.WrapMessagesOut(subsystemABA, a.nodeIdx[nodeID])
	if err != nil {
		panic(fmt.Errorf("cannot wrap ABA messages: %w", err))
	}
	a.out.PutAll(subMsgs)

	abaOut := abaInst.Output()
	if abaOut == nil {
		return // Output not ready yet.
	}
	if abaOut.Terminated {
		a.termCond.abaTerminated(nodeID)
	}

	if _, ok := a.abaOutputs[nodeID]; ok {
		return // Already handled.
	}
	a.abaOutputs[nodeID] = abaOut.Value
	a.tryOutput()
	//
	// Provide false as inputs to all the remaining ABAs, if we have N-F ABA outputs.
	if len(a.abaOutputs) < a.n-a.f || len(a.abaInputs) == a.n {
		return
	}
	count := 0
	for _, abaOut := range a.abaOutputs {
		if abaOut {
			count++
		}
	}
	if count >= a.n-a.f {
		for _, nid := range a.nodeIDs {
			if _, ok := a.abaInputs[nid]; ok {
				continue // Input was already provided.
			}
			a.abaInputs[nid] = false
			aba := a.abaInsts[nid]
			aba.Input(false)
			a.tryHandleABAOutput(nid, aba)
		}
	}
}

// >   • once all instances of BA have completed, let C ⊂ [1..N] be the
// >     indexes of each BA that delivered 1. Wait for the output v_j for
// >     each RBC_j such that j ∈ C. Finally output ∪_{j∈C} v_j.
func (a *ACS) tryOutput() {
	if a.output != nil {
		return // Output already provided.
	}
	if len(a.abaOutputs) < a.n {
		return // Not all ABAs have provided an output.
	}
	values := map[gpa.NodeID][]byte{}
	for nid, abaOut := range a.abaOutputs {
		if abaOut {
			if rbcOut, ok := a.rbcOutputs[nid]; ok {
				values[nid] = rbcOut
				continue
			}
			return // Some RBC output are still missing.
		}
	}
	a.output = &Output{
		Values:     values,
		Terminated: a.termCond.canTerminate(),
	}
}

func (a *ACS) uponTermCondition() []gpa.MessageOut {
	if a.output != nil {
		a.output.Terminated = true
	}
	return nil
}

func (a *ACS) Output() *Output {
	return a.output
}

func (a *ACS) StatusString() string {
	if a.output != nil {
		return fmt.Sprintf(
			"{ACS, |outVals|=%v, outTerm=%+v, n=%v, f=%v, |rbcOut|=%v, |abaOut|=%v}",
			len(a.output.Values), a.output.Terminated, a.n, a.f, len(a.rbcOutputs), len(a.abaOutputs),
		)
	}
	return fmt.Sprintf(
		"{ACS, out=nil, n=%v, f=%v, |rbcOut|=%v, |abaOut|=%v}",
		a.n, a.f, len(a.rbcOutputs), len(a.abaOutputs),
	)
}
