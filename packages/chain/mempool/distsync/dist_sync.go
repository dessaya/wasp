// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Package distsync implements distributed synchronization mechanisms for the mempool.
package distsync

import (
	"context"
	"fmt"
	"math/rand"
	"slices"

	"github.com/samber/lo"

	"github.com/iotaledger/hive.go/ds/shrinkingmap"
	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/util"
)

const (
	maxTTL byte = 1
)

// The implementation is trivial and naive for now. A proper gossip or structured
// broadcast (possibly a mix of both) should be implemented here.
//
// In the current algorithm, for sharing a message:
//   - Just send a message to all the committee nodes.
//
// For querying a message:
//   - First ask all the committee for the message.
//   - If response not received, ask random subsets of server nodes.
//
// TODO: For the future releases: Implement proper dissemination algorithm.
type MempoolSync struct {
	out               gpa.OutBuffer
	me                gpa.NodeID
	serverNodes       []gpa.NodeID // Should be used to push and query for requests.
	accessNodes       []gpa.NodeID // Maybe is not needed? Lets keep it until the redesign.
	committeeNodes    []gpa.NodeID // Subset of serverNodes and accessNodes.
	requestNeededCB   func(*isc.RequestRef) isc.Request
	requestReceivedCB func(isc.Request) bool
	nodeCountToShare  int // Number of nodes to share a request per iteration.
	maxMsgsPerTick    int
	needed            *shrinkingmap.ShrinkingMap[isc.RequestRefKey, *distSyncReqNeeded]
	missingReqsMetric func(count int)
	rnd               *rand.Rand
	log               log.Logger
}

var _ gpa.GPA = &MempoolSync{}

type distSyncReqNeeded struct {
	reqRef  *isc.RequestRef
	waiters []context.Context
}

func New(
	me gpa.NodeID,
	requestNeededCB func(*isc.RequestRef) isc.Request,
	requestReceivedCB func(isc.Request) bool,
	maxMsgsPerTick int,
	missingReqsMetric func(count int),
	log log.Logger,
) *MempoolSync {
	return &MempoolSync{
		me:                me,
		serverNodes:       []gpa.NodeID{},
		accessNodes:       []gpa.NodeID{},
		committeeNodes:    []gpa.NodeID{},
		requestNeededCB:   requestNeededCB,
		requestReceivedCB: requestReceivedCB,
		nodeCountToShare:  0,
		maxMsgsPerTick:    maxMsgsPerTick,
		needed:            shrinkingmap.New[isc.RequestRefKey, *distSyncReqNeeded](),
		missingReqsMetric: missingReqsMetric,
		rnd:               util.NewPseudoRand(),
		log:               log,
	}
}

func (dsi *MempoolSync) SwapOutBuffer() []gpa.MessageOut {
	return dsi.out.Swap()
}

func (dsi *MempoolSync) Message(msg gpa.MessageIn) {
	switch msg.Payload.(type) {
	case *msgMissingRequest:
		dsi.handleMsgMissingRequest(gpa.AsTypedMessageIn[*msgMissingRequest](msg))
	case *msgShareRequest:
		dsi.handleMsgShareRequest(gpa.AsTypedMessageIn[*msgShareRequest](msg))
	}
	dsi.log.LogWarnf("unexpected message %T: %+v", msg, msg)
}

func (dsi *MempoolSync) StatusString() string {
	return fmt.Sprintf("{MP, neededReqs=%v, nodeCountToShare=%v}", dsi.needed.Size(), dsi.nodeCountToShare)
}

func (dsi *MempoolSync) InputServerNodes(serverNodes, committeeNodes []gpa.NodeID) {
	dsi.log.LogDebugf("InputServerNodes: %v %v", serverNodes, committeeNodes)
	dsi.handleCommitteeNodes(committeeNodes)
	dsi.serverNodes = serverNodes
	for i := range dsi.committeeNodes { // Ensure server nodes contain the committee nodes.
		if slices.Index(dsi.serverNodes, dsi.committeeNodes[i]) == -1 {
			dsi.serverNodes = append(dsi.serverNodes, dsi.committeeNodes[i])
		}
	}
	dsi.InputTimeTick() // Re-send requests if node set has changed.
}

func (dsi *MempoolSync) InputAccessNodes(accessNodes, committeeNodes []gpa.NodeID) {
	dsi.log.LogDebugf("InputAccessNodes: %v %v", accessNodes, committeeNodes)
	dsi.handleCommitteeNodes(committeeNodes)
	dsi.accessNodes = accessNodes
	for i := range dsi.committeeNodes { // Ensure access nodes contain the committee nodes.
		if slices.Index(dsi.accessNodes, dsi.committeeNodes[i]) == -1 {
			dsi.accessNodes = append(dsi.accessNodes, dsi.committeeNodes[i])
		}
	}
	dsi.InputTimeTick() // Re-send requests if node set has changed.
}

func (dsi *MempoolSync) handleCommitteeNodes(committeeNodes []gpa.NodeID) {
	dsi.committeeNodes = committeeNodes
	dsi.nodeCountToShare = (len(dsi.committeeNodes)-1)/3 + 1 // F+1
	if dsi.nodeCountToShare < 2 {
		dsi.nodeCountToShare = 2
	}
	if dsi.nodeCountToShare > len(dsi.committeeNodes) {
		dsi.nodeCountToShare = len(dsi.committeeNodes)
	}
}

// In the current algorithm, for sharing a message:
//   - Just send a message to all the committee nodes (or server nodes, if committee is not known).
func (dsi *MempoolSync) InputPublishRequest(request isc.Request) {
	dsi.propagateRequest(request)
	//
	// Delete the it from the "needed" list, if any.
	// This node has the request, if it tries to publish it.
	reqRef := isc.RequestRefFromRequest(request)
	if dsi.needed.Delete(reqRef.AsKey()) {
		dsi.missingReqsMetric(dsi.needed.Size())
	}
}

func (dsi *MempoolSync) propagateRequest(request isc.Request) {
	var publishToNodes []gpa.NodeID
	if len(dsi.committeeNodes) > 0 {
		publishToNodes = dsi.committeeNodes
		dsi.log.LogDebugf("Forwarding request %v to committee nodes: %v", request.ID(), dsi.committeeNodes)
	} else {
		dsi.log.LogDebugf("Forwarding request %v to server nodes: %v", request.ID(), dsi.serverNodes)
		publishToNodes = dsi.serverNodes
	}
	for i := range publishToNodes {
		dsi.out.Put(newMsgShareRequest(request, 0, publishToNodes[i]))
	}
}

// For querying a message:
//   - First ask all the committee for the message.
//   - ...
func (dsi *MempoolSync) InputRequestNeeded(ctx context.Context, requestRef *isc.RequestRef) {
	reqRefKey := requestRef.AsKey()
	reqNeeded, have := dsi.needed.Get(reqRefKey)
	if have {
		if lo.Contains(reqNeeded.waiters, ctx) {
			return // Duplicate call, ignore it.
		}
		reqNeeded.waiters = append(reqNeeded.waiters, ctx)
	} else {
		reqNeeded = &distSyncReqNeeded{
			reqRef:  requestRef,
			waiters: []context.Context{ctx},
		}
	}
	if dsi.needed.Set(reqRefKey, reqNeeded) {
		dsi.missingReqsMetric(dsi.needed.Size())
	}
	for _, nid := range dsi.committeeNodes {
		dsi.out.Put(newMsgMissingRequest(requestRef, nid))
	}
}

// For querying a message:
//   - ...
//   - If response not received, ask random subsets of server nodes.
func (dsi *MempoolSync) InputTimeTick() {
	if dsi.needed.Size() == 0 {
		return
	}
	nodeCount := len(dsi.serverNodes)
	if nodeCount == 0 {
		return
	}
	nodePerm := dsi.rnd.Perm(nodeCount)
	counter := 0
	dsi.needed.ForEach(func(reqRefKey isc.RequestRefKey, reqNeeded *distSyncReqNeeded) bool { // Access is randomized.
		stillNeeded := lo.ContainsBy(reqNeeded.waiters, func(ctx context.Context) bool { return ctx.Err() == nil })
		if !stillNeeded {
			dsi.needed.Delete(reqRefKey)
			dsi.log.LogDebugf("Clearing MsgMissingRequest, not needed anymore: %v", reqNeeded.reqRef)
			return true
		}
		recipient := dsi.serverNodes[nodePerm[counter%nodeCount]]
		dsi.log.LogDebugf("Sending MsgMissingRequest for %v to %v", reqNeeded.reqRef, recipient)
		dsi.out.Put(newMsgMissingRequest(reqNeeded.reqRef, recipient))
		counter++
		return counter <= dsi.maxMsgsPerTick
	})
	dsi.missingReqsMetric(dsi.needed.Size())
}

func (dsi *MempoolSync) handleMsgMissingRequest(msg gpa.TypedMessageIn[*msgMissingRequest]) {
	req := dsi.requestNeededCB(msg.Payload.requestRef)
	if req != nil {
		dsi.out.Put(newMsgShareRequest(req, 0, msg.Sender))
	}
}

func (dsi *MempoolSync) handleMsgShareRequest(msg gpa.TypedMessageIn[*msgShareRequest]) {
	reqRefKey := isc.RequestRefFromRequest(msg.Payload.request).AsKey()
	added := dsi.requestReceivedCB(msg.Payload.request)
	if dsi.needed.Delete(reqRefKey) {
		dsi.missingReqsMetric(dsi.needed.Size())
	}
	//
	// Propagate the message, if it was new to us, and was received from outside of the committee.
	// The "outside of the committee" condition is used here to decrease echo-factor of the synchronization.
	// Each fair committee will send the request to all the committee nodes, thus we can avoid repeating it.
	// Follow the logic as if the message is received via the API.
	if added && !lo.Contains(dsi.committeeNodes, msg.Sender) {
		dsi.propagateRequest(msg.Payload.request)
	}
	//
	// The following is de-factor unused, as TTL is always 0 currently.
	if msg.Payload.ttl > 0 {
		ttl := min(msg.Payload.ttl, maxTTL)
		perm := dsi.rnd.Perm(len(dsi.committeeNodes))
		for i := 0; i < dsi.nodeCountToShare; i++ {
			dsi.out.Put(newMsgShareRequest(msg.Payload.request, ttl-1, dsi.committeeNodes[perm[i]]))
		}
		return
	}
}
