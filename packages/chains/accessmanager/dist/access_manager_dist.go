// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Package dist implements chain access management following the specification `WaspChainAccessNodesV4.tla`.
// The specification actions are mapped to GPA inputs here as follows:
//
//   - ChainActivate  -- first reception of inputAccessNodes.
//   - ChainDeactivate -- inputChainDisabled.
//   - AccessNodeAdd -- inputAccessNodes, then compare with info we had before.
//   - AccessNodeDel -- inputAccessNodes, then compare with info we had before.
//   - Reboot -- inputTrustedNodes.
package dist

import (
	"fmt"

	"github.com/iotaledger/hive.go/ds/shrinkingmap"
	"github.com/iotaledger/hive.go/log"

	"github.com/iotaledger/wasp/v2/packages/cryptolib"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/util"
)

type Output interface {
	ChainServerNodes(chainID isc.ChainID) []*cryptolib.PublicKey
}

type AccessMgrDist struct {
	out              gpa.OutBuffer
	nodes            *shrinkingmap.ShrinkingMap[gpa.NodeID, *accessMgrNode]   // State for each peer.
	chains           *shrinkingmap.ShrinkingMap[isc.ChainID, *accessMgrChain] // State for each chain.
	pubKeyToNodeID   func(*cryptolib.PublicKey) gpa.NodeID                    // Convert PubKeys to NodeIDs.
	serversUpdatedCB func(isc.ChainID, []*cryptolib.PublicKey)                // Called when a set of servers has changed for a chain.
	dismissPeerCB    func(*cryptolib.PublicKey)                               // To stop redelivery at the upper layer.
	log              log.Logger
}

var _ gpa.GPA = &AccessMgrDist{}

func NewAccessMgr(
	pubKeyToNodeID func(*cryptolib.PublicKey) gpa.NodeID,
	serversUpdatedCB func(chainID isc.ChainID, servers []*cryptolib.PublicKey),
	dismissPeerCB func(*cryptolib.PublicKey),
	log log.Logger,
) *AccessMgrDist {
	return &AccessMgrDist{
		nodes:            shrinkingmap.New[gpa.NodeID, *accessMgrNode](),
		chains:           shrinkingmap.New[isc.ChainID, *accessMgrChain](),
		pubKeyToNodeID:   pubKeyToNodeID,
		serversUpdatedCB: serversUpdatedCB,
		dismissPeerCB:    dismissPeerCB,
		log:              log,
	}
}

func (amd *AccessMgrDist) SwapOutBuffer() []gpa.MessageOut {
	return amd.out.Swap()
}

// Implements the Output interface.
func (amd *AccessMgrDist) ChainServerNodes(chainID isc.ChainID) []*cryptolib.PublicKey {
	if chain, exists := amd.chains.Get(chainID); exists {
		return chain.server.Values()
	}
	return []*cryptolib.PublicKey{}
}

func (amd *AccessMgrDist) DisableChain(chainID isc.ChainID) {
	amd.handleInputChainDisabled(chainID)
}

func (amd *AccessMgrDist) UpdateAccessNodes(chainID isc.ChainID, accessNodes []*cryptolib.PublicKey) {
	amd.handleInputAccessNodes(chainID, accessNodes)
}

func (amd *AccessMgrDist) UpdateTrustedNodes(trustedNodes []*cryptolib.PublicKey) {
	amd.handleInputTrustedNodes(trustedNodes)
}

// Implements the gpa.GPA interface.
func (amd *AccessMgrDist) Message(msg gpa.MessageIn) {
	if _, ok := msg.Payload.(*msgAccess); ok {
		amd.handleMsgAccess(gpa.AsTypedMessageIn[*msgAccess](msg))
	}
	panic(fmt.Errorf("unexpected message %T: %+v", msg, msg))
}

func (amd *AccessMgrDist) Output() Output {
	return amd
}

// Implements the gpa.GPA interface.
func (amd *AccessMgrDist) StatusString() string {
	return fmt.Sprintf("{accessMgr, |nodes|=%v, |chains|=%v}", amd.nodes.Size(), amd.chains.Size())
}

// > Notify all the trusted access nodes, that we will not serve the requests anymore.
func (amd *AccessMgrDist) handleInputChainDisabled(chainID isc.ChainID) {
	chain, exists := amd.chains.Get(chainID)
	if !exists {
		return // Already disabled.
	}
	chain.Disabled()
	amd.chains.Delete(chainID)
	amd.nodes.ForEach(func(_ gpa.NodeID, node *accessMgrNode) bool {
		node.SetChainAccess(chainID, false)
		return true
	})
}

// Access node list has updated for a particular chain.
//
// > Send disabled for nodes not in the access list anymore.
// > Send enabled for new access nodes.
func (amd *AccessMgrDist) handleInputAccessNodes(chainID isc.ChainID, accessNodes []*cryptolib.PublicKey) {
	//
	// Update the info from the chain perspective.
	chain, exists := amd.chains.Get(chainID)
	if !exists {
		initialServers := []*cryptolib.PublicKey{}
		amd.nodes.ForEach(func(_ gpa.NodeID, node *accessMgrNode) bool {
			if node.serverFor.Has(chainID) {
				initialServers = append(initialServers, node.pubKey)
			}
			return true
		})
		chain = newAccessMgrChain(chainID, amd.pubKeyToNodeID, initialServers, amd.serversUpdatedCB, amd.log)
		amd.chains.Set(chainID, chain)
	}
	chain.AccessGrantedFor(accessNodes)
	//
	// Update the info for each node.
	amd.nodes.ForEach(func(nodeID gpa.NodeID, node *accessMgrNode) bool {
		node.SetChainAccess(chainID, chain.IsAccessGrantedFor(nodeID))
		return true
	})
}

func (amd *AccessMgrDist) handleInputTrustedNodes(trustedNodes []*cryptolib.PublicKey) {
	//
	// Setup new nodes.
	trustedIndex := map[gpa.NodeID]bool{}
	for _, trustedNodePubKey := range trustedNodes {
		trustedNodeID := amd.pubKeyToNodeID(trustedNodePubKey)
		trustedIndex[trustedNodeID] = true
		if amd.nodes.Has(trustedNodeID) {
			continue
		}
		accessFor := newChainSet()
		amd.chains.ForEach(func(chainID isc.ChainID, chain *accessMgrChain) bool {
			if chain.IsAccessGrantedFor(trustedNodeID) {
				accessFor.Add(chainID)
			}
			return true
		})
		trustedNode := newAccessMgrNode(amd, trustedNodeID, trustedNodePubKey, accessFor)
		amd.nodes.Set(trustedNodeID, trustedNode)
	}
	//
	// Disconnect distrusted peers.
	amd.nodes.ForEach(func(nodeID gpa.NodeID, node *accessMgrNode) bool {
		if _, ok := trustedIndex[nodeID]; ok {
			return true
		}
		amd.chains.ForEach(func(_ isc.ChainID, chain *accessMgrChain) bool {
			chain.MarkAsServerFor(node.pubKey, false)
			node.SetChainAccess(chain.chainID, false)
			return true
		})
		amd.nodes.Delete(nodeID)
		amd.dismissPeerCB(node.pubKey)
		return true
	})
}

func (amd *AccessMgrDist) handleMsgAccess(msg gpa.TypedMessageIn[*msgAccess]) {
	node, exists := amd.nodes.Get(msg.Sender)
	if !exists {
		return
	}
	node.handleMsgAccess(msg)

	amd.chains.ForEach(func(chainID isc.ChainID, chain *accessMgrChain) bool {
		chain.MarkAsServerFor(node.pubKey, node.serverFor.Has(chainID))
		return true
	})
}

////////////////////////////////////////////////////////////////////////////////

type accessMgrChain struct {
	chainID          isc.ChainID
	access           map[gpa.NodeID]*cryptolib.PublicKey
	server           *shrinkingmap.ShrinkingMap[gpa.NodeID, *cryptolib.PublicKey]
	pubKeyToNodeID   func(*cryptolib.PublicKey) gpa.NodeID
	serversUpdatedCB func(isc.ChainID, []*cryptolib.PublicKey)
	log              log.Logger
}

func newAccessMgrChain(
	chainID isc.ChainID,
	pubKeyToNodeID func(*cryptolib.PublicKey) gpa.NodeID,
	initialServers []*cryptolib.PublicKey,
	serversUpdatedCB func(isc.ChainID, []*cryptolib.PublicKey),
	log log.Logger,
) *accessMgrChain {
	amc := &accessMgrChain{
		chainID:          chainID,
		access:           map[gpa.NodeID]*cryptolib.PublicKey{},
		server:           shrinkingmap.New[gpa.NodeID, *cryptolib.PublicKey](),
		pubKeyToNodeID:   pubKeyToNodeID,
		serversUpdatedCB: serversUpdatedCB,
		log:              log,
	}
	for i := range initialServers {
		nodeID := pubKeyToNodeID(initialServers[i])
		amc.server.Set(nodeID, initialServers[i])
	}

	serverNodes := amc.server.Values()
	amc.log.LogDebugf("Chain %v server nodes updated to %+v on init.", amc.chainID.ShortString(), serverNodes)
	amc.serversUpdatedCB(amc.chainID, serverNodes)
	return amc
}

func (amc *accessMgrChain) AccessGrantedFor(accessPubKeys []*cryptolib.PublicKey) {
	accessNodes := map[gpa.NodeID]*cryptolib.PublicKey{}
	for _, accessNodePubKey := range accessPubKeys {
		accessNodes[amc.pubKeyToNodeID(accessNodePubKey)] = accessNodePubKey
	}
	amc.access = accessNodes
}

func (amc *accessMgrChain) MarkAsServerFor(nodePubKey *cryptolib.PublicKey, granted bool) {
	nodeID := amc.pubKeyToNodeID(nodePubKey)
	wasServer := amc.server.Has(nodeID)
	if granted {
		amc.server.Set(nodeID, nodePubKey)
	} else {
		amc.server.Delete(nodeID)
	}
	if wasServer != granted {
		serverNodes := amc.server.Values()
		amc.log.LogDebugf("Chain %v server nodes updated to %+v.", amc.chainID.ShortString(), serverNodes)
		amc.serversUpdatedCB(amc.chainID, serverNodes)
	}
}

func (amc *accessMgrChain) IsAccessGrantedFor(nodeID gpa.NodeID) bool {
	_, ok := amc.access[nodeID]
	return ok
}

func (amc *accessMgrChain) Disabled() {
	if amc.server.Size() == 0 {
		return
	}
	amc.log.LogDebugf("Chain %v server nodes updated to [] on dismiss.", amc.chainID.ShortString())
	amc.serversUpdatedCB(amc.chainID, []*cryptolib.PublicKey{})
}

////////////////////////////////////////////////////////////////////////////////

type accessMgrNode struct {
	amd       *AccessMgrDist
	nodeID    gpa.NodeID
	pubKey    *cryptolib.PublicKey
	ourLC     int
	peerLC    int
	accessFor *chainSet
	serverFor *chainSet
}

func newAccessMgrNode(
	amd *AccessMgrDist,
	nodeID gpa.NodeID,
	pubKey *cryptolib.PublicKey,
	accessFor *chainSet,
) *accessMgrNode {
	amn := &accessMgrNode{
		amd:       amd,
		nodeID:    nodeID,
		pubKey:    pubKey,
		ourLC:     1,
		peerLC:    0,
		accessFor: accessFor,
		serverFor: newChainSet(),
	}
	amd.out.Put(newMsgAccess(amn.nodeID, amn.ourLC, amn.peerLC, amn.accessFor.AsSlice(), amn.serverFor.AsSlice()))
	return amn
}

func (amn *accessMgrNode) SetChainAccess(chainID isc.ChainID, access bool) {
	if access {
		amn.grantAccess(chainID)
	} else {
		amn.revokeAccess(chainID)
	}
}

func (amn *accessMgrNode) grantAccess(chainID isc.ChainID) {
	if amn.accessFor.Has(chainID) {
		return
	}
	amn.accessFor.Add(chainID)
	amn.ourLC++
	amn.amd.out.Put(
		newMsgAccess(amn.nodeID, amn.ourLC, amn.peerLC, amn.accessFor.AsSlice(), amn.serverFor.AsSlice()),
	)
}

func (amn *accessMgrNode) revokeAccess(chainID isc.ChainID) {
	if !amn.accessFor.Has(chainID) {
		return
	}
	amn.accessFor.Delete(chainID)
	amn.ourLC++
	amn.amd.out.Put(
		newMsgAccess(amn.nodeID, amn.ourLC, amn.peerLC, amn.accessFor.AsSlice(), amn.serverFor.AsSlice()),
	)
}

func (amn *accessMgrNode) handleMsgAccess(msg gpa.TypedMessageIn[*msgAccess]) {
	// This has to be checked before updating the state.
	// > IF /\ m.access = serverForChains(n, m.src)    \* Peer's info hasn't changed, so we don't need to ack it.
	// >    /\ m.server = H(accessForChains(n, m.src)) \* Our info echoed, so that was an ack.
	// >    /\ m.src_lc >= lClock[n][m.src]            \* Peer's clock is not outdated, we don't need to push it forward.
	// >    /\ m.dst_lc <= lClock[n][n]                \* And the echoed clock don't exceed our clock, so we don't need to push it.
	// > THEN sendAndAck(m, {})
	// > ELSE sendAndAck(m, accessMsgs(n))
	sendDone := true &&
		util.Same(msg.Payload.accessForChains, amn.serverFor.AsSlice()) &&
		util.Same(msg.Payload.serverForChains, amn.accessFor.AsSlice()) &&
		msg.Payload.senderLClock >= amn.peerLC &&
		msg.Payload.receiverLClock <= amn.ourLC
	//
	// Update serverFor and peerLC.
	if msg.Payload.senderLClock > amn.peerLC {
		amn.serverFor.FromSlice(msg.Payload.accessForChains)
		amn.peerLC = msg.Payload.senderLClock
	}
	//
	// Update ourLC.
	if amn.ourLC <= msg.Payload.receiverLClock {
		amn.ourLC = msg.Payload.receiverLClock
		msgServerFor := newChainSet()
		msgServerFor.FromSlice(msg.Payload.serverForChains)
		if !amn.accessFor.Equals(msgServerFor) {
			amn.ourLC++
		}
	}
	//
	// Send message back, if needed.
	if !sendDone {
		amn.amd.out.Put(
			newMsgAccess(msg.Sender, amn.ourLC, amn.peerLC, amn.accessFor.AsSlice(), amn.serverFor.AsSlice()),
		)
	}
}

////////////////////////////////////////////////////////////////////////////////

type chainSet struct {
	elements *shrinkingmap.ShrinkingMap[isc.ChainID, struct{}]
}

func newChainSet() *chainSet {
	return &chainSet{elements: shrinkingmap.New[isc.ChainID, struct{}]()}
}

func (cs *chainSet) Add(elem isc.ChainID) {
	cs.elements.Set(elem, struct{}{})
}

func (cs *chainSet) Delete(elem isc.ChainID) {
	cs.elements.Delete(elem)
}

func (cs *chainSet) Has(elem isc.ChainID) bool {
	return cs.elements.Has(elem)
}

func (cs *chainSet) AsSlice() []isc.ChainID {
	return cs.elements.Keys()
}

func (cs *chainSet) FromSlice(els []isc.ChainID) {
	cs.elements = shrinkingmap.New[isc.ChainID, struct{}]()
	for _, el := range els {
		cs.elements.Set(el, struct{}{})
	}
}

func (cs *chainSet) Equals(other *chainSet) bool {
	if cs.elements.Size() != other.elements.Size() {
		return false
	}

	equal := true
	cs.elements.ForEach(func(ci isc.ChainID, s struct{}) bool {
		if !other.elements.Has(ci) {
			equal = false
			return false
		}
		return true
	})

	return equal
}
