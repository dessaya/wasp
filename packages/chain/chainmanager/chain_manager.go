// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: Cleanup the committees not used for a long time.

// Package chainmanager implements a protocol for running a chain in a node.
// Its main responsibilities:
//   - Track, which branch is the latest/correct one.
//   - Maintain a set of committee logs (1 for each committee this node participates in).
//   - Maintain a set of consensus instances (one of them is the current one).
//   - Supervise the Mempool and StateMgr.
//   - Handle messages from the NodeConn (Anchor confirmed / rejected, Request received).
//   - Posting StateTX to NodeConn.
//
// > VARIABLES:
// >     LatestActiveCmt -- The latest committee, that was active.
// >        This field will be nil if the node is not part of the committee.
// >        On the resynchronization it will store the previous active committee.
// >     LatestActiveAnchor -- The latest Anchor we are building upon.
// >        Derived, equal to NeedConsensus.BaseAnchor.
// >     LatestConfirmedAnchor -- The latest ConfirmedAnchor from L1.
// >        This one usually follows the LatestAnchor,
// >        but can be published from outside and override the LatestAnchor.
// >     AccessNodes -- The set of access nodes for the current head.
// >        Union of On-Chain access nodes and the nodes permitted by this node.
// >     NeedConsensus -- A request to run consensus.
// >        Always set based on output of the main CommitteeLog.
// >     NeedPublishTX -- Requests to publish TX'es.
// >        - Added upon reception of the Consensus Output,
// >          if it is still in NeedConsensus at the time.
// >        - Removed on PublishResult from the NodeConn.
// >
// > UPON Reception of ConfirmedAnchor:
// >     Set LatestConfirmedAnchor <- ConfirmedAnchor
// >     IF this node is in the committee THEN
// >         Pass it to the corresponding CommitteeLog; HandleCommitteeLogOutput.
// >     ELSE
// >         IF LatestActiveCmt != nil THEN
// >     	     Send Suspend to Last Active CommitteeLog; HandleCommitteeLogOutput
// >         Set LatestActiveCmt <- NIL
// >         Set NeedConsensus <- NIL
// > UPON Reception of PublishResult:
// >     Clear the TX from the NeedPublishTX variable.
// >     If result.confirmed = false THEN
// >         Forward it to ChainMgr; HandleCommitteeLogOutput.
// >     ELSE
// >         NOP // Anchor has to be received as ConfirmedAnchor.
// > UPON Reception of Consensus Output/DONE:
// >     IF ConsensusOutput.BaseAnchor == NeedConsensus THEN
// >         Add ConsensusOutput.TX to NeedPublishTX
// >     Forward the message to the corresponding CommitteeLog; HandleCommitteeLogOutput.
// >     Update AccessNodes.
// > UPON Reception of Consensus Output/SKIP:
// >     Forward the message to the corresponding CommitteeLog; HandleCommitteeLogOutput.
// > UPON Reception of Consensus Timeout:
// >     Forward the message to the corresponding CommitteeLog; HandleCommitteeLogOutput.
// > UPON Reception of CommitteeLog.NextLI message:
// >     Forward it to the corresponding CommitteeLog; HandleCommitteeLogOutput.
// >
// > PROCEDURE HandleCommitteeLogOutput(cmt):
// >     Wrap out messages.
// >     IF cmt == LatestActiveCmt || LatestActiveCmt == NIL THEN
// >         Set LatestActiveCmt <- cmt
// >         Set NeedConsensus <- output.NeedConsensus // Can be nil
// >     ELSE
// >         IF output.NeedConsensus == nil THEN
// >             RETURN // No need to change the committee.
// >         IF LatestActiveCmt != nil THEN
// >             Suspend(LatestActiveCmt)
// >         Set LatestActiveCmt <- cmt
// >         Set NeedConsensus <- output.NeedConsensus
//
// TODO: Why AM is not notified on the committee nodes after rotation?
package chainmanager

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/samber/lo"

	"github.com/iotaledger/hive.go/ds/shrinkingmap"
	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotago"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotasigner"
	"github.com/iotaledger/wasp/v2/packages/chain/committeelog"
	"github.com/iotaledger/wasp/v2/packages/chain/consensus"
	"github.com/iotaledger/wasp/v2/packages/cryptolib"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/hashing"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/metrics"
	"github.com/iotaledger/wasp/v2/packages/registry"
	"github.com/iotaledger/wasp/v2/packages/state"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
)

var ErrNotInCommittee = errors.New("ErrNotInCommittee")

type Output struct {
	cmi *ChainMgr
}

func (o *Output) LatestActiveAnchor() *isc.StateAnchor {
	// There is no pipelining possible with the SUI based L1,
	// thus there is no difference between the active and confirmed Anchor.
	return o.cmi.latestConfirmedAnchor
}
func (o *Output) LatestConfirmedAnchor() *isc.StateAnchor { return o.cmi.latestConfirmedAnchor }
func (o *Output) NeedPublishTX() *NeedPublishTXMap {
	return o.cmi.needPublishTX
}

func (o *Output) String() string {
	needPublishTX := "{"
	for txID, needPub := range o.NeedPublishTX().AsMap() {
		needPublishTX += fmt.Sprintf("%s => %v; ", txID.Hex(), needPub)
	}
	needPublishTX += "}"

	return fmt.Sprintf(
		"{chainMgr.Output, LatestConfirmedAnchor=%v, NeedConsensus=%v, NeedPublishTX=%s}",
		o.LatestConfirmedAnchor(),
		o.cmi.needConsensus,
		needPublishTX,
	)
}

// NeedConsensusKeySize is the required consensus key size in bytes
// We use NeedConsensusKey to address the the instances in a map.
const NeedConsensusKeySize = cryptolib.AddressSize + 4

type NeedConsensusKey [NeedConsensusKeySize]byte

func (nck NeedConsensusKey) String() string {
	return hexutil.Encode(nck[:])
}

type NeedConsensusMap = shrinkingmap.ShrinkingMap[NeedConsensusKey, *NeedConsensus]

func MakeConsensusKey(committeeAddr cryptolib.Address, logIndex committeelog.LogIndex) NeedConsensusKey {
	var buf [NeedConsensusKeySize]byte
	cak := committeeAddr.Key()
	lib := logIndex.Bytes()
	copy(buf[0:cryptolib.AddressSize], cak[0:cryptolib.AddressSize])
	copy(buf[cryptolib.AddressSize:NeedConsensusKeySize], lib[0:4])
	return buf
}

type NeedConsensus struct {
	CommitteeAddr   cryptolib.Address
	DKShare         tcrypto.DKShare
	LogIndex        committeelog.LogIndex
	BaseStateAnchor *isc.StateAnchor
}

func (nc *NeedConsensus) String() string {
	return fmt.Sprintf(
		"{chainMgr.NeedConsensus, CommitteeAddr=%v, LogIndex=%v, BaseStateAnchor=%v}",
		nc.CommitteeAddr.String(),
		nc.LogIndex,
		nc.BaseStateAnchor,
	)
}

type NeedPublishTXMap = shrinkingmap.ShrinkingMap[hashing.HashValue, *NeedPublishTX]

type NeedPublishTX struct {
	CommitteeAddr cryptolib.Address
	LogIndex      committeelog.LogIndex
	Tx            *iotasigner.SignedTransaction
	BaseAnchorRef *iotago.ObjectRef // The consumed Anchor object/version.
}

func (npt *NeedPublishTX) String() string {
	return fmt.Sprintf(
		"{chainMgr.NeedPublishTX, CommitteeAddr=%v, LogIndex=%v, TX=..., BaseAnchorRef=%v}",
		npt.CommitteeAddr.String(),
		npt.LogIndex,
		npt.BaseAnchorRef,
	)
}

type committeeLogInst struct {
	*committeelog.CommitteeLog
	dkShare tcrypto.DKShare
}

type ChainMgr struct {
	out                        gpa.OutBuffer
	chainID                    isc.ChainID                                             // This instance is responsible for this chain.
	chainStore                 state.Store                                             // Store of the chain state.
	committeeLogs              map[cryptolib.AddressKey]*committeeLogInst              // All the committee log instances for this chain.
	consensusStateRegistry     committeelog.ConsensusStateRegistry                     // Persistent store for log indexes.
	latestActiveCommittee      *cryptolib.Address                                      // The latest active committee.
	latestConfirmedAnchor      *isc.StateAnchor                                        // The latest confirmed Anchor (follows Active Anchor).
	activeNodesCB              func() ([]*cryptolib.PublicKey, []*cryptolib.PublicKey) // All the nodes authorized for being access nodes (for the ActiveAnchor).
	trackActiveStateCB         func(ao *isc.StateAnchor)                               // We will call this to set new Anchor for the active state.
	savePreliminaryBlockCB     func(block state.Block)                                 // We will call this, when a preliminary block matching the tx signatures is received.
	committeeUpdatedCB         func(dkShare tcrypto.DKShare)                           // Will be called, when a committee changes.
	needConsensus              *NeedConsensusMap                                       // Query for a consensus.
	needConsensusCB            func(upd *NeedConsensusMap)                             // A callback.
	needPublishTX              *NeedPublishTXMap                                       // Query to post TXes.
	needPublishCB              func(upd *NeedPublishTXMap)                             // A callback.
	dkShareRegistry            registry.DKShareRegistry                                // Source for DKShares.
	varAccessNodeState         *VarAccessNodeState
	output                     *Output
	me                         gpa.NodeID
	nodeIDFromPubKey           func(pubKey *cryptolib.PublicKey) gpa.NodeID
	deriveAnchorByQuorum       bool // Config parameter.
	pipeliningLimit            int  // Config parameter.
	postponeRecoveryMilestones int  // Config parameter.
	metrics                    *metrics.ChainCommitteeLogMetrics
	log                        log.Logger
}

var _ gpa.GPA = &ChainMgr{}

func New(
	me gpa.NodeID,
	chainID isc.ChainID,
	chainStore state.Store,
	consensusStateRegistry committeelog.ConsensusStateRegistry,
	dkShareRegistry registry.DKShareRegistry,
	nodeIDFromPubKey func(pubKey *cryptolib.PublicKey) gpa.NodeID,
	needConsensusCB func(upd *NeedConsensusMap),
	needPublishCB func(upd *NeedPublishTXMap),
	activeNodesCB func() ([]*cryptolib.PublicKey, []*cryptolib.PublicKey),
	trackActiveStateCB func(ao *isc.StateAnchor),
	savePreliminaryBlockCB func(block state.Block),
	committeeUpdatedCB func(dkShare tcrypto.DKShare),
	deriveAnchorByQuorum bool, // TODO: Review, some of them are outdated.
	pipeliningLimit int,
	postponeRecoveryMilestones int,
	metrics *metrics.ChainCommitteeLogMetrics,
	log log.Logger,
) (*ChainMgr, error) {
	cmi := &ChainMgr{
		chainID:                    chainID,
		chainStore:                 chainStore,
		committeeLogs:              map[cryptolib.AddressKey]*committeeLogInst{},
		consensusStateRegistry:     consensusStateRegistry,
		activeNodesCB:              activeNodesCB,
		trackActiveStateCB:         trackActiveStateCB,
		savePreliminaryBlockCB:     savePreliminaryBlockCB,
		committeeUpdatedCB:         committeeUpdatedCB,
		needConsensus:              shrinkingmap.New[NeedConsensusKey, *NeedConsensus](),
		needConsensusCB:            needConsensusCB,
		needPublishTX:              shrinkingmap.New[hashing.HashValue, *NeedPublishTX](),
		needPublishCB:              needPublishCB,
		dkShareRegistry:            dkShareRegistry,
		varAccessNodeState:         NewVarAccessNodeState(chainID, log.NewChildLogger("VAS")),
		me:                         me,
		nodeIDFromPubKey:           nodeIDFromPubKey,
		deriveAnchorByQuorum:       deriveAnchorByQuorum,
		pipeliningLimit:            pipeliningLimit,
		metrics:                    metrics,
		postponeRecoveryMilestones: postponeRecoveryMilestones,
		log:                        log,
	}
	cmi.output = &Output{cmi: cmi}
	return cmi, nil
}

func (cmi *ChainMgr) SwapOutBuffer() []gpa.MessageOut {
	return cmi.out.Swap()
}

// Message implements the gpa.GPA interface.
func (cmi *ChainMgr) Message(msg gpa.MessageIn) {
	switch msg.Payload.(type) {
	case *msgCommitteeLog:
		cmi.handleMsgCommitteeLog(gpa.AsTypedMessageIn[*msgCommitteeLog](msg))
	case *msgBlockProduced:
		cmi.handleMsgBlockProduced(gpa.AsTypedMessageIn[*msgBlockProduced](msg))
	}
	panic(fmt.Errorf("unexpected message %T: %+v", msg, msg))
}

// > UPON Reception of ConfirmedAnchor:
// >     Set LatestConfirmedAnchor <- ConfirmedAnchor
// >     IF this node is in the committee THEN
// >         Pass it to the corresponding CommitteeLog; HandleCommitteeLogOutput(ConfirmedAnchor.Cmt).
// >     ELSE
// >         IF LatestActiveCmt != nil THEN
// >     	     Send Suspend to Last Active CommitteeLog; HandleCommitteeLogOutput(LatestActiveCmt)
// >         Set LatestActiveCmt <- NIL
// >         Set NeedConsensus <- NIL
func (cmi *ChainMgr) InputAnchorConfirmed(stateController *cryptolib.Address, anchor *isc.StateAnchor) {
	cmi.log.LogDebugf("handleInputAnchorConfirmed: [%s %s]", stateController, anchor)
	//
	// >     Set LatestConfirmedAnchor <- ConfirmedAnchor
	vsaTip, vsaUpdated := cmi.varAccessNodeState.BlockConfirmed(anchor)
	cmi.latestConfirmedAnchor = anchor

	committeeLog, err := cmi.ensureCommitteeLog(*stateController) // TODO: stateController.Key()
	if errors.Is(err, ErrNotInCommittee) {
		// >     IF this node is in the committee THEN ... ELSE
		// >         IF LatestActiveCmt != nil THEN
		// >     	     Send Suspend to Last Active CommitteeLog; HandleCommitteeLogOutput(LatestActiveCmt)
		// >         Set LatestActiveCmt <- NIL
		// >         Set NeedConsensus <- NIL
		if cmi.latestActiveCommittee != nil {
			cmi.suspendCommittee(cmi.latestActiveCommittee)
			cmi.committeeUpdatedCB(nil)
			cmi.latestActiveCommittee = nil
		}
		cmi.needConsensus.Clear()
		if vsaUpdated && vsaTip != nil {
			cmi.log.LogDebugf("⊢ going to track %v as an access node on confirmed block.", vsaTip)
			cmi.trackActiveStateCB(vsaTip)
		}
		cmi.log.LogDebugf("This node is not in the committee for anchor: %v", anchor)
		return
	}
	if err != nil {
		cmi.log.LogWarnf("Failed to get CommitteeLog: %v", err)
		return
	}
	// >     IF this node is in the committee THEN
	// >         Pass it to the corresponding CommitteeLog; HandleCommitteeLogOutput.
	committeeLog.InputAnchorConfirmed(anchor)
	cmi.handleCommitteeLogOutput(committeeLog)
}

// > UPON Reception of PublishResult:
// >     Clear the TX from the NeedPublishTX variable.
// >     If result.confirmed = false THEN
// >         Forward it to ChainMgr; HandleCommitteeLogOutput.
// >     ELSE
// >         NOP // Anchor has to be received as Confirmed Anchor.
func (cmi *ChainMgr) InputChainTxPublishResult(
	committeeAddr cryptolib.Address,
	logIndex committeelog.LogIndex,
	txDigest iotago.Digest,
	anchor *isc.StateAnchor,
	confirmed bool,
) {
	cmi.log.LogDebugf("handleInputChainTxPublishResult: [%s %d %s confirmed=%v]", committeeAddr, logIndex, txDigest, confirmed)
	// >     Clear the TX from the NeedPublishTX variable.
	if cmi.needPublishTX.Has(txDigest.HashValue()) {
		cmi.needPublishTX.Delete(txDigest.HashValue())
		cmi.needPublishCB(cmi.needPublishTX)
	}
	if confirmed {
		// >     If result.confirmed = false THEN ... ELSE
		// >         NOP // Anchor has to be received as Confirmed Anchor. // TODO: Not true, anymore.
		cmi.withCommitteeLog(committeeAddr, func(cli *committeeLogInst) {
			cli.InputConsensusOutputConfirmed(anchor, logIndex)
		})
		return
	}
	// >     If result.confirmed = false THEN
	// >         Forward it to ChainMgr; HandleCommitteeLogOutput.
	cmi.withCommitteeLog(committeeAddr, func(cli *committeeLogInst) {
		cli.InputConsensusOutputRejected(anchor, logIndex)
	})
}

// > UPON Reception of Consensus Output/DONE:
// >     IF ConsensusOutput.BaseAnchor == NeedConsensus THEN
// >         Add ConsensusOutput.TX to NeedPublishTX
// >     Forward the message to the corresponding CommitteeLog; HandleCommitteeLogOutput.
// >     Update AccessNodes.
func (cmi *ChainMgr) InputConsensusOutputDone(
	committeeAddr cryptolib.Address,
	logIndex committeelog.LogIndex,
	proposedBaseAnchor *isc.StateAnchor,
	consensusResult *consensus.Result,
) {
	cmi.log.LogDebugf("handleInputConsensusOutputDone: %+v", consensusResult)

	baseAnchorRef := consensusResult.Transaction.FindInputByID(cmi.chainID.AsObjectID())
	if baseAnchorRef == nil {
		panic("produced tx is not consuming the anchor")
	}

	// >     IF ConsensusOutput.BaseAnchor == NeedConsensus THEN
	// >         Add ConsensusOutput.TX to NeedPublishTX
	if true { // TODO: Reconsider this condition. Several recent consensus instances should be published, if we run consensus instances in parallel.
		txDigest := lo.Must(consensusResult.Transaction.Digest())
		if !cmi.needPublishTX.Has(txDigest.HashValue()) && consensusResult.Block != nil {
			// Inform the access nodes on new block produced.
			block := consensusResult.Block
			activeAccessNodes, activeCommitteeNodes := cmi.activeNodesCB()
			cmi.log.LogDebugf(
				"Sending MsgBlockProduced (stateIndex=%v, l1Commitment=%v, txDigest=%s) to access nodes: %v except committeeNodes %v",
				block.StateIndex(), block.L1Commitment(), txDigest, activeAccessNodes, activeCommitteeNodes,
			)
			for i := range activeAccessNodes {
				if lo.Contains(activeCommitteeNodes, activeAccessNodes[i]) {
					continue
				}
				cmi.out.Put(NewMsgBlockProduced(cmi.nodeIDFromPubKey(activeAccessNodes[i]), consensusResult.Transaction, block))
			}
		}
		if !cmi.needPublishTX.Has(txDigest.HashValue()) {
			cmi.needPublishTX.Set(txDigest.HashValue(), &NeedPublishTX{
				CommitteeAddr: committeeAddr,
				LogIndex:      logIndex,
				Tx:            consensusResult.Transaction,
				BaseAnchorRef: baseAnchorRef,
			})
			cmi.needPublishCB(cmi.needPublishTX)
		}
	}
	//
	// >     Forward the message to the corresponding CommitteeLog; HandleCommitteeLogOutput.
	//
	// TODO: This event is not needed anymore.
	// msgs.AddAll(cmi.withCommitteeLog(committeeAddr, func(cl gpa.GPA) {
	// 	return cl.Input(cmtlog.NewInputConsensusOutputDone(logIndex, proposedBaseAnchor, consensusResult))
	// }))
}

// > UPON Reception of Consensus Output/SKIP:
// >     Forward the message to the corresponding CommitteeLog; HandleCommitteeLogOutput.
func (cmi *ChainMgr) InputConsensusOutputSkip(committeeAddr cryptolib.Address, logIndex committeelog.LogIndex) {
	cmi.log.LogDebugf("handleInputConsensusOutputSkip: %+v", logIndex)
	cmi.withCommitteeLog(committeeAddr, func(cli *committeeLogInst) {
		cli.InputConsensusOutputSkip(logIndex)
	})
}

// > UPON Reception of Consensus Timeout:
// >     Forward the message to the corresponding CommitteeLog; HandleCommitteeLogOutput.
func (cmi *ChainMgr) InputConsensusTimeout(committeeAddr cryptolib.Address, logIndex committeelog.LogIndex) {
	cmi.log.LogDebugf("handleInputConsensusTimeout: %+v", logIndex)
	cmi.withCommitteeLog(committeeAddr, func(cli *committeeLogInst) {
		cli.InputConsensusTimeout(logIndex)
	})
}

func (cmi *ChainMgr) InputCanPropose() {
	cmi.log.LogDebugf("handleInputCanPropose")
	cmi.withAllCommitteeLogs(func(cli *committeeLogInst) {
		cli.InputCanPropose()
	})
}

// > UPON Reception of CommitteeLog.NextLI message:
// >     Forward it to the corresponding CommitteeLog; HandleCommitteeLogOutput.
func (cmi *ChainMgr) handleMsgCommitteeLog(msg gpa.TypedMessageIn[*msgCommitteeLog]) {
	cmi.log.LogDebugf("handleMsgCommitteeLog: %+v", msg)
	cmi.withCommitteeLog(msg.Payload.committeeAddr, func(cli *committeeLogInst) {
		cli.Message(gpa.NewMessageIn(msg.Sender, msg.Payload.wrapped))
	})
}

func (cmi *ChainMgr) handleMsgBlockProduced(msg gpa.TypedMessageIn[*msgBlockProduced]) {
	cmi.log.LogDebugf("handleMsgBlockProduced: %+v", msg)
	vsaTip, vsaUpdated, l1Commitment := cmi.varAccessNodeState.BlockProduced(msg.Payload.tx)
	//
	// Save the block, if it matches all the signatures by the current committee.
	// This will save us a round-trip to query the block from the sender.
	if l1Commitment != nil {
		if msg.Payload.block.L1Commitment().Equals(l1Commitment) {
			cmi.savePreliminaryBlockCB(msg.Payload.block)
		} else {
			cmi.log.LogWarnf("Received msgBlockProduced, but publishedAnchor.l1Commitment != block.l1Commitment.")
		}
	}
	//
	// Update the active state, if needed.
	if vsaUpdated && vsaTip != nil && cmi.latestActiveCommittee == nil {
		cmi.log.LogDebugf("⊢ going to track %v as an access node on unconfirmed block.", vsaTip)
		cmi.trackActiveStateCB(vsaTip)
	}
}

// > PROCEDURE HandleCommitteeLogOutput(cmt):
// >     Wrap out messages.
// >     IF cmt == LatestActiveCmt || LatestActiveCmt == NIL THEN
// >         Set LatestActiveCmt <- cmt
// >         Set NeedConsensus <- output.NeedConsensus // Can be nil
// >     ELSE
// >         IF output.NeedConsensus == nil THEN
// >             RETURN // No need to change the committee.
// >         IF LatestActiveCmt != nil THEN
// >             Suspend(LatestActiveCmt)
// >         Set LatestActiveCmt <- cmt
// >         Set NeedConsensus <- output.NeedConsensus
func (cmi *ChainMgr) handleCommitteeLogOutput(cli *committeeLogInst) {
	//
	// >     Wrap out messages.
	cmi.wrapCommitteeLogMsgs(cli)
	output := cli.Output()
	// >     IF cmt == LatestActiveCmt || LatestActiveCmt == NIL THEN
	// >         Set LatestActiveCmt <- cmt
	// >         Set NeedConsensus <- output.NeedConsensus // Can be nil
	if cmi.latestActiveCommittee == nil || cli.CommitteeAddr.Equals(cmi.latestActiveCommittee) {
		cmi.committeeUpdatedCB(cli.dkShare)
		cmi.ensureNeedConsensus(cli, output)
		cmi.latestActiveCommittee = cli.CommitteeAddr
		return
	}
	// >     ELSE
	// >         IF output.NeedConsensus == nil THEN
	// >             RETURN // No need to change the committee.
	// >         IF LatestActiveCmt != nil THEN
	// >             Suspend(LatestActiveCmt)
	// >         Set LatestActiveCmt <- cmt
	// >         Set NeedConsensus <- output.NeedConsensus
	if output == nil {
		return
	}
	if !cmi.latestActiveCommittee.Equals(cli.CommitteeAddr) {
		cmi.suspendCommittee(cmi.latestActiveCommittee)
		cmi.committeeUpdatedCB(cli.dkShare)
		cmi.latestActiveCommittee = cli.CommitteeAddr
	}
	cmi.ensureNeedConsensus(cli, output)
	return
}

func (cmi *ChainMgr) ensureNeedConsensus(cli *committeeLogInst, output committeelog.Output) {
	wasEmpty := cmi.needConsensus.IsEmpty()
	if output == nil {
		cmi.needConsensus.Clear()
		if !wasEmpty {
			cmi.needConsensusCB(cmi.needConsensus)
		}
		return
	}
	// if cmi.needConsensus != nil && cmi.needConsensus.IsFor(output) {
	// 	// Not changed, keep it.
	// 	return
	// }
	dkShare, err := cmi.dkShareRegistry.LoadDKShare(cli.CommitteeAddr)
	if errors.Is(err, tcrypto.ErrDKShareNotFound) {
		// Rotated to other nodes, so we don't need to start the next consensus.
		cmi.needConsensus.Clear()
		if !wasEmpty {
			cmi.needConsensusCB(cmi.needConsensus)
		}
		return
	}
	if err != nil {
		panic(fmt.Errorf("ensureNeedConsensus cannot load DKShare for %v: %w", cli.CommitteeAddr, err))
	}

	//
	// Add new entries, remove those not needed anymore.
	ids := map[NeedConsensusKey]bool{}
	mod := false
	for li, ao := range output {
		key := MakeConsensusKey(*cli.CommitteeAddr, li)
		ids[key] = true
		if cmi.needConsensus.Has(key) {
			continue
		}
		mod = true
		cmi.needConsensus.Set(key, &NeedConsensus{
			CommitteeAddr:   *cli.CommitteeAddr,
			LogIndex:        li,
			DKShare:         dkShare,
			BaseStateAnchor: ao,
		})
	}
	cmi.needConsensus.ForEachKey(func(nck NeedConsensusKey) bool {
		if _, ok := ids[nck]; !ok {
			mod = true
			cmi.needConsensus.Delete(nck)
		}
		return true
	})
	if mod {
		cmi.needConsensusCB(cmi.needConsensus)
	}
}

func (cmi *ChainMgr) Output() *Output {
	return cmi.output
}

// StatusString implements the gpa.GPA interface.
func (cmi *ChainMgr) StatusString() string { // TODO: Call it periodically. Show the active committee.
	return "{ChainMgr,...}" // TODO: Add more info.
	// return fmt.Sprintf("{ChainMgr,confirmedAnchor=%v,activeAnchor=%v}",
	// 	cmi.output.LatestConfirmedAnchor().GetObjectID().String(),
	// 	cmi.output.LatestActiveAnchor().GetObjectID().String(),
	// )
}

////////////////////////////////////////////////////////////////////////////////
// Helper functions.

func (cmi *ChainMgr) wrapCommitteeLogMsgs(cli *committeeLogInst) {
	outMsgs := cli.SwapOutBuffer()
	cmi.out.PutAll(lo.Map(outMsgs, func(msg gpa.MessageOut, _ int) gpa.MessageOut {
		return gpa.NewMessageOut(msg.Recipient, NewMsgCommitteeLog(*cli.CommitteeAddr, msg.Payload))
	}))
}

func (cmi *ChainMgr) suspendCommittee(committeeAddr *cryptolib.Address) {
	for _, cli := range cmi.committeeLogs {
		if !cli.CommitteeAddr.Equals(committeeAddr) {
			continue
		}
		cli.InputSuspend()
		cmi.wrapCommitteeLogMsgs(cli)
		return
	}
}

func (cmi *ChainMgr) withCommitteeLog(committeeAddr cryptolib.Address, handler func(cl *committeeLogInst)) {
	cli, err := cmi.ensureCommitteeLog(committeeAddr)
	if err != nil {
		cmi.log.LogWarnf("cannot find committee: %v", committeeAddr)
		return
	}
	handler(cli)
	cmi.handleCommitteeLogOutput(cli)
}

func (cmi *ChainMgr) withAllCommitteeLogs(handler func(cli *committeeLogInst)) {
	for _, cli := range cmi.committeeLogs {
		handler(cli)
		cmi.handleCommitteeLogOutput(cli)
	}
}

// NOTE: ErrNotInCommittee
func (cmi *ChainMgr) ensureCommitteeLog(committeeAddr cryptolib.Address) (*committeeLogInst, error) {
	if cli, ok := cmi.committeeLogs[committeeAddr.Key()]; ok {
		return cli, nil
	}
	//
	// Create a committee if not created yet.
	dkShare, err := cmi.dkShareRegistry.LoadDKShare(&committeeAddr)
	if errors.Is(err, tcrypto.ErrDKShareNotFound) {
		return nil, ErrNotInCommittee
	}
	if err != nil {
		return nil, fmt.Errorf("ensureCommitteeLog cannot load DKShare for committeeAddress=%v: %w", committeeAddr, err)
	}

	nodePKs := dkShare.GetNodePubKeys()
	for i := range nodePKs {
		cmi.log.LogInfof("Committee node[%v]=%v", i, nodePKs[i])
	}

	nodeIDs := make([]gpa.NodeID, len(nodePKs))
	for i := range nodeIDs {
		nodeIDs[i] = cmi.nodeIDFromPubKey(nodePKs[i])
	}

	clInst, err := committeelog.New(
		cmi.me,
		cmi.chainID,
		committeeAddr.Clone(),
		nodeIDs,
		dkShare.DSS().MaxFaulty(),
		cmi.consensusStateRegistry,
		cmi.deriveAnchorByQuorum,
		cmi.pipeliningLimit,
		cmi.metrics,
		cmi.log.NewChildLogger(fmt.Sprintf("CL-%v", dkShare.GetSharedPublic().AsAddress().String()[:10])),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create committeeLog for committeeAddress=%v: %w", committeeAddr, err)
	}
	cli := &committeeLogInst{
		CommitteeLog: clInst,
		dkShare:      dkShare,
	}
	cmi.committeeLogs[committeeAddr.Key()] = cli
	return cli, nil
}
