// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/state"
)

type SyncStateMgr struct {
	c *Consensus
	//
	// Query for a proposal.
	proposedBaseAnchor         *isc.StateAnchor
	proposedBaseAnchorReceived bool
	stateProposalReceived      bool
	//
	// Query for a decided Virtual State.
	decidedBaseAnchor    *isc.StateAnchor
	decidedStateReceived bool
	//
	// Save the produced block.
	producedBlock         state.StateDraft // In the case of rotation the block will be nil.
	producedBlockReceived bool
	saveProducedBlockDone bool
}

func NewSyncStateMgr(c *Consensus) *SyncStateMgr {
	return &SyncStateMgr{c: c}
}

func (s *SyncStateMgr) ProposedBaseAnchorReceived(baseAnchor *isc.StateAnchor) {
	if s.proposedBaseAnchorReceived {
		return
	}
	s.proposedBaseAnchor = baseAnchor
	s.proposedBaseAnchorReceived = true
	s.c.uponStateMgrStateProposalQueryInputsReady(s.proposedBaseAnchor)
}

func (s *SyncStateMgr) StateProposalConfirmedByStateMgr() {
	if s.stateProposalReceived {
		return
	}
	s.stateProposalReceived = true
	s.c.uponStateMgrStateProposalReceived(s.proposedBaseAnchor)
}

func (s *SyncStateMgr) DecidedVirtualStateNeeded(decidedBaseAnchor *isc.StateAnchor) {
	if s.decidedBaseAnchor != nil {
		return
	}
	s.decidedBaseAnchor = decidedBaseAnchor
	s.c.uponStateMgrDecidedStateQueryInputsReady(s.decidedBaseAnchor)
}

func (s *SyncStateMgr) DecidedVirtualStateReceived(chainState state.State) {
	if s.decidedStateReceived {
		return
	}
	s.decidedStateReceived = true
	s.c.uponStateMgrDecidedStateReceived(chainState)
}

func (s *SyncStateMgr) BlockProduced(block state.StateDraft) {
	if s.producedBlockReceived {
		return
	}
	s.producedBlock = block
	s.producedBlockReceived = true
	s.c.uponStateMgrSaveProducedBlockInputsReady(s.producedBlock)
}

func (s *SyncStateMgr) BlockSaved(block state.Block) {
	if s.saveProducedBlockDone {
		return
	}
	s.saveProducedBlockDone = true
	s.c.uponStateMgrSaveProducedBlockDone(block)
}

// String tries to provide useful human-readable compact status.
func (s *SyncStateMgr) String() string {
	str := "SM"
	if s.stateProposalReceived && s.decidedStateReceived {
		return str + statusStrOK
	}
	if s.stateProposalReceived {
		str += "/proposal=OK"
	} else if !s.proposedBaseAnchorReceived {
		str += "/proposal=WAIT[BaseAnchor]"
	} else {
		str += "/proposal=WAIT[RespFromStateMgr]"
	}
	if s.decidedStateReceived {
		str += "/state=OK"
	} else if s.decidedBaseAnchor == nil {
		str += "/state=WAIT[AcsDecision]"
	} else {
		str += "/state=WAIT[RespFromStateMgr]"
	}
	if s.saveProducedBlockDone {
		str += "/state=OK"
	} else if s.producedBlock == nil {
		str += "/state=WAIT[BlockFromVM]"
	} else {
		str += "/state=WAIT[RespFromStateMgr]"
	}
	return str
}
