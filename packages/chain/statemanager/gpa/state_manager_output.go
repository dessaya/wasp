package gpa

import (
	"github.com/iotaledger/wasp/v2/packages/chain/statemanager/snapshots"
	"github.com/iotaledger/wasp/v2/packages/state"
)

type StateManagerOutput struct {
	blocksCommitted []snapshots.SnapshotInfo
	blocksToCommit  [][]*state.L1Commitment
}

func newOutput() *StateManagerOutput {
	return &StateManagerOutput{}
}

func (smoi *StateManagerOutput) addBlockCommitted(stateIndex uint32, commitment *state.L1Commitment) {
	smoi.blocksCommitted = append(smoi.blocksCommitted, snapshots.NewSnapshotInfo(stateIndex, commitment))
}

func (smoi *StateManagerOutput) TakeBlocksCommitted() []snapshots.SnapshotInfo {
	result := smoi.blocksCommitted
	smoi.blocksCommitted = make([]snapshots.SnapshotInfo, 0)
	return result
}

func (smoi *StateManagerOutput) addBlocksToCommit(commitments []*state.L1Commitment) {
	smoi.blocksToCommit = append(smoi.blocksToCommit, commitments)
}

func (smoi *StateManagerOutput) TakeBlocksToCommit() [][]*state.L1Commitment {
	result := smoi.blocksToCommit
	smoi.blocksToCommit = nil
	return result
}
