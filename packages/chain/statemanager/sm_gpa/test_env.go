package sm_gpa

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/hive.go/kvstore/mapdb"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/wasp/packages/chain/statemanager/sm_gpa/sm_gpa_utils"
	"github.com/iotaledger/wasp/packages/chain/statemanager/sm_gpa/sm_inputs"
	"github.com/iotaledger/wasp/packages/chain/statemanager/sm_utils"
	"github.com/iotaledger/wasp/packages/gpa"
	"github.com/iotaledger/wasp/packages/metrics"
	"github.com/iotaledger/wasp/packages/origin"
	"github.com/iotaledger/wasp/packages/state"
	"github.com/iotaledger/wasp/packages/testutil/testlogger"
	"github.com/iotaledger/wasp/packages/util"
)

type testEnv struct {
	t            *testing.T
	bf           *sm_gpa_utils.BlockFactory
	nodeIDs      []gpa.NodeID
	timeProvider sm_gpa_utils.TimeProvider
	sms          map[gpa.NodeID]gpa.GPA
	stores       map[gpa.NodeID]state.Store
	tc           *gpa.TestContext
	log          *logger.Logger
}

func newTestEnv(t *testing.T, nodeIDs []gpa.NodeID, createWALFun func() sm_gpa_utils.TestBlockWAL, timersOpt ...StateManagerTimers) *testEnv {
	bf := sm_gpa_utils.NewBlockFactory(t)
	chainID := bf.GetChainID()
	log := testlogger.NewLogger(t).Named("c-" + chainID.ShortString())
	sms := make(map[gpa.NodeID]gpa.GPA)
	stores := make(map[gpa.NodeID]state.Store)
	var timers StateManagerTimers
	if len(timersOpt) > 0 {
		timers = timersOpt[0]
	} else {
		timers = NewStateManagerTimers()
	}
	timers.TimeProvider = sm_gpa_utils.NewArtifficialTimeProvider()
	for _, nodeID := range nodeIDs {
		var err error
		smLog := log.Named(nodeID.ShortString())
		nr := sm_utils.NewNodeRandomiser(nodeID, nodeIDs, smLog)
		wal := createWALFun()
		store := state.NewStore(mapdb.NewMapDB())
		origin.InitChain(store, nil, 0)
		stores[nodeID] = store
		metrics := metrics.NewEmptyChainStateManagerMetric()
		sms[nodeID], err = New(chainID, nr, wal, store, metrics, smLog, timers)
		require.NoError(t, err)
	}
	return &testEnv{
		t:            t,
		bf:           bf,
		nodeIDs:      nodeIDs,
		timeProvider: timers.TimeProvider,
		sms:          sms,
		stores:       stores,
		tc:           gpa.NewTestContext(sms),
		log:          log,
	}
}

func (teT *testEnv) finalize() {
	_ = teT.log.Sync()
}

func (teT *testEnv) sendBlocksToNode(nodeID gpa.NodeID, timeStep time.Duration, blocks ...state.Block) {
	// If `ConsensusBlockProduced` is sent to the node, the node has definitely obtained all the blocks
	// needed to commit this block. This is ensured by consensus.
	require.True(teT.t, teT.sendAndEnsureCompletedConsensusStateProposal(blocks[0].PreviousL1Commitment(), nodeID, 100, timeStep))
	for i := range blocks {
		teT.t.Logf("Supplying block %s to node %s", blocks[i].L1Commitment(), nodeID.ShortString())
		teT.sendAndEnsureCompletedConsensusBlockProduced(blocks[i], nodeID, 100, timeStep)
	}
}

func (teT *testEnv) sendBlocksToRandomNode(nodeIDs []gpa.NodeID, timeStep time.Duration, blocks ...state.Block) {
	for _, block := range blocks {
		teT.sendBlocksToNode(nodeIDs[rand.Intn(len(nodeIDs))], timeStep, block)
	}
}

// --------

func (teT *testEnv) sendAndEnsureCompletedConsensusBlockProduced(block state.Block, nodeID gpa.NodeID, maxTimeIterations int, timeStep time.Duration) bool {
	responseCh := teT.sendConsensusBlockProduced(block, nodeID)
	return teT.ensureCompletedConsensusBlockProduced(responseCh, maxTimeIterations, timeStep)
}

func (teT *testEnv) sendConsensusBlockProduced(block state.Block, nodeID gpa.NodeID) <-chan state.Block {
	input, responseCh := sm_inputs.NewConsensusBlockProduced(context.Background(), teT.bf.GetStateDraft(block))
	teT.tc.WithInputs(map[gpa.NodeID]gpa.Input{nodeID: input}).RunAll()
	return responseCh
}

func (teT *testEnv) ensureCompletedConsensusBlockProduced(respChan <-chan state.Block, maxTimeIterations int, timeStep time.Duration) bool {
	return teT.ensureTrue("response from ConsensusBlockProduced", func() bool {
		select {
		case block := <-respChan:
			require.NotNil(teT.t, block)
			return true
		default:
			return false
		}
	}, maxTimeIterations, timeStep)
}

// --------

func (teT *testEnv) sendAndEnsureCompletedConsensusStateProposal(commitment *state.L1Commitment, nodeID gpa.NodeID, maxTimeIterations int, timeStep time.Duration) bool {
	responseCh := teT.sendConsensusStateProposal(commitment, nodeID)
	return teT.ensureCompletedConsensusStateProposal(responseCh, maxTimeIterations, timeStep)
}

func (teT *testEnv) sendConsensusStateProposal(commitment *state.L1Commitment, nodeID gpa.NodeID) <-chan interface{} {
	input, responseCh := sm_inputs.NewConsensusStateProposal(context.Background(), teT.bf.GetAliasOutput(commitment))
	teT.tc.WithInputs(map[gpa.NodeID]gpa.Input{nodeID: input}).RunAll()
	return responseCh
}

func (teT *testEnv) ensureCompletedConsensusStateProposal(respChan <-chan interface{}, maxTimeIterations int, timeStep time.Duration) bool {
	return teT.ensureTrue("response from ConsensusStateProposal", func() bool {
		select {
		case result := <-respChan:
			require.Nil(teT.t, result)
			return true
		default:
			return false
		}
	}, maxTimeIterations, timeStep)
}

// --------

func (teT *testEnv) sendAndEnsureCompletedConsensusDecidedState(commitment *state.L1Commitment, nodeID gpa.NodeID, maxTimeIterations int, timeStep time.Duration) bool {
	responseCh := teT.sendConsensusDecidedState(commitment, nodeID)
	return teT.ensureCompletedConsensusDecidedState(responseCh, commitment, maxTimeIterations, timeStep)
}

func (teT *testEnv) sendConsensusDecidedState(commitment *state.L1Commitment, nodeID gpa.NodeID) <-chan state.State {
	input, responseCh := sm_inputs.NewConsensusDecidedState(context.Background(), teT.bf.GetAliasOutput(commitment))
	teT.tc.WithInputs(map[gpa.NodeID]gpa.Input{nodeID: input}).RunAll()
	return responseCh
}

func (teT *testEnv) ensureCompletedConsensusDecidedState(respChan <-chan state.State, expectedCommitment *state.L1Commitment, maxTimeIterations int, timeStep time.Duration) bool {
	expectedState := teT.bf.GetState(expectedCommitment)
	return teT.ensureTrue("response from ConsensusDecidedState", func() bool {
		select {
		case s := <-respChan:
			// Should be require.True(teT.t, expected.Equals(s))
			expectedTrieRoot := expectedState.TrieRoot()
			receivedTrieRoot := s.TrieRoot()
			require.Equal(teT.t, expectedState.BlockIndex(), s.BlockIndex())
			teT.t.Logf("Checking trie roots: expected %s, obtained %s", expectedTrieRoot, receivedTrieRoot)
			require.True(teT.t, expectedTrieRoot.Equals(receivedTrieRoot))
			return true
		default:
			return false
		}
	}, maxTimeIterations, timeStep)
}

// --------

func (teT *testEnv) sendAndEnsureCompletedChainFetchStateDiff(oldCommitment, newCommitment *state.L1Commitment, expectedOldBlocks, expectedNewBlocks []state.Block, nodeID gpa.NodeID, maxTimeIterations int, timeStep time.Duration) bool {
	responseCh := teT.sendChainFetchStateDiff(oldCommitment, newCommitment, nodeID)
	return teT.ensureCompletedChainFetchStateDiff(responseCh, expectedOldBlocks, expectedNewBlocks, maxTimeIterations, timeStep)
}

func (teT *testEnv) sendChainFetchStateDiff(oldCommitment, newCommitment *state.L1Commitment, nodeID gpa.NodeID) <-chan *sm_inputs.ChainFetchStateDiffResults {
	input, responseCh := sm_inputs.NewChainFetchStateDiff(context.Background(), teT.bf.GetAliasOutput(oldCommitment), teT.bf.GetAliasOutput(newCommitment))
	teT.tc.WithInputs(map[gpa.NodeID]gpa.Input{nodeID: input}).RunAll()
	return responseCh
}

func (teT *testEnv) ensureCompletedChainFetchStateDiff(respChan <-chan *sm_inputs.ChainFetchStateDiffResults, expectedOldBlocks, expectedNewBlocks []state.Block, maxTimeIterations int, timeStep time.Duration) bool {
	return teT.ensureTrue("response from ChainFetchStateDiff", func() bool {
		select {
		case cfsdr := <-respChan:
			newStateTrieRoot := cfsdr.GetNewState().TrieRoot()
			lastNewBlockTrieRoot := expectedNewBlocks[len(expectedNewBlocks)-1].TrieRoot()
			teT.t.Logf("Checking trie roots: expected %s, obtained %s", lastNewBlockTrieRoot, newStateTrieRoot)
			require.True(teT.t, newStateTrieRoot.Equals(lastNewBlockTrieRoot))
			requireEqualsFun := func(expected, received []state.Block) {
				teT.t.Logf("\tExpected %v elements, obtained %v elements", len(expected), len(received))
				require.Equal(teT.t, len(expected), len(received))
				for i := range expected {
					expectedCommitment := expected[i].L1Commitment()
					receivedCommitment := received[i].L1Commitment()
					teT.t.Logf("\tchecking %v-th element: expected %s, received %s", i, expectedCommitment, receivedCommitment)
					require.True(teT.t, expectedCommitment.Equals(receivedCommitment))
				}
			}
			teT.t.Log("Checking added blocks...")
			requireEqualsFun(expectedNewBlocks, cfsdr.GetAdded())
			teT.t.Log("Checking removed blocks...")
			requireEqualsFun(expectedOldBlocks, cfsdr.GetRemoved())
			return true
		default:
			return false
		}
	}, maxTimeIterations, timeStep)
}

// --------

func (teT *testEnv) ensureStoreContainsBlocksNoWait(nodeID gpa.NodeID, blocks []state.Block) bool {
	return teT.ensureTrue("store to contain blocks", func() bool {
		for _, block := range blocks {
			commitment := block.L1Commitment()
			teT.t.Logf("Checking block %s on node %s...", commitment, nodeID.ShortString())
			store, ok := teT.stores[nodeID]
			require.True(teT.t, ok)
			if store.HasTrieRoot(commitment.TrieRoot) {
				teT.t.Logf("Node %s contains block %s", nodeID.ShortString(), commitment)
			} else {
				teT.t.Logf("Node %s does not contain block %s", nodeID.ShortString(), commitment)
				return false
			}
		}
		return true
	}, 1, 0*time.Second)
}

// --------

func (teT *testEnv) ensureTrue(title string, predicate func() bool, maxTimeIterations int, timeStep time.Duration) bool {
	if predicate() {
		return true
	}
	for i := 1; i < maxTimeIterations; i++ {
		teT.t.Logf("Waiting for %s iteration %v", title, i)
		teT.sendTimerTickToNodes(timeStep)
		if predicate() {
			return true
		}
	}
	return false
}

func (teT *testEnv) sendTimerTickToNodes(delay time.Duration) {
	now := teT.timeProvider.GetNow().Add(delay)
	teT.timeProvider.SetNow(now)
	teT.t.Logf("Time %v is sent to nodes %s", now, util.SliceShortString(teT.nodeIDs))
	teT.sendInputToNodes(func(_ gpa.NodeID) gpa.Input {
		return sm_inputs.NewStateManagerTimerTick(now)
	})
}

func (teT *testEnv) sendInputToNodes(makeInputFun func(gpa.NodeID) gpa.Input) {
	inputs := make(map[gpa.NodeID]gpa.Input)
	for _, nodeID := range teT.nodeIDs {
		inputs[nodeID] = makeInputFun(nodeID)
	}
	teT.tc.WithInputs(inputs).RunAll()
}
