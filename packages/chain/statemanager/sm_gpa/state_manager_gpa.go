//
//
//
//
//
//

package sm_gpa

import (
	"fmt"
	"time"

	"github.com/samber/lo"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/wasp/packages/chain/statemanager/sm_gpa/sm_gpa_utils"
	"github.com/iotaledger/wasp/packages/chain/statemanager/sm_gpa/sm_inputs"
	"github.com/iotaledger/wasp/packages/chain/statemanager/sm_gpa/sm_messages"
	"github.com/iotaledger/wasp/packages/chain/statemanager/sm_utils"
	"github.com/iotaledger/wasp/packages/gpa"
	"github.com/iotaledger/wasp/packages/isc"
	"github.com/iotaledger/wasp/packages/metrics"
	"github.com/iotaledger/wasp/packages/state"
	"github.com/iotaledger/wasp/packages/util"
)

type stateManagerGPA struct {
	log                     *logger.Logger
	chainID                 isc.ChainID
	blockCache              sm_gpa_utils.BlockCache
	blocksToFetch           blockFetchers
	blocksFetched           blockFetchers
	nodeRandomiser          sm_utils.NodeRandomiser
	store                   state.Store
	timers                  StateManagerTimers
	lastGetBlocksTime       time.Time
	lastCleanBlockCacheTime time.Time
	lastCleanRequestsTime   time.Time
	lastStatusLogTime       time.Time
	metrics                 metrics.IChainStateManagerMetrics
}

var _ gpa.GPA = &stateManagerGPA{}

const (
	numberOfNodesToRequestBlockFromConst = 5
	statusLogPeriodConst                 = 10 * time.Second
)

func New(
	chainID isc.ChainID,
	nr sm_utils.NodeRandomiser,
	wal sm_gpa_utils.BlockWAL,
	store state.Store,
	metrics metrics.IChainStateManagerMetrics,
	log *logger.Logger,
	timers StateManagerTimers,
) (gpa.GPA, error) {
	var err error
	smLog := log.Named("gpa")
	blockCache, err := sm_gpa_utils.NewBlockCache(timers.TimeProvider, timers.BlockCacheMaxSize, wal, metrics, smLog)
	if err != nil {
		return nil, fmt.Errorf("error creating block cache: %v", err)
	}
	result := &stateManagerGPA{
		log:                     smLog,
		chainID:                 chainID,
		blockCache:              blockCache,
		blocksToFetch:           newBlockFetchers(newBlockFetchersMetrics(metrics.IncBlocksFetching, metrics.DecBlocksFetching, metrics.StateManagerBlockFetched)),
		blocksFetched:           newBlockFetchers(newBlockFetchersMetrics(metrics.IncBlocksPending, metrics.DecBlocksPending, bfmNopDurationFun)),
		nodeRandomiser:          nr,
		store:                   store,
		timers:                  timers,
		lastGetBlocksTime:       time.Time{},
		lastCleanBlockCacheTime: time.Time{},
		lastStatusLogTime:       time.Time{},
		metrics:                 metrics,
	}

	return result, nil
}

// -------------------------------------
// Implementation for gpa.GPA interface
// -------------------------------------

func (smT *stateManagerGPA) Input(input gpa.Input) gpa.OutMessages {
	switch inputCasted := input.(type) {
	case *sm_inputs.ConsensusStateProposal: // From consensus
		return smT.handleConsensusStateProposal(inputCasted)
	case *sm_inputs.ConsensusDecidedState: // From consensus
		return smT.handleConsensusDecidedState(inputCasted)
	case *sm_inputs.ConsensusBlockProduced: // From consensus
		return smT.handleConsensusBlockProduced(inputCasted)
	case *sm_inputs.ChainFetchStateDiff: // From mempool
		return smT.handleChainFetchStateDiff(inputCasted)
	case *sm_inputs.StateManagerTimerTick: // From state manager go routine
		return smT.handleStateManagerTimerTick(inputCasted.GetTime())
	default:
		smT.log.Warnf("Unknown input received, ignoring it: type=%T, message=%v", input, input)
		return nil // No messages to send
	}
}

func (smT *stateManagerGPA) Message(msg gpa.Message) gpa.OutMessages {
	switch msgCasted := msg.(type) {
	case *sm_messages.GetBlockMessage:
		return smT.handlePeerGetBlock(msgCasted.Sender(), msgCasted.GetL1Commitment())
	case *sm_messages.BlockMessage:
		return smT.handlePeerBlock(msgCasted.Sender(), msgCasted.GetBlock())
	default:
		smT.log.Warnf("Unknown message received, ignoring it: type=%T, message=%v", msg, msg)
		return nil // No messages to send
	}
}

func (smT *stateManagerGPA) Output() gpa.Output {
	return nil
}

func (smT *stateManagerGPA) StatusString() string {
	return fmt.Sprintf(
		"State manager is waiting for %v blocks from other nodes; "+
			"%v blocks are obtained and waiting to be committed; "+
			"%v requests are waiting for response; "+
			"last time blocks were requested from peer nodes: %v (every %v); "+
			"last time outdated requests were cleared: %v (every %v); "+
			"last time block cache was cleaned: %v (every %v).",
		smT.blocksToFetch.getSize(),
		smT.blocksFetched.getSize(),
		smT.getWaitingCallbacksCount(),
		util.TimeOrNever(smT.lastGetBlocksTime), smT.timers.StateManagerGetBlockRetry,
		util.TimeOrNever(smT.lastCleanRequestsTime), smT.timers.StateManagerRequestCleaningPeriod,
		util.TimeOrNever(smT.lastCleanBlockCacheTime), smT.timers.BlockCacheBlockCleaningPeriod,
	)
}

func (smT *stateManagerGPA) UnmarshalMessage(data []byte) (gpa.Message, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("error unmarshalling message: slice of length %d is too short", len(data))
	}
	var message gpa.Message
	switch data[0] {
	case sm_messages.MsgTypeBlockMessage:
		message = sm_messages.NewEmptyBlockMessage()
	case sm_messages.MsgTypeGetBlockMessage:
		message = sm_messages.NewEmptyGetBlockMessage()
	default:
		return nil, fmt.Errorf("error unmarshalling message: message type %v unknown", data[0])
	}
	err := message.UnmarshalBinary(data)
	return message, err
}

// -------------------------------------
// Internal functions
// -------------------------------------

func (smT *stateManagerGPA) handlePeerGetBlock(from gpa.NodeID, commitment *state.L1Commitment) gpa.OutMessages {
	// TODO: [KP] Only accept queries from access nodes.
	fromLog := from.ShortString()
	smT.log.Debugf("Message GetBlock %s received from peer %s", commitment, fromLog)
	block := smT.getBlock(commitment)
	if block == nil {
		smT.log.Debugf("Message GetBlock %s: block not found, peer %s request ignored", commitment, fromLog)
		return nil // No messages to send
	}
	smT.log.Debugf("Message GetBlock %s: block index %v found, sending it to peer %s", commitment, block.StateIndex(), fromLog)
	return gpa.NoMessages().Add(sm_messages.NewBlockMessage(block, from))
}

func (smT *stateManagerGPA) handlePeerBlock(from gpa.NodeID, block state.Block) gpa.OutMessages {
	blockIndex := block.StateIndex()
	blockCommitment := block.L1Commitment()
	fromLog := from.ShortString()
	smT.log.Debugf("Message Block index %v %s received from peer %s", blockIndex, blockCommitment, fromLog)
	fetcher := smT.blocksToFetch.takeFetcher(blockCommitment)
	if fetcher == nil {
		smT.log.Debugf("Message Block index %v %s: block is not needed, ignoring it", blockIndex, blockCommitment)
		return nil // No messages to send
	}
	smT.blockCache.AddBlock(block)
	messages := smT.traceBlockChain(fetcher)
	smT.log.Debugf("Message Block index %v %s from peer %s handled", blockIndex, blockCommitment, fromLog)
	return messages
}

func (smT *stateManagerGPA) handleConsensusStateProposal(csp *sm_inputs.ConsensusStateProposal) gpa.OutMessages {
	start := time.Now()
	smT.log.Debugf("Input consensus state proposal %s received...", csp.GetL1Commitment())
	callback := newBlockRequestCallback(
		func() bool {
			return csp.IsValid()
		},
		func() {
			csp.Respond()
			smT.log.Debugf("Input consensus state proposal %s: responded to consensus", csp.GetL1Commitment())
			smT.metrics.ConsensusStateProposalHandled(time.Since(start))
		},
	)
	messages := smT.traceBlockChainWithCallback(csp.GetL1Commitment(), callback)
	smT.log.Debugf("Input consensus state proposal %s handled", csp.GetL1Commitment())
	return messages
}

func (smT *stateManagerGPA) handleConsensusDecidedState(cds *sm_inputs.ConsensusDecidedState) gpa.OutMessages {
	start := time.Now()
	smT.log.Debugf("Input consensus decided state %s received...", cds.GetL1Commitment())
	callback := newBlockRequestCallback(
		func() bool {
			return cds.IsValid()
		},
		func() {
			state, err := smT.store.StateByTrieRoot(cds.GetL1Commitment().TrieRoot)
			if err != nil {
				smT.log.Errorf("Input consensus decided state %s: error obtaining state: %w", cds.GetL1Commitment(), err)
				return
			}
			cds.Respond(state)
			smT.log.Debugf("Input consensus decided state %s: responded to consensus with state index %v", cds.GetL1Commitment(), state.BlockIndex())
			smT.metrics.ConsensusDecidedStateHandled(time.Since(start))
		},
	)
	messages := smT.traceBlockChainWithCallback(cds.GetL1Commitment(), callback)
	smT.log.Debugf("Input consensus decided state %s handled", cds.GetL1Commitment())
	return messages
}

func (smT *stateManagerGPA) handleConsensusBlockProduced(input *sm_inputs.ConsensusBlockProduced) gpa.OutMessages {
	start := time.Now()
	stateIndex := input.GetStateDraft().BlockIndex()
	commitment := input.GetStateDraft().BaseL1Commitment()
	smT.log.Debugf("Input block produced on state index %v %s received...", stateIndex, commitment)
	if !smT.store.HasTrieRoot(commitment.TrieRoot) {
		smT.log.Panicf("Input block produced on state index %v %s: state, on which this block is produced, is not yet in the store", stateIndex, commitment)
	}
	// NOTE: committing already committed block is allowed (see `TestDoubleCommit` test in `packages/state/state_test.go`)
	block := smT.store.Commit(input.GetStateDraft())
	smT.metrics.IncBlocksCommitted()
	blockCommitment := block.L1Commitment()
	smT.blockCache.AddBlock(block)
	input.Respond(block)
	smT.log.Debugf("Input block produced on state index %v %s: state draft index %v has been committed to the store, responded to consensus with resulting block %s",
		stateIndex, commitment, input.GetStateDraft().BlockIndex(), blockCommitment)
	fetcher := smT.blocksToFetch.takeFetcher(blockCommitment)
	var result gpa.OutMessages
	if fetcher != nil {
		result = smT.markFetched(fetcher)
	}
	smT.log.Debugf("Input block produced on state index %v %s handled", stateIndex, commitment)
	smT.metrics.ConsensusBlockProducedHandled(time.Since(start))
	return result // No messages to send
}

func (smT *stateManagerGPA) handleChainFetchStateDiff(input *sm_inputs.ChainFetchStateDiff) gpa.OutMessages {
	start := time.Now()
	smT.log.Debugf("Input mempool state request for state index %v %s is received compared to state index %v %s...",
		input.GetNewStateIndex(), input.GetNewL1Commitment(), input.GetOldStateIndex(), input.GetOldL1Commitment())
	oldBlockRequestCompleted := false
	newBlockRequestCompleted := false
	isValidFun := func() bool { return input.IsValid() }
	obtainCommittedBlockFun := func(commitment *state.L1Commitment) state.Block {
		result := smT.getBlock(commitment)
		if result == nil {
			smT.log.Panicf("Input mempool state request for state index %v %s: cannot obtain block %s", input.GetNewStateIndex(), input.GetNewL1Commitment(), commitment)
		}
		return result
	}
	lastBlockFun := func(blocks []state.Block) state.Block {
		return blocks[len(blocks)-1]
	}
	respondFun := func() {
		oldBlock := obtainCommittedBlockFun(input.GetOldL1Commitment())
		newBlock := obtainCommittedBlockFun(input.GetNewL1Commitment())
		oldChainOfBlocks := []state.Block{oldBlock}
		newChainOfBlocks := []state.Block{newBlock}
		for lastBlockFun(oldChainOfBlocks).StateIndex() > lastBlockFun(newChainOfBlocks).StateIndex() {
			oldChainOfBlocks = append(oldChainOfBlocks, obtainCommittedBlockFun(lastBlockFun(oldChainOfBlocks).PreviousL1Commitment()))
		}
		for lastBlockFun(oldChainOfBlocks).StateIndex() < lastBlockFun(newChainOfBlocks).StateIndex() {
			newChainOfBlocks = append(newChainOfBlocks, obtainCommittedBlockFun(lastBlockFun(newChainOfBlocks).PreviousL1Commitment()))
		}
		for lastBlockFun(oldChainOfBlocks).StateIndex() > 0 {
			if lastBlockFun(oldChainOfBlocks).L1Commitment().Equals(lastBlockFun(newChainOfBlocks).L1Commitment()) {
				break
			}
			oldChainOfBlocks = append(oldChainOfBlocks, obtainCommittedBlockFun(lastBlockFun(oldChainOfBlocks).PreviousL1Commitment()))
			newChainOfBlocks = append(newChainOfBlocks, obtainCommittedBlockFun(lastBlockFun(newChainOfBlocks).PreviousL1Commitment()))
		}
		commonIndex := lastBlockFun(oldChainOfBlocks).StateIndex()
		commonCommitment := lastBlockFun(oldChainOfBlocks).L1Commitment()
		oldChainOfBlocks = lo.Reverse(oldChainOfBlocks[:len(oldChainOfBlocks)-1])
		newChainOfBlocks = lo.Reverse(newChainOfBlocks[:len(newChainOfBlocks)-1])
		newState, err := smT.store.StateByTrieRoot(input.GetNewL1Commitment().TrieRoot)
		if err != nil {
			smT.log.Errorf("Input mempool state request for state index %v %s: error obtaining state: %w",
				input.GetNewStateIndex(), input.GetNewL1Commitment(), err)
			return
		}
		input.Respond(sm_inputs.NewChainFetchStateDiffResults(newState, newChainOfBlocks, oldChainOfBlocks))
		smT.log.Debugf("Input mempool state request for state index %v %s: responded to chain with requested state, "+
			"and block chains of length %v (requested) and %v (old) with common ancestor index %v %s",
			input.GetNewStateIndex(), input.GetNewL1Commitment(), len(newChainOfBlocks), len(oldChainOfBlocks),
			commonIndex, commonCommitment)
		smT.metrics.ChainFetchStateDiffHandled(time.Since(start))
	}
	respondIfNeededFun := func() {
		if oldBlockRequestCompleted && newBlockRequestCompleted {
			respondFun()
		}
	}
	oldRequestCallback := newBlockRequestCallback(isValidFun, func() {
		oldBlockRequestCompleted = true
		smT.log.Debugf("Input mempool state request for state index %v %s: new block request completed",
			input.GetNewStateIndex(), input.GetNewL1Commitment())
		respondIfNeededFun()
	})
	newRequestCallback := newBlockRequestCallback(isValidFun, func() {
		newBlockRequestCompleted = true
		smT.log.Debugf("Input mempool state request for state index %v %s: old block request completed",
			input.GetNewStateIndex(), input.GetNewL1Commitment())
		respondIfNeededFun()
	})
	result := gpa.NoMessages()
	result.AddAll(smT.traceBlockChainWithCallback(input.GetOldL1Commitment(), oldRequestCallback))
	result.AddAll(smT.traceBlockChainWithCallback(input.GetNewL1Commitment(), newRequestCallback))
	smT.log.Debugf("Input mempool state request for state index %v %s handled",
		input.GetNewStateIndex(), input.GetNewL1Commitment())
	return result
}

func (smT *stateManagerGPA) getBlock(commitment *state.L1Commitment) state.Block {
	block := smT.blockCache.GetBlock(commitment)
	if block != nil {
		return block
	}

	// Check in store (DB).
	if !smT.store.HasTrieRoot(commitment.TrieRoot) {
		return nil
	}
	var err error
	block, err = smT.store.BlockByTrieRoot(commitment.TrieRoot)
	if err != nil {
		smT.log.Errorf("Loading block %s from the DB failed: %v", commitment, err)
		return nil
	}
	if !commitment.BlockHash.Equals(block.Hash()) {
		smT.log.Errorf("Block %s loaded from the database has hash %s",
			commitment, block.Hash())
		return nil
	}
	if !commitment.TrieRoot.Equals(block.TrieRoot()) {
		smT.log.Errorf("Block %s loaded from the database has trie root %s",
			commitment, block.TrieRoot())
		return nil
	}
	smT.log.Debugf("Block %s with index %v loaded from the database", commitment, block.StateIndex())
	smT.blockCache.AddBlock(block)
	return block
}

func (smT *stateManagerGPA) traceBlockChainWithCallback(lastCommitment *state.L1Commitment, callback blockRequestCallback) gpa.OutMessages {
	if smT.store.HasTrieRoot(lastCommitment.TrieRoot) {
		smT.log.Debugf("Tracing block %s chain: the block is already in the store, calling back", lastCommitment)
		callback.requestCompleted()
		return nil // No messages to send
	}
	if smT.blocksToFetch.addCallback(lastCommitment, callback) {
		smT.metrics.IncRequestsWaiting()
		smT.log.Debugf("Tracing block %s chain: the block is already being fetched", lastCommitment)
		return nil
	}
	if smT.blocksFetched.addCallback(lastCommitment, callback) {
		smT.metrics.IncRequestsWaiting()
		smT.log.Debugf("Tracing block %s chain: the block is already fetched, but cannot yet be committed", lastCommitment)
		return nil
	}
	fetcher := newBlockFetcherWithCallback(lastCommitment, callback)
	smT.metrics.IncRequestsWaiting()
	return smT.traceBlockChain(fetcher)
}

// TODO: state manager may ask for several requests at once: the request can be
// formulated as "give me blocks from some commitment till some index". If the
// requested node has the required block committed into the store, it certainly
// has all the blocks before it.
func (smT *stateManagerGPA) traceBlockChain(fetcher blockFetcher) gpa.OutMessages {
	commitment := fetcher.getCommitment()
	if !smT.store.HasTrieRoot(commitment.TrieRoot) {
		block := smT.blockCache.GetBlock(commitment)
		if block == nil {
			smT.blocksToFetch.addFetcher(fetcher)
			smT.log.Debugf("Block %s is missing, starting fetching it", commitment)
			return smT.makeGetBlockRequestMessages(commitment)
		}
		blockIndex := block.StateIndex()
		previousBlockIndex := blockIndex - 1
		previousCommitment := block.PreviousL1Commitment()
		smT.log.Debugf("Tracing block index %v %s -> previous block %v %s", blockIndex, commitment, previousBlockIndex, previousCommitment)
		if previousCommitment == nil {
			result := smT.markFetched(fetcher)
			smT.log.Debugf("Traced to the initial block")
			return result
		}
		smT.blocksFetched.addFetcher(fetcher)
		if smT.blocksToFetch.addRelatedFetcher(previousCommitment, fetcher) {
			smT.log.Debugf("Block %v %s is already being fetched", previousBlockIndex, previousCommitment)
			return nil
		}
		if smT.blocksFetched.addRelatedFetcher(previousCommitment, fetcher) {
			smT.log.Debugf("Block %v %s is already fetched, but cannot yet be committed", previousBlockIndex, previousCommitment)
			return nil
		}
		return smT.traceBlockChain(newBlockFetcherWithRelatedFetcher(previousCommitment, fetcher))
	}
	result := smT.markFetched(fetcher)
	smT.log.Debugf("Block %s is already committed", commitment)
	return result
}

func (smT *stateManagerGPA) markFetched(fetcher blockFetcher) gpa.OutMessages {
	result := gpa.NoMessages()
	fetcher.notifyFetched(func(bf blockFetcher) bool {
		commitment := bf.getCommitment()
		block := smT.blockCache.GetBlock(commitment)
		if block == nil {
			// Block was previously received but it is no longer in cache and
			// for some unexpected reasons it is not in WAL: rerequest it
			smT.log.Warnf("Block %s was previously obtained, but it can neither be found in cache nor in WAL. Rerequesting it.", commitment)
			smT.blocksToFetch.addFetcher(bf)
			result.AddAll(smT.makeGetBlockRequestMessages(commitment))
			return false
		}
		blockIndex := block.StateIndex()
		// Commit block
		var stateDraft state.StateDraft
		previousCommitment := block.PreviousL1Commitment()
		if previousCommitment == nil {
			// origin block
			stateDraft = smT.store.NewOriginStateDraft()
		} else {
			var err error
			stateDraft, err = smT.store.NewEmptyStateDraft(previousCommitment)
			if err != nil {
				smT.log.Panicf("Error creating empty state draft to store block index %v %s: %w", blockIndex, commitment, err)
			}
		}
		block.Mutations().ApplyTo(stateDraft)
		committedBlock := smT.store.Commit(stateDraft)
		smT.metrics.IncBlocksCommitted()
		committedCommitment := committedBlock.L1Commitment()
		if !committedCommitment.Equals(commitment) {
			smT.log.Panicf("Block index %v, received after committing (%s), differs from the block, which was committed (%s)",
				blockIndex, committedCommitment, commitment)
		}
		smT.log.Debugf("Block index %v %s has been committed to the store on state %s",
			blockIndex, commitment, previousCommitment)
		_ = smT.blocksFetched.takeFetcher(commitment)
		smT.metrics.SubRequestsWaiting(bf.getCallbacksCount())
		return true
	})
	return result
}

// Make `numberOfNodesToRequestBlockFromConst` messages to random peers
func (smT *stateManagerGPA) makeGetBlockRequestMessages(commitment *state.L1Commitment) gpa.OutMessages {
	nodeIDs := smT.nodeRandomiser.GetRandomOtherNodeIDs(numberOfNodesToRequestBlockFromConst)
	response := gpa.NoMessages()
	for _, nodeID := range nodeIDs {
		response.Add(sm_messages.NewGetBlockMessage(commitment, nodeID))
	}
	return response
}

func (smT *stateManagerGPA) handleStateManagerTimerTick(now time.Time) gpa.OutMessages {
	start := time.Now()
	result := gpa.NoMessages()
	nextStatusLogTime := smT.lastStatusLogTime.Add(statusLogPeriodConst)
	if now.After(nextStatusLogTime) {
		smT.log.Debugf("State manager gpa status: %s", smT.StatusString())
		smT.lastStatusLogTime = now
	}
	nextGetBlocksTime := smT.lastGetBlocksTime.Add(smT.timers.StateManagerGetBlockRetry)
	if now.After(nextGetBlocksTime) {
		commitments := smT.blocksToFetch.getCommitments()
		for _, commitment := range commitments {
			result.AddAll(smT.makeGetBlockRequestMessages(commitment))
		}
		smT.lastGetBlocksTime = now
		smT.log.Debugf("Resent getBlock messages for blocks %s, next resend not earlier than %v",
			commitments, smT.lastGetBlocksTime.Add(smT.timers.StateManagerGetBlockRetry))
	}
	nextCleanBlockCacheTime := smT.lastCleanBlockCacheTime.Add(smT.timers.BlockCacheBlockCleaningPeriod)
	if now.After(nextCleanBlockCacheTime) {
		smT.blockCache.CleanOlderThan(now.Add(-smT.timers.BlockCacheBlocksInCacheDuration))
		smT.lastCleanBlockCacheTime = now
		smT.log.Debugf("Block cache cleaned, %v blocks remaining, next cleaning not earlier than %v",
			smT.blockCache.Size(), smT.lastCleanBlockCacheTime.Add(smT.timers.BlockCacheBlockCleaningPeriod))
	}
	nextCleanRequestsTime := smT.lastCleanRequestsTime.Add(smT.timers.StateManagerRequestCleaningPeriod)
	if now.After(nextCleanRequestsTime) {
		smT.blocksToFetch.cleanCallbacks()
		smT.blocksFetched.cleanCallbacks()
		smT.lastCleanRequestsTime = now
		waitingCallbacks := smT.getWaitingCallbacksCount()
		smT.metrics.SetRequestsWaiting(waitingCallbacks)
		smT.log.Debugf("Callbacks of block fetchers cleaned, %v waiting callbacks remained, next cleaning not earlier than %v",
			waitingCallbacks, smT.lastCleanRequestsTime.Add(smT.timers.StateManagerRequestCleaningPeriod))
	}
	smT.metrics.StateManagerTimerTickHandled(time.Since(start))
	return result
}

func (smT *stateManagerGPA) getWaitingCallbacksCount() int {
	return smT.blocksToFetch.getCallbacksCount() + smT.blocksFetched.getCallbacksCount()
}
