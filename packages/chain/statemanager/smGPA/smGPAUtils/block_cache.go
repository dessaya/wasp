package smGPAUtils

import (
	"time"

	"github.com/iotaledger/hive.go/ds/shrinkingmap"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/wasp/packages/state"
)

type blockTime struct {
	time     time.Time
	blockKey BlockKey
}

type blockCache struct {
	log          *logger.Logger
	blocks       *shrinkingmap.ShrinkingMap[BlockKey, state.Block]
	maxCacheSize int
	wal          BlockWAL
	times        []*blockTime
	timeProvider TimeProvider
}

var _ BlockCache = &blockCache{}

func NewBlockCache(tp TimeProvider, maxCacheSize int, wal BlockWAL, log *logger.Logger) (BlockCache, error) {
	return &blockCache{
		log:          log.Named("bc"),
		blocks:       shrinkingmap.New[BlockKey, state.Block](),
		maxCacheSize: maxCacheSize,
		wal:          wal,
		times:        make([]*blockTime, 0),
		timeProvider: tp,
	}, nil
}

// Adds block to cache and WAL
func (bcT *blockCache) AddBlock(block state.Block) {
	commitment := block.L1Commitment()
	blockKey := NewBlockKey(commitment)
	err := bcT.wal.Write(block)
	if err != nil {
		bcT.log.Errorf("Failed writing block %s to WAL: %v", commitment, err)
	}

	bcT.blocks.Set(blockKey, block)
	bcT.times = append(bcT.times, &blockTime{
		time:     bcT.timeProvider.GetNow(),
		blockKey: blockKey,
	})
	bcT.log.Debugf("Block %s added to cache", commitment)

	if bcT.Size() > bcT.maxCacheSize {
		bt := bcT.times[0]
		bcT.times = bcT.times[1:]
		bcT.blocks.Delete(bt.blockKey)
		bcT.log.Debugf("Block %s deleted from cache, because cache is too large", bt.blockKey)
	}
}

func (bcT *blockCache) GetBlock(commitment *state.L1Commitment) state.Block {
	blockKey := NewBlockKey(commitment)
	// Check in cache
	block, exists := bcT.blocks.Get(blockKey)
	if exists {
		bcT.log.Debugf("Block %s retrieved from cache", commitment)
		return block
	}

	// Check in WAL
	if bcT.wal.Contains(commitment.BlockHash()) {
		block, err := bcT.wal.Read(commitment.BlockHash())
		if err != nil {
			bcT.log.Errorf("Error reading block %s from WAL: %w", commitment, err)
			return nil
		}
		bcT.log.Debugf("Block %s retrieved from WAL", commitment)
		return block
	}

	return nil
}

func (bcT *blockCache) CleanOlderThan(limit time.Time) {
	for i, bt := range bcT.times {
		if bt.time.After(limit) {
			bcT.times = bcT.times[i:]
			return
		}
		bcT.blocks.Delete(bt.blockKey)
		bcT.log.Debugf("Block %s deleted from cache, because it is too old", bt.blockKey)
	}
	bcT.times = make([]*blockTime, 0) // All the blocks were deleted
}

func (bcT *blockCache) Size() int {
	return bcT.blocks.Size()
}
