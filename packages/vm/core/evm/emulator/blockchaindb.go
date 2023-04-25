// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package emulator

import (
	"bytes"
	"encoding/gob"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/iotaledger/hive.go/serializer/v2/marshalutil"
	"github.com/iotaledger/wasp/packages/evm/evmtypes"
	"github.com/iotaledger/wasp/packages/evm/evmutil"
	"github.com/iotaledger/wasp/packages/kv"
	"github.com/iotaledger/wasp/packages/kv/codec"
	"github.com/iotaledger/wasp/packages/kv/collections"
	"github.com/iotaledger/wasp/packages/wbf"
)

const (
	// config values:

	// EVM chain ID
	keyChainID = "c"
	// Amount of blocks to keep in DB. Older blocks will be pruned every time a transaction is added
	keyKeepAmount = "k"

	// blocks:

	keyNumber                    = "n"
	keyPendingTimestamp          = "pt"
	keyTransactionsByBlockNumber = "n:t"
	keyReceiptsByBlockNumber     = "n:r"
	keyBlockHeaderByBlockNumber  = "n:bh"

	// indexes:

	keyBlockNumberByBlockHash = "bh:n"
	keyBlockNumberByTxHash    = "th:n"
	keyBlockIndexByTxHash     = "th:i"
)

// BlockchainDB contains logic for storing a fake blockchain (more like a list of blocks),
// intended for satisfying EVM tools that depend on the concept of a block.
type BlockchainDB struct {
	kv            kv.KVStore
	blockGasLimit uint64
}

func NewBlockchainDB(store kv.KVStore, blockGasLimit uint64) *BlockchainDB {
	return &BlockchainDB{kv: store, blockGasLimit: blockGasLimit}
}

func (bc *BlockchainDB) Initialized() bool {
	return bc.kv.Get(keyChainID) != nil
}

func (bc *BlockchainDB) Init(chainID uint16, keepAmount int32, timestamp uint64) {
	bc.SetChainID(chainID)
	bc.SetKeepAmount(keepAmount)
	bc.addBlock(bc.makeHeader(nil, nil, 0, timestamp), timestamp+1)
}

func (bc *BlockchainDB) SetChainID(chainID uint16) {
	bc.kv.Set(keyChainID, codec.EncodeUint16(chainID))
}

func (bc *BlockchainDB) GetChainID() uint16 {
	chainID, err := codec.DecodeUint16(bc.kv.Get(keyChainID))
	if err != nil {
		panic(err)
	}
	return chainID
}

func (bc *BlockchainDB) SetKeepAmount(keepAmount int32) {
	bc.kv.Set(keyKeepAmount, codec.EncodeInt32(keepAmount))
}

func (bc *BlockchainDB) keepAmount() int32 {
	gas, err := codec.DecodeInt32(bc.kv.Get(keyKeepAmount), -1)
	if err != nil {
		panic(err)
	}
	return gas
}

func (bc *BlockchainDB) setPendingTimestamp(timestamp uint64) {
	bc.kv.Set(keyPendingTimestamp, codec.EncodeUint64(timestamp))
}

func (bc *BlockchainDB) getPendingTimestamp() uint64 {
	timestamp, err := codec.DecodeUint64(bc.kv.Get(keyPendingTimestamp))
	if err != nil {
		panic(err)
	}
	return timestamp
}

func (bc *BlockchainDB) setNumber(n uint64) {
	bc.kv.Set(keyNumber, codec.EncodeUint64(n))
}

func (bc *BlockchainDB) GetNumber() uint64 {
	n, err := codec.DecodeUint64(bc.kv.Get(keyNumber))
	if err != nil {
		panic(err)
	}
	return n
}

func makeTransactionsByBlockNumberKey(blockNumber uint64) kv.Key {
	return keyTransactionsByBlockNumber + kv.Key(codec.EncodeUint64(blockNumber))
}

func makeReceiptsByBlockNumberKey(blockNumber uint64) kv.Key {
	return keyReceiptsByBlockNumber + kv.Key(codec.EncodeUint64(blockNumber))
}

func makeBlockHeaderByBlockNumberKey(blockNumber uint64) kv.Key {
	return keyBlockHeaderByBlockNumber + kv.Key(codec.EncodeUint64(blockNumber))
}

func makeBlockNumberByBlockHashKey(hash common.Hash) kv.Key {
	return keyBlockNumberByBlockHash + kv.Key(hash.Bytes())
}

func makeBlockNumberByTxHashKey(hash common.Hash) kv.Key {
	return keyBlockNumberByTxHash + kv.Key(hash.Bytes())
}

func makeBlockIndexByTxHashKey(hash common.Hash) kv.Key {
	return keyBlockIndexByTxHash + kv.Key(hash.Bytes())
}

func (bc *BlockchainDB) getTxArray(blockNumber uint64) *collections.Array32 {
	return collections.NewArray32(bc.kv, string(makeTransactionsByBlockNumberKey(blockNumber)))
}

func (bc *BlockchainDB) getReceiptArray(blockNumber uint64) *collections.Array32 {
	return collections.NewArray32(bc.kv, string(makeReceiptsByBlockNumberKey(blockNumber)))
}

func (bc *BlockchainDB) GetPendingBlockNumber() uint64 {
	return bc.GetNumber() + 1
}

func (bc *BlockchainDB) GetPendingHeader() *types.Header {
	return &types.Header{
		Difficulty: &big.Int{},
		Number:     new(big.Int).SetUint64(bc.GetPendingBlockNumber()),
		GasLimit:   bc.blockGasLimit,
		Time:       bc.getPendingTimestamp(),
	}
}

func (bc *BlockchainDB) GetLatestPendingReceipt() *types.Receipt {
	blockNumber := bc.GetPendingBlockNumber()
	receiptArray := bc.getReceiptArray(blockNumber)
	n := receiptArray.Len()
	if n == 0 {
		return nil
	}
	return bc.GetReceiptByBlockNumberAndIndex(blockNumber, n-1)
}

func (bc *BlockchainDB) AddTransaction(tx *types.Transaction, receipt *types.Receipt) {
	blockNumber := bc.GetPendingBlockNumber()

	txArray := bc.getTxArray(blockNumber)
	txArray.Push(evmtypes.EncodeTransaction(tx))
	bc.kv.Set(
		makeBlockNumberByTxHashKey(tx.Hash()),
		codec.EncodeUint64(blockNumber),
	)
	bc.kv.Set(
		makeBlockIndexByTxHashKey(tx.Hash()),
		codec.EncodeUint32(txArray.Len()-1),
	)

	receiptArray := bc.getReceiptArray(blockNumber)
	receiptArray.Push(evmtypes.EncodeReceipt(receipt))
}

func (bc *BlockchainDB) MintBlock(timestamp uint64) {
	blockNumber := bc.GetPendingBlockNumber()
	header := bc.makeHeader(
		bc.GetTransactionsByBlockNumber(blockNumber),
		bc.GetReceiptsByBlockNumber(blockNumber),
		blockNumber,
		bc.getPendingTimestamp(),
	)
	bc.addBlock(header, timestamp)
	bc.prune(header.Number.Uint64())
}

func (bc *BlockchainDB) prune(currentNumber uint64) {
	keepAmount := bc.keepAmount()
	if keepAmount < 0 {
		// keep all blocks
		return
	}
	if currentNumber <= uint64(keepAmount) {
		return
	}
	toDelete := currentNumber - uint64(keepAmount)
	// assume that all blocks prior to `toDelete` have been already deleted, so
	// we only need to delete this one.
	bc.deleteBlock(toDelete)
}

func (bc *BlockchainDB) deleteBlock(blockNumber uint64) {
	header := bc.getHeaderByBlockNumber(blockNumber)
	if header == nil {
		// already deleted?
		return
	}
	txs := bc.getTxArray(blockNumber)
	n := txs.Len()
	for i := uint32(0); i < n; i++ {
		txHash := bc.GetTransactionByBlockNumberAndIndex(blockNumber, i).Hash()
		bc.kv.Del(makeBlockNumberByTxHashKey(txHash))
		bc.kv.Del(makeBlockIndexByTxHashKey(txHash))
	}
	txs.Erase()
	bc.getReceiptArray(blockNumber).Erase()
	bc.kv.Del(makeBlockHeaderByBlockNumberKey(blockNumber))
	bc.kv.Del(makeBlockNumberByBlockHashKey(header.Hash))
}

type header struct {
	Hash        common.Hash
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	TxHash      common.Hash
	ReceiptHash common.Hash
	Bloom       types.Bloom
}

var headerSize = common.HashLength*3 + marshalutil.Uint64Size*3 + types.BloomByteLength

func makeHeader(h *types.Header) *header {
	return &header{
		Hash:        h.Hash(),
		GasLimit:    h.GasLimit,
		GasUsed:     h.GasUsed,
		Time:        h.Time,
		TxHash:      h.TxHash,
		ReceiptHash: h.ReceiptHash,
		Bloom:       h.Bloom,
	}
}

func encodeHeader(g *header) []byte {
	return wbf.MustMarshal(g)
}

func decodeHeader(b []byte) *header {
	if len(b) != headerSize {
		// old format
		return decodeHeaderGobOld(b)
	}
	var h header
	wbf.MustUnmarshal(&h, b)
	return &h
}

func readBytes(m *marshalutil.MarshalUtil, size int, dst []byte) (err error) {
	var buf []byte
	buf, err = m.ReadBytes(size)
	if err == nil {
		copy(dst, buf)
	}
	return err
}

// deprecated
func decodeHeaderGobOld(b []byte) *header {
	var g header
	err := gob.NewDecoder(bytes.NewReader(b)).Decode(&g)
	if err != nil {
		panic(err)
	}
	return &g
}

func (bc *BlockchainDB) makeEthereumHeader(g *header, blockNumber uint64) *types.Header {
	var parentHash common.Hash
	if blockNumber > 0 {
		parentHash = bc.GetBlockHashByBlockNumber(blockNumber - 1)
	}
	return &types.Header{
		Difficulty:  &big.Int{},
		Number:      new(big.Int).SetUint64(blockNumber),
		GasLimit:    g.GasLimit,
		Time:        g.Time,
		ParentHash:  parentHash,
		GasUsed:     g.GasUsed,
		TxHash:      g.TxHash,
		ReceiptHash: g.ReceiptHash,
		Bloom:       g.Bloom,
		UncleHash:   types.EmptyUncleHash,
	}
}

func (bc *BlockchainDB) addBlock(header *types.Header, pendingTimestamp uint64) {
	blockNumber := header.Number.Uint64()
	bc.kv.Set(
		makeBlockHeaderByBlockNumberKey(blockNumber),
		encodeHeader(makeHeader(header)),
	)
	bc.kv.Set(
		makeBlockNumberByBlockHashKey(header.Hash()),
		codec.EncodeUint64(blockNumber),
	)
	bc.setNumber(blockNumber)
	bc.setPendingTimestamp(pendingTimestamp)
}

func (bc *BlockchainDB) GetReceiptByBlockNumberAndIndex(blockNumber uint64, txIndex uint32) *types.Receipt {
	receipts := bc.getReceiptArray(blockNumber)
	if txIndex >= receipts.Len() {
		return nil
	}
	r, err := evmtypes.DecodeReceipt(receipts.GetAt(txIndex))
	if err != nil {
		panic(err)
	}
	tx := bc.GetTransactionByBlockNumberAndIndex(blockNumber, txIndex)
	r.TxHash = tx.Hash()
	r.BlockHash = bc.GetBlockHashByBlockNumber(blockNumber)
	for i, log := range r.Logs {
		log.TxHash = r.TxHash
		log.TxIndex = uint(txIndex)
		log.BlockHash = r.BlockHash
		log.BlockNumber = blockNumber
		log.Index = uint(i)
	}
	if tx.To() == nil {
		from, _ := types.Sender(evmutil.Signer(big.NewInt(int64(bc.GetChainID()))), tx)
		r.ContractAddress = crypto.CreateAddress(from, tx.Nonce())
	}
	r.GasUsed = r.CumulativeGasUsed
	if txIndex > 0 {
		prev, err := evmtypes.DecodeReceipt(receipts.GetAt(txIndex - 1))
		if err != nil {
			panic(err)
		}
		r.GasUsed -= prev.CumulativeGasUsed
	}
	r.BlockNumber = new(big.Int).SetUint64(blockNumber)
	return r
}

func (bc *BlockchainDB) getBlockNumberBy(key kv.Key) (uint64, bool) {
	b := bc.kv.Get(key)
	if b == nil {
		return 0, false
	}
	n, err := codec.DecodeUint64(b)
	if err != nil {
		panic(err)
	}
	return n, true
}

func (bc *BlockchainDB) GetBlockNumberByTxHash(txHash common.Hash) (uint64, bool) {
	return bc.getBlockNumberBy(makeBlockNumberByTxHashKey(txHash))
}

func (bc *BlockchainDB) GetBlockIndexByTxHash(txHash common.Hash) uint32 {
	n, err := codec.DecodeUint32(bc.kv.Get(makeBlockIndexByTxHashKey(txHash)), 0)
	if err != nil {
		panic(err)
	}
	return n
}

func (bc *BlockchainDB) GetReceiptByTxHash(txHash common.Hash) *types.Receipt {
	blockNumber, ok := bc.GetBlockNumberByTxHash(txHash)
	if !ok {
		return nil
	}
	i := bc.GetBlockIndexByTxHash(txHash)
	return bc.GetReceiptByBlockNumberAndIndex(blockNumber, i)
}

func (bc *BlockchainDB) GetTransactionByBlockNumberAndIndex(blockNumber uint64, i uint32) *types.Transaction {
	txs := bc.getTxArray(blockNumber)
	if i >= txs.Len() {
		return nil
	}
	tx, err := evmtypes.DecodeTransaction(txs.GetAt(i))
	if err != nil {
		panic(err)
	}
	return tx
}

func (bc *BlockchainDB) GetTransactionByHash(txHash common.Hash) *types.Transaction {
	blockNumber, ok := bc.GetBlockNumberByTxHash(txHash)
	if !ok {
		return nil
	}
	i := bc.GetBlockIndexByTxHash(txHash)
	return bc.GetTransactionByBlockNumberAndIndex(blockNumber, i)
}

func (bc *BlockchainDB) GetBlockHashByBlockNumber(blockNumber uint64) common.Hash {
	g := bc.getHeaderByBlockNumber(blockNumber)
	if g == nil {
		return common.Hash{}
	}
	return g.Hash
}

func (bc *BlockchainDB) GetBlockNumberByBlockHash(hash common.Hash) (uint64, bool) {
	return bc.getBlockNumberBy(makeBlockNumberByBlockHashKey(hash))
}

func (bc *BlockchainDB) GetTimestampByBlockNumber(blockNumber uint64) uint64 {
	g := bc.getHeaderByBlockNumber(blockNumber)
	if g == nil {
		return 0
	}
	return g.Time
}

func (bc *BlockchainDB) makeHeader(txs []*types.Transaction, receipts []*types.Receipt, blockNumber, timestamp uint64) *types.Header {
	header := &types.Header{
		Difficulty:  &big.Int{},
		Number:      new(big.Int).SetUint64(blockNumber),
		GasLimit:    bc.blockGasLimit,
		Time:        timestamp,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		UncleHash:   types.EmptyUncleHash,
	}
	if blockNumber == 0 {
		// genesis block hash
		return header
	}
	prevBlockNumber := blockNumber - 1
	gasUsed := uint64(0)
	if len(receipts) > 0 {
		gasUsed = receipts[len(receipts)-1].CumulativeGasUsed
	}
	header.ParentHash = bc.GetBlockHashByBlockNumber(prevBlockNumber)
	header.GasUsed = gasUsed
	if len(txs) > 0 {
		header.TxHash = types.DeriveSha(types.Transactions(txs), &fakeHasher{})
		header.ReceiptHash = types.DeriveSha(types.Receipts(receipts), &fakeHasher{})
	}
	header.Bloom = types.CreateBloom(receipts)
	return header
}

func (bc *BlockchainDB) GetHeaderByBlockNumber(blockNumber uint64) *types.Header {
	if blockNumber > bc.GetNumber() {
		return nil
	}
	return bc.makeEthereumHeader(bc.getHeaderByBlockNumber(blockNumber), blockNumber)
}

func (bc *BlockchainDB) getHeaderByBlockNumber(blockNumber uint64) *header {
	b := bc.kv.Get(makeBlockHeaderByBlockNumberKey(blockNumber))
	if b == nil {
		return nil
	}
	return decodeHeader(b)
}

func (bc *BlockchainDB) GetHeaderByHash(hash common.Hash) *types.Header {
	n, ok := bc.GetBlockNumberByBlockHash(hash)
	if !ok {
		return nil
	}
	return bc.GetHeaderByBlockNumber(n)
}

func (bc *BlockchainDB) GetBlockByHash(hash common.Hash) *types.Block {
	return bc.makeBlock(bc.GetHeaderByHash(hash))
}

func (bc *BlockchainDB) GetBlockByNumber(blockNumber uint64) *types.Block {
	return bc.makeBlock(bc.GetHeaderByBlockNumber(blockNumber))
}

func (bc *BlockchainDB) GetCurrentBlock() *types.Block {
	return bc.GetBlockByNumber(bc.GetNumber())
}

func (bc *BlockchainDB) GetTransactionsByBlockNumber(blockNumber uint64) []*types.Transaction {
	txArray := bc.getTxArray(blockNumber)
	n := txArray.Len()
	txs := make([]*types.Transaction, n)
	for i := uint32(0); i < n; i++ {
		txs[i] = bc.GetTransactionByBlockNumberAndIndex(blockNumber, i)
	}
	return txs
}

func (bc *BlockchainDB) GetReceiptsByBlockNumber(blockNumber uint64) []*types.Receipt {
	txArray := bc.getTxArray(blockNumber)
	n := txArray.Len()
	receipts := make([]*types.Receipt, n)
	for txIndex := uint32(0); txIndex < n; txIndex++ {
		receipts[txIndex] = bc.GetReceiptByBlockNumberAndIndex(blockNumber, txIndex)
	}
	return receipts
}

func (bc *BlockchainDB) makeBlock(header *types.Header) *types.Block {
	if header == nil {
		return nil
	}
	blockNumber := header.Number.Uint64()
	return types.NewBlock(
		header,
		bc.GetTransactionsByBlockNumber(blockNumber),
		[]*types.Header{},
		bc.GetReceiptsByBlockNumber(blockNumber),
		&fakeHasher{},
	)
}

const (
	maxBlocksInFilterRange = 1_000
	maxLogsInResult        = 10_000
)

// FilterLogs executes a log filter operation, blocking during execution and
// returning all the results in one batch.
//
//nolint:gocyclo
func (bc *BlockchainDB) FilterLogs(query *ethereum.FilterQuery) ([]*types.Log, error) {
	logs := make([]*types.Log, 0)

	if query.BlockHash != nil {
		blockNumber, ok := bc.GetBlockNumberByBlockHash(*query.BlockHash)
		if !ok {
			return nil, nil
		}
		receipts := bc.GetReceiptsByBlockNumber(blockNumber)
		err := filterAndAppendToLogs(query, receipts, &logs)
		if err != nil {
			return nil, err
		}
		return logs, nil
	}

	// Initialize unset filter boundaries to run from genesis to chain head
	first := big.NewInt(1) // skip genesis since it has no logs
	last := new(big.Int).SetUint64(bc.GetNumber())
	from := first
	if query.FromBlock != nil && query.FromBlock.Cmp(first) >= 0 && query.FromBlock.Cmp(last) <= 0 {
		from = query.FromBlock
	}
	to := last
	if query.ToBlock != nil && query.ToBlock.Cmp(first) >= 0 && query.ToBlock.Cmp(last) <= 0 {
		to = query.ToBlock
	}

	if !from.IsUint64() || !to.IsUint64() {
		return nil, errors.New("block number is too large")
	}
	{
		from := from.Uint64()
		to := to.Uint64()
		if to > from && to-from > maxBlocksInFilterRange {
			return nil, errors.New("too many blocks in filter range")
		}
		for i := from; i <= to; i++ {
			err := filterAndAppendToLogs(
				query,
				bc.GetReceiptsByBlockNumber(i),
				&logs,
			)
			if err != nil {
				return nil, err
			}
		}
	}
	return logs, nil
}

func filterAndAppendToLogs(query *ethereum.FilterQuery, receipts []*types.Receipt, logs *[]*types.Log) error {
	for _, r := range receipts {
		if !evmtypes.BloomFilter(r.Bloom, query.Addresses, query.Topics) {
			continue
		}
		for _, log := range r.Logs {
			if !evmtypes.LogMatches(log, query.Addresses, query.Topics) {
				continue
			}
			if len(*logs) >= maxLogsInResult {
				return errors.New("too many logs in result")
			}
			*logs = append(*logs, log)
		}
	}
	return nil
}

type fakeHasher struct{}

func (d *fakeHasher) Reset() {
}

func (d *fakeHasher) Update(i1, i2 []byte) {
}

func (d *fakeHasher) Hash() common.Hash {
	return common.Hash{}
}
