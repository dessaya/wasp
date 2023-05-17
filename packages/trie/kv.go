package trie

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

//----------------------------------------------------------------------------
// generic abstraction interfaces of key/value storage

// KVReader is a key/value reader
type KVReader interface {
	// Get retrieves value by key. Returned nil means absence of the key
	Get(key []byte) []byte
	// Has checks presence of the key in the key/value store
	Has(key []byte) bool // for performance
}

// KVWriter is a key/value writer
type KVWriter interface {
	// Set writes new or updates existing key with the value.
	// value == nil means deletion of the key from the store
	Set(key, value []byte)
	Del(key []byte)
}

// KVIterator is an interface to iterate through a set of key/value pairs.
// Order of iteration is NON-DETERMINISTIC in general
type KVIterator interface {
	Iterate(func(k, v []byte) bool)
	IterateKeys(func(k []byte) bool)
}

// KVStore is a compound interface
type KVStore interface {
	KVReader
	KVWriter
	KVIterator
}

// Traversable is an interface which provides with partial iterators
type Traversable interface {
	Iterator(prefix []byte) KVIterator
}

type kvStorePartition struct {
	prefix byte
	s      KVStore
}

func (p *kvStorePartition) Get(key []byte) []byte {
	return p.s.Get(concat([]byte{p.prefix}, key))
}

func (p *kvStorePartition) Has(key []byte) bool {
	return p.s.Has(concat([]byte{p.prefix}, key))
}

func (p *kvStorePartition) Del(key []byte) {
	p.s.Del(concat([]byte{p.prefix}, key))
}

func (p *kvStorePartition) Set(key []byte, value []byte) {
	p.s.Set(concat([]byte{p.prefix}, key), value)
}

func (p *kvStorePartition) Iterate(func(k []byte, v []byte) bool) {
	panic("unimplemented")
}

func (p *kvStorePartition) IterateKeys(func(k []byte) bool) {
	panic("unimplemented")
}

func makeKVStorePartition(s KVStore, prefix byte) *kvStorePartition {
	return &kvStorePartition{
		prefix: prefix,
		s:      s,
	}
}

type readerPartition struct {
	prefix byte
	r      KVReader
}

func (p *readerPartition) Get(key []byte) []byte {
	return p.r.Get(concat([]byte{p.prefix}, key))
}

func (p *readerPartition) Has(key []byte) bool {
	return p.r.Has(concat([]byte{p.prefix}, key))
}

func makeReaderPartition(r KVReader, prefix byte) KVReader {
	return &readerPartition{
		prefix: prefix,
		r:      r,
	}
}

type writerPartition struct {
	prefix byte
	w      KVWriter
}

func (w *writerPartition) Set(key, value []byte) {
	w.w.Set(concat([]byte{w.prefix}, key), value)
}

func (w *writerPartition) Del(key []byte) {
	w.w.Del(concat([]byte{w.prefix}, key))
}

func makeWriterPartition(w KVWriter, prefix byte) KVWriter {
	return &writerPartition{
		prefix: prefix,
		w:      w,
	}
}

type cachedKVReader struct {
	r     KVReader
	cache *lru.Cache[string, []byte]
}

func makeCachedKVReader(r KVReader, size int) KVReader {
	cache, err := lru.New[string, []byte](size)
	if err != nil {
		panic(err)
	}
	return &cachedKVReader{r: r, cache: cache}
}

func (c *cachedKVReader) Get(key []byte) []byte {
	if v, ok := c.cache.Get(string(key)); ok {
		return v
	}
	v := c.r.Get(key)
	c.cache.Add(string(key), v)
	return v
}

func (c *cachedKVReader) Has(key []byte) bool {
	if v, ok := c.cache.Get(string(key)); ok {
		return v != nil
	}
	v := c.r.Get(key)
	c.cache.Add(string(key), v)
	return v != nil
}
