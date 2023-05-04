package main

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/wasp/packages/chaindb"
	"github.com/iotaledger/wasp/packages/trie"
)

type trieDiffStats struct {
	start     time.Time
	lastShown time.Time
	visited1  int
	visited2  int
	onlyOn1   int
	onlyOn2   int
}

func trieDiff(ctx context.Context, kvs kvstore.KVStore) {
	if blockIndex > blockIndex2 {
		blockIndex, blockIndex2 = blockIndex2, blockIndex
	}
	state1 := getState(kvs, blockIndex)
	tr1, err := trie.NewTrieReader(trie.NewHiveKVStoreAdapter(kvs, []byte{chaindb.PrefixTrie}), state1.TrieRoot())
	mustNoError(err)

	state2 := getState(kvs, blockIndex2)
	tr2, err := trie.NewTrieReader(trie.NewHiveKVStoreAdapter(kvs, []byte{chaindb.PrefixTrie}), state2.TrieRoot())
	mustNoError(err)

	diff := trieDiffStats{
		start:     time.Now(),
		lastShown: time.Now(),
	}

	type nodeData struct {
		*trie.NodeData
		key []byte
	}

	iterateTrie := func(tr *trie.TrieReader) func(trie.IterateNodesAction) *nodeData {
		nodes := make(chan *nodeData, 1)
		actions := make(chan trie.IterateNodesAction, 1)

		go func() {
			defer close(nodes)
			tr.IterateNodes(func(nodeKey []byte, node *trie.NodeData, depth int) trie.IterateNodesAction {
				if ctx.Err() != nil {
					fmt.Println("err -> stop")
					return trie.IterateStop
				}
				nodes <- &nodeData{NodeData: node, key: nodeKey}
				if ctx.Err() != nil {
					fmt.Println("err -> stop 2")
					return trie.IterateStop
				}
				action := <-actions
				return action
			})
		}()

		first := true
		return func(a trie.IterateNodesAction) *nodeData {
			if !first {
				actions <- a
			}
			first = false
			node, ok := <-nodes
			if !ok {
				actions <- trie.IterateStop
				return nil
			}
			return node
		}
	}
	next1 := iterateTrie(tr1)
	next2 := iterateTrie(tr2)

	// This is similar to the 'merge' function in mergeSort.
	// We iterate both tries in order, advancing the iterator of the smallest
	// node between the two.

	var current1 *nodeData
	var current2 *nodeData
	current1 = next1(trie.IterateContinue)
	diff.visited1++
	current2 = next2(trie.IterateContinue)
	diff.visited2++
	for current1 != nil && current2 != nil {
		if current1.Commitment == current2.Commitment {
			current1 = next1(trie.IterateSkipSubtree)
			diff.visited1++
			current2 = next2(trie.IterateSkipSubtree)
			diff.visited2++
		} else if bytes.Compare(current1.key, current2.key) < 0 {
			diff.onlyOn1++
			current1 = next1(trie.IterateContinue)
			diff.visited1++
		} else {
			diff.onlyOn2++
			current2 = next2(trie.IterateContinue)
			diff.visited2++
		}
		showDiff(false, &diff)
	}
	for current1 != nil {
		diff.onlyOn1++
		current1 = next1(trie.IterateContinue)
		diff.visited1++
		showDiff(false, &diff)
	}
	for current2 != nil {
		diff.onlyOn2++
		current2 = next2(trie.IterateContinue)
		diff.visited2++
		showDiff(false, &diff)
	}

	fmt.Print("\n--- Done ---\n")
	showDiff(true, &diff)
}

func showDiff(force bool, diff *trieDiffStats) {
	now := time.Now()
	if !force && now.Sub(diff.lastShown) < 1*time.Second {
		return
	}
	diff.lastShown = now

	clearScreen()
	fmt.Println()
	fmt.Printf("Diff between blocks #%d -> #%d\n", blockIndex, blockIndex2)
	fmt.Println()
	fmt.Printf("visited %d nodes on #%d\n", diff.visited1, blockIndex)
	fmt.Printf("visited %d nodes on #%d\n", diff.visited2, blockIndex2)
	fmt.Println()
	fmt.Printf("only on #%d: %d\n", blockIndex, diff.onlyOn1)
	fmt.Printf("only on #%d: %d\n", blockIndex2, diff.onlyOn2)
	fmt.Println()
	elapsed := time.Since(diff.start)
	fmt.Printf("Elapsed: %s\n", elapsed)
	fmt.Printf("Speed: %d nodes/s\n", int(float64(diff.visited1+diff.visited2)/(elapsed.Seconds())))
}
