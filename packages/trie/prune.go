package trie

import (
	"bytes"
)

// TODO: this data should be stored in the DB
var refcounts struct {
	// the latest N trie roots that are kept alive
	trieRoots []Hash

	nodes  map[Hash]uint
	values map[Hash]uint
}

// TODO: this should be local
var PruneStats struct {
	DeletedNodes   uint
	DeletedValues  uint
	SizeOfRefcouns uint
}

func init() {
	refcounts.nodes = make(map[Hash]uint)
	refcounts.values = make(map[Hash]uint)
}

func increaseRefcount(node *NodeData) {
	refcounts.nodes[node.Commitment]++
	if node.Terminal != nil && !node.Terminal.IsValue {
		hash, _ := node.Terminal.ValueHash()
		refcounts.values[hash]++
	}
}

func decreaseRefcount(node *NodeData) (deleteNode, deleteValue bool) {
	if refcounts.nodes[node.Commitment] == 0 {
		panic("inconsistency: ngative node reference count")
	}
	refcounts.nodes[node.Commitment]--
	if refcounts.nodes[node.Commitment] == 0 {
		deleteNode = true
		delete(refcounts.nodes, node.Commitment)
	}
	if node.Terminal != nil && !node.Terminal.IsValue {
		hash, _ := node.Terminal.ValueHash()
		if refcounts.values[hash] == 0 {
			panic("inconsistency: ngative value reference count")
		}
		refcounts.values[hash]--
		if refcounts.values[hash] == 0 {
			deleteValue = true
			delete(refcounts.values, hash)
		}
	}
	return
}

func Prune(store KVStore, addedTrieRoot Hash, keepLatest int) {
	refcounts.trieRoots = append(refcounts.trieRoots, addedTrieRoot)

	if len(refcounts.trieRoots) == 1 {
		tr, err := NewTrieReader(store, addedTrieRoot)
		mustNoErr(err)

		tr.IterateNodes(func(nodeKey []byte, n *NodeData, depth int) IterateNodesAction {
			increaseRefcount(n)
			return IterateContinue
		})
	} else {
		_, newNodes := Diff(store, refcounts.trieRoots[len(refcounts.trieRoots)-2], refcounts.trieRoots[len(refcounts.trieRoots)-1])
		for _, node := range newNodes {
			increaseRefcount(node)
		}
	}

	if len(refcounts.trieRoots) > keepLatest {
		droppedNodes, _ := Diff(store, refcounts.trieRoots[0], refcounts.trieRoots[1])
		triePartition := makeWriterPartition(store, partitionTrieNodes)
		valuePartition := makeWriterPartition(store, partitionValues)
		for _, node := range droppedNodes {
			deleteNode, deleteValue := decreaseRefcount(node)
			if deleteNode {
				triePartition.Del(node.Commitment[:])
				PruneStats.DeletedNodes++
			}
			if deleteValue {
				hash, _ := node.Terminal.ValueHash()
				valuePartition.Del(hash[:])
				PruneStats.DeletedValues++
			}
		}
		refcounts.trieRoots = refcounts.trieRoots[1:]
	}
	PruneStats.SizeOfRefcouns = uint(len(refcounts.trieRoots) * HashSizeBytes)
	PruneStats.SizeOfRefcouns += uint(len(refcounts.nodes) * (HashSizeBytes + 4))
	PruneStats.SizeOfRefcouns += uint(len(refcounts.values) * (HashSizeBytes + 4))
}

func Diff(store KVStore, root1, root2 Hash) (onlyOn1, onlyOn2 []*NodeData) {
	type nodeData struct {
		*NodeData
		key []byte
	}

	iterateTrie := func(tr *TrieReader) (*nodeData, func(IterateNodesAction) *nodeData) {
		nodes := make(chan *nodeData, 1)
		actions := make(chan IterateNodesAction, 1)

		go func() {
			defer close(nodes)
			tr.IterateNodes(func(nodeKey []byte, node *NodeData, depth int) IterateNodesAction {
				nodes <- &nodeData{NodeData: node, key: nodeKey}
				action := <-actions
				return action
			})
		}()

		firstNode := <-nodes
		next := func(a IterateNodesAction) *nodeData {
			actions <- a
			node, ok := <-nodes
			if !ok {
				actions <- IterateStop
				return nil
			}
			return node
		}
		return firstNode, next
	}

	tr1, err := NewTrieReader(store, root1)
	mustNoErr(err)
	tr2, err := NewTrieReader(store, root2)
	mustNoErr(err)
	current1, next1 := iterateTrie(tr1)
	current2, next2 := iterateTrie(tr2)

	// This is similar to the 'merge' function in mergeSort.
	// We iterate both tries in order, advancing the iterator of the smallest
	// node between the two.

	for current1 != nil && current2 != nil {
		if current1.Commitment == current2.Commitment {
			current1 = next1(IterateSkipSubtree)
			current2 = next2(IterateSkipSubtree)
		} else if bytes.Compare(current1.key, current2.key) < 0 {
			onlyOn1 = append(onlyOn1, current1.NodeData)
			current1 = next1(IterateContinue)
		} else {
			onlyOn2 = append(onlyOn2, current2.NodeData)
			current2 = next2(IterateContinue)
		}
	}
	for current1 != nil {
		onlyOn1 = append(onlyOn1, current1.NodeData)
		current1 = next1(IterateContinue)
	}
	for current2 != nil {
		onlyOn2 = append(onlyOn2, current2.NodeData)
		current2 = next2(IterateContinue)
	}
	return
}
