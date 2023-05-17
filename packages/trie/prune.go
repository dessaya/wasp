package trie

type PruneStats struct {
	DeletedNodes  uint
	DeletedValues uint
}

func Prune(store KVStore, trieRoot Hash) (PruneStats, error) {
	refcounts := newRefcounts(store)

	stats := PruneStats{}

	tr, err := NewTrieReader(store, trieRoot)
	if err != nil {
		return stats, err
	}

	var deletedNodes []Hash
	var deletedValues [][]byte

	tr.IterateNodes(func(nodeKey []byte, n *NodeData, depth int) IterateNodesAction {
		deleteNode, deleteValue := refcounts.Dec(n)
		if deleteNode {
			deletedNodes = append(deletedNodes, n.Commitment)
		}
		if deleteValue {
			deletedValues = append(deletedValues, n.Terminal.Bytes())
		}
		if deleteNode {
			return IterateContinue
		}
		return IterateSkipSubtree
	})

	triePartition := makeWriterPartition(store, partitionTrieNodes)
	for _, hash := range deletedNodes {
		triePartition.Del(hash[:])
	}
	valuePartition := makeWriterPartition(store, partitionValues)
	for _, key := range deletedValues {
		valuePartition.Del(key)
	}
	return PruneStats{
		DeletedNodes:  uint(len(deletedNodes)),
		DeletedValues: uint(len(deletedValues)),
	}, nil
}
