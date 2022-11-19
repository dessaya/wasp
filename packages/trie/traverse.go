package trie

import (
	"bytes"
)

// pathEndingCode is a tag how trie path ends wrt the trieKey
type pathEndingCode byte

const (
	endingNone = pathEndingCode(iota)
	endingTerminal
	endingSplit
	endingExtend
)

func (e pathEndingCode) String() string {
	switch e {
	case endingNone:
		return "EndingNone"
	case endingTerminal:
		return "EndingTerminal"
	case endingSplit:
		return "EndingSplit"
	case endingExtend:
		return "EndingExtend"
	default:
		panic("invalid ending code")
	}
}

// pathElement proof element is NodeData together with the index of
// the next child in the path (except the last one in the proof path)
// Sequence of pathElement is used to generate proof
type pathElement struct {
	NodeData   *nodeData
	ChildIndex byte
}

// nodePath returns path PathElement-s along the triePath (the key) with the ending code
// to determine is it a proof of inclusion or absence
// Each path element contains index of the subsequent child, except the last one is set to 0
func (tr *TrieReader) nodePath(triePath []byte) ([]*pathElement, pathEndingCode) {
	ret := make([]*pathElement, 0)
	var endingCode pathEndingCode
	tr.traversePath(triePath, func(n *nodeData, trieKey []byte, ending pathEndingCode) {
		elem := &pathElement{
			NodeData: n,
		}
		nextChildIdx := len(trieKey) + len(n.PathFragment)
		if nextChildIdx < len(triePath) {
			elem.ChildIndex = triePath[nextChildIdx]
		}
		endingCode = ending
		ret = append(ret, elem)
	})
	assert(len(ret) > 0, "len(ret)>0")
	ret[len(ret)-1].ChildIndex = 0
	return ret, endingCode
}

func (tr *TrieReader) traversePath(triePath []byte, fun func(n *nodeData, trieKey []byte, ending pathEndingCode)) {
	n, found := tr.nodeStore.FetchNodeData(tr.persistentRoot)
	if !found {
		return
	}
	var trieKey []byte
	for {
		keyPlusPathFragment := concat(trieKey, n.PathFragment)
		switch {
		case len(triePath) < len(keyPlusPathFragment):
			fun(n, trieKey, endingSplit)
			return
		case len(triePath) == len(keyPlusPathFragment):
			if bytes.Equal(keyPlusPathFragment, triePath) {
				fun(n, trieKey, endingTerminal)
			} else {
				fun(n, trieKey, endingSplit)
			}
			return
		default:
			assert(len(keyPlusPathFragment) < len(triePath), "len(keyPlusPathFragment) < len(triePath)")
			prefix, _, _ := commonPrefix(keyPlusPathFragment, triePath)
			if !bytes.Equal(prefix, keyPlusPathFragment) {
				fun(n, trieKey, endingSplit)
				return
			}
			childIndex := triePath[len(keyPlusPathFragment)]
			child, childTrieKey := tr.nodeStore.FetchChild(n, childIndex, trieKey)
			if child == nil {
				fun(n, childTrieKey, endingExtend)
				return
			}
			fun(n, trieKey, endingNone)
			trieKey = childTrieKey
			n = child
		}
	}
}

func (tr *TrieUpdatable) traverseMutatedPath(triePath []byte, fun func(n *bufferedNode, ending pathEndingCode)) {
	n := tr.mutatedRoot
	for {
		keyPlusPathFragment := concat(n.triePath, n.pathFragment)
		switch {
		case len(triePath) < len(keyPlusPathFragment):
			fun(n, endingSplit)
			return
		case len(triePath) == len(keyPlusPathFragment):
			if bytes.Equal(keyPlusPathFragment, triePath) {
				fun(n, endingTerminal)
			} else {
				fun(n, endingSplit)
			}
			return
		default:
			assert(len(keyPlusPathFragment) < len(triePath), "len(keyPlusPathFragment) < len(triePath)")
			prefix, _, _ := commonPrefix(keyPlusPathFragment, triePath)
			if !bytes.Equal(prefix, keyPlusPathFragment) {
				fun(n, endingSplit)
				return
			}
			childIndex := triePath[len(keyPlusPathFragment)]
			child := n.getChild(childIndex, tr.nodeStore)
			if child == nil {
				fun(n, endingExtend)
				return
			}
			fun(n, endingNone)
			n = child
		}
	}
}

func commonPrefix(b1, b2 []byte) ([]byte, []byte, []byte) {
	ret := make([]byte, 0)
	i := 0
	for ; i < len(b1) && i < len(b2); i++ {
		if b1[i] != b2[i] {
			break
		}
		ret = append(ret, b1[i])
	}
	var r1, r2 []byte
	if i < len(b1) {
		r1 = b1[i:]
	}
	if i < len(b2) {
		r2 = b2[i:]
	}

	return ret, r1, r2
}
