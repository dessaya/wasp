package trie

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	// NumChildren is the maximum amount of children for each trie node
	NumChildren = 16
)

func isValidChildIndex(i int) bool {
	return i >= 0 && i < NumChildren
}

// nodeData contains all data trie node needs to compute commitment
type nodeData struct {
	PathFragment     []byte
	Terminal         TCommitment
	ChildCommitments [NumChildren]VCommitment
	// persisted in the key
	Commitment VCommitment
}

func newNodeData() *nodeData {
	return &nodeData{}
}

func nodeDataFromBytes(data []byte) (*nodeData, error) {
	ret := newNodeData()
	rdr := bytes.NewReader(data)
	if err := ret.Read(rdr); err != nil {
		return nil, err
	}
	if rdr.Len() != 0 {
		// not all data was consumed
		return nil, ErrNotAllBytesConsumed
	}
	return ret, nil
}

func (n *nodeData) ChildrenCount() int {
	count := 0
	for _, c := range n.ChildCommitments {
		if c != nil {
			count++
		}
	}
	return count
}

// Clone deep copy
func (n *nodeData) Clone() *nodeData {
	ret := &nodeData{
		PathFragment: concat(n.PathFragment),
	}
	if n.Terminal != nil {
		ret.Terminal = n.Terminal.Clone()
	}
	if n.Commitment != nil {
		ret.Commitment = n.Commitment.Clone()
	}
	for i, c := range n.ChildCommitments {
		if c != nil {
			ret.ChildCommitments[i] = c.Clone()
		}
	}
	return ret
}

func (n *nodeData) String() string {
	t := "<nil>"
	if n.Terminal != nil {
		t = n.Terminal.String()
	}
	childIdx := make([]byte, 0)
	for i := range n.ChildCommitments {
		if n.ChildCommitments[i] != nil {
			childIdx = append(childIdx, byte(i))
		}
	}
	return fmt.Sprintf("c: %s, pf: '%s', childrenIdx: %v, term: '%s'",
		n.Commitment, string(n.PathFragment), childIdx, t)
}

// Read/Write implements optimized serialization of the trie node
// The serialization of the node takes advantage of the fact that most of the
// nodes has just few children.
// the 'smallFlags' (1 byte) contains information:
// - 'serializeChildrenFlag' does node contain at least one child
// - 'terminalExistsFlag' is optimization case when commitment to the terminal == commitment to the unpackedKey
//    In this case terminal is not serialized
// - 'serializePathFragmentFlag' flag means node has non-empty path fragment
// By the semantics of the trie, 'smallFlags' cannot be 0
// 'childrenFlags' (2 bytes array or 16 bits) are only present if node contains at least one child commitment
// In this case:
// if node has a child commitment at the position of i, 0 <= p <= 255, it has a bit in the byte array
// at the index i/8. The bit position in the byte is i % 8

const (
	terminalExistsFlag = 1 << iota
	serializeChildrenFlag
	serializePathFragmentFlag
)

// cflags 16 flags, one for each child
type cflags uint16

func readCflags(r io.Reader) (cflags, error) {
	var ret uint16
	err := readUint16(r, &ret)
	if err != nil {
		return 0, err
	}
	return cflags(ret), nil
}

func (fl *cflags) setFlag(i byte) {
	*fl |= 0x1 << i
}

func (fl cflags) hasFlag(i byte) bool {
	return fl&(0x1<<i) != 0
}

// Write serialized node data
func (n *nodeData) Write(w io.Writer) error {
	var smallFlags byte
	if n.Terminal != nil {
		smallFlags |= terminalExistsFlag
	}

	childrenFlags := cflags(0)
	// compress children childrenFlags 32 bytes, if any
	for i := range n.ChildCommitments {
		if n.ChildCommitments[i] != nil {
			childrenFlags.setFlag(byte(i))
		}
	}

	if childrenFlags != 0 {
		smallFlags |= serializeChildrenFlag
	}
	if smallFlags == 0 {
		return errors.New("non-committing node can't be serialized")
	}
	var pathFragmentEncoded []byte
	var err error
	if len(n.PathFragment) > 0 {
		smallFlags |= serializePathFragmentFlag
		if pathFragmentEncoded, err = encodeUnpackedBytes(n.PathFragment); err != nil {
			return err
		}
	}
	if err = writeByte(w, smallFlags); err != nil {
		return err
	}
	if smallFlags&serializePathFragmentFlag != 0 {
		if err = writeBytes16(w, pathFragmentEncoded); err != nil {
			return err
		}
	}
	if smallFlags&terminalExistsFlag != 0 {
		if err = n.Terminal.Write(w); err != nil {
			return err
		}
	}
	// write child commitments if any
	if smallFlags&serializeChildrenFlag != 0 {
		if err = writeUint16(w, uint16(childrenFlags)); err != nil {
			return err
		}
		for _, child := range n.ChildCommitments {
			if child != nil {
				if err = child.Write(w); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Read deserialize node data
func (n *nodeData) Read(r io.Reader) error {
	var err error
	var smallFlags byte
	if smallFlags, err = readByte(r); err != nil {
		return err
	}
	if smallFlags&serializePathFragmentFlag != 0 {
		encoded, err := readBytes16(r)
		if err != nil {
			return err
		}
		if n.PathFragment, err = decodeToUnpackedBytes(encoded); err != nil {
			return err
		}
	} else {
		n.PathFragment = nil
	}
	n.Terminal = nil
	if smallFlags&terminalExistsFlag != 0 {
		n.Terminal = newTerminalCommitment()
		if err = n.Terminal.Read(r); err != nil {
			return err
		}
	}
	if smallFlags&serializeChildrenFlag != 0 {
		var flags cflags
		if flags, err = readCflags(r); err != nil {
			return err
		}
		for i := 0; i < NumChildren; i++ {
			ib := uint8(i)
			if flags.hasFlag(ib) {
				n.ChildCommitments[ib] = newVectorCommitment()
				if err = n.ChildCommitments[ib].Read(r); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (n *nodeData) iterateChildren(f func(byte, VCommitment) bool) bool {
	for i, v := range n.ChildCommitments {
		if v != nil {
			if !f(byte(i), v) {
				return false
			}
		}
	}
	return true
}
