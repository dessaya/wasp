package trie

import (
	"bytes"
	"io"
)

// MerkleProof blake2b model specific proof of inclusion
type MerkleProof struct {
	Key  []byte
	Path []*MerkleProofElement
}

type MerkleProofElement struct {
	PathFragment []byte
	Children     [NumChildren]*Hash
	Terminal     []byte
	ChildIndex   int
}

func ProofFromBytes(data []byte) (*MerkleProof, error) {
	ret := &MerkleProof{}
	rdr := bytes.NewReader(data)
	if err := ret.Read(rdr); err != nil {
		return nil, err
	}
	if rdr.Len() != 0 {
		return nil, ErrNotAllBytesConsumed
	}
	return ret, nil
}

func (p *MerkleProof) Bytes() []byte {
	return mustBytes(p)
}

func (p *MerkleProof) Write(w io.Writer) error {
	var err error
	encodedKey, err := encodeUnpackedBytes(p.Key)
	if err != nil {
		return err
	}
	if err = writeBytes16(w, encodedKey); err != nil {
		return err
	}
	if err = writeUint16(w, uint16(len(p.Path))); err != nil {
		return err
	}
	for _, e := range p.Path {
		if err = e.Write(w); err != nil {
			return err
		}
	}
	return nil
}

func (p *MerkleProof) Read(r io.Reader) error {
	var err error
	var encodedKey []byte
	if encodedKey, err = readBytes16(r); err != nil {
		return err
	}
	if p.Key, err = decodeToUnpackedBytes(encodedKey); err != nil {
		return err
	}
	var size uint16
	if err = readUint16(r, &size); err != nil {
		return err
	}
	p.Path = make([]*MerkleProofElement, size)
	for i := range p.Path {
		p.Path[i] = &MerkleProofElement{}
		if err = p.Path[i].Read(r); err != nil {
			return err
		}
	}
	return nil
}

const (
	hasTerminalValueFlag = 0x01
	hasChildrenFlag      = 0x02
)

func (e *MerkleProofElement) Write(w io.Writer) error {
	encodedPathFragment, err := encodeUnpackedBytes(e.PathFragment)
	if err != nil {
		return err
	}
	if err = writeBytes16(w, encodedPathFragment); err != nil {
		return err
	}
	if err = writeUint16(w, uint16(e.ChildIndex)); err != nil {
		return err
	}
	var smallFlags byte
	if e.Terminal != nil {
		smallFlags = hasTerminalValueFlag
	}
	// compress children flags 32 bytes (if any)
	var flags [32]byte
	for i, h := range e.Children {
		if h != nil {
			flags[i/8] |= 0x1 << (i % 8)
			smallFlags |= hasChildrenFlag
		}
	}
	if err := writeByte(w, smallFlags); err != nil {
		return err
	}
	// write terminal commitment if any
	if smallFlags&hasTerminalValueFlag != 0 {
		if err = writeBytes8(w, e.Terminal); err != nil {
			return err
		}
	}
	// write child commitments if any
	if smallFlags&hasChildrenFlag != 0 {
		if _, err = w.Write(flags[:]); err != nil {
			return err
		}
		for _, child := range e.Children {
			if child == nil {
				continue
			}
			if _, err = w.Write(child[:]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *MerkleProofElement) Read(r io.Reader) error {
	var err error
	var encodedPathFragment []byte
	if encodedPathFragment, err = readBytes16(r); err != nil {
		return err
	}
	if e.PathFragment, err = decodeToUnpackedBytes(encodedPathFragment); err != nil {
		return err
	}
	var idx uint16
	if err := readUint16(r, &idx); err != nil {
		return err
	}
	e.ChildIndex = int(idx)
	var smallFlags byte
	if smallFlags, err = readByte(r); err != nil {
		return err
	}
	if smallFlags&hasTerminalValueFlag != 0 {
		if e.Terminal, err = readBytes8(r); err != nil {
			return err
		}
	} else {
		e.Terminal = nil
	}
	if smallFlags&hasChildrenFlag != 0 {
		var flags [32]byte
		if _, err = r.Read(flags[:]); err != nil {
			return err
		}
		for i := 0; i < NumChildren; i++ {
			ib := uint8(i)
			if flags[i/8]&(0x1<<(i%8)) != 0 {
				var h Hash
				if _, err = r.Read(h[:]); err != nil {
					return err
				}
				e.Children[ib] = &h
			}
		}
	}
	return nil
}

func (tr *TrieReader) MerkleProof(key []byte) *MerkleProof {
	unpackedKey := unpackBytes(key)
	nodePath, ending := tr.nodePath(unpackedKey)
	ret := &MerkleProof{
		Key:  unpackedKey,
		Path: make([]*MerkleProofElement, len(nodePath)),
	}
	for i, e := range nodePath {
		elem := &MerkleProofElement{
			PathFragment: e.NodeData.PathFragment,
			Terminal:     nil,
			ChildIndex:   int(e.ChildIndex),
		}
		if e.NodeData.Terminal != nil {
			elem.Terminal, _ = compressToHashSize(e.NodeData.Terminal.Bytes())
		}
		isLast := i == len(nodePath)-1
		for childIndex, childCommitment := range e.NodeData.ChildCommitments {
			if childCommitment == nil {
				continue
			}
			if !isLast && childIndex == int(e.ChildIndex) {
				// commitment to the next child is not included, it must be calculated by the verifier
				continue
			}
			hash := childCommitment.Hash()
			elem.Children[childIndex] = &hash
		}
		ret.Path[i] = elem
	}
	assert(len(ret.Path) > 0, "len(ret.Path)")
	last := ret.Path[len(ret.Path)-1]
	switch ending {
	case endingTerminal:
		last.ChildIndex = terminalCommitmentIndex
	case endingExtend, endingSplit:
		last.ChildIndex = pathFragmentCommitmentIndex
	default:
		panic("wrong ending code")
	}
	return ret
}
