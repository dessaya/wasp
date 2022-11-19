package trie

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
)

// blake2b_* contains implementation of commitment model for the trie
// based on `blake2b` 20 byte (160 bit) hashing.

// terminalCommitment commits to data of arbitrary size.
// len(bytes) is <= 32
// if isHash == true, len(bytes) must be 32
// otherwise it is not hashed value, mus be len(bytes) <= 32
type terminalCommitment struct {
	bytes               []byte
	isValueInCommitment bool
}

const (
	HashSizeBits  = 160
	HashSizeBytes = HashSizeBits / 8

	vectorLength                = NumChildren + 2 // 16 children + terminal + path fragment
	terminalCommitmentIndex     = NumChildren
	pathFragmentCommitmentIndex = NumChildren + 1
)

type Hash [HashSizeBytes]byte

// vectorCommitment is a blake2b hash of the vector elements
type vectorCommitment Hash

const (
	terminalCommitmentSizeMax = 0x3F // 63
	valueInCommitmentMask     = 0x40
)

// updateNodeCommitment computes update to the node data and, optionally, updates existing commitment.
func updateNodeCommitment(mutate *nodeData, childUpdates map[byte]VCommitment, newTerminalUpdate TCommitment, pathFragment []byte) {
	for i, upd := range childUpdates {
		mutate.ChildCommitments[i] = upd
	}
	mutate.Terminal = newTerminalUpdate // for hash commitment just replace
	mutate.PathFragment = pathFragment
	if mutate.ChildrenCount() == 0 && mutate.Terminal == nil {
		return
	}
	v := vectorCommitment(makeHashVector(mutate).Hash())
	mutate.Commitment = &v
}

// compressToHashSize hashes data if longer than hash size, otherwise copies it
func compressToHashSize(data []byte) (ret []byte, valueInCommitment bool) {
	if len(data) <= HashSizeBytes {
		ret = make([]byte, len(data))
		valueInCommitment = true
		copy(ret, data)
	} else {
		hash := blake2b160(data)
		ret = hash[:]
	}
	return
}

func CommitToData(data []byte) TCommitment {
	if len(data) == 0 {
		// empty slice -> no data (deleted)
		return nil
	}
	var commitmentBytes []byte
	var isValueInCommitment bool

	if len(data) > terminalCommitmentSizeMax {
		isValueInCommitment = false
		// taking the hash as commitment data for long values
		hash := blake2b160(data)
		commitmentBytes = hash[:]
	} else {
		isValueInCommitment = true
		// just cloning bytes. The data is its own commitment
		commitmentBytes = concat(data)
	}
	assert(len(commitmentBytes) <= terminalCommitmentSizeMax,
		"len(commitmentBytes) <= m.terminalCommitmentSizeMax")
	return &terminalCommitment{
		bytes:               commitmentBytes,
		isValueInCommitment: isValueInCommitment,
	}
}

type hashVector [vectorLength][]byte

// makeHashVector makes the node vector to be hashed. Missing children are nil
func makeHashVector(nodeData *nodeData) *hashVector {
	hashes := &hashVector{}
	for i, c := range nodeData.ChildCommitments {
		if c != nil {
			hash := c.Hash()
			hashes[i] = hash[:]
		}
	}
	if nodeData.Terminal != nil {
		// squeeze terminal it into the hash size, if longer than hash size
		hashes[terminalCommitmentIndex], _ = compressToHashSize(nodeData.Terminal.Bytes())
	}
	pathFragmentCommitmentBytes, _ := compressToHashSize(nodeData.PathFragment)
	hashes[pathFragmentCommitmentIndex] = pathFragmentCommitmentBytes
	return hashes
}

func (hashes *hashVector) Hash() Hash {
	buf := make([]byte, vectorLength*HashSizeBytes)
	for i, h := range hashes {
		if h == nil {
			continue
		}
		pos := i * HashSizeBytes
		copy(buf[pos:pos+HashSizeBytes], h[:])
	}
	return blake2b160(buf)
}

// *vectorCommitment implements trie_go.VCommitment
var _ VCommitment = &vectorCommitment{}

func newVectorCommitment() *vectorCommitment {
	return &vectorCommitment{}
}

func (v *vectorCommitment) Clone() VCommitment {
	c := vectorCommitment{}
	copy(c[:], v[:])
	return &c
}

func (v *vectorCommitment) Hash() Hash {
	return Hash(*v)
}

func (v *vectorCommitment) Bytes() []byte {
	return mustBytes(v)
}

func (v *vectorCommitment) Read(r io.Reader) error {
	_, err := r.Read(v[:])
	return err
}

func (v *vectorCommitment) Write(w io.Writer) error {
	_, err := w.Write(v[:])
	return err
}

func (v *vectorCommitment) String() string {
	return hex.EncodeToString(v[:])
}

func (v *vectorCommitment) Equals(c Commitment) bool {
	v2, ok := c.(*vectorCommitment)
	if !ok {
		return false
	}
	return *v == *v2
}

// *terminalCommitment implements trie_go.TCommitment
var _ TCommitment = &terminalCommitment{}

func newTerminalCommitment() *terminalCommitment {
	// all 0 non hashed value
	return &terminalCommitment{
		bytes:               make([]byte, 0, HashSizeBytes),
		isValueInCommitment: false,
	}
}

func (t *terminalCommitment) Equals(c Commitment) bool {
	t2, ok := c.(*terminalCommitment)
	if !ok {
		return false
	}
	return bytes.Equal(t.bytes, t2.bytes)
}

func (t *terminalCommitment) Clone() TCommitment {
	return &terminalCommitment{
		bytes:               concat(t.bytes),
		isValueInCommitment: t.isValueInCommitment,
	}
}

func (t *terminalCommitment) Write(w io.Writer) error {
	size := byte(len(t.bytes))
	assert(size <= terminalCommitmentSizeMax, "size <= terminalCommitmentSizeMax")
	if t.isValueInCommitment {
		size |= valueInCommitmentMask
	}
	if err := writeByte(w, size); err != nil {
		return err
	}
	_, err := w.Write(t.bytes)
	return err
}

func (t *terminalCommitment) Read(r io.Reader) error {
	var err error
	var l byte
	if l, err = readByte(r); err != nil {
		return err
	}
	t.isValueInCommitment = (l & valueInCommitmentMask) != 0
	l &= terminalCommitmentSizeMax
	if l > 0 {
		t.bytes = make([]byte, l)

		n, err := r.Read(t.bytes)
		if err != nil {
			return err
		}
		if n != int(l) {
			return errors.New("bad data length")
		}
	}
	return nil
}

func (t *terminalCommitment) Bytes() []byte {
	return mustBytes(t)
}

func (t *terminalCommitment) String() string {
	return hex.EncodeToString(t.bytes[:])
}

func (t *terminalCommitment) ExtractValue() ([]byte, bool) {
	if t.isValueInCommitment {
		return t.bytes, true
	}
	return nil, false
}

func ReadVectorCommitment(r io.Reader) (VCommitment, error) {
	ret := newVectorCommitment()
	if err := ret.Read(r); err != nil {
		return nil, err
	}
	return ret, nil
}

func ReadTerminalCommitment(r io.Reader) (TCommitment, error) {
	ret := newTerminalCommitment()
	if err := ret.Read(r); err != nil {
		return nil, err
	}
	return ret, nil
}

func VectorCommitmentFromBytes(data []byte) (VCommitment, error) {
	rdr := bytes.NewReader(data)
	ret, err := ReadVectorCommitment(rdr)
	if err != nil {
		return nil, err
	}
	if rdr.Len() > 0 {
		return nil, ErrNotAllBytesConsumed
	}
	return ret, nil
}

func TerminalCommitmentFromBytes(data []byte) (TCommitment, error) {
	rdr := bytes.NewReader(data)
	ret, err := ReadTerminalCommitment(rdr)
	if err != nil {
		return nil, err
	}
	if rdr.Len() > 0 {
		return nil, ErrNotAllBytesConsumed
	}
	return ret, nil
}
