package trie

import (
	"io"
)

// Commitment is the common interface for VCommitment and TCommitment
type Commitment interface {
	Read(r io.Reader) error
	Write(w io.Writer) error
	Bytes() []byte
	String() string
	Equals(Commitment) bool
}

// VCommitment represents interface to the vector commitment. It can be hash, or it can be a curve element
type VCommitment interface {
	Commitment
	Hash() Hash
	Clone() VCommitment
}

// TCommitment represents commitment to the terminal data. Usually it is a hash of the data of a scalar field element
type TCommitment interface {
	ExtractValue() ([]byte, bool)
	Commitment
	Clone() TCommitment
}
