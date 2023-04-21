package wbf

import (
	"io"
	"math/big"
)

type BigInt big.Int

type bigIntWbf struct {
	Bytes []byte `wbf:"u8size"`
}

func (b *BigInt) WBFWrite(w io.Writer) error {
	return WriteValue(bigIntWbf{Bytes: (*big.Int)(b).Bytes()}, w)
}

func (b *BigInt) WBFRead(r io.Reader) error {
	var w bigIntWbf
	err := ReadValue(&w, r)
	if err != nil {
		return err
	}
	(*big.Int)(b).SetBytes(w.Bytes)
	return nil
}

func (b *BigInt) String() string { return (*big.Int)(b).String() }

// BigInt32 encodes a *big.Int as a byte slice prepended with a 32bit length.
// It exists for backwards compatibility.
// Use BigInt instead for new types.
type BigInt32 big.Int

type bigInt32Wbf struct {
	Bytes []byte `wbf:"u32size"`
}

func (b *BigInt32) WBFWrite(w io.Writer) error {
	return WriteValue(bigInt32Wbf{Bytes: (*big.Int)(b).Bytes()}, w)
}

func (b *BigInt32) WBFRead(r io.Reader) error {
	var w bigInt32Wbf
	err := ReadValue(&w, r)
	if err != nil {
		return err
	}
	(*big.Int)(b).SetBytes(w.Bytes)
	return nil
}

func (b *BigInt32) String() string { return (*big.Int)(b).String() }
