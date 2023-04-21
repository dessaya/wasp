package wbf

import (
	"io"
	"math/big"
)

type BigInt big.Int

type bigIntWbf struct {
	Bytes []byte `wbf:"u32size"` // TODO: using u32 for backwards compatibility
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
