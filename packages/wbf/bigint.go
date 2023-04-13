package wbf

import (
	"io"
	"math/big"
)

type BigInt big.Int

type bigIntWbf struct {
	Bytes []byte `wbf:"u32size"` // TODO: u32 for backwards compatibility
}

func (b *BigInt) WBFWrite(w io.Writer) error {
	return WriteValue(bigIntWbf{Bytes: (*big.Int)(b).Bytes()}, w)
}

func (b *BigInt) WBFRead(v []byte) ([]byte, error) {
	var w bigIntWbf
	var err error
	v, err = ReadValue(&w, v)
	if err != nil {
		return nil, err
	}
	(*big.Int)(b).SetBytes(w.Bytes)
	return v, nil
}

func (b *BigInt) String() string { return (*big.Int)(b).String() }
