package util

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/iotaledger/hive.go/serializer/v2"
	"github.com/iotaledger/wasp/packages/wbf"
)

// A + B
const RatioByteSize = serializer.UInt32ByteSize + serializer.UInt32ByteSize

// Ratio32 represents a ratio (a:b) between two quantities, expressed as two uint32 values.
type Ratio32 struct {
	A uint32 `json:"a" swagger:"min(0),required"`
	B uint32 `json:"b" swagger:"min(0),required"`
}

func (r Ratio32) String() string {
	return fmt.Sprintf("%d:%d", r.A, r.B)
}

func Ratio32FromString(s string) (Ratio32, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return Ratio32{}, fmt.Errorf("invalid string")
	}
	a, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return Ratio32{}, err
	}
	b, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return Ratio32{}, err
	}
	return Ratio32{A: uint32(a), B: uint32(b)}, nil
}

func (r Ratio32) Bytes() []byte {
	return wbf.MustMarshal(&r)
}

func Ratio32FromBytes(bytes []byte) (Ratio32, error) {
	var r Ratio32
	err := wbf.Unmarshal(&r, bytes)
	return r, err
}

func ceil(x, dividend, divisor uint64) uint64 {
	return (x*dividend + (divisor - 1)) / divisor
}

// YFloor64 computes y = floor(x * b / a)
func (r Ratio32) YFloor64(x uint64) uint64 {
	return x * uint64(r.B) / uint64(r.A)
}

// YCeil64 computes y = ceil(x * b / a)
func (r Ratio32) YCeil64(x uint64) uint64 {
	return ceil(x, uint64(r.B), uint64(r.A))
}

// XFloor64 computes x = floor(y * a / b)
func (r Ratio32) XFloor64(y uint64) uint64 {
	return y * uint64(r.A) / uint64(r.B)
}

// XCeil64 computes x = ceil(y * a / b)
func (r Ratio32) XCeil64(y uint64) uint64 {
	return ceil(y, uint64(r.A), uint64(r.B))
}

// Set is part of the pflag.Value interface. It accepts a string in the form "a:b".
func (r *Ratio32) Set(s string) error {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return errors.New("invalid format for Ratio32")
	}
	a, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return err
	}
	b, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return err
	}
	r.A = uint32(a)
	r.B = uint32(b)
	return nil
}

// Type is part of the pflag.Value interface.
func (r Ratio32) Type() string {
	return "Ratio32"
}

func (r Ratio32) HasZeroComponent() bool {
	return r.A == 0 || r.B == 0
}
