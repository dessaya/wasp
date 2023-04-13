package wbf_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/wasp/packages/wbf"
)

func TestInt8(t *testing.T) {
	var x int8 = -5
	b := wbf.MustMarshal(x)
	require.Len(t, b, 1)

	var x2 int8
	wbf.MustUnmarshal(&x2, b)
	require.EqualValues(t, x, x2)
}

func TestInt8Pointer(t *testing.T) {
	var x int8 = -5
	b := wbf.MustMarshal(&x)
	require.Len(t, b, 1)

	var x2 int8
	wbf.MustUnmarshal(&x2, b)
	require.EqualValues(t, x, x2)
}

func TestInt8Like(t *testing.T) {
	type d int8
	var x d = -5
	b := wbf.MustMarshal(x)
	require.Len(t, b, 1)

	var x2 d
	wbf.MustUnmarshal(&x2, b)
	require.EqualValues(t, x, x2)
}

func TestEncodeNilPointer(t *testing.T) {
	var x *int8
	_, err := wbf.Marshal(&x)
	require.ErrorContains(t, err, "nil pointer")
}

func TestDecodeNilPointer(t *testing.T) {
	var x2 *int8
	err := wbf.Unmarshal(x2, []byte{1})
	require.ErrorContains(t, err, "nil pointer")
}

func TestUint8(t *testing.T) {
	var x uint8 = 250
	b := wbf.MustMarshal(x)
	require.Len(t, b, 1)

	var x2 uint8
	wbf.MustUnmarshal(&x2, b)
	require.EqualValues(t, x, x2)
}

func TestUint8Like(t *testing.T) {
	type d uint8
	var x d = 250
	b := wbf.MustMarshal(x)
	require.Len(t, b, 1)

	var x2 d
	wbf.MustUnmarshal(&x2, b)
	require.EqualValues(t, x, x2)
}

func TestStruct(t *testing.T) {
	type s struct {
		U uint8
		I int8
	}

	x := s{U: 250, I: -5}
	b := wbf.MustMarshal(x)
	require.Len(t, b, 2)

	var x2 s
	wbf.MustUnmarshal(&x2, b)
	require.EqualValues(t, x, x2)
}
