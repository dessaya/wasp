// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

package timestamp

import "github.com/iotaledger/wasp/packages/wasmvm/wasmlib/go/wasmlib/wasmtypes"

type ImmutableGetTimestampResults struct {
	proxy wasmtypes.Proxy
}

func (s ImmutableGetTimestampResults) Timestamp() wasmtypes.ScImmutableUint64 {
	return wasmtypes.NewScImmutableUint64(s.proxy.Root(ResultTimestamp))
}

type MutableGetTimestampResults struct {
	proxy wasmtypes.Proxy
}

func (s MutableGetTimestampResults) Timestamp() wasmtypes.ScMutableUint64 {
	return wasmtypes.NewScMutableUint64(s.proxy.Root(ResultTimestamp))
}
