// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

package testcore

import "github.com/iotaledger/wasp/packages/wasmvm/wasmlib/go/wasmlib/wasmtypes"

type ImmutableTestCoreState struct {
	proxy wasmtypes.Proxy
}

func (s ImmutableTestCoreState) Counter() wasmtypes.ScImmutableUint64 {
	return wasmtypes.NewScImmutableUint64(s.proxy.Root(StateCounter))
}

func (s ImmutableTestCoreState) Ints() MapStringToImmutableInt64 {
	return MapStringToImmutableInt64{proxy: s.proxy.Root(StateInts)}
}

func (s ImmutableTestCoreState) Strings() MapStringToImmutableString {
	return MapStringToImmutableString{proxy: s.proxy.Root(StateStrings)}
}

type MutableTestCoreState struct {
	proxy wasmtypes.Proxy
}

func (s MutableTestCoreState) AsImmutable() ImmutableTestCoreState {
	return ImmutableTestCoreState(s)
}

func (s MutableTestCoreState) Counter() wasmtypes.ScMutableUint64 {
	return wasmtypes.NewScMutableUint64(s.proxy.Root(StateCounter))
}

func (s MutableTestCoreState) Ints() MapStringToMutableInt64 {
	return MapStringToMutableInt64{proxy: s.proxy.Root(StateInts)}
}

func (s MutableTestCoreState) Strings() MapStringToMutableString {
	return MapStringToMutableString{proxy: s.proxy.Root(StateStrings)}
}