// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

package testwasmlib

import "github.com/iotaledger/wasp/packages/wasmvm/wasmlib/go/wasmlib"

var exportMap = wasmlib.ScExportMap{
	Names: []string{
		FuncAddressMapOfAddressArrayAppend,
		FuncAddressMapOfAddressArrayClear,
		FuncAddressMapOfAddressArraySet,
		FuncAddressMapOfAddressMapClear,
		FuncAddressMapOfAddressMapSet,
		FuncArrayOfAddressArrayAppend,
		FuncArrayOfAddressArrayClear,
		FuncArrayOfAddressArraySet,
		FuncArrayOfAddressMapClear,
		FuncArrayOfAddressMapSet,
		FuncArrayOfStringArrayAppend,
		FuncArrayOfStringArrayClear,
		FuncArrayOfStringArraySet,
		FuncArrayOfStringMapClear,
		FuncArrayOfStringMapSet,
		FuncParamTypes,
		FuncRandom,
		FuncStringMapOfStringArrayAppend,
		FuncStringMapOfStringArrayClear,
		FuncStringMapOfStringArraySet,
		FuncStringMapOfStringMapClear,
		FuncStringMapOfStringMapSet,
		FuncTakeAllowance,
		FuncTakeBalance,
		FuncTriggerEvent,
		ViewAddressMapOfAddressArrayLength,
		ViewAddressMapOfAddressArrayValue,
		ViewAddressMapOfAddressMapValue,
		ViewArrayOfAddressArrayLength,
		ViewArrayOfAddressArrayValue,
		ViewArrayOfAddressMapValue,
		ViewArrayOfStringArrayLength,
		ViewArrayOfStringArrayValue,
		ViewArrayOfStringMapValue,
		ViewBigIntAdd,
		ViewBigIntDiv,
		ViewBigIntMod,
		ViewBigIntMul,
		ViewBigIntSub,
		ViewBlockRecord,
		ViewBlockRecords,
		ViewGetRandom,
		ViewIotaBalance,
		ViewStringMapOfStringArrayLength,
		ViewStringMapOfStringArrayValue,
		ViewStringMapOfStringMapValue,
	},
	Funcs: []wasmlib.ScFuncContextFunction{
		funcAddressMapOfAddressArrayAppendThunk,
		funcAddressMapOfAddressArrayClearThunk,
		funcAddressMapOfAddressArraySetThunk,
		funcAddressMapOfAddressMapClearThunk,
		funcAddressMapOfAddressMapSetThunk,
		funcArrayOfAddressArrayAppendThunk,
		funcArrayOfAddressArrayClearThunk,
		funcArrayOfAddressArraySetThunk,
		funcArrayOfAddressMapClearThunk,
		funcArrayOfAddressMapSetThunk,
		funcArrayOfStringArrayAppendThunk,
		funcArrayOfStringArrayClearThunk,
		funcArrayOfStringArraySetThunk,
		funcArrayOfStringMapClearThunk,
		funcArrayOfStringMapSetThunk,
		funcParamTypesThunk,
		funcRandomThunk,
		funcStringMapOfStringArrayAppendThunk,
		funcStringMapOfStringArrayClearThunk,
		funcStringMapOfStringArraySetThunk,
		funcStringMapOfStringMapClearThunk,
		funcStringMapOfStringMapSetThunk,
		funcTakeAllowanceThunk,
		funcTakeBalanceThunk,
		funcTriggerEventThunk,
	},
	Views: []wasmlib.ScViewContextFunction{
		viewAddressMapOfAddressArrayLengthThunk,
		viewAddressMapOfAddressArrayValueThunk,
		viewAddressMapOfAddressMapValueThunk,
		viewArrayOfAddressArrayLengthThunk,
		viewArrayOfAddressArrayValueThunk,
		viewArrayOfAddressMapValueThunk,
		viewArrayOfStringArrayLengthThunk,
		viewArrayOfStringArrayValueThunk,
		viewArrayOfStringMapValueThunk,
		viewBigIntAddThunk,
		viewBigIntDivThunk,
		viewBigIntModThunk,
		viewBigIntMulThunk,
		viewBigIntSubThunk,
		viewBlockRecordThunk,
		viewBlockRecordsThunk,
		viewGetRandomThunk,
		viewIotaBalanceThunk,
		viewStringMapOfStringArrayLengthThunk,
		viewStringMapOfStringArrayValueThunk,
		viewStringMapOfStringMapValueThunk,
	},
}

func OnLoad(index int32) {
	if index >= 0 {
		wasmlib.ScExportsCall(index, &exportMap)
		return
	}

	wasmlib.ScExportsExport(&exportMap)
}

type AddressMapOfAddressArrayAppendContext struct {
	Events TestWasmLibEvents
	Params ImmutableAddressMapOfAddressArrayAppendParams
	State  MutableTestWasmLibState
}

func funcAddressMapOfAddressArrayAppendThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcAddressMapOfAddressArrayAppend")
	f := &AddressMapOfAddressArrayAppendContext{
		Params: ImmutableAddressMapOfAddressArrayAppendParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	ctx.Require(f.Params.ValueAddr().Exists(), "missing mandatory valueAddr")
	funcAddressMapOfAddressArrayAppend(ctx, f)
	ctx.Log("testwasmlib.funcAddressMapOfAddressArrayAppend ok")
}

type AddressMapOfAddressArrayClearContext struct {
	Events TestWasmLibEvents
	Params ImmutableAddressMapOfAddressArrayClearParams
	State  MutableTestWasmLibState
}

func funcAddressMapOfAddressArrayClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcAddressMapOfAddressArrayClear")
	f := &AddressMapOfAddressArrayClearContext{
		Params: ImmutableAddressMapOfAddressArrayClearParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	funcAddressMapOfAddressArrayClear(ctx, f)
	ctx.Log("testwasmlib.funcAddressMapOfAddressArrayClear ok")
}

type AddressMapOfAddressArraySetContext struct {
	Events TestWasmLibEvents
	Params ImmutableAddressMapOfAddressArraySetParams
	State  MutableTestWasmLibState
}

func funcAddressMapOfAddressArraySetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcAddressMapOfAddressArraySet")
	f := &AddressMapOfAddressArraySetContext{
		Params: ImmutableAddressMapOfAddressArraySetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	ctx.Require(f.Params.ValueAddr().Exists(), "missing mandatory valueAddr")
	funcAddressMapOfAddressArraySet(ctx, f)
	ctx.Log("testwasmlib.funcAddressMapOfAddressArraySet ok")
}

type AddressMapOfAddressMapClearContext struct {
	Events TestWasmLibEvents
	Params ImmutableAddressMapOfAddressMapClearParams
	State  MutableTestWasmLibState
}

func funcAddressMapOfAddressMapClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcAddressMapOfAddressMapClear")
	f := &AddressMapOfAddressMapClearContext{
		Params: ImmutableAddressMapOfAddressMapClearParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	funcAddressMapOfAddressMapClear(ctx, f)
	ctx.Log("testwasmlib.funcAddressMapOfAddressMapClear ok")
}

type AddressMapOfAddressMapSetContext struct {
	Events TestWasmLibEvents
	Params ImmutableAddressMapOfAddressMapSetParams
	State  MutableTestWasmLibState
}

func funcAddressMapOfAddressMapSetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcAddressMapOfAddressMapSet")
	f := &AddressMapOfAddressMapSetContext{
		Params: ImmutableAddressMapOfAddressMapSetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.KeyAddr().Exists(), "missing mandatory keyAddr")
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	ctx.Require(f.Params.ValueAddr().Exists(), "missing mandatory valueAddr")
	funcAddressMapOfAddressMapSet(ctx, f)
	ctx.Log("testwasmlib.funcAddressMapOfAddressMapSet ok")
}

type ArrayOfAddressArrayAppendContext struct {
	Events TestWasmLibEvents
	Params ImmutableArrayOfAddressArrayAppendParams
	State  MutableTestWasmLibState
}

func funcArrayOfAddressArrayAppendThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfAddressArrayAppend")
	f := &ArrayOfAddressArrayAppendContext{
		Params: ImmutableArrayOfAddressArrayAppendParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	funcArrayOfAddressArrayAppend(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfAddressArrayAppend ok")
}

type ArrayOfAddressArrayClearContext struct {
	Events TestWasmLibEvents
	State  MutableTestWasmLibState
}

func funcArrayOfAddressArrayClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfAddressArrayClear")
	f := &ArrayOfAddressArrayClearContext{
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcArrayOfAddressArrayClear(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfAddressArrayClear ok")
}

type ArrayOfAddressArraySetContext struct {
	Events TestWasmLibEvents
	Params ImmutableArrayOfAddressArraySetParams
	State  MutableTestWasmLibState
}

func funcArrayOfAddressArraySetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfAddressArraySet")
	f := &ArrayOfAddressArraySetContext{
		Params: ImmutableArrayOfAddressArraySetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index0().Exists(), "missing mandatory index0")
	ctx.Require(f.Params.Index1().Exists(), "missing mandatory index1")
	ctx.Require(f.Params.ValueAddr().Exists(), "missing mandatory valueAddr")
	funcArrayOfAddressArraySet(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfAddressArraySet ok")
}

type ArrayOfAddressMapClearContext struct {
	Events TestWasmLibEvents
	State  MutableTestWasmLibState
}

func funcArrayOfAddressMapClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfAddressMapClear")
	f := &ArrayOfAddressMapClearContext{
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcArrayOfAddressMapClear(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfAddressMapClear ok")
}

type ArrayOfAddressMapSetContext struct {
	Events TestWasmLibEvents
	Params ImmutableArrayOfAddressMapSetParams
	State  MutableTestWasmLibState
}

func funcArrayOfAddressMapSetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfAddressMapSet")
	f := &ArrayOfAddressMapSetContext{
		Params: ImmutableArrayOfAddressMapSetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.KeyAddr().Exists(), "missing mandatory keyAddr")
	ctx.Require(f.Params.ValueAddr().Exists(), "missing mandatory valueAddr")
	funcArrayOfAddressMapSet(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfAddressMapSet ok")
}

type ArrayOfStringArrayAppendContext struct {
	Events TestWasmLibEvents
	Params ImmutableArrayOfStringArrayAppendParams
	State  MutableTestWasmLibState
}

func funcArrayOfStringArrayAppendThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfStringArrayAppend")
	f := &ArrayOfStringArrayAppendContext{
		Params: ImmutableArrayOfStringArrayAppendParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	funcArrayOfStringArrayAppend(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfStringArrayAppend ok")
}

type ArrayOfStringArrayClearContext struct {
	Events TestWasmLibEvents
	State  MutableTestWasmLibState
}

func funcArrayOfStringArrayClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfStringArrayClear")
	f := &ArrayOfStringArrayClearContext{
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcArrayOfStringArrayClear(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfStringArrayClear ok")
}

type ArrayOfStringArraySetContext struct {
	Events TestWasmLibEvents
	Params ImmutableArrayOfStringArraySetParams
	State  MutableTestWasmLibState
}

func funcArrayOfStringArraySetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfStringArraySet")
	f := &ArrayOfStringArraySetContext{
		Params: ImmutableArrayOfStringArraySetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index0().Exists(), "missing mandatory index0")
	ctx.Require(f.Params.Index1().Exists(), "missing mandatory index1")
	ctx.Require(f.Params.Value().Exists(), "missing mandatory value")
	funcArrayOfStringArraySet(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfStringArraySet ok")
}

type ArrayOfStringMapClearContext struct {
	Events TestWasmLibEvents
	State  MutableTestWasmLibState
}

func funcArrayOfStringMapClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfStringMapClear")
	f := &ArrayOfStringMapClearContext{
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcArrayOfStringMapClear(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfStringMapClear ok")
}

type ArrayOfStringMapSetContext struct {
	Events TestWasmLibEvents
	Params ImmutableArrayOfStringMapSetParams
	State  MutableTestWasmLibState
}

func funcArrayOfStringMapSetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcArrayOfStringMapSet")
	f := &ArrayOfStringMapSetContext{
		Params: ImmutableArrayOfStringMapSetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.Key().Exists(), "missing mandatory key")
	ctx.Require(f.Params.Value().Exists(), "missing mandatory value")
	funcArrayOfStringMapSet(ctx, f)
	ctx.Log("testwasmlib.funcArrayOfStringMapSet ok")
}

type ParamTypesContext struct {
	Events TestWasmLibEvents
	Params ImmutableParamTypesParams
	State  MutableTestWasmLibState
}

func funcParamTypesThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcParamTypes")
	f := &ParamTypesContext{
		Params: ImmutableParamTypesParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcParamTypes(ctx, f)
	ctx.Log("testwasmlib.funcParamTypes ok")
}

type RandomContext struct {
	Events TestWasmLibEvents
	State  MutableTestWasmLibState
}

func funcRandomThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcRandom")
	f := &RandomContext{
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcRandom(ctx, f)
	ctx.Log("testwasmlib.funcRandom ok")
}

type StringMapOfStringArrayAppendContext struct {
	Events TestWasmLibEvents
	Params ImmutableStringMapOfStringArrayAppendParams
	State  MutableTestWasmLibState
}

func funcStringMapOfStringArrayAppendThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcStringMapOfStringArrayAppend")
	f := &StringMapOfStringArrayAppendContext{
		Params: ImmutableStringMapOfStringArrayAppendParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	ctx.Require(f.Params.Value().Exists(), "missing mandatory value")
	funcStringMapOfStringArrayAppend(ctx, f)
	ctx.Log("testwasmlib.funcStringMapOfStringArrayAppend ok")
}

type StringMapOfStringArrayClearContext struct {
	Events TestWasmLibEvents
	Params ImmutableStringMapOfStringArrayClearParams
	State  MutableTestWasmLibState
}

func funcStringMapOfStringArrayClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcStringMapOfStringArrayClear")
	f := &StringMapOfStringArrayClearContext{
		Params: ImmutableStringMapOfStringArrayClearParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	funcStringMapOfStringArrayClear(ctx, f)
	ctx.Log("testwasmlib.funcStringMapOfStringArrayClear ok")
}

type StringMapOfStringArraySetContext struct {
	Events TestWasmLibEvents
	Params ImmutableStringMapOfStringArraySetParams
	State  MutableTestWasmLibState
}

func funcStringMapOfStringArraySetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcStringMapOfStringArraySet")
	f := &StringMapOfStringArraySetContext{
		Params: ImmutableStringMapOfStringArraySetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	ctx.Require(f.Params.Value().Exists(), "missing mandatory value")
	funcStringMapOfStringArraySet(ctx, f)
	ctx.Log("testwasmlib.funcStringMapOfStringArraySet ok")
}

type StringMapOfStringMapClearContext struct {
	Events TestWasmLibEvents
	Params ImmutableStringMapOfStringMapClearParams
	State  MutableTestWasmLibState
}

func funcStringMapOfStringMapClearThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcStringMapOfStringMapClear")
	f := &StringMapOfStringMapClearContext{
		Params: ImmutableStringMapOfStringMapClearParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	funcStringMapOfStringMapClear(ctx, f)
	ctx.Log("testwasmlib.funcStringMapOfStringMapClear ok")
}

type StringMapOfStringMapSetContext struct {
	Events TestWasmLibEvents
	Params ImmutableStringMapOfStringMapSetParams
	State  MutableTestWasmLibState
}

func funcStringMapOfStringMapSetThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcStringMapOfStringMapSet")
	f := &StringMapOfStringMapSetContext{
		Params: ImmutableStringMapOfStringMapSetParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Key().Exists(), "missing mandatory key")
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	ctx.Require(f.Params.Value().Exists(), "missing mandatory value")
	funcStringMapOfStringMapSet(ctx, f)
	ctx.Log("testwasmlib.funcStringMapOfStringMapSet ok")
}

type TakeAllowanceContext struct {
	Events TestWasmLibEvents
	State  MutableTestWasmLibState
}

func funcTakeAllowanceThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcTakeAllowance")
	f := &TakeAllowanceContext{
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcTakeAllowance(ctx, f)
	ctx.Log("testwasmlib.funcTakeAllowance ok")
}

type TakeBalanceContext struct {
	Events  TestWasmLibEvents
	Results MutableTakeBalanceResults
	State   MutableTestWasmLibState
}

func funcTakeBalanceThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcTakeBalance")
	results := wasmlib.NewScDict()
	f := &TakeBalanceContext{
		Results: MutableTakeBalanceResults{
			proxy: results.AsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	funcTakeBalance(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.funcTakeBalance ok")
}

type TriggerEventContext struct {
	Events TestWasmLibEvents
	Params ImmutableTriggerEventParams
	State  MutableTestWasmLibState
}

func funcTriggerEventThunk(ctx wasmlib.ScFuncContext) {
	ctx.Log("testwasmlib.funcTriggerEvent")
	f := &TriggerEventContext{
		Params: ImmutableTriggerEventParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		State: MutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Address().Exists(), "missing mandatory address")
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	funcTriggerEvent(ctx, f)
	ctx.Log("testwasmlib.funcTriggerEvent ok")
}

type AddressMapOfAddressArrayLengthContext struct {
	Params  ImmutableAddressMapOfAddressArrayLengthParams
	Results MutableAddressMapOfAddressArrayLengthResults
	State   ImmutableTestWasmLibState
}

func viewAddressMapOfAddressArrayLengthThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewAddressMapOfAddressArrayLength")
	results := wasmlib.NewScDict()
	f := &AddressMapOfAddressArrayLengthContext{
		Params: ImmutableAddressMapOfAddressArrayLengthParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableAddressMapOfAddressArrayLengthResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	viewAddressMapOfAddressArrayLength(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewAddressMapOfAddressArrayLength ok")
}

type AddressMapOfAddressArrayValueContext struct {
	Params  ImmutableAddressMapOfAddressArrayValueParams
	Results MutableAddressMapOfAddressArrayValueResults
	State   ImmutableTestWasmLibState
}

func viewAddressMapOfAddressArrayValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewAddressMapOfAddressArrayValue")
	results := wasmlib.NewScDict()
	f := &AddressMapOfAddressArrayValueContext{
		Params: ImmutableAddressMapOfAddressArrayValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableAddressMapOfAddressArrayValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	viewAddressMapOfAddressArrayValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewAddressMapOfAddressArrayValue ok")
}

type AddressMapOfAddressMapValueContext struct {
	Params  ImmutableAddressMapOfAddressMapValueParams
	Results MutableAddressMapOfAddressMapValueResults
	State   ImmutableTestWasmLibState
}

func viewAddressMapOfAddressMapValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewAddressMapOfAddressMapValue")
	results := wasmlib.NewScDict()
	f := &AddressMapOfAddressMapValueContext{
		Params: ImmutableAddressMapOfAddressMapValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableAddressMapOfAddressMapValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.KeyAddr().Exists(), "missing mandatory keyAddr")
	ctx.Require(f.Params.NameAddr().Exists(), "missing mandatory nameAddr")
	viewAddressMapOfAddressMapValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewAddressMapOfAddressMapValue ok")
}

type ArrayOfAddressArrayLengthContext struct {
	Results MutableArrayOfAddressArrayLengthResults
	State   ImmutableTestWasmLibState
}

func viewArrayOfAddressArrayLengthThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewArrayOfAddressArrayLength")
	results := wasmlib.NewScDict()
	f := &ArrayOfAddressArrayLengthContext{
		Results: MutableArrayOfAddressArrayLengthResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	viewArrayOfAddressArrayLength(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewArrayOfAddressArrayLength ok")
}

type ArrayOfAddressArrayValueContext struct {
	Params  ImmutableArrayOfAddressArrayValueParams
	Results MutableArrayOfAddressArrayValueResults
	State   ImmutableTestWasmLibState
}

func viewArrayOfAddressArrayValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewArrayOfAddressArrayValue")
	results := wasmlib.NewScDict()
	f := &ArrayOfAddressArrayValueContext{
		Params: ImmutableArrayOfAddressArrayValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableArrayOfAddressArrayValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index0().Exists(), "missing mandatory index0")
	ctx.Require(f.Params.Index1().Exists(), "missing mandatory index1")
	viewArrayOfAddressArrayValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewArrayOfAddressArrayValue ok")
}

type ArrayOfAddressMapValueContext struct {
	Params  ImmutableArrayOfAddressMapValueParams
	Results MutableArrayOfAddressMapValueResults
	State   ImmutableTestWasmLibState
}

func viewArrayOfAddressMapValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewArrayOfAddressMapValue")
	results := wasmlib.NewScDict()
	f := &ArrayOfAddressMapValueContext{
		Params: ImmutableArrayOfAddressMapValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableArrayOfAddressMapValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.KeyAddr().Exists(), "missing mandatory keyAddr")
	viewArrayOfAddressMapValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewArrayOfAddressMapValue ok")
}

type ArrayOfStringArrayLengthContext struct {
	Results MutableArrayOfStringArrayLengthResults
	State   ImmutableTestWasmLibState
}

func viewArrayOfStringArrayLengthThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewArrayOfStringArrayLength")
	results := wasmlib.NewScDict()
	f := &ArrayOfStringArrayLengthContext{
		Results: MutableArrayOfStringArrayLengthResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	viewArrayOfStringArrayLength(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewArrayOfStringArrayLength ok")
}

type ArrayOfStringArrayValueContext struct {
	Params  ImmutableArrayOfStringArrayValueParams
	Results MutableArrayOfStringArrayValueResults
	State   ImmutableTestWasmLibState
}

func viewArrayOfStringArrayValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewArrayOfStringArrayValue")
	results := wasmlib.NewScDict()
	f := &ArrayOfStringArrayValueContext{
		Params: ImmutableArrayOfStringArrayValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableArrayOfStringArrayValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index0().Exists(), "missing mandatory index0")
	ctx.Require(f.Params.Index1().Exists(), "missing mandatory index1")
	viewArrayOfStringArrayValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewArrayOfStringArrayValue ok")
}

type ArrayOfStringMapValueContext struct {
	Params  ImmutableArrayOfStringMapValueParams
	Results MutableArrayOfStringMapValueResults
	State   ImmutableTestWasmLibState
}

func viewArrayOfStringMapValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewArrayOfStringMapValue")
	results := wasmlib.NewScDict()
	f := &ArrayOfStringMapValueContext{
		Params: ImmutableArrayOfStringMapValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableArrayOfStringMapValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.Key().Exists(), "missing mandatory key")
	viewArrayOfStringMapValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewArrayOfStringMapValue ok")
}

type BigIntAddContext struct {
	Params  ImmutableBigIntAddParams
	Results MutableBigIntAddResults
	State   ImmutableTestWasmLibState
}

func viewBigIntAddThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewBigIntAdd")
	results := wasmlib.NewScDict()
	f := &BigIntAddContext{
		Params: ImmutableBigIntAddParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableBigIntAddResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Lhs().Exists(), "missing mandatory lhs")
	ctx.Require(f.Params.Rhs().Exists(), "missing mandatory rhs")
	viewBigIntAdd(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewBigIntAdd ok")
}

type BigIntDivContext struct {
	Params  ImmutableBigIntDivParams
	Results MutableBigIntDivResults
	State   ImmutableTestWasmLibState
}

func viewBigIntDivThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewBigIntDiv")
	results := wasmlib.NewScDict()
	f := &BigIntDivContext{
		Params: ImmutableBigIntDivParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableBigIntDivResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Lhs().Exists(), "missing mandatory lhs")
	ctx.Require(f.Params.Rhs().Exists(), "missing mandatory rhs")
	viewBigIntDiv(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewBigIntDiv ok")
}

type BigIntModContext struct {
	Params  ImmutableBigIntModParams
	Results MutableBigIntModResults
	State   ImmutableTestWasmLibState
}

func viewBigIntModThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewBigIntMod")
	results := wasmlib.NewScDict()
	f := &BigIntModContext{
		Params: ImmutableBigIntModParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableBigIntModResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Lhs().Exists(), "missing mandatory lhs")
	ctx.Require(f.Params.Rhs().Exists(), "missing mandatory rhs")
	viewBigIntMod(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewBigIntMod ok")
}

type BigIntMulContext struct {
	Params  ImmutableBigIntMulParams
	Results MutableBigIntMulResults
	State   ImmutableTestWasmLibState
}

func viewBigIntMulThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewBigIntMul")
	results := wasmlib.NewScDict()
	f := &BigIntMulContext{
		Params: ImmutableBigIntMulParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableBigIntMulResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Lhs().Exists(), "missing mandatory lhs")
	ctx.Require(f.Params.Rhs().Exists(), "missing mandatory rhs")
	viewBigIntMul(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewBigIntMul ok")
}

type BigIntSubContext struct {
	Params  ImmutableBigIntSubParams
	Results MutableBigIntSubResults
	State   ImmutableTestWasmLibState
}

func viewBigIntSubThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewBigIntSub")
	results := wasmlib.NewScDict()
	f := &BigIntSubContext{
		Params: ImmutableBigIntSubParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableBigIntSubResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Lhs().Exists(), "missing mandatory lhs")
	ctx.Require(f.Params.Rhs().Exists(), "missing mandatory rhs")
	viewBigIntSub(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewBigIntSub ok")
}

type BlockRecordContext struct {
	Params  ImmutableBlockRecordParams
	Results MutableBlockRecordResults
	State   ImmutableTestWasmLibState
}

func viewBlockRecordThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewBlockRecord")
	results := wasmlib.NewScDict()
	f := &BlockRecordContext{
		Params: ImmutableBlockRecordParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableBlockRecordResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.BlockIndex().Exists(), "missing mandatory blockIndex")
	ctx.Require(f.Params.RecordIndex().Exists(), "missing mandatory recordIndex")
	viewBlockRecord(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewBlockRecord ok")
}

type BlockRecordsContext struct {
	Params  ImmutableBlockRecordsParams
	Results MutableBlockRecordsResults
	State   ImmutableTestWasmLibState
}

func viewBlockRecordsThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewBlockRecords")
	results := wasmlib.NewScDict()
	f := &BlockRecordsContext{
		Params: ImmutableBlockRecordsParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableBlockRecordsResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.BlockIndex().Exists(), "missing mandatory blockIndex")
	viewBlockRecords(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewBlockRecords ok")
}

type GetRandomContext struct {
	Results MutableGetRandomResults
	State   ImmutableTestWasmLibState
}

func viewGetRandomThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewGetRandom")
	results := wasmlib.NewScDict()
	f := &GetRandomContext{
		Results: MutableGetRandomResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	viewGetRandom(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewGetRandom ok")
}

type IotaBalanceContext struct {
	Results MutableIotaBalanceResults
	State   ImmutableTestWasmLibState
}

func viewIotaBalanceThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewIotaBalance")
	results := wasmlib.NewScDict()
	f := &IotaBalanceContext{
		Results: MutableIotaBalanceResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	viewIotaBalance(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewIotaBalance ok")
}

type StringMapOfStringArrayLengthContext struct {
	Params  ImmutableStringMapOfStringArrayLengthParams
	Results MutableStringMapOfStringArrayLengthResults
	State   ImmutableTestWasmLibState
}

func viewStringMapOfStringArrayLengthThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewStringMapOfStringArrayLength")
	results := wasmlib.NewScDict()
	f := &StringMapOfStringArrayLengthContext{
		Params: ImmutableStringMapOfStringArrayLengthParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableStringMapOfStringArrayLengthResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	viewStringMapOfStringArrayLength(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewStringMapOfStringArrayLength ok")
}

type StringMapOfStringArrayValueContext struct {
	Params  ImmutableStringMapOfStringArrayValueParams
	Results MutableStringMapOfStringArrayValueResults
	State   ImmutableTestWasmLibState
}

func viewStringMapOfStringArrayValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewStringMapOfStringArrayValue")
	results := wasmlib.NewScDict()
	f := &StringMapOfStringArrayValueContext{
		Params: ImmutableStringMapOfStringArrayValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableStringMapOfStringArrayValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Index().Exists(), "missing mandatory index")
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	viewStringMapOfStringArrayValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewStringMapOfStringArrayValue ok")
}

type StringMapOfStringMapValueContext struct {
	Params  ImmutableStringMapOfStringMapValueParams
	Results MutableStringMapOfStringMapValueResults
	State   ImmutableTestWasmLibState
}

func viewStringMapOfStringMapValueThunk(ctx wasmlib.ScViewContext) {
	ctx.Log("testwasmlib.viewStringMapOfStringMapValue")
	results := wasmlib.NewScDict()
	f := &StringMapOfStringMapValueContext{
		Params: ImmutableStringMapOfStringMapValueParams{
			proxy: wasmlib.NewParamsProxy(),
		},
		Results: MutableStringMapOfStringMapValueResults{
			proxy: results.AsProxy(),
		},
		State: ImmutableTestWasmLibState{
			proxy: wasmlib.NewStateProxy(),
		},
	}
	ctx.Require(f.Params.Key().Exists(), "missing mandatory key")
	ctx.Require(f.Params.Name().Exists(), "missing mandatory name")
	viewStringMapOfStringMapValue(ctx, f)
	ctx.Results(results)
	ctx.Log("testwasmlib.viewStringMapOfStringMapValue ok")
}
