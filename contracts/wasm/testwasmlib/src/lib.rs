// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

#![allow(dead_code)]
#![allow(unused_imports)]

use testwasmlib::*;
use wasmlib::*;

use crate::consts::*;
use crate::events::*;
use crate::params::*;
use crate::results::*;
use crate::state::*;
use crate::structs::*;
use crate::typedefs::*;

mod consts;
mod contract;
mod events;
mod params;
mod results;
mod state;
mod structs;
mod typedefs;

mod testwasmlib;

const EXPORT_MAP: ScExportMap = ScExportMap {
    names: &[
    	FUNC_ADDRESS_MAP_OF_ADDRESS_ARRAY_APPEND,
    	FUNC_ADDRESS_MAP_OF_ADDRESS_ARRAY_CLEAR,
    	FUNC_ADDRESS_MAP_OF_ADDRESS_ARRAY_SET,
    	FUNC_ADDRESS_MAP_OF_ADDRESS_MAP_CLEAR,
    	FUNC_ADDRESS_MAP_OF_ADDRESS_MAP_SET,
    	FUNC_ARRAY_OF_ADDRESS_ARRAY_APPEND,
    	FUNC_ARRAY_OF_ADDRESS_ARRAY_CLEAR,
    	FUNC_ARRAY_OF_ADDRESS_ARRAY_SET,
    	FUNC_ARRAY_OF_ADDRESS_MAP_CLEAR,
    	FUNC_ARRAY_OF_ADDRESS_MAP_SET,
    	FUNC_ARRAY_OF_STRING_ARRAY_APPEND,
    	FUNC_ARRAY_OF_STRING_ARRAY_CLEAR,
    	FUNC_ARRAY_OF_STRING_ARRAY_SET,
    	FUNC_ARRAY_OF_STRING_MAP_CLEAR,
    	FUNC_ARRAY_OF_STRING_MAP_SET,
    	FUNC_PARAM_TYPES,
    	FUNC_RANDOM,
    	FUNC_STRING_MAP_OF_STRING_ARRAY_APPEND,
    	FUNC_STRING_MAP_OF_STRING_ARRAY_CLEAR,
    	FUNC_STRING_MAP_OF_STRING_ARRAY_SET,
    	FUNC_STRING_MAP_OF_STRING_MAP_CLEAR,
    	FUNC_STRING_MAP_OF_STRING_MAP_SET,
    	FUNC_TAKE_ALLOWANCE,
    	FUNC_TAKE_BALANCE,
    	FUNC_TRIGGER_EVENT,
    	VIEW_ADDRESS_MAP_OF_ADDRESS_ARRAY_LENGTH,
    	VIEW_ADDRESS_MAP_OF_ADDRESS_ARRAY_VALUE,
    	VIEW_ADDRESS_MAP_OF_ADDRESS_MAP_VALUE,
    	VIEW_ARRAY_OF_ADDRESS_ARRAY_LENGTH,
    	VIEW_ARRAY_OF_ADDRESS_ARRAY_VALUE,
    	VIEW_ARRAY_OF_ADDRESS_MAP_VALUE,
    	VIEW_ARRAY_OF_STRING_ARRAY_LENGTH,
    	VIEW_ARRAY_OF_STRING_ARRAY_VALUE,
    	VIEW_ARRAY_OF_STRING_MAP_VALUE,
    	VIEW_BIG_INT_ADD,
    	VIEW_BIG_INT_DIV,
    	VIEW_BIG_INT_MOD,
    	VIEW_BIG_INT_MUL,
    	VIEW_BIG_INT_SUB,
    	VIEW_BLOCK_RECORD,
    	VIEW_BLOCK_RECORDS,
    	VIEW_GET_RANDOM,
    	VIEW_IOTA_BALANCE,
    	VIEW_STRING_MAP_OF_STRING_ARRAY_LENGTH,
    	VIEW_STRING_MAP_OF_STRING_ARRAY_VALUE,
    	VIEW_STRING_MAP_OF_STRING_MAP_VALUE,
	],
    funcs: &[
    	func_address_map_of_address_array_append_thunk,
    	func_address_map_of_address_array_clear_thunk,
    	func_address_map_of_address_array_set_thunk,
    	func_address_map_of_address_map_clear_thunk,
    	func_address_map_of_address_map_set_thunk,
    	func_array_of_address_array_append_thunk,
    	func_array_of_address_array_clear_thunk,
    	func_array_of_address_array_set_thunk,
    	func_array_of_address_map_clear_thunk,
    	func_array_of_address_map_set_thunk,
    	func_array_of_string_array_append_thunk,
    	func_array_of_string_array_clear_thunk,
    	func_array_of_string_array_set_thunk,
    	func_array_of_string_map_clear_thunk,
    	func_array_of_string_map_set_thunk,
    	func_param_types_thunk,
    	func_random_thunk,
    	func_string_map_of_string_array_append_thunk,
    	func_string_map_of_string_array_clear_thunk,
    	func_string_map_of_string_array_set_thunk,
    	func_string_map_of_string_map_clear_thunk,
    	func_string_map_of_string_map_set_thunk,
    	func_take_allowance_thunk,
    	func_take_balance_thunk,
    	func_trigger_event_thunk,
	],
    views: &[
    	view_address_map_of_address_array_length_thunk,
    	view_address_map_of_address_array_value_thunk,
    	view_address_map_of_address_map_value_thunk,
    	view_array_of_address_array_length_thunk,
    	view_array_of_address_array_value_thunk,
    	view_array_of_address_map_value_thunk,
    	view_array_of_string_array_length_thunk,
    	view_array_of_string_array_value_thunk,
    	view_array_of_string_map_value_thunk,
    	view_big_int_add_thunk,
    	view_big_int_div_thunk,
    	view_big_int_mod_thunk,
    	view_big_int_mul_thunk,
    	view_big_int_sub_thunk,
    	view_block_record_thunk,
    	view_block_records_thunk,
    	view_get_random_thunk,
    	view_iota_balance_thunk,
    	view_string_map_of_string_array_length_thunk,
    	view_string_map_of_string_array_value_thunk,
    	view_string_map_of_string_map_value_thunk,
	],
};

#[no_mangle]
fn on_call(index: i32) {
	ScExports::call(index, &EXPORT_MAP);
}

#[no_mangle]
fn on_load() {
    ScExports::export(&EXPORT_MAP);
}

pub struct AddressMapOfAddressArrayAppendContext {
	events:  TestWasmLibEvents,
	params: ImmutableAddressMapOfAddressArrayAppendParams,
	state: MutableTestWasmLibState,
}

fn func_address_map_of_address_array_append_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcAddressMapOfAddressArrayAppend");
	let f = AddressMapOfAddressArrayAppendContext {
		events:  TestWasmLibEvents {},
		params: ImmutableAddressMapOfAddressArrayAppendParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	ctx.require(f.params.value_addr().exists(), "missing mandatory valueAddr");
	func_address_map_of_address_array_append(ctx, &f);
	ctx.log("testwasmlib.funcAddressMapOfAddressArrayAppend ok");
}

pub struct AddressMapOfAddressArrayClearContext {
	events:  TestWasmLibEvents,
	params: ImmutableAddressMapOfAddressArrayClearParams,
	state: MutableTestWasmLibState,
}

fn func_address_map_of_address_array_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcAddressMapOfAddressArrayClear");
	let f = AddressMapOfAddressArrayClearContext {
		events:  TestWasmLibEvents {},
		params: ImmutableAddressMapOfAddressArrayClearParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	func_address_map_of_address_array_clear(ctx, &f);
	ctx.log("testwasmlib.funcAddressMapOfAddressArrayClear ok");
}

pub struct AddressMapOfAddressArraySetContext {
	events:  TestWasmLibEvents,
	params: ImmutableAddressMapOfAddressArraySetParams,
	state: MutableTestWasmLibState,
}

fn func_address_map_of_address_array_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcAddressMapOfAddressArraySet");
	let f = AddressMapOfAddressArraySetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableAddressMapOfAddressArraySetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	ctx.require(f.params.value_addr().exists(), "missing mandatory valueAddr");
	func_address_map_of_address_array_set(ctx, &f);
	ctx.log("testwasmlib.funcAddressMapOfAddressArraySet ok");
}

pub struct AddressMapOfAddressMapClearContext {
	events:  TestWasmLibEvents,
	params: ImmutableAddressMapOfAddressMapClearParams,
	state: MutableTestWasmLibState,
}

fn func_address_map_of_address_map_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcAddressMapOfAddressMapClear");
	let f = AddressMapOfAddressMapClearContext {
		events:  TestWasmLibEvents {},
		params: ImmutableAddressMapOfAddressMapClearParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	func_address_map_of_address_map_clear(ctx, &f);
	ctx.log("testwasmlib.funcAddressMapOfAddressMapClear ok");
}

pub struct AddressMapOfAddressMapSetContext {
	events:  TestWasmLibEvents,
	params: ImmutableAddressMapOfAddressMapSetParams,
	state: MutableTestWasmLibState,
}

fn func_address_map_of_address_map_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcAddressMapOfAddressMapSet");
	let f = AddressMapOfAddressMapSetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableAddressMapOfAddressMapSetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.key_addr().exists(), "missing mandatory keyAddr");
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	ctx.require(f.params.value_addr().exists(), "missing mandatory valueAddr");
	func_address_map_of_address_map_set(ctx, &f);
	ctx.log("testwasmlib.funcAddressMapOfAddressMapSet ok");
}

pub struct ArrayOfAddressArrayAppendContext {
	events:  TestWasmLibEvents,
	params: ImmutableArrayOfAddressArrayAppendParams,
	state: MutableTestWasmLibState,
}

fn func_array_of_address_array_append_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfAddressArrayAppend");
	let f = ArrayOfAddressArrayAppendContext {
		events:  TestWasmLibEvents {},
		params: ImmutableArrayOfAddressArrayAppendParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	func_array_of_address_array_append(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfAddressArrayAppend ok");
}

pub struct ArrayOfAddressArrayClearContext {
	events:  TestWasmLibEvents,
	state: MutableTestWasmLibState,
}

fn func_array_of_address_array_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfAddressArrayClear");
	let f = ArrayOfAddressArrayClearContext {
		events:  TestWasmLibEvents {},
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_array_of_address_array_clear(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfAddressArrayClear ok");
}

pub struct ArrayOfAddressArraySetContext {
	events:  TestWasmLibEvents,
	params: ImmutableArrayOfAddressArraySetParams,
	state: MutableTestWasmLibState,
}

fn func_array_of_address_array_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfAddressArraySet");
	let f = ArrayOfAddressArraySetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableArrayOfAddressArraySetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index0().exists(), "missing mandatory index0");
	ctx.require(f.params.index1().exists(), "missing mandatory index1");
	ctx.require(f.params.value_addr().exists(), "missing mandatory valueAddr");
	func_array_of_address_array_set(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfAddressArraySet ok");
}

pub struct ArrayOfAddressMapClearContext {
	events:  TestWasmLibEvents,
	state: MutableTestWasmLibState,
}

fn func_array_of_address_map_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfAddressMapClear");
	let f = ArrayOfAddressMapClearContext {
		events:  TestWasmLibEvents {},
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_array_of_address_map_clear(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfAddressMapClear ok");
}

pub struct ArrayOfAddressMapSetContext {
	events:  TestWasmLibEvents,
	params: ImmutableArrayOfAddressMapSetParams,
	state: MutableTestWasmLibState,
}

fn func_array_of_address_map_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfAddressMapSet");
	let f = ArrayOfAddressMapSetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableArrayOfAddressMapSetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.key_addr().exists(), "missing mandatory keyAddr");
	ctx.require(f.params.value_addr().exists(), "missing mandatory valueAddr");
	func_array_of_address_map_set(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfAddressMapSet ok");
}

pub struct ArrayOfStringArrayAppendContext {
	events:  TestWasmLibEvents,
	params: ImmutableArrayOfStringArrayAppendParams,
	state: MutableTestWasmLibState,
}

fn func_array_of_string_array_append_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfStringArrayAppend");
	let f = ArrayOfStringArrayAppendContext {
		events:  TestWasmLibEvents {},
		params: ImmutableArrayOfStringArrayAppendParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	func_array_of_string_array_append(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfStringArrayAppend ok");
}

pub struct ArrayOfStringArrayClearContext {
	events:  TestWasmLibEvents,
	state: MutableTestWasmLibState,
}

fn func_array_of_string_array_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfStringArrayClear");
	let f = ArrayOfStringArrayClearContext {
		events:  TestWasmLibEvents {},
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_array_of_string_array_clear(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfStringArrayClear ok");
}

pub struct ArrayOfStringArraySetContext {
	events:  TestWasmLibEvents,
	params: ImmutableArrayOfStringArraySetParams,
	state: MutableTestWasmLibState,
}

fn func_array_of_string_array_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfStringArraySet");
	let f = ArrayOfStringArraySetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableArrayOfStringArraySetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index0().exists(), "missing mandatory index0");
	ctx.require(f.params.index1().exists(), "missing mandatory index1");
	ctx.require(f.params.value().exists(), "missing mandatory value");
	func_array_of_string_array_set(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfStringArraySet ok");
}

pub struct ArrayOfStringMapClearContext {
	events:  TestWasmLibEvents,
	state: MutableTestWasmLibState,
}

fn func_array_of_string_map_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfStringMapClear");
	let f = ArrayOfStringMapClearContext {
		events:  TestWasmLibEvents {},
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_array_of_string_map_clear(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfStringMapClear ok");
}

pub struct ArrayOfStringMapSetContext {
	events:  TestWasmLibEvents,
	params: ImmutableArrayOfStringMapSetParams,
	state: MutableTestWasmLibState,
}

fn func_array_of_string_map_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcArrayOfStringMapSet");
	let f = ArrayOfStringMapSetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableArrayOfStringMapSetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.key().exists(), "missing mandatory key");
	ctx.require(f.params.value().exists(), "missing mandatory value");
	func_array_of_string_map_set(ctx, &f);
	ctx.log("testwasmlib.funcArrayOfStringMapSet ok");
}

pub struct ParamTypesContext {
	events:  TestWasmLibEvents,
	params: ImmutableParamTypesParams,
	state: MutableTestWasmLibState,
}

fn func_param_types_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcParamTypes");
	let f = ParamTypesContext {
		events:  TestWasmLibEvents {},
		params: ImmutableParamTypesParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_param_types(ctx, &f);
	ctx.log("testwasmlib.funcParamTypes ok");
}

pub struct RandomContext {
	events:  TestWasmLibEvents,
	state: MutableTestWasmLibState,
}

fn func_random_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcRandom");
	let f = RandomContext {
		events:  TestWasmLibEvents {},
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_random(ctx, &f);
	ctx.log("testwasmlib.funcRandom ok");
}

pub struct StringMapOfStringArrayAppendContext {
	events:  TestWasmLibEvents,
	params: ImmutableStringMapOfStringArrayAppendParams,
	state: MutableTestWasmLibState,
}

fn func_string_map_of_string_array_append_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcStringMapOfStringArrayAppend");
	let f = StringMapOfStringArrayAppendContext {
		events:  TestWasmLibEvents {},
		params: ImmutableStringMapOfStringArrayAppendParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name().exists(), "missing mandatory name");
	ctx.require(f.params.value().exists(), "missing mandatory value");
	func_string_map_of_string_array_append(ctx, &f);
	ctx.log("testwasmlib.funcStringMapOfStringArrayAppend ok");
}

pub struct StringMapOfStringArrayClearContext {
	events:  TestWasmLibEvents,
	params: ImmutableStringMapOfStringArrayClearParams,
	state: MutableTestWasmLibState,
}

fn func_string_map_of_string_array_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcStringMapOfStringArrayClear");
	let f = StringMapOfStringArrayClearContext {
		events:  TestWasmLibEvents {},
		params: ImmutableStringMapOfStringArrayClearParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name().exists(), "missing mandatory name");
	func_string_map_of_string_array_clear(ctx, &f);
	ctx.log("testwasmlib.funcStringMapOfStringArrayClear ok");
}

pub struct StringMapOfStringArraySetContext {
	events:  TestWasmLibEvents,
	params: ImmutableStringMapOfStringArraySetParams,
	state: MutableTestWasmLibState,
}

fn func_string_map_of_string_array_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcStringMapOfStringArraySet");
	let f = StringMapOfStringArraySetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableStringMapOfStringArraySetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.name().exists(), "missing mandatory name");
	ctx.require(f.params.value().exists(), "missing mandatory value");
	func_string_map_of_string_array_set(ctx, &f);
	ctx.log("testwasmlib.funcStringMapOfStringArraySet ok");
}

pub struct StringMapOfStringMapClearContext {
	events:  TestWasmLibEvents,
	params: ImmutableStringMapOfStringMapClearParams,
	state: MutableTestWasmLibState,
}

fn func_string_map_of_string_map_clear_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcStringMapOfStringMapClear");
	let f = StringMapOfStringMapClearContext {
		events:  TestWasmLibEvents {},
		params: ImmutableStringMapOfStringMapClearParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name().exists(), "missing mandatory name");
	func_string_map_of_string_map_clear(ctx, &f);
	ctx.log("testwasmlib.funcStringMapOfStringMapClear ok");
}

pub struct StringMapOfStringMapSetContext {
	events:  TestWasmLibEvents,
	params: ImmutableStringMapOfStringMapSetParams,
	state: MutableTestWasmLibState,
}

fn func_string_map_of_string_map_set_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcStringMapOfStringMapSet");
	let f = StringMapOfStringMapSetContext {
		events:  TestWasmLibEvents {},
		params: ImmutableStringMapOfStringMapSetParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.key().exists(), "missing mandatory key");
	ctx.require(f.params.name().exists(), "missing mandatory name");
	ctx.require(f.params.value().exists(), "missing mandatory value");
	func_string_map_of_string_map_set(ctx, &f);
	ctx.log("testwasmlib.funcStringMapOfStringMapSet ok");
}

pub struct TakeAllowanceContext {
	events:  TestWasmLibEvents,
	state: MutableTestWasmLibState,
}

fn func_take_allowance_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcTakeAllowance");
	let f = TakeAllowanceContext {
		events:  TestWasmLibEvents {},
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_take_allowance(ctx, &f);
	ctx.log("testwasmlib.funcTakeAllowance ok");
}

pub struct TakeBalanceContext {
	events:  TestWasmLibEvents,
	results: MutableTakeBalanceResults,
	state: MutableTestWasmLibState,
}

fn func_take_balance_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcTakeBalance");
	let f = TakeBalanceContext {
		events:  TestWasmLibEvents {},
		results: MutableTakeBalanceResults { proxy: results_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	func_take_balance(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.funcTakeBalance ok");
}

pub struct TriggerEventContext {
	events:  TestWasmLibEvents,
	params: ImmutableTriggerEventParams,
	state: MutableTestWasmLibState,
}

fn func_trigger_event_thunk(ctx: &ScFuncContext) {
	ctx.log("testwasmlib.funcTriggerEvent");
	let f = TriggerEventContext {
		events:  TestWasmLibEvents {},
		params: ImmutableTriggerEventParams { proxy: params_proxy() },
		state: MutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.address().exists(), "missing mandatory address");
	ctx.require(f.params.name().exists(), "missing mandatory name");
	func_trigger_event(ctx, &f);
	ctx.log("testwasmlib.funcTriggerEvent ok");
}

pub struct AddressMapOfAddressArrayLengthContext {
	params: ImmutableAddressMapOfAddressArrayLengthParams,
	results: MutableAddressMapOfAddressArrayLengthResults,
	state: ImmutableTestWasmLibState,
}

fn view_address_map_of_address_array_length_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewAddressMapOfAddressArrayLength");
	let f = AddressMapOfAddressArrayLengthContext {
		params: ImmutableAddressMapOfAddressArrayLengthParams { proxy: params_proxy() },
		results: MutableAddressMapOfAddressArrayLengthResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	view_address_map_of_address_array_length(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewAddressMapOfAddressArrayLength ok");
}

pub struct AddressMapOfAddressArrayValueContext {
	params: ImmutableAddressMapOfAddressArrayValueParams,
	results: MutableAddressMapOfAddressArrayValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_address_map_of_address_array_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewAddressMapOfAddressArrayValue");
	let f = AddressMapOfAddressArrayValueContext {
		params: ImmutableAddressMapOfAddressArrayValueParams { proxy: params_proxy() },
		results: MutableAddressMapOfAddressArrayValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	view_address_map_of_address_array_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewAddressMapOfAddressArrayValue ok");
}

pub struct AddressMapOfAddressMapValueContext {
	params: ImmutableAddressMapOfAddressMapValueParams,
	results: MutableAddressMapOfAddressMapValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_address_map_of_address_map_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewAddressMapOfAddressMapValue");
	let f = AddressMapOfAddressMapValueContext {
		params: ImmutableAddressMapOfAddressMapValueParams { proxy: params_proxy() },
		results: MutableAddressMapOfAddressMapValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.key_addr().exists(), "missing mandatory keyAddr");
	ctx.require(f.params.name_addr().exists(), "missing mandatory nameAddr");
	view_address_map_of_address_map_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewAddressMapOfAddressMapValue ok");
}

pub struct ArrayOfAddressArrayLengthContext {
	results: MutableArrayOfAddressArrayLengthResults,
	state: ImmutableTestWasmLibState,
}

fn view_array_of_address_array_length_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewArrayOfAddressArrayLength");
	let f = ArrayOfAddressArrayLengthContext {
		results: MutableArrayOfAddressArrayLengthResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	view_array_of_address_array_length(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewArrayOfAddressArrayLength ok");
}

pub struct ArrayOfAddressArrayValueContext {
	params: ImmutableArrayOfAddressArrayValueParams,
	results: MutableArrayOfAddressArrayValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_array_of_address_array_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewArrayOfAddressArrayValue");
	let f = ArrayOfAddressArrayValueContext {
		params: ImmutableArrayOfAddressArrayValueParams { proxy: params_proxy() },
		results: MutableArrayOfAddressArrayValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index0().exists(), "missing mandatory index0");
	ctx.require(f.params.index1().exists(), "missing mandatory index1");
	view_array_of_address_array_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewArrayOfAddressArrayValue ok");
}

pub struct ArrayOfAddressMapValueContext {
	params: ImmutableArrayOfAddressMapValueParams,
	results: MutableArrayOfAddressMapValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_array_of_address_map_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewArrayOfAddressMapValue");
	let f = ArrayOfAddressMapValueContext {
		params: ImmutableArrayOfAddressMapValueParams { proxy: params_proxy() },
		results: MutableArrayOfAddressMapValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.key_addr().exists(), "missing mandatory keyAddr");
	view_array_of_address_map_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewArrayOfAddressMapValue ok");
}

pub struct ArrayOfStringArrayLengthContext {
	results: MutableArrayOfStringArrayLengthResults,
	state: ImmutableTestWasmLibState,
}

fn view_array_of_string_array_length_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewArrayOfStringArrayLength");
	let f = ArrayOfStringArrayLengthContext {
		results: MutableArrayOfStringArrayLengthResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	view_array_of_string_array_length(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewArrayOfStringArrayLength ok");
}

pub struct ArrayOfStringArrayValueContext {
	params: ImmutableArrayOfStringArrayValueParams,
	results: MutableArrayOfStringArrayValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_array_of_string_array_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewArrayOfStringArrayValue");
	let f = ArrayOfStringArrayValueContext {
		params: ImmutableArrayOfStringArrayValueParams { proxy: params_proxy() },
		results: MutableArrayOfStringArrayValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index0().exists(), "missing mandatory index0");
	ctx.require(f.params.index1().exists(), "missing mandatory index1");
	view_array_of_string_array_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewArrayOfStringArrayValue ok");
}

pub struct ArrayOfStringMapValueContext {
	params: ImmutableArrayOfStringMapValueParams,
	results: MutableArrayOfStringMapValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_array_of_string_map_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewArrayOfStringMapValue");
	let f = ArrayOfStringMapValueContext {
		params: ImmutableArrayOfStringMapValueParams { proxy: params_proxy() },
		results: MutableArrayOfStringMapValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.key().exists(), "missing mandatory key");
	view_array_of_string_map_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewArrayOfStringMapValue ok");
}

pub struct BigIntAddContext {
	params: ImmutableBigIntAddParams,
	results: MutableBigIntAddResults,
	state: ImmutableTestWasmLibState,
}

fn view_big_int_add_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewBigIntAdd");
	let f = BigIntAddContext {
		params: ImmutableBigIntAddParams { proxy: params_proxy() },
		results: MutableBigIntAddResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.lhs().exists(), "missing mandatory lhs");
	ctx.require(f.params.rhs().exists(), "missing mandatory rhs");
	view_big_int_add(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewBigIntAdd ok");
}

pub struct BigIntDivContext {
	params: ImmutableBigIntDivParams,
	results: MutableBigIntDivResults,
	state: ImmutableTestWasmLibState,
}

fn view_big_int_div_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewBigIntDiv");
	let f = BigIntDivContext {
		params: ImmutableBigIntDivParams { proxy: params_proxy() },
		results: MutableBigIntDivResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.lhs().exists(), "missing mandatory lhs");
	ctx.require(f.params.rhs().exists(), "missing mandatory rhs");
	view_big_int_div(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewBigIntDiv ok");
}

pub struct BigIntModContext {
	params: ImmutableBigIntModParams,
	results: MutableBigIntModResults,
	state: ImmutableTestWasmLibState,
}

fn view_big_int_mod_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewBigIntMod");
	let f = BigIntModContext {
		params: ImmutableBigIntModParams { proxy: params_proxy() },
		results: MutableBigIntModResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.lhs().exists(), "missing mandatory lhs");
	ctx.require(f.params.rhs().exists(), "missing mandatory rhs");
	view_big_int_mod(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewBigIntMod ok");
}

pub struct BigIntMulContext {
	params: ImmutableBigIntMulParams,
	results: MutableBigIntMulResults,
	state: ImmutableTestWasmLibState,
}

fn view_big_int_mul_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewBigIntMul");
	let f = BigIntMulContext {
		params: ImmutableBigIntMulParams { proxy: params_proxy() },
		results: MutableBigIntMulResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.lhs().exists(), "missing mandatory lhs");
	ctx.require(f.params.rhs().exists(), "missing mandatory rhs");
	view_big_int_mul(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewBigIntMul ok");
}

pub struct BigIntSubContext {
	params: ImmutableBigIntSubParams,
	results: MutableBigIntSubResults,
	state: ImmutableTestWasmLibState,
}

fn view_big_int_sub_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewBigIntSub");
	let f = BigIntSubContext {
		params: ImmutableBigIntSubParams { proxy: params_proxy() },
		results: MutableBigIntSubResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.lhs().exists(), "missing mandatory lhs");
	ctx.require(f.params.rhs().exists(), "missing mandatory rhs");
	view_big_int_sub(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewBigIntSub ok");
}

pub struct BlockRecordContext {
	params: ImmutableBlockRecordParams,
	results: MutableBlockRecordResults,
	state: ImmutableTestWasmLibState,
}

fn view_block_record_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewBlockRecord");
	let f = BlockRecordContext {
		params: ImmutableBlockRecordParams { proxy: params_proxy() },
		results: MutableBlockRecordResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.block_index().exists(), "missing mandatory blockIndex");
	ctx.require(f.params.record_index().exists(), "missing mandatory recordIndex");
	view_block_record(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewBlockRecord ok");
}

pub struct BlockRecordsContext {
	params: ImmutableBlockRecordsParams,
	results: MutableBlockRecordsResults,
	state: ImmutableTestWasmLibState,
}

fn view_block_records_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewBlockRecords");
	let f = BlockRecordsContext {
		params: ImmutableBlockRecordsParams { proxy: params_proxy() },
		results: MutableBlockRecordsResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.block_index().exists(), "missing mandatory blockIndex");
	view_block_records(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewBlockRecords ok");
}

pub struct GetRandomContext {
	results: MutableGetRandomResults,
	state: ImmutableTestWasmLibState,
}

fn view_get_random_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewGetRandom");
	let f = GetRandomContext {
		results: MutableGetRandomResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	view_get_random(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewGetRandom ok");
}

pub struct IotaBalanceContext {
	results: MutableIotaBalanceResults,
	state: ImmutableTestWasmLibState,
}

fn view_iota_balance_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewIotaBalance");
	let f = IotaBalanceContext {
		results: MutableIotaBalanceResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	view_iota_balance(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewIotaBalance ok");
}

pub struct StringMapOfStringArrayLengthContext {
	params: ImmutableStringMapOfStringArrayLengthParams,
	results: MutableStringMapOfStringArrayLengthResults,
	state: ImmutableTestWasmLibState,
}

fn view_string_map_of_string_array_length_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewStringMapOfStringArrayLength");
	let f = StringMapOfStringArrayLengthContext {
		params: ImmutableStringMapOfStringArrayLengthParams { proxy: params_proxy() },
		results: MutableStringMapOfStringArrayLengthResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.name().exists(), "missing mandatory name");
	view_string_map_of_string_array_length(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewStringMapOfStringArrayLength ok");
}

pub struct StringMapOfStringArrayValueContext {
	params: ImmutableStringMapOfStringArrayValueParams,
	results: MutableStringMapOfStringArrayValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_string_map_of_string_array_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewStringMapOfStringArrayValue");
	let f = StringMapOfStringArrayValueContext {
		params: ImmutableStringMapOfStringArrayValueParams { proxy: params_proxy() },
		results: MutableStringMapOfStringArrayValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.index().exists(), "missing mandatory index");
	ctx.require(f.params.name().exists(), "missing mandatory name");
	view_string_map_of_string_array_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewStringMapOfStringArrayValue ok");
}

pub struct StringMapOfStringMapValueContext {
	params: ImmutableStringMapOfStringMapValueParams,
	results: MutableStringMapOfStringMapValueResults,
	state: ImmutableTestWasmLibState,
}

fn view_string_map_of_string_map_value_thunk(ctx: &ScViewContext) {
	ctx.log("testwasmlib.viewStringMapOfStringMapValue");
	let f = StringMapOfStringMapValueContext {
		params: ImmutableStringMapOfStringMapValueParams { proxy: params_proxy() },
		results: MutableStringMapOfStringMapValueResults { proxy: results_proxy() },
		state: ImmutableTestWasmLibState { proxy: state_proxy() },
	};
	ctx.require(f.params.key().exists(), "missing mandatory key");
	ctx.require(f.params.name().exists(), "missing mandatory name");
	view_string_map_of_string_map_value(ctx, &f);
	ctx.results(&f.results.proxy.kv_store);
	ctx.log("testwasmlib.viewStringMapOfStringMapValue ok");
}
