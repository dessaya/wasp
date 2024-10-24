// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

#![allow(dead_code)]
#![allow(unused_imports)]

use wasmlib::*;
use wasmlib::host::*;

use crate::*;
use crate::keys::*;
use crate::typedefs::*;

#[derive(Clone, Copy)]
pub struct ImmutableArrayClearParams {
    pub(crate) id: i32,
}

impl ImmutableArrayClearParams {
    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableArrayClearParams {
    pub(crate) id: i32,
}

impl MutableArrayClearParams {
    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableArrayCreateParams {
    pub(crate) id: i32,
}

impl ImmutableArrayCreateParams {
    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableArrayCreateParams {
    pub(crate) id: i32,
}

impl MutableArrayCreateParams {
    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableArraySetParams {
    pub(crate) id: i32,
}

impl ImmutableArraySetParams {
    pub fn index(&self) -> ScImmutableInt32 {
		ScImmutableInt32::new(self.id, PARAM_INDEX.get_key_id())
	}

    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}

    pub fn value(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_VALUE.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableArraySetParams {
    pub(crate) id: i32,
}

impl MutableArraySetParams {
    pub fn index(&self) -> ScMutableInt32 {
		ScMutableInt32::new(self.id, PARAM_INDEX.get_key_id())
	}

    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}

    pub fn value(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_VALUE.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableMapClearParams {
    pub(crate) id: i32,
}

impl ImmutableMapClearParams {
    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableMapClearParams {
    pub(crate) id: i32,
}

impl MutableMapClearParams {
    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableMapCreateParams {
    pub(crate) id: i32,
}

impl ImmutableMapCreateParams {
    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableMapCreateParams {
    pub(crate) id: i32,
}

impl MutableMapCreateParams {
    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableMapSetParams {
    pub(crate) id: i32,
}

impl ImmutableMapSetParams {
    pub fn key(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_KEY.get_key_id())
	}

    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}

    pub fn value(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_VALUE.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableMapSetParams {
    pub(crate) id: i32,
}

impl MutableMapSetParams {
    pub fn key(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_KEY.get_key_id())
	}

    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}

    pub fn value(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_VALUE.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MapStringToImmutableBytes {
	pub(crate) obj_id: i32,
}

impl MapStringToImmutableBytes {
    pub fn get_bytes(&self, key: &str) -> ScImmutableBytes {
        ScImmutableBytes::new(self.obj_id, key.get_key_id())
    }
}

#[derive(Clone, Copy)]
pub struct ImmutableParamTypesParams {
    pub(crate) id: i32,
}

impl ImmutableParamTypesParams {
    pub fn address(&self) -> ScImmutableAddress {
		ScImmutableAddress::new(self.id, PARAM_ADDRESS.get_key_id())
	}

    pub fn agent_id(&self) -> ScImmutableAgentID {
		ScImmutableAgentID::new(self.id, PARAM_AGENT_ID.get_key_id())
	}

    pub fn bool(&self) -> ScImmutableBool {
		ScImmutableBool::new(self.id, PARAM_BOOL.get_key_id())
	}

    pub fn bytes(&self) -> ScImmutableBytes {
		ScImmutableBytes::new(self.id, PARAM_BYTES.get_key_id())
	}

    pub fn chain_id(&self) -> ScImmutableChainID {
		ScImmutableChainID::new(self.id, PARAM_CHAIN_ID.get_key_id())
	}

    pub fn color(&self) -> ScImmutableColor {
		ScImmutableColor::new(self.id, PARAM_COLOR.get_key_id())
	}

    pub fn hash(&self) -> ScImmutableHash {
		ScImmutableHash::new(self.id, PARAM_HASH.get_key_id())
	}

    pub fn hname(&self) -> ScImmutableHname {
		ScImmutableHname::new(self.id, PARAM_HNAME.get_key_id())
	}

    pub fn int16(&self) -> ScImmutableInt16 {
		ScImmutableInt16::new(self.id, PARAM_INT16.get_key_id())
	}

    pub fn int32(&self) -> ScImmutableInt32 {
		ScImmutableInt32::new(self.id, PARAM_INT32.get_key_id())
	}

    pub fn int64(&self) -> ScImmutableInt64 {
		ScImmutableInt64::new(self.id, PARAM_INT64.get_key_id())
	}

    pub fn int8(&self) -> ScImmutableInt8 {
		ScImmutableInt8::new(self.id, PARAM_INT8.get_key_id())
	}

    pub fn param(&self) -> MapStringToImmutableBytes {
		MapStringToImmutableBytes { obj_id: self.id }
	}

    pub fn request_id(&self) -> ScImmutableRequestID {
		ScImmutableRequestID::new(self.id, PARAM_REQUEST_ID.get_key_id())
	}

    pub fn string(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_STRING.get_key_id())
	}

    pub fn uint16(&self) -> ScImmutableUint16 {
		ScImmutableUint16::new(self.id, PARAM_UINT16.get_key_id())
	}

    pub fn uint32(&self) -> ScImmutableUint32 {
		ScImmutableUint32::new(self.id, PARAM_UINT32.get_key_id())
	}

    pub fn uint64(&self) -> ScImmutableUint64 {
		ScImmutableUint64::new(self.id, PARAM_UINT64.get_key_id())
	}

    pub fn uint8(&self) -> ScImmutableUint8 {
		ScImmutableUint8::new(self.id, PARAM_UINT8.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MapStringToMutableBytes {
	pub(crate) obj_id: i32,
}

impl MapStringToMutableBytes {
    pub fn clear(&self) {
        clear(self.obj_id);
    }

    pub fn get_bytes(&self, key: &str) -> ScMutableBytes {
        ScMutableBytes::new(self.obj_id, key.get_key_id())
    }
}

#[derive(Clone, Copy)]
pub struct MutableParamTypesParams {
    pub(crate) id: i32,
}

impl MutableParamTypesParams {
    pub fn address(&self) -> ScMutableAddress {
		ScMutableAddress::new(self.id, PARAM_ADDRESS.get_key_id())
	}

    pub fn agent_id(&self) -> ScMutableAgentID {
		ScMutableAgentID::new(self.id, PARAM_AGENT_ID.get_key_id())
	}

    pub fn bool(&self) -> ScMutableBool {
		ScMutableBool::new(self.id, PARAM_BOOL.get_key_id())
	}

    pub fn bytes(&self) -> ScMutableBytes {
		ScMutableBytes::new(self.id, PARAM_BYTES.get_key_id())
	}

    pub fn chain_id(&self) -> ScMutableChainID {
		ScMutableChainID::new(self.id, PARAM_CHAIN_ID.get_key_id())
	}

    pub fn color(&self) -> ScMutableColor {
		ScMutableColor::new(self.id, PARAM_COLOR.get_key_id())
	}

    pub fn hash(&self) -> ScMutableHash {
		ScMutableHash::new(self.id, PARAM_HASH.get_key_id())
	}

    pub fn hname(&self) -> ScMutableHname {
		ScMutableHname::new(self.id, PARAM_HNAME.get_key_id())
	}

    pub fn int16(&self) -> ScMutableInt16 {
		ScMutableInt16::new(self.id, PARAM_INT16.get_key_id())
	}

    pub fn int32(&self) -> ScMutableInt32 {
		ScMutableInt32::new(self.id, PARAM_INT32.get_key_id())
	}

    pub fn int64(&self) -> ScMutableInt64 {
		ScMutableInt64::new(self.id, PARAM_INT64.get_key_id())
	}

    pub fn int8(&self) -> ScMutableInt8 {
		ScMutableInt8::new(self.id, PARAM_INT8.get_key_id())
	}

    pub fn param(&self) -> MapStringToMutableBytes {
		MapStringToMutableBytes { obj_id: self.id }
	}

    pub fn request_id(&self) -> ScMutableRequestID {
		ScMutableRequestID::new(self.id, PARAM_REQUEST_ID.get_key_id())
	}

    pub fn string(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_STRING.get_key_id())
	}

    pub fn uint16(&self) -> ScMutableUint16 {
		ScMutableUint16::new(self.id, PARAM_UINT16.get_key_id())
	}

    pub fn uint32(&self) -> ScMutableUint32 {
		ScMutableUint32::new(self.id, PARAM_UINT32.get_key_id())
	}

    pub fn uint64(&self) -> ScMutableUint64 {
		ScMutableUint64::new(self.id, PARAM_UINT64.get_key_id())
	}

    pub fn uint8(&self) -> ScMutableUint8 {
		ScMutableUint8::new(self.id, PARAM_UINT8.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableTriggerEventParams {
    pub(crate) id: i32,
}

impl ImmutableTriggerEventParams {
    pub fn address(&self) -> ScImmutableAddress {
		ScImmutableAddress::new(self.id, PARAM_ADDRESS.get_key_id())
	}

    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableTriggerEventParams {
    pub(crate) id: i32,
}

impl MutableTriggerEventParams {
    pub fn address(&self) -> ScMutableAddress {
		ScMutableAddress::new(self.id, PARAM_ADDRESS.get_key_id())
	}

    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableArrayLengthParams {
    pub(crate) id: i32,
}

impl ImmutableArrayLengthParams {
    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableArrayLengthParams {
    pub(crate) id: i32,
}

impl MutableArrayLengthParams {
    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableArrayValueParams {
    pub(crate) id: i32,
}

impl ImmutableArrayValueParams {
    pub fn index(&self) -> ScImmutableInt32 {
		ScImmutableInt32::new(self.id, PARAM_INDEX.get_key_id())
	}

    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableArrayValueParams {
    pub(crate) id: i32,
}

impl MutableArrayValueParams {
    pub fn index(&self) -> ScMutableInt32 {
		ScMutableInt32::new(self.id, PARAM_INDEX.get_key_id())
	}

    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableBlockRecordParams {
    pub(crate) id: i32,
}

impl ImmutableBlockRecordParams {
    pub fn block_index(&self) -> ScImmutableInt32 {
		ScImmutableInt32::new(self.id, PARAM_BLOCK_INDEX.get_key_id())
	}

    pub fn record_index(&self) -> ScImmutableInt32 {
		ScImmutableInt32::new(self.id, PARAM_RECORD_INDEX.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableBlockRecordParams {
    pub(crate) id: i32,
}

impl MutableBlockRecordParams {
    pub fn block_index(&self) -> ScMutableInt32 {
		ScMutableInt32::new(self.id, PARAM_BLOCK_INDEX.get_key_id())
	}

    pub fn record_index(&self) -> ScMutableInt32 {
		ScMutableInt32::new(self.id, PARAM_RECORD_INDEX.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableBlockRecordsParams {
    pub(crate) id: i32,
}

impl ImmutableBlockRecordsParams {
    pub fn block_index(&self) -> ScImmutableInt32 {
		ScImmutableInt32::new(self.id, PARAM_BLOCK_INDEX.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableBlockRecordsParams {
    pub(crate) id: i32,
}

impl MutableBlockRecordsParams {
    pub fn block_index(&self) -> ScMutableInt32 {
		ScMutableInt32::new(self.id, PARAM_BLOCK_INDEX.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct ImmutableMapValueParams {
    pub(crate) id: i32,
}

impl ImmutableMapValueParams {
    pub fn key(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_KEY.get_key_id())
	}

    pub fn name(&self) -> ScImmutableString {
		ScImmutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}

#[derive(Clone, Copy)]
pub struct MutableMapValueParams {
    pub(crate) id: i32,
}

impl MutableMapValueParams {
    pub fn key(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_KEY.get_key_id())
	}

    pub fn name(&self) -> ScMutableString {
		ScMutableString::new(self.id, PARAM_NAME.get_key_id())
	}
}
