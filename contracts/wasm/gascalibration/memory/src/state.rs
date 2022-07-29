// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

#![allow(dead_code)]
#![allow(unused_imports)]

use wasmlib::*;

use crate::*;

#[derive(Clone)]
pub struct ImmutablememoryState {
	pub(crate) proxy: Proxy,
}

impl ImmutablememoryState {
    // current owner of this smart contract
    pub fn owner(&self) -> ScImmutableAgentID {
		ScImmutableAgentID::new(self.proxy.root(STATE_OWNER))
	}
}

#[derive(Clone)]
pub struct MutablememoryState {
	pub(crate) proxy: Proxy,
}

impl MutablememoryState {
    pub fn as_immutable(&self) -> ImmutablememoryState {
		ImmutablememoryState { proxy: self.proxy.root("") }
	}

    // current owner of this smart contract
    pub fn owner(&self) -> ScMutableAgentID {
		ScMutableAgentID::new(self.proxy.root(STATE_OWNER))
	}
}