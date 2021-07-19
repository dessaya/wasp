// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

// @formatter:off

#![allow(dead_code)]

use std::ptr;

use crate::*;
use crate::corecontracts::coreaccounts::*;

pub struct DepositCall {
    pub func:   ScFunc,
    pub params: MutableDepositParams,
}

pub struct WithdrawCall {
    pub func: ScFunc,
}

pub struct AccountsCall {
    pub func:    ScView,
    pub results: ImmutableAccountsResults,
}

pub struct BalanceCall {
    pub func:    ScView,
    pub params:  MutableBalanceParams,
    pub results: ImmutableBalanceResults,
}

pub struct TotalAssetsCall {
    pub func:    ScView,
    pub results: ImmutableTotalAssetsResults,
}

pub struct ScFuncs {
}

impl ScFuncs {
    pub fn deposit(_ctx: & dyn ScFuncCallContext) -> DepositCall {
        let mut f = DepositCall {
            func:   ScFunc::new(HSC_NAME, HFUNC_DEPOSIT),
            params: MutableDepositParams { id: 0 },
        };
        f.func.set_ptrs(&mut f.params.id, ptr::null_mut());
        f
    }
    pub fn withdraw(_ctx: & dyn ScFuncCallContext) -> WithdrawCall {
        WithdrawCall {
            func: ScFunc::new(HSC_NAME, HFUNC_WITHDRAW),
        }
    }
    pub fn accounts(_ctx: & dyn ScViewCallContext) -> AccountsCall {
        let mut f = AccountsCall {
            func:    ScView::new(HSC_NAME, HVIEW_ACCOUNTS),
            results: ImmutableAccountsResults { id: 0 },
        };
        f.func.set_ptrs(ptr::null_mut(), &mut f.results.id);
        f
    }
    pub fn balance(_ctx: & dyn ScViewCallContext) -> BalanceCall {
        let mut f = BalanceCall {
            func:    ScView::new(HSC_NAME, HVIEW_BALANCE),
            params:  MutableBalanceParams { id: 0 },
            results: ImmutableBalanceResults { id: 0 },
        };
        f.func.set_ptrs(&mut f.params.id, &mut f.results.id);
        f
    }
    pub fn total_assets(_ctx: & dyn ScViewCallContext) -> TotalAssetsCall {
        let mut f = TotalAssetsCall {
            func:    ScView::new(HSC_NAME, HVIEW_TOTAL_ASSETS),
            results: ImmutableTotalAssetsResults { id: 0 },
        };
        f.func.set_ptrs(ptr::null_mut(), &mut f.results.id);
        f
    }
}

// @formatter:on
