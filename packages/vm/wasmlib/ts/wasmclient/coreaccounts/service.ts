// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// (Re-)generated by schema tool
// >>>> DO NOT CHANGE THIS FILE! <<<<
// Change the json schema instead

import * as wasmclient from "wasmclient"

const ArgAgentID = "a";
const ArgWithdrawAmount = "m";
const ArgWithdrawColor = "c";

const ResAccountNonce = "n";
const ResAgents = "this";
const ResBalances = "this";

///////////////////////////// deposit /////////////////////////////

export class DepositFunc extends wasmclient.ClientFunc {
	private args: wasmclient.Arguments = new wasmclient.Arguments();
	
	public agentID(v: wasmclient.AgentID): void {
		this.args.set(ArgAgentID, this.args.fromAgentID(v));
	}
	
	public async post(): Promise<wasmclient.RequestID> {
		return await super.post(0xbdc9102d, this.args);
	}
}

///////////////////////////// harvest /////////////////////////////

export class HarvestFunc extends wasmclient.ClientFunc {
	private args: wasmclient.Arguments = new wasmclient.Arguments();
	
	public withdrawAmount(v: wasmclient.Int64): void {
		this.args.set(ArgWithdrawAmount, this.args.fromInt64(v));
	}
	
	public withdrawColor(v: wasmclient.Color): void {
		this.args.set(ArgWithdrawColor, this.args.fromColor(v));
	}
	
	public async post(): Promise<wasmclient.RequestID> {
		return await super.post(0x7b40efbd, this.args);
	}
}

///////////////////////////// withdraw /////////////////////////////

export class WithdrawFunc extends wasmclient.ClientFunc {
	
	public async post(): Promise<wasmclient.RequestID> {
		return await super.post(0x9dcc0f41, null);
	}
}

///////////////////////////// accounts /////////////////////////////

export class AccountsView extends wasmclient.ClientView {

	public async call(): Promise<AccountsResults> {
		const res = new AccountsResults();
		await this.callView("accounts", null, res);
		return res;
	}
}

export class AccountsResults extends wasmclient.Results {

	agents(): Map<wasmclient.AgentID, wasmclient.Bytes> {
		const res = new Map<wasmclient.AgentID, wasmclient.Bytes>();
		this.forEach((key, val) => {
			res.set(this.toAgentID(key), this.toBytes(val));
		});
		return res;
	}
}

///////////////////////////// balance /////////////////////////////

export class BalanceView extends wasmclient.ClientView {
	private args: wasmclient.Arguments = new wasmclient.Arguments();
	
	public agentID(v: wasmclient.AgentID): void {
		this.args.set(ArgAgentID, this.args.fromAgentID(v));
	}

	public async call(): Promise<BalanceResults> {
		this.args.mandatory(ArgAgentID);
		const res = new BalanceResults();
		await this.callView("balance", this.args, res);
		return res;
	}
}

export class BalanceResults extends wasmclient.Results {

	balances(): Map<wasmclient.Color, wasmclient.Int64> {
		const res = new Map<wasmclient.Color, wasmclient.Int64>();
		this.forEach((key, val) => {
			res.set(this.toColor(key), this.toInt64(val));
		});
		return res;
	}
}

///////////////////////////// getAccountNonce /////////////////////////////

export class GetAccountNonceView extends wasmclient.ClientView {
	private args: wasmclient.Arguments = new wasmclient.Arguments();
	
	public agentID(v: wasmclient.AgentID): void {
		this.args.set(ArgAgentID, this.args.fromAgentID(v));
	}

	public async call(): Promise<GetAccountNonceResults> {
		this.args.mandatory(ArgAgentID);
		const res = new GetAccountNonceResults();
		await this.callView("getAccountNonce", this.args, res);
		return res;
	}
}

export class GetAccountNonceResults extends wasmclient.Results {

	accountNonce(): wasmclient.Int64 {
		return this.toInt64(this.get(ResAccountNonce));
	}
}

///////////////////////////// totalAssets /////////////////////////////

export class TotalAssetsView extends wasmclient.ClientView {

	public async call(): Promise<TotalAssetsResults> {
		const res = new TotalAssetsResults();
		await this.callView("totalAssets", null, res);
		return res;
	}
}

export class TotalAssetsResults extends wasmclient.Results {

	balances(): Map<wasmclient.Color, wasmclient.Int64> {
		const res = new Map<wasmclient.Color, wasmclient.Int64>();
		this.forEach((key, val) => {
			res.set(this.toColor(key), this.toInt64(val));
		});
		return res;
	}
}

///////////////////////////// CoreAccountsService /////////////////////////////

export class CoreAccountsService extends wasmclient.Service {

	public constructor(cl: wasmclient.ServiceClient) {
		super(cl, 0x3c4b5e02, new Map());
	}

	public deposit(): DepositFunc {
		return new DepositFunc(this);
	}

	public harvest(): HarvestFunc {
		return new HarvestFunc(this);
	}

	public withdraw(): WithdrawFunc {
		return new WithdrawFunc(this);
	}

	public accounts(): AccountsView {
		return new AccountsView(this);
	}

	public balance(): BalanceView {
		return new BalanceView(this);
	}

	public getAccountNonce(): GetAccountNonceView {
		return new GetAccountNonceView(this);
	}

	public totalAssets(): TotalAssetsView {
		return new TotalAssetsView(this);
	}
}
