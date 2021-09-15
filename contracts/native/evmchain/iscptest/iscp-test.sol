// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.8.5;

import "@iscpcontract/iscp.sol";

ISCP constant iscp = ISCP(ISCP_CONTRACT_ADDRESS);

contract ISCPTest {
    function getChainId() public view returns (ISCPAddress memory) {
		ISCPAddress memory r = iscp.getChainId();
		return r;
    }

	function sayHi() public {
		iscp.sayHi();
	}
}
