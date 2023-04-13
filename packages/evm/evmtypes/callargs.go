// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package evmtypes

import (
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/iotaledger/wasp/packages/wbf"
)

type callMsgWbf struct {
	From  common.Address
	To    *common.Address `wbf:"optional"`
	Gas   uint64
	Value *wbf.BigInt `wbf:"optional"`
	Data  []byte      `wbf:"u32size"`
}

func EncodeCallMsg(c ethereum.CallMsg) []byte {
	return wbf.MustMarshal(&callMsgWbf{
		From:  c.From,
		To:    c.To,
		Gas:   c.Gas,
		Value: (*wbf.BigInt)(c.Value),
		Data:  c.Data,
	})
}

func DecodeCallMsg(callArgsBytes []byte) (ret ethereum.CallMsg, err error) {
	var w callMsgWbf
	err = wbf.Unmarshal(&w, callArgsBytes)
	if err != nil {
		return ret, err
	}
	ret.From = w.From
	ret.To = w.To
	ret.Gas = w.Gas
	ret.Value = (*big.Int)(w.Value)
	ret.Data = w.Data
	return ret, nil
}
