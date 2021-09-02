// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package iscpcontract

import (
	_ "embed"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/iotaledger/goshimmer/packages/ledgerstate"
	"github.com/iotaledger/wasp/packages/iscp"
)

var (
	// EVMAddress is the arbitrary address on which the standard
	// ISCP EVM contract lives
	EVMAddress = common.HexToAddress("0x1074")
	//go:embed ISCP.abi
	ABI string
	//go:embed ISCP.bin-runtime
	bytecodeHex string

	evmYulAddress = common.HexToAddress("0x1075")
	//go:embed ISCPYul.bin-runtime
	yulBytecodeHex string
)

// ISCPAddress maps to the equally-named struct in iscp.sol
type ISCPAddress struct {
	TypeID [1]byte
	Digest [32]byte
}

func ChainIDToISCPAddress(chainID *iscp.ChainID) (ret ISCPAddress) {
	ret.TypeID[0] = byte(chainID.AliasAddress.Type())
	copy(ret.Digest[:], chainID.AliasAddress.Digest())
	return ret
}

func ChainIDFromISCPAddress(a ISCPAddress) *iscp.ChainID {
	if a.TypeID[0] != byte(ledgerstate.AliasAddressType) {
		panic(fmt.Sprintf("expected type id %d, got %d", ledgerstate.AliasAddressType, a.TypeID[0]))
	}
	var addressBytes []byte
	addressBytes = append(addressBytes, a.TypeID[0])
	addressBytes = append(addressBytes, a.Digest[:]...)
	chainID, err := iscp.ChainIDFromBytes(addressBytes)
	if err != nil {
		// should not happen
		panic(err.Error())
	}
	return chainID
}

// DeployOnGenesis sets up the initial state of the ISCP EVM contract
// which will go into the EVM genesis block
func DeployOnGenesis(genesisAlloc core.GenesisAlloc, chainID *iscp.ChainID) {
	chainIDAsISCPAddress := ChainIDToISCPAddress(chainID)
	var typeIDHash common.Hash
	typeIDHash[31] = chainIDAsISCPAddress.TypeID[0]
	var digestHash common.Hash
	copy(digestHash[:], chainIDAsISCPAddress.Digest[:])

	genesisAlloc[EVMAddress] = core.GenesisAccount{
		Code: common.FromHex(strings.TrimSpace(bytecodeHex)),
		Storage: map[common.Hash]common.Hash{
			// offset 0 / slot 0: chainID.typeId
			common.HexToHash("00"): typeIDHash,
			// offset 0 / slot 1: chainID.digest
			common.HexToHash("01"): digestHash,
		},
		Balance: &big.Int{},
	}

	genesisAlloc[evmYulAddress] = core.GenesisAccount{
		Code:    common.FromHex(strings.TrimSpace(yulBytecodeHex)),
		Balance: &big.Int{},
	}
}
