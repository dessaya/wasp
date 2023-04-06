// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"

	"github.com/iotaledger/wasp/clients/chainclient"
	"github.com/iotaledger/wasp/packages/evm/evmtest"
	"github.com/iotaledger/wasp/packages/evm/jsonrpc/jsonrpctest"
	"github.com/iotaledger/wasp/packages/isc"
	"github.com/iotaledger/wasp/packages/kv"
	"github.com/iotaledger/wasp/packages/kv/codec"
	"github.com/iotaledger/wasp/packages/vm/core/accounts"
	"github.com/iotaledger/wasp/packages/vm/core/evm"
)

type clusterTestEnv struct {
	jsonrpctest.Env
	ChainEnv
	DialWebsocket func() *ethclient.Client
}

func newClusterTestEnv(t *testing.T, env *ChainEnv, nodeIndex int) *clusterTestEnv {
	evmtest.InitGoEthLogger(t)

	jsonRPCEndpoint := func(path string) string {
		return env.Clu.Config.APIHost(nodeIndex) + path
	}
	wsRPCEndpoint := func(path string) string {
		return strings.Replace(env.Clu.Config.APIHost(nodeIndex), "http", "ws", 1) + path
	}

	evmJSONRPCPath := fmt.Sprintf("/v1/chains/%v/evm", env.Chain.ChainID.String())
	rawClient, err := rpc.DialHTTP(jsonRPCEndpoint(evmJSONRPCPath))
	t.Cleanup(rawClient.Close)
	require.NoError(t, err)
	client := ethclient.NewClient(rawClient)
	t.Cleanup(client.Close)

	dialWs := func() *ethclient.Client {
		wsPath := fmt.Sprintf("/v1/chains/%v/evm/ws", env.Chain.ChainID.String())
		wsClient, err := rpc.DialWebsocket(context.Background(), wsRPCEndpoint(wsPath), "")
		require.NoError(t, err)
		t.Cleanup(wsClient.Close)
		client := ethclient.NewClient(wsClient)
		t.Cleanup(client.Close)
		return client
	}

	waitTxConfirmed := func(txHash common.Hash) error {
		c := env.Chain.Client(nil, nodeIndex)
		reqID, err := c.RequestIDByEVMTransactionHash(context.Background(), txHash)
		if err != nil {
			return err
		}
		receipt, _, err := c.WaspClient.RequestsApi.
			WaitForRequest(context.Background(), env.Chain.ChainID.String(), reqID.String()).
			TimeoutSeconds(60).
			Execute()
		if err != nil {
			return err
		}

		if receipt.Error != nil {
			return errors.New(receipt.Error.Message)
		}

		return nil
	}

	e := &clusterTestEnv{
		Env: jsonrpctest.Env{
			T:               t,
			Client:          client,
			RawClient:       rawClient,
			ChainID:         evm.DefaultChainID,
			WaitTxConfirmed: waitTxConfirmed,
		},
		ChainEnv:      *env,
		DialWebsocket: dialWs,
	}
	e.Env.NewAccountWithL2Funds = e.newEthereumAccountWithL2Funds
	return e
}

func newEthereumAccount() (*ecdsa.PrivateKey, common.Address) {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey)
}

const transferAllowanceToGasBudgetBaseTokens = 1 * isc.Million

func (e *clusterTestEnv) newEthereumAccountWithL2Funds(baseTokens ...uint64) (*ecdsa.PrivateKey, common.Address) {
	ethKey, ethAddr := newEthereumAccount()
	walletKey, walletAddr, err := e.Clu.NewKeyPairWithFunds()
	require.NoError(e.T, err)

	var amount uint64
	if len(baseTokens) > 0 {
		amount = baseTokens[0]
	} else {
		amount = e.Clu.L1BaseTokens(walletAddr) - transferAllowanceToGasBudgetBaseTokens
	}
	tx, err := e.Chain.Client(walletKey).Post1Request(accounts.Contract.Hname(), accounts.FuncTransferAllowanceTo.Hname(), chainclient.PostRequestParams{
		Transfer: isc.NewAssets(amount+transferAllowanceToGasBudgetBaseTokens, nil),
		Args: map[kv.Key][]byte{
			accounts.ParamAgentID: codec.EncodeAgentID(isc.NewEthereumAddressAgentID(ethAddr)),
		},
		Allowance: isc.NewAssetsBaseTokens(amount),
	})
	require.NoError(e.T, err)

	// We have to wait not only for the committee to process the request, but also for access nodes to get that info.
	_, err = e.Chain.AllNodesMultiClient().WaitUntilAllRequestsProcessedSuccessfully(e.Chain.ChainID, tx, 30*time.Second)
	require.NoError(e.T, err)

	return ethKey, ethAddr
}

// executed in cluster_test.go
func testEVMJsonRPCCluster(t *testing.T, env *ChainEnv) {
	e := newClusterTestEnv(t, env, 0)
	e.TestRPCGetLogs()
	e.TestRPCInvalidNonce()
	e.TestRPCGasLimitTooLow()
	e.TestRPCAccessHistoricalState()
	e.TestGasPrice()
}

func TestEVMJsonRPCClusterAccessNode(t *testing.T) {
	clu := newCluster(t, waspClusterOpts{nNodes: 5})
	chain, err := clu.DeployChainWithDKG(clu.Config.AllNodes(), []int{0, 1, 2, 3}, uint16(3))
	require.NoError(t, err)
	env := newChainEnv(t, clu, chain)
	e := newClusterTestEnv(t, env, 4) // node #4 is an access node
	e.TestRPCGetLogs()
}

func TestEVMJsonRPCSpam(t *testing.T) {
	run := createTestWrapper(t, 4, []int{0, 1, 2, 3})
	run(t, func(t *testing.T, chenv *ChainEnv) {
		e := newClusterTestEnv(t, chenv, 0)

		walletKey, walletAddr, err := e.Clu.NewKeyPairWithFunds()
		require.NoError(t, err)

		totalL2 := e.Clu.L1BaseTokens(walletAddr) / 2
		const nAccounts = 10
		l2PerEthAccount := totalL2 / (uint64(nAccounts) * 2)

		{
			tx, err := e.Chain.Client(walletKey).DepositFunds(totalL2)
			_, err = e.Chain.AllNodesMultiClient().WaitUntilAllRequestsProcessedSuccessfully(e.Chain.ChainID, tx, 30*time.Second)
			require.NoError(t, err)
		}

		var ethKeys []*ecdsa.PrivateKey
		var ethAddrs []common.Address
		{
			for i := 0; i < nAccounts; i++ {
				ethKey, ethAddr := newEthereumAccount()
				req, err := e.Chain.Client(walletKey).PostOffLedgerRequest(context.Background(), accounts.Contract.Hname(), accounts.FuncTransferAllowanceTo.Hname(), chainclient.PostRequestParams{
					Args: map[kv.Key][]byte{
						accounts.ParamAgentID: codec.EncodeAgentID(isc.NewEthereumAddressAgentID(ethAddr)),
					},
					Allowance: isc.NewAssetsBaseTokens(l2PerEthAccount),
				})
				require.NoError(t, err)
				_, err = e.Chain.AllNodesMultiClient().WaitUntilRequestProcessedSuccessfully(e.Chain.ChainID, req.ID(), 30*time.Second)
				require.NoError(t, err)
				ethKeys = append(ethKeys, ethKey)
				ethAddrs = append(ethAddrs, ethAddr)
			}
		}

		done := make(chan bool)
		wsdone := make(chan bool)

		type wsblock struct {
			header *types.Header
			ts     time.Time
		}

		var wsblocks []wsblock
		go func() {
			defer close(wsdone)
			ch := make(chan *types.Header, 10)

			sub, err := e.DialWebsocket().SubscribeNewHead(context.Background(), ch)
			require.NoError(t, err)
			defer sub.Unsubscribe()

			for {
				select {
				case header := <-ch:
					wsblocks = append(wsblocks, wsblock{
						header: header,
						ts:     time.Now(),
					})

				case err := <-sub.Err():
					require.NoError(t, err)

				case <-done:
					return
				}
			}
		}()

		t.Log("=========== starting the spam ==============")

		endTime := time.Now().Add(60 * time.Second)

		{
			var wg sync.WaitGroup
			wg.Add(nAccounts)
			for i := 0; i < nAccounts; i++ {
				go func(i int, ethKey *ecdsa.PrivateKey, ethAddr common.Address) {
					defer wg.Done()
					nonce := e.NonceAt(ethAddr)
					for time.Now().Before(endTime) {
						toAddress := common.Address{}
						gasLimit := uint64(100_000)
						value := big.NewInt(100)
						tx, err := types.SignTx(
							types.NewTransaction(nonce, toAddress, value, gasLimit, evm.GasPrice, nil),
							e.Signer(),
							ethKey,
						)
						require.NoError(t, err)
						err = e.Client.SendTransaction(context.Background(), tx)
						require.NoError(t, err)
						err = e.WaitTxConfirmed(tx.Hash())
						require.NoError(t, err)
						nonce++
					}
				}(i, ethKeys[i], ethAddrs[i])
			}
			wg.Wait()
		}

		close(done)
		<-wsdone

		type blockdata struct {
			Index              uint64
			Received           string
			BlockinfoTimestamp string
			TotalReqs          uint32
		}
		var blocks []blockdata
		var outOfOrder []uint64
		for i, b := range wsblocks {
			index := b.header.Number.Uint64()
			if i > 0 && index != wsblocks[i-1].header.Number.Uint64()+1 {
				outOfOrder = append(outOfOrder, index)
			}

			block, _, err := e.Clu.
				WaspClient().CorecontractsApi.BlocklogGetBlockInfo(context.Background(), e.Chain.ChainID.String(), uint32(index)).
				Execute() //nolint:bodyclose // false positive
			require.NoError(t, err)

			blocks = append(blocks, blockdata{
				Index:              index,
				Received:           b.ts.Format("15:04:05.00"),
				BlockinfoTimestamp: block.Timestamp.Format("15:04:05.00"),
				TotalReqs:          block.TotalRequests,
			})
		}
		t.Logf("total %d blocks", len(blocks))
		j, _ := json.Marshal(blocks)
		t.Logf("blocks: %s", j)
		require.Empty(t, outOfOrder)
	})
}
