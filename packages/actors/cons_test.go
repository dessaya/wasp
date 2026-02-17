package actors_test

import (
	"fmt"
	"log/slog"
	"math/rand"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/iotaledger/bcs-go"
	hivelog "github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotago"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotago/iotatest"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotajsonrpc"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotasigner"
	"github.com/iotaledger/wasp/v2/clients/iscmove"
	"github.com/iotaledger/wasp/v2/packages/actors"
	"github.com/iotaledger/wasp/v2/packages/actors/actorstest"
	"github.com/iotaledger/wasp/v2/packages/coin"
	"github.com/iotaledger/wasp/v2/packages/cryptolib"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/isc/isctest"
	"github.com/iotaledger/wasp/v2/packages/kvstore/mapdb"
	"github.com/iotaledger/wasp/v2/packages/origin"
	"github.com/iotaledger/wasp/v2/packages/parameters/parameterstest"
	"github.com/iotaledger/wasp/v2/packages/state"
	"github.com/iotaledger/wasp/v2/packages/state/indexedstore"
	"github.com/iotaledger/wasp/v2/packages/state/statetest"
	"github.com/iotaledger/wasp/v2/packages/testutil/testpeers"
	"github.com/iotaledger/wasp/v2/packages/transaction"
	"github.com/iotaledger/wasp/v2/packages/vm/core/accounts"
	"github.com/iotaledger/wasp/v2/packages/vm/core/coreprocessors"
	"github.com/iotaledger/wasp/v2/packages/vm/core/migrations/allmigrations"
	"github.com/iotaledger/wasp/v2/packages/vm/vmimpl"
)

func TestConsBasic(t *testing.T) {
	type test struct {
		n int
		f int
	}
	tests := []test{
		{n: 1, f: 0},  // Low N.
		{n: 2, f: 0},  // Low N.
		{n: 3, f: 0},  // Low N.
		{n: 4, f: 1},  // Smallest reasonable config.
		{n: 10, f: 3}, // Typical config?
		{n: 12, f: 3}, // Non-optimal N/F.
	}
	if !testing.Short() {
		tests = append(tests, test{n: 31, f: 10}) // Large cluster.
	}
	for _, test := range tests {
		t.Run(
			fmt.Sprintf("N=%v,F=%v", test.n, test.f),
			func(tt *testing.T) { testConsBasic(tt, test.n, test.f) },
		)
	}
}

func testConsBasic(t *testing.T, n int, f int) {
	_, peerIdentities := testpeers.SetupKeys(uint16(n))
	nodePKs := testpeers.PublicKeys(peerIdentities)
	committeeAddress, dkShareProviders := testpeers.SetupDistributedKeyGenerationTrivial(t, n, f, peerIdentities, nil)

	initParams := origin.DefaultInitParams(isc.NewAddressAgentID(committeeAddress)).Encode()
	db := mapdb.NewMapDB()
	store := indexedstore.New(statetest.NewStoreWithUniqueWriteMutex(db))
	_, stateMetadata := origin.InitChain(allmigrations.LatestSchemaVersion, store, initParams, iotago.ObjectID{}, 0, parameterstest.L1Mock)

	stateAnchor0x := isctest.RandomStateAnchor(isctest.RandomAnchorOption{StateMetadata: stateMetadata})
	stateAnchor0 := &stateAnchor0x
	chainID := isc.ChainIDFromObjectID(*stateAnchor0.GetObjectID())

	reqs := []isc.Request{
		RandomOnLedgerDepositRequest(stateAnchor0.Owner()),
		RandomOnLedgerDepositRequest(stateAnchor0.Owner()),
		RandomOnLedgerDepositRequest(stateAnchor0.Owner()),
	}
	reqRefs := isc.RequestRefsFromRequests(reqs)
	gasCoin := coin.CoinWithRef{
		Type:  coin.BaseTokenType,
		Value: coin.Value(100),
		Ref:   iotatest.RandomObjectRef(),
	}

	consInstID := []byte{1, 2, 3} // ID of the consensus.
	chainStates := map[actors.NodeID]state.Store{}
	procConfig := coreprocessors.NewConfig()

	nodeIDs := lo.Map(nodePKs, func(pk *cryptolib.PublicKey, _ int) actors.NodeID {
		return actors.NodeIDFromPublicKey(pk)
	})

	ctx, stop, nodeIDs, routers := actorstest.MakeRoutersWithNodeIDs(t, nodeIDs, true)
	defer stop()

	const path = "cons"
	nodes := map[actors.NodeID]*actors.Consensus{}
	for i, nid := range nodeIDs {
		endpoint := routers[nid].GetEndpoint(path)
		nodeSK := peerIdentities[i].GetPrivateKey()
		nodeDKShare := lo.Must(dkShareProviders[i].LoadDKShare(committeeAddress))
		chainStates[nid] = statetest.NewStoreWithUniqueWriteMutex(mapdb.NewMapDB())
		_ = lo.Must(origin.InitChainByStateMetadataBytes(chainStates[nid], stateAnchor0.GetStateMetadata(), 0, parameterstest.L1Mock))
		nodes[nid] = actors.NewConsensus(
			endpoint,
			chainID,
			chainStates[nid],
			nodeSK,
			nodeDKShare,
			nil, // rotateTo
			procConfig,
			consInstID,
			accounts.CommonAccount(),
			slog.Default(),
		)
		nodes[nid].Start(stateAnchor0)
	}

	actorstest.Start(t, ctx, routers)

	// Provide SM and MP responses on proposals, and some other needed inputs.
	for nid := range nodes {
		proposedAnchor := nodes[nid].Outputs.ProposedAnchor.Wait()
		require.Equal(t, stateAnchor0, proposedAnchor)
		nodes[nid].InputMempoolProposal(reqRefs)
		nodes[nid].InputStateMgrProposalConfirmed()
		nodes[nid].InputTimeData(time.Now())
		nodes[nid].InputL1Info([]*coin.CoinWithRef{&gasCoin}, parameterstest.L1Mock)
	}

	// Provide decided data from SM and MP.
	for nid := range nodes {
		aggr := nodes[nid].Outputs.AggregatedBatchProposals.Wait()
		require.Len(t, aggr.DecidedRequestRefs(), len(reqs))
		nodes[nid].InputMempoolRequests(reqs)
		l1Commitment := lo.Must(transaction.L1CommitmentFromAnchor(aggr.DecidedBaseAnchor()))
		chainState := lo.Must(chainStates[nid].StateByTrieRoot(l1Commitment.TrieRoot()))
		nodes[nid].InputStateMgrDecidedState(chainState)
	}

	// Run VM
	for nid := range nodes {
		vmTask := nodes[nid].Outputs.VMTask.Wait()
		vmTask.Log = hivelog.NewLogger(hivelog.WithLevel(hivelog.LevelError)) // Decrease VM logging.
		vmResult, err := vmimpl.Run(vmTask)
		require.NoError(t, err)
		nodes[nid].InputVMResult(vmResult)
	}

	// save the state
	for nid := range nodes {
		stateDraft := nodes[nid].Outputs.StateDraft.Wait()
		block, _, _ := lo.Must3(chainStates[nid].Commit(stateDraft))
		require.NotNil(t, block)
		nodes[nid].InputStateMgrBlockSaved(block)
	}

	// sign the tx
	var tx *iotasigner.SignedTransaction
	for nid := range nodes {
		result := nodes[nid].Outputs.Result.Wait()
		require.EqualValues(t, actors.ConsensusDecided, result.Type)
		if tx == nil {
			tx = result.Transaction
		}
		require.Equal(t, tx, result.Transaction)
	}
}

func RandomOnLedgerDepositRequest(senders ...*cryptolib.Address) isc.OnLedgerRequest {
	sender := cryptolib.NewRandomAddress()
	if len(senders) != 0 {
		sender = senders[0]
	}
	ref := iotatest.RandomObjectRef()
	a := iscmove.AssetsBagWithBalances{
		AssetsBag: iscmove.AssetsBag{ID: *iotatest.RandomAddress(), Size: 1},
		Assets:    *iscmove.NewAssets(iotajsonrpc.CoinValue(rand.Int63())),
	}
	req := iscmove.RefWithObject[iscmove.Request]{
		ObjectRef: *ref,
		Object: &iscmove.Request{
			ID:        *ref.ObjectID,
			Sender:    sender,
			AssetsBag: a,
			Message: iscmove.Message{
				Contract: uint32(isc.Hn("accounts")),
				Function: uint32(isc.Hn("deposit")),
			},
			AllowanceBCS: bcs.MustMarshal(iscmove.NewAssets(10000)),
			GasBudget:    100000,
		},
		Owner: sender.AsIotaAddress(),
	}
	onReq, err := isc.OnLedgerFromMoveRequest(&req, sender)
	if err != nil {
		panic(err)
	}
	return onReq
}
