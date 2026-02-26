package actors

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"time"

	"fortio.org/safecast"
	"go.dedis.ch/kyber/v3"

	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/samber/lo"

	"github.com/iotaledger/bcs-go"
	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotago"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotasigner"
	"github.com/iotaledger/wasp/v2/packages/coin"
	"github.com/iotaledger/wasp/v2/packages/cryptolib"
	"github.com/iotaledger/wasp/v2/packages/hashing"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/parameters"
	"github.com/iotaledger/wasp/v2/packages/state"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
	"github.com/iotaledger/wasp/v2/packages/util"
	"github.com/iotaledger/wasp/v2/packages/vm"
	"github.com/iotaledger/wasp/v2/packages/vm/core/migrations/allmigrations"
	"github.com/iotaledger/wasp/v2/packages/vm/processors"
	"github.com/iotaledger/wasp/v2/packages/vm/vmtxbuilder"
)

// Consensus is the actor responsible for selecting a set of requests to process,
// running the VM and then producing a L1 transaction.
type Consensus struct {
	Actor
	chainID          isc.ChainID
	chainStore       state.Store
	mySK             *cryptolib.PrivateKey
	dkShare          tcrypto.DKShare
	rotateTo         *iotago.Address
	processorCache   *processors.Config
	instID           []byte
	validatorAgentID isc.AgentID

	inputMempoolProposal           chan []*isc.RequestRef
	inputStateMgrProposalConfirmed chan struct{}
	inputL1Info                    chan l1Info
	inputTimeData                  chan time.Time
	inputMempoolRequests           chan []isc.Request
	inputStateMgrState             chan state.State
	inputVMResult                  chan *vm.VMTaskResult
	inputStateMgrBlockSaved        chan state.Block

	Outputs ConsensusOutputs
}

type ConsensusOutputs struct {
	ProposedAnchor           *Output[*isc.StateAnchor]
	AggregatedBatchProposals *Output[*AggregatedBatchProposals]
	VMTask                   *Output[*vm.VMTask]
	StateDraft               *Output[state.StateDraft]
	Result                   *Output[ConsensusResult]
}

type ConsensusResultType byte

const (
	ConsensusSkipped ConsensusResultType = iota
	ConsensusDecided
)

type ConsensusResult struct {
	Type ConsensusResultType

	// Only set if Type == Decided:
	DecidedAnchor *isc.StateAnchor              // The consumed state anchor.
	Transaction   *iotasigner.SignedTransaction // The TX for committing the block.
	Block         state.Block                   // The state diff produced.
}

type l1Info struct {
	gasCoins []*coin.CoinWithRef
	l1Params *parameters.L1Params
}

type msgConsensusPartialSig struct {
	partialSig []byte `bcs:"export"`
}

func (m *msgConsensusPartialSig) MsgType() MessageType { return 0 }
func (m *msgConsensusPartialSig) String() string       { return "msgConsensusPartialSig" }

func NewConsensus(
	endpoint *Endpoint,
	chainID isc.ChainID,
	chainStore state.Store,
	mySK *cryptolib.PrivateKey,
	dkShare tcrypto.DKShare,
	rotateTo *iotago.Address,
	processorCache *processors.Config,
	instID []byte,
	validatorAgentID isc.AgentID,
) *Consensus {
	return &Consensus{
		Actor:            NewActor(endpoint),
		chainID:          chainID,
		chainStore:       chainStore,
		mySK:             mySK,
		dkShare:          dkShare,
		rotateTo:         rotateTo,
		processorCache:   processorCache,
		instID:           instID,
		validatorAgentID: validatorAgentID,

		inputMempoolProposal:           make(chan []*isc.RequestRef, 1),
		inputStateMgrProposalConfirmed: make(chan struct{}, 1),
		inputL1Info:                    make(chan l1Info, 1),
		inputTimeData:                  make(chan time.Time, 1),
		inputMempoolRequests:           make(chan []isc.Request, 1),
		inputStateMgrState:             make(chan state.State, 1),
		inputVMResult:                  make(chan *vm.VMTaskResult, 1),
		inputStateMgrBlockSaved:        make(chan state.Block, 1),

		Outputs: ConsensusOutputs{
			ProposedAnchor:           NewOutput[*isc.StateAnchor](endpoint.Context()),
			AggregatedBatchProposals: NewOutput[*AggregatedBatchProposals](endpoint.Context()),
			VMTask:                   NewOutput[*vm.VMTask](endpoint.Context()),
			StateDraft:               NewOutput[state.StateDraft](endpoint.Context()),
			Result:                   NewOutput[ConsensusResult](endpoint.Context()),
		},
	}
}

func (c *Consensus) Start(proposedStateAnchor *isc.StateAnchor) {
	c.Go(func() {
		c.Outputs.ProposedAnchor.Set(proposedStateAnchor)

		f := c.Endpoint().N() - int(c.dkShare.GetT())

		dkShareNodePubKeys := c.dkShare.GetNodePubKeys()
		nodeIDs := make([]NodeID, len(dkShareNodePubKeys))
		nodePKs := map[NodeID]kyber.Point{}
		for i := range dkShareNodePubKeys {
			nodeIDs[i] = NodeIDFromPublicKey(dkShareNodePubKeys[i])
			nodePKs[nodeIDs[i]] = lo.Must(dkShareNodePubKeys[i].AsKyberPoint())
		}
		myKyberKeys := lo.Must(c.mySK.AsKyberKeyPair())
		distSign := NewDistSign(
			c.Endpoint().Sub("dss"),
			f,
			tcrypto.DefaultEd25519Suite(),
			nodePKs,
			myKyberKeys.Private,
			c.dkShare.DSS(),
		)
		distSign.Start()
		distSignProposedIndexesChan := distSign.OutputProposedIndexes.ReadyChan()
		distSignOutputSignatureChan := distSign.OutputSignature.ReadyChan()

		var requestRefs []*isc.RequestRef
		var stateMgrProposalConfirmed bool
		var l1Info *l1Info
		var timeData *time.Time
		var distSignIndexProposal []int
		var acs *ACS
		var acsOutputReadyChan <-chan struct{}
		var blsData []byte
		blsPartialSigs := map[NodeID][]byte{}
		var randomness *hashing.HashValue
		var mempoolDecidedRequests []isc.Request
		var stateMgrDecidedState state.State
		var unsignedTX *iotago.TransactionData
		var distSignInputDone bool
		var decidedAnchor *isc.StateAnchor
		var blockSaved struct {
			ready bool
			block state.Block
		}
		var signature []byte

		blsSuite := tcrypto.DefaultBLSSuite()

		tryACSInputs := func() {
			if acs != nil {
				return
			}
			if requestRefs == nil || !stateMgrProposalConfirmed || l1Info == nil || timeData == nil || distSignIndexProposal == nil {
				return
			}
			c.Log().Info("ACS inputs ready")
			rotateTo := c.rotateTo
			if rotateTo != nil && rotateTo.Equals(*c.dkShare.GetAddress().AsIotaAddress()) {
				// Do not propose to rotate to the existing committee.
				rotateTo = nil
			}
			batchProposal := NewBatchProposal(
				*c.dkShare.GetIndex(),
				proposedStateAnchor, // Will be NIL in the case of ⊥ proposal.
				util.NewFixedSizeBitVector(c.dkShare.GetN()).SetBits(distSignIndexProposal),
				rotateTo,
				*timeData,
				c.validatorAgentID,
				requestRefs,     // Will be [] in the case of ⊥ proposal.
				l1Info.gasCoins, // Will be NIL in the case of ⊥ proposal.
				l1Info.l1Params, // Will be NIL in the case of ⊥ proposal.
			)
			acs = NewACS(c.Endpoint().Sub("acs"), f, CommonCoinBLSSigParams{
				T:        int(c.dkShare.BLSThreshold()),
				Suite:    blsSuite,
				PubPoly:  c.dkShare.BLSCommits(),
				PriShare: c.dkShare.BLSPriShare(),
				SID:      c.instID,
			})
			acs.Run(batchProposal.Bytes())
			acsOutputReadyChan = acs.Output.ReadyChan()
		}

		tryMakeVMTask := func() {
			if c.Outputs.VMTask.IsReady() {
				return
			}
			if !c.Outputs.AggregatedBatchProposals.IsReady() || mempoolDecidedRequests == nil || stateMgrDecidedState == nil || randomness == nil {
				return
			}
			c.Log().Info("Preparing VM task")
			aggregatedProposals := c.Outputs.AggregatedBatchProposals.MustGet()
			decidedBaseAnchor := aggregatedProposals.DecidedBaseAnchor()
			stateAnchor := isc.NewStateAnchor(decidedBaseAnchor.Anchor(), decidedBaseAnchor.ISCPackage())
			gasCoins := aggregatedProposals.AggregatedGasCoins()
			// FIXME we need only one
			if len(gasCoins) != 1 {
				panic("FIXME we support only one gas coin now")
			}
			gasCoin := gasCoins[0]

			c.Outputs.VMTask.Set(&vm.VMTask{
				Processors:           c.processorCache,
				Anchor:               &stateAnchor,
				GasCoin:              gasCoin,
				L1Params:             aggregatedProposals.AggregatedL1Params(),
				Store:                c.chainStore,
				Requests:             aggregatedProposals.OrderedRequests(mempoolDecidedRequests, *randomness),
				Timestamp:            aggregatedProposals.AggregatedTime(),
				Entropy:              *randomness,
				ValidatorFeeTarget:   aggregatedProposals.ValidatorFeeTarget(*randomness),
				EstimateGasMode:      false,
				EnableGasBurnLogging: false,
				Log:                  log.NewLogger(log.WithHandler(slog.Default().Handler()), log.WithName("VM")),
				Migrations:           allmigrations.DefaultScheme,
			})
		}

		tryProduceRandomness := func() {
			if randomness != nil {
				return
			}
			if blsData == nil || len(blsPartialSigs) < int(c.dkShare.BLSThreshold()) {
				return
			}
			c.Log().Info("Producing randomness")
			sig, err := c.dkShare.BLSRecoverMasterSignature(lo.Values(blsPartialSigs), blsData)
			if err != nil {
				c.Log().Warn(fmt.Sprintf("Cannot reconstruct BLS signature from %v/%v sigShares", len(blsPartialSigs), c.dkShare.GetN()), "err", err)
				return
			}
			hash := hashing.HashDataBlake2b(sig.Signature.Bytes())
			randomness = &hash
			tryMakeVMTask()
		}

		tryDistSignInputs := func() {
			if distSignInputDone {
				return
			}
			if !c.Outputs.AggregatedBatchProposals.IsReady() || unsignedTX == nil {
				return
			}
			c.Log().Info("Providing inputs to distributed signing")
			indexProposals := c.Outputs.AggregatedBatchProposals.MustGet().DecidedDistributedSignatureIndexProposals()
			distSign.InputDecided(indexProposals, c.makeTransactionSigningBytes(unsignedTX))
			distSignInputDone = true
		}

		trySignTx := func() {
			if c.Outputs.Result.IsReady() {
				return
			}
			if decidedAnchor == nil || unsignedTX == nil || !blockSaved.ready || signature == nil {
				return
			}
			suiSignature := cryptolib.NewSignature(c.dkShare.GetSharedPublic(), signature).AsIotaSignature()
			signedTX := iotasigner.NewSignedTransaction(unsignedTX, suiSignature)
			c.Outputs.Result.Set(ConsensusResult{
				Type:          ConsensusDecided,
				DecidedAnchor: decidedAnchor,
				Transaction:   signedTX,
				Block:         blockSaved.block,
			})
			c.Log().Info("Terminated with type = Decided")
		}

		for {
			select {
			case <-c.Context().Done():
				return

			case <-c.Endpoint().Status():
				c.Log().Info("status",
					"haveRequestRefs", requestRefs != nil,
					"stateMgrProposalConfirmed", stateMgrProposalConfirmed,
					"haveL1Info", l1Info != nil,
					"haveTimeData", timeData != nil,
					"haveDistSignIndexProposal", distSignIndexProposal != nil,
					"acsStarted", acs != nil,
					"acsDone", acs.Output.IsReady(),
					"haveBLSData", blsData != nil,
					"haveBLSSigs", len(blsPartialSigs),
					"haveRandomness", randomness != nil,
					"haveMempoolDecidedRequests", mempoolDecidedRequests != nil,
					"haveStateMgrDecidedState", stateMgrDecidedState != nil,
					"haveUnsignedTX", unsignedTX != nil,
					"distSignInputDone", distSignInputDone,
					"haveDecidedAnchor", decidedAnchor != nil,
					"blockSavedReady", blockSaved.ready,
					"haveSignature", signature != nil,
					"outputProposedAnchor", c.Outputs.ProposedAnchor.IsReady(),
					"outputAggregatedBatchProposals", c.Outputs.AggregatedBatchProposals.IsReady(),
					"outputVMTask", c.Outputs.VMTask.IsReady(),
					"outputStateDraft", c.Outputs.StateDraft.IsReady(),
					"outputResult", c.Outputs.Result.IsReady(),
				)

			case refs := <-c.inputMempoolProposal:
				c.Log().Info("Received mempool proposal", "requestRefs", refs)
				c.inputMempoolProposal = nil
				requestRefs = refs
				tryACSInputs()

			case <-c.inputStateMgrProposalConfirmed:
				c.Log().Info("Received state manager proposal confirmation")
				c.inputStateMgrProposalConfirmed = nil
				stateMgrProposalConfirmed = true
				tryACSInputs()

			case l1i := <-c.inputL1Info:
				c.Log().Info("Received L1 info", "gasCoins", l1i.gasCoins, "l1Params", l1i.l1Params)
				c.inputL1Info = nil
				l1Info = &l1i
				tryACSInputs()

			case t := <-c.inputTimeData:
				c.Log().Info("Received time data", "time", t)
				c.inputTimeData = nil
				timeData = &t
				tryACSInputs()

			case <-distSignProposedIndexesChan:
				c.Log().Info("Received distributed signature index proposal")
				distSignProposedIndexesChan = nil
				distSignIndexProposal = distSign.OutputProposedIndexes.MustGet()
				tryACSInputs()

			case <-acsOutputReadyChan:
				c.Log().Info("Received ACS output")
				acsOutputReadyChan = nil
				acsOutput := acs.Output.MustGet()
				aggr := AggregateBatchProposals(acsOutput, c.Endpoint().Router.Peers, f, c.Log())
				c.Outputs.AggregatedBatchProposals.Set(aggr)
				if aggr.ShouldBeSkipped() {
					// Cannot proceed with such proposals.
					// Have to retry the consensus after some time with the next log index.
					c.Log().Info("Terminating consensus with status=Skipped, there is no way to aggregate batch proposal.")
					c.Outputs.Result.Set(ConsensusResult{Type: ConsensusSkipped})
					return
				}
				decidedAnchor = aggr.DecidedBaseAnchor()
				reqs := aggr.DecidedRequestRefs()
				c.Log().Debug("ACS decision", "baseAnchor", decidedAnchor, "requests", reqs)
				if aggr.DecidedRotateTo() != nil {
					c.Log().Debug("Will rotate", "to", aggr.DecidedRotateTo().ToHex())
					rotationPTB := vmtxbuilder.NewAnchorTransactionBuilder(decidedAnchor.ISCPackage(), decidedAnchor, c.dkShare.GetAddress())
					rotationPTB.RotationTransaction(aggr.DecidedRotateTo())
					rotationPTX := rotationPTB.BuildTransactionEssence(decidedAnchor.GetStateMetadata(), 0)
					unsignedTX = c.makeTransactionData(&rotationPTX, aggr)
					c.Log().Debug("Rotation", "TxDataBytes", hex.EncodeToString(makeTransactionDataBytes(unsignedTX)))
					blockSaved.ready = true // no block is saved for rotation, but we can proceed to sign the rotation transaction.
				} else {
					blsData = decidedAnchor.GetObjectRef().Bytes()
					sigShare := lo.Must(c.dkShare.BLSSignShare(blsData))
					c.Endpoint().SendToAll(&msgConsensusPartialSig{sigShare})
					tryProduceRandomness()
				}
				tryDistSignInputs()

			case m, ok := <-c.Endpoint().In():
				if !ok {
					panic(context.Canceled)
				}
				payload, ok := m.Payload.(*msgConsensusPartialSig)
				if !ok {
					c.Log().Warn("unexpected message type", "type", m.Payload.MsgType())
					continue
				}
				if blsPartialSigs[m.Sender] != nil {
					c.Log().Warn("received duplicate BLS partial signature", "from", m.Sender)
					continue
				}
				c.Log().Info("Received BLS partial signature", "from", m.Sender)
				blsPartialSigs[m.Sender] = payload.partialSig
				tryProduceRandomness()

			case reqs := <-c.inputMempoolRequests:
				c.Log().Info("Received mempool decided requests", "requests", reqs)
				c.inputMempoolRequests = nil
				mempoolDecidedRequests = reqs
				tryMakeVMTask()

			case s := <-c.inputStateMgrState:
				c.Log().Info("Received state manager decided state")
				c.inputStateMgrState = nil
				stateMgrDecidedState = s
				tryMakeVMTask()

			case vmResult := <-c.inputVMResult:
				c.Log().Info("Received VM result")
				c.inputVMResult = nil
				if len(vmResult.RequestResults) == 0 {
					// No requests were processed, don't have what to do.
					// Will need to retry the consensus with the next log index some time later.
					c.Log().Info("Terminating consensus with status=Skipped, 0 requests processed.")
					c.Outputs.Result.Set(ConsensusResult{Type: ConsensusSkipped})
				} else {
					unsignedTX = c.makeTransactionData(&vmResult.UnsignedTransaction, c.Outputs.AggregatedBatchProposals.MustGet())
					tryDistSignInputs()
					c.Outputs.StateDraft.Set(vmResult.StateDraft)
					c.Log().Debug("VM produced", "TxDataBytes", hex.EncodeToString(makeTransactionDataBytes(unsignedTX)))
				}

			case <-distSignOutputSignatureChan:
				c.Log().Info("Received distributed signature")
				distSignOutputSignatureChan = nil
				signature = distSign.OutputSignature.MustGet()
				trySignTx()

			case block := <-c.inputStateMgrBlockSaved:
				c.Log().Info("Received state manager block saved", "blockHash", block.Hash().String())
				c.inputStateMgrBlockSaved = nil
				blockSaved.block = block
				blockSaved.ready = true
				trySignTx()
			}
		}
	})
}

func makeTransactionDataBytes(txData *iotago.TransactionData) []byte {
	return lo.Must(bcs.Marshal(txData))
}

func (c *Consensus) makeTransactionData(pt *iotago.ProgrammableTransaction, aggregatedProposals *AggregatedBatchProposals) *iotago.TransactionData {
	sender := c.dkShare.GetAddress().AsIotaAddress()
	l1params := aggregatedProposals.AggregatedL1Params()
	gasPrice := l1params.Protocol.ReferenceGasPrice.Uint64()
	gasBudget := pt.EstimateGasBudget(gasPrice)
	gasPaymentCoinRef := aggregatedProposals.AggregatedGasCoins()
	gasPayment := make([]*iotago.ObjectRef, len(gasPaymentCoinRef))
	for i, coinRef := range gasPaymentCoinRef {
		gasPayment[i] = coinRef.Ref
	}

	tx := iotago.NewProgrammable(sender, *pt, gasPayment, gasBudget, gasPrice)
	return &tx
}

func (c *Consensus) makeTransactionSigningBytes(txData *iotago.TransactionData) []byte {
	txnBytes := makeTransactionDataBytes(txData)
	txnBytes = iotasigner.MessageWithIntent(iotasigner.DefaultIntent(), txnBytes)
	txnBytesHash := blake2b.Sum256(txnBytes)
	return txnBytesHash[:]
}

func (c *Consensus) InputMempoolProposal(reqRefs []*isc.RequestRef) {
	c.inputMempoolProposal <- reqRefs
}

func (c *Consensus) InputStateMgrProposalConfirmed() {
	c.inputStateMgrProposalConfirmed <- struct{}{}
}

func (c *Consensus) InputL1Info(gasCoins []*coin.CoinWithRef, l1params *parameters.L1Params) {
	c.inputL1Info <- l1Info{
		gasCoins: gasCoins,
		l1Params: l1params,
	}
}

func (c *Consensus) InputTimeData(now time.Time) {
	c.inputTimeData <- now
}

func (c *Consensus) InputMempoolRequests(reqs []isc.Request) {
	c.inputMempoolRequests <- reqs
}

func (c *Consensus) InputStateMgrDecidedState(state state.State) {
	c.inputStateMgrState <- state
}

func (c *Consensus) InputVMResult(result *vm.VMTaskResult) {
	c.inputVMResult <- result
}

func (c *Consensus) InputStateMgrBlockSaved(block state.Block) {
	c.inputStateMgrBlockSaved <- block
}

type BatchProposal struct {
	nodeIndex                     uint16               `bcs:"export"`          // Just for a double-check.
	baseAnchor                    *isc.StateAnchor     `bcs:"export,optional"` // Proposed Base Anchor to use.
	distributedStateIndexProposal util.BitVector       `bcs:"export"`          // DSS Index proposal.
	rotateTo                      *iotago.Address      `bcs:"export,optional"` // Suggestion to rotate the committee, optional.
	timeData                      time.Time            `bcs:"export"`          // Our view of time.
	validatorFeeDestination       isc.AgentID          `bcs:"export"`          // Proposed destination for fees.
	requestRefs                   []*isc.RequestRef    `bcs:"export"`          // Requests we propose to include into the execution.
	gasCoins                      []*coin.CoinWithRef  `bcs:"export,optional"` // Coins to use for gas payment.
	l1params                      *parameters.L1Params `bcs:"export,optional"` // The L1Params for current state
}

func NewBatchProposal(
	nodeIndex uint16,
	baseAnchor *isc.StateAnchor,
	distSignIndexProposal util.BitVector,
	rotateTo *iotago.Address,
	timeData time.Time,
	validatorFeeDestination isc.AgentID,
	requestRefs []*isc.RequestRef,
	gasCoins []*coin.CoinWithRef,
	l1params *parameters.L1Params,
) *BatchProposal {
	return &BatchProposal{
		nodeIndex:                     nodeIndex,
		baseAnchor:                    baseAnchor,
		distributedStateIndexProposal: distSignIndexProposal,
		rotateTo:                      rotateTo,
		timeData:                      timeData,
		validatorFeeDestination:       validatorFeeDestination,
		requestRefs:                   requestRefs,
		gasCoins:                      gasCoins,
		l1params:                      l1params,
	}
}

func (b *BatchProposal) Bytes() []byte {
	return bcs.MustMarshal(b)
}

// IsVoid returns true if a proposal is ⊥, in which case it will not contain request refs nor base Anchor.
// Other fields are required to help other participants to sign a TX, if such is produced from other node's inputs.
func (b *BatchProposal) IsVoid() bool {
	return b.baseAnchor == nil
}

// AggregatedBatchProposals stores just an aggregated info.
type AggregatedBatchProposals struct {
	shouldBeSkipped       bool
	batchProposalSet      batchProposalSet
	decidedIndexProposals map[NodeID][]int
	decidedBaseAnchor     *isc.StateAnchor
	decidedRequestRefs    []*isc.RequestRef
	decidedRotateTo       *iotago.Address
	aggregatedTime        time.Time
	aggregatedGasCoins    []*coin.CoinWithRef
	aggregatedL1Params    *parameters.L1Params
}

func AggregateBatchProposals(inputs map[NodeID][]byte, nodeIDs []NodeID, f int, log *slog.Logger) *AggregatedBatchProposals {
	batchProposals := batchProposalSet{}
	//
	// Parse and validate the batch proposals. Skip the invalid ones.
	nilCount := 0
	for nid := range inputs {
		if len(inputs[nid]) == 0 {
			log.Warn("cannot decode empty BatchProposal", "from", nid)
			continue
		}
		batchProposal, err := bcs.Unmarshal[*BatchProposal](inputs[nid])
		if err != nil {
			log.Warn("cannot decode BatchProposal", "from", nid, "err", err.Error())
			continue
		}
		if batchProposal.baseAnchor == nil {
			nilCount++
		}
		if int(batchProposal.nodeIndex) >= len(nodeIDs) || nodeIDs[batchProposal.nodeIndex] != nid {
			log.Warn("invalid nodeIndex in batchProposal", "nodeIndex", batchProposal.nodeIndex, "from", nid.ShortString())
			continue
		}
		batchProposals[nid] = batchProposal
	}
	//
	// Store the aggregated values.
	if nilCount > f {
		log.Debug("Can't aggregate batch proposal: have >= f+1 nil proposals.")
		return &AggregatedBatchProposals{shouldBeSkipped: true}
	}
	if len(batchProposals) == 0 {
		log.Debug("Can't aggregate batch proposal: have 0 batch proposals.")
		return &AggregatedBatchProposals{shouldBeSkipped: true}
	}
	aggregatedTime := batchProposals.aggregatedTime(f)
	decidedBaseAnchor := batchProposals.decidedBaseAnchor(f)
	aggregatedGasCoins := batchProposals.aggregatedGasCoins(f)
	aggregatedL1Params := batchProposals.aggregatedL1Params(f)
	aggregatedBatchProposals := &AggregatedBatchProposals{
		batchProposalSet:      batchProposals,
		decidedIndexProposals: batchProposals.decidedDistributedSignatureIndexProposals(),
		decidedBaseAnchor:     decidedBaseAnchor,
		decidedRequestRefs:    batchProposals.decidedRequestRefs(f, decidedBaseAnchor),
		decidedRotateTo:       batchProposals.decidedRotateTo(f),
		aggregatedTime:        aggregatedTime,
		aggregatedGasCoins:    aggregatedGasCoins,
		aggregatedL1Params:    aggregatedL1Params,
	}
	if aggregatedBatchProposals.decidedBaseAnchor == nil ||
		len(aggregatedBatchProposals.decidedRequestRefs) == 0 ||
		// No need to check the rotateTo field here.
		aggregatedBatchProposals.aggregatedTime.IsZero() ||
		len(aggregatedBatchProposals.aggregatedGasCoins) == 0 ||
		aggregatedBatchProposals.aggregatedL1Params == nil {
		log.Debug(
			"Can't aggregate batch proposal",
			"decidedBaseAnchor", aggregatedBatchProposals.decidedBaseAnchor,
			"|decidedRequestRefs|", len(aggregatedBatchProposals.decidedRequestRefs),
			"|aggregatedGasCoins|", len(aggregatedBatchProposals.aggregatedGasCoins),
			"|aggregatedL1Params|", aggregatedBatchProposals.aggregatedL1Params,
			"aggregatedTime", aggregatedBatchProposals.aggregatedTime,
		)
		aggregatedBatchProposals.shouldBeSkipped = true
	}
	return aggregatedBatchProposals
}

func (p *AggregatedBatchProposals) ShouldBeSkipped() bool {
	return p.shouldBeSkipped
}

func (p *AggregatedBatchProposals) DecidedDistributedSignatureIndexProposals() map[NodeID][]int {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.decidedIndexProposals
}

func (p *AggregatedBatchProposals) DecidedBaseAnchor() *isc.StateAnchor {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.decidedBaseAnchor
}

func (p *AggregatedBatchProposals) DecidedRotateTo() *iotago.Address {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.decidedRotateTo
}

func (p *AggregatedBatchProposals) AggregatedTime() time.Time {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.aggregatedTime
}

func (p *AggregatedBatchProposals) ValidatorFeeTarget(randomness hashing.HashValue) isc.AgentID {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.batchProposalSet.selectedFeeDestination(p.aggregatedTime, randomness)
}

func (p *AggregatedBatchProposals) DecidedRequestRefs() []*isc.RequestRef {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.decidedRequestRefs
}

// OrderedRequests returns ordered requests.
// TODO: should this be moved to the VM?
func (p *AggregatedBatchProposals) OrderedRequests(requests []isc.Request, randomness hashing.HashValue) []isc.Request {
	type sortStruct struct {
		key hashing.HashValue
		ref *isc.RequestRef
		req isc.Request
	}

	sortBuf := make([]*sortStruct, len(p.decidedRequestRefs))
	for i := range p.decidedRequestRefs {
		ref := p.decidedRequestRefs[i]
		var found isc.Request
		for j := range requests {
			if ref.IsFor(requests[j]) {
				found = requests[j]
				break
			}
		}
		if found == nil {
			panic("request was not provided by mempool")
		}
		sortBuf[i] = &sortStruct{
			key: hashing.HashDataBlake2b(ref.ID.Bytes(), ref.Hash[:], randomness[:]),
			ref: ref,
			req: found,
		}
	}
	sort.Slice(sortBuf, func(i, j int) bool {
		return bytes.Compare(sortBuf[i].key[:], sortBuf[j].key[:]) < 0
	})

	// Make sure the requests are sorted such way, that the nonces per account are increasing.
	// This is needed to handle several requests per batch for the VMs that expect the in-order nonces.
	// We make a second pass here to tain the overall ordering of requests (module account) without
	// making requests from a single account grouped together while sorting.
	for i := range sortBuf {
		oi, ok := sortBuf[i].req.(isc.OffLedgerRequest)
		if !ok {
			continue
		}
		for j := i + 1; j < len(sortBuf); j++ {
			oj, ok := sortBuf[j].req.(isc.OffLedgerRequest)
			if !ok {
				continue
			}
			if oi.SenderAccount().Equals(oj.SenderAccount()) && oi.Nonce() > oj.Nonce() {
				sortBuf[i], sortBuf[j] = sortBuf[j], sortBuf[i]
				oi = oj
			}
		}
	}

	sorted := make([]isc.Request, len(p.decidedRequestRefs))
	for i := range sortBuf {
		sorted[i] = sortBuf[i].req
	}
	return sorted
}

func (p *AggregatedBatchProposals) AggregatedGasCoins() []*coin.CoinWithRef {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.aggregatedGasCoins
}

func (p *AggregatedBatchProposals) AggregatedL1Params() *parameters.L1Params {
	if p.shouldBeSkipped {
		panic("trying to use aggregated proposal marked to be skipped")
	}
	return p.aggregatedL1Params
}

type batchProposalSet map[NodeID]*BatchProposal

func (s batchProposalSet) decidedDistributedSignatureIndexProposals() map[NodeID][]int {
	ips := map[NodeID][]int{}
	for nid, batchProposal := range s {
		ips[nid] = batchProposal.distributedStateIndexProposal.AsInts()
	}
	return ips
}

// Decided Base Alias Output is the one, that was proposed by F+1 nodes or more.
// If there is more that 1 such ID, we refuse to use all of them.
func (s batchProposalSet) decidedBaseAnchor(f int) *isc.StateAnchor {
	counts := map[hashing.HashValue]int{}
	values := map[hashing.HashValue]*isc.StateAnchor{}
	for _, batchProposal := range s {
		if batchProposal.baseAnchor == nil {
			continue
		}
		h := batchProposal.baseAnchor.Hash()
		counts[h]++
		if _, ok := values[h]; !ok {
			values[h] = batchProposal.baseAnchor
		}
	}

	var found *isc.StateAnchor
	var uncertain bool
	for h, count := range counts {
		if count > f {
			if found != nil && found.GetStateIndex() == values[h].GetStateIndex() {
				// Found more that 1 Anchor proposed by F+1 or more nodes.
				uncertain = true
				continue
			}
			if found == nil || found.GetStateIndex() < values[h].GetStateIndex() {
				found = values[h]
				uncertain = false
			}
		}
	}
	if uncertain {
		return nil
	}
	return found
}

// Take requests proposed by at least F+1 nodes. Then the request is proposed at least by 1 fair node.
// We should only consider the proposals from the nodes that proposed the decided Anchor, otherwise we can select already processed requests.
func (s batchProposalSet) decidedRequestRefs(f int, ao *isc.StateAnchor) []*isc.RequestRef {
	minNumberMentioned := f + 1
	requestsByKey := map[isc.RequestRefKey]*isc.RequestRef{}
	numMentioned := map[isc.RequestRefKey]int{}
	//
	// Count number of nodes proposing a request.
	maxLen := 0
	for _, batchProposal := range s {
		if batchProposal.baseAnchor == nil || !batchProposal.baseAnchor.Equals(ao) {
			continue
		}
		for _, reqRef := range batchProposal.requestRefs {
			reqRefFey := reqRef.AsKey()
			numMentioned[reqRefFey]++
			if _, ok := requestsByKey[reqRefFey]; !ok {
				requestsByKey[reqRefFey] = reqRef
			}
		}
		if len(batchProposal.requestRefs) > maxLen {
			maxLen = len(batchProposal.requestRefs)
		}
	}
	//
	// Select the requests proposed by F+1 nodes.
	decided := make([]*isc.RequestRef, 0, maxLen)
	for key, num := range numMentioned {
		if num < minNumberMentioned {
			continue
		}
		decided = append(decided, requestsByKey[key])
	}
	return decided
}

func (s batchProposalSet) decidedRotateTo(f int) *iotago.Address {
	votes := map[iotago.Address]int{}
	for _, batchProposal := range s {
		if batchProposal.rotateTo != nil {
			votes[*batchProposal.rotateTo] += 1
		}
	}

	var found *iotago.Address
	for address, count := range votes {
		thisAddr := address
		if count > f {
			if found != nil {
				// 2 values with counter > f, thus a collision.
				return nil
			}
			found = &thisAddr
		}
	}
	return found
}

// Returns zero time, if fails to aggregate the time.
func (s batchProposalSet) aggregatedTime(f int) time.Time {
	ts := make([]time.Time, 0, len(s))
	for _, batchProposal := range s {
		ts = append(ts, batchProposal.timeData)
	}
	sort.Slice(ts, func(i, j int) bool {
		return ts[i].Before(ts[j])
	})

	proposalCount := len(s) // |acsProposals| >= N-F by ACS logic.
	if proposalCount <= f {
		return time.Time{} // Zero time marks a failure.
	}
	return ts[proposalCount-f-1] // Max(|acsProposals|-F Lowest) ~= 66 percentile.
}

func (s batchProposalSet) selectedProposal(aggregatedTime time.Time, randomness hashing.HashValue) NodeID {
	peers := make([]NodeID, 0, len(s))
	for nid := range s {
		peers = append(peers, nid)
	}
	slices.SortFunc(peers, func(a NodeID, b NodeID) int {
		return bytes.Compare(a[:], b[:])
	})
	uint64Bytes := make([]byte, 8)

	timeNano, err := safecast.Convert[uint64](aggregatedTime.UnixNano())
	if err != nil {
		panic("proposal aggregated time overflows uint64")
	}
	binary.BigEndian.PutUint64(uint64Bytes, timeNano)
	hashed := hashing.HashDataBlake2b(
		uint64Bytes,
		randomness[:],
	)
	randomUint := binary.BigEndian.Uint64(hashed[:])
	lens, err := safecast.Convert[uint64](len(s))
	if err != nil {
		panic("length of batch proposal set overflows uint64")
	}
	randomPosU64 := randomUint % lens
	randomPos, err := safecast.Convert[int](randomPosU64)
	if err != nil {
		panic("random proposal from set overflows int")
	}
	return peers[randomPos]
}

func (s batchProposalSet) selectedFeeDestination(aggregatedTime time.Time, randomness hashing.HashValue) isc.AgentID {
	batchProposal := s[s.selectedProposal(aggregatedTime, randomness)]
	return batchProposal.validatorFeeDestination
}

type l1paramsCounter struct {
	counter  int
	l1params *parameters.L1Params
}

// Take the L1Params which is shared more than f+1 nodes
func (s batchProposalSet) aggregatedL1Params(f int) *parameters.L1Params {
	proposalCount := len(s) // |acsProposals| >= N-F by ACS logic.
	ps := make([]*parameters.L1Params, 0, proposalCount)
	for _, batchProposal := range s {
		if batchProposal.l1params == nil {
			continue
		}
		ps = append(ps, batchProposal.l1params)
	}

	// count the amount of each L1Params
	protocolMap := make(map[string]l1paramsCounter)
	var l1paramsCounterMax l1paramsCounter
	for _, l1params := range ps {
		elt, ok := protocolMap[l1params.Hash().Hex()]
		if ok {
			elt.counter += 1
			protocolMap[l1params.Hash().Hex()] = elt
		} else {
			elt = l1paramsCounter{
				counter:  1,
				l1params: l1params,
			}
			protocolMap[l1params.Hash().Hex()] = elt
		}
		if elt.counter > l1paramsCounterMax.counter {
			l1paramsCounterMax.counter = elt.counter
			l1paramsCounterMax.l1params = elt.l1params
		}
	}

	matchingCount := lo.CountBy(lo.Values(protocolMap), func(elt l1paramsCounter) bool {
		return elt.counter > f
	})
	if matchingCount != 1 {
		return nil
	}

	return l1paramsCounterMax.l1params
}

// Here we return coins that are proposed by at least F+1 peers.
func (s batchProposalSet) aggregatedGasCoins(f int) []*coin.CoinWithRef {
	coinRefs := map[string]*coin.CoinWithRef{}
	coinFrom := map[string]map[NodeID]bool{}
	for from, batchProposal := range s {
		for i := range batchProposal.gasCoins {
			coinRef := batchProposal.gasCoins[i]
			bytesStr := string(coinRef.Ref.Bytes())
			if _, ok := coinRefs[bytesStr]; !ok {
				coinRefs[bytesStr] = coinRef
				coinFrom[bytesStr] = map[NodeID]bool{}
			}
			coinFrom[bytesStr][from] = true
		}
	}

	// Drop the coins proposed by less than F+1 nodes.
	for i, cf := range coinFrom {
		if len(cf) < f+1 {
			delete(coinFrom, i)
		}
	}

	// Drop older versions of the same coin.
	for i := range coinFrom {
		ci := coinRefs[i].Ref
		haveNewer := lo.ContainsBy(lo.Keys(coinFrom), func(j string) bool {
			cj := coinRefs[i].Ref
			return ci.ObjectID.Equals(*cj.ObjectID) && ci.Version < cj.Version
		})
		if haveNewer {
			delete(coinFrom, i)
		}
	}

	// Sort them by the proposal frequency, then by the bytes.
	coinKeys := lo.Keys(coinFrom)
	sort.Slice(coinKeys, func(i, j int) bool {
		fromI := len(coinFrom[coinKeys[i]])
		fromJ := len(coinFrom[coinKeys[j]])
		return fromI < fromJ || (fromI == fromJ && coinKeys[i] < coinKeys[j])
	})

	// Return the selected coins.
	result := []*coin.CoinWithRef{}
	for _, coinKey := range coinKeys {
		result = append(result, coinRefs[coinKey])
	}
	return result
}
