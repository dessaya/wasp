// Package consensus implements consensus functionality for IOTA Smart Contracts.
// A single instance of it.
//
// We move all the synchronization logic to separate objects (upon_...). They are
// responsible for waiting specific data and then triggering the next state action
// once. This way we hope to solve a lot of race conditions gracefully. The `upon`
// predicates and the corresponding done functions should not depend on each other.
// If some data is needed at several places, it should be passed to several predicates.
package consensus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"fortio.org/safecast"
	"github.com/minio/blake2b-simd"
	"github.com/samber/lo"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"

	bcs "github.com/iotaledger/bcs-go"
	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotago"
	"github.com/iotaledger/wasp/v2/clients/iota-go/iotasigner"
	"github.com/iotaledger/wasp/v2/packages/chain/consensus/batchproposal"
	"github.com/iotaledger/wasp/v2/packages/chain/distsign"
	"github.com/iotaledger/wasp/v2/packages/coin"
	"github.com/iotaledger/wasp/v2/packages/cryptolib"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/gpa/acs"
	"github.com/iotaledger/wasp/v2/packages/gpa/cc"
	"github.com/iotaledger/wasp/v2/packages/gpa/cc/blssig"
	"github.com/iotaledger/wasp/v2/packages/gpa/cc/semi"
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

type OutputStatus byte

func (os OutputStatus) String() string {
	switch os {
	case Running:
		return "Running"
	case Completed:
		return "Completed"
	case Skipped:
		return "Skipped"
	default:
		return fmt.Sprintf("Unexpected-%v", byte(os))
	}
}

const (
	Running   OutputStatus = iota // Instance is still running.
	Completed                     // Consensus reached, TX is prepared for publication.
	Skipped                       // Consensus reached, no TX should be posted for this LogIndex.
)

type Output struct {
	Status     OutputStatus
	Terminated bool
	//
	// Requests for other components.
	NeedMempoolProposal       *isc.StateAnchor  // Requests for the mempool are needed for this Base Alias Output.
	NeedMempoolRequests       []*isc.RequestRef // Request payloads are needed from mempool for this IDs/Hash.
	NeedStateMgrStateProposal *isc.StateAnchor  // Query for a proposal for Virtual State (it will go to the batch proposal).
	NeedStateMgrDecidedState  *isc.StateAnchor  // Query for a decided Virtual State to be used by VM.
	NeedStateMgrSaveBlock     state.StateDraft  // Ask StateMgr to save the produced block.
	NeedNodeConnL1Info        *isc.StateAnchor  // Ask NodeConn for the L1Info related to this anchor.
	NeedVMResult              *vm.VMTask        // VM Result is needed for this (agreed) batch.
	//
	// Following is the final result.
	// All the fields are filled, if State == Completed.
	Result *Result
}

type Result struct {
	DecidedAnchor *isc.StateAnchor              // The consumed state anchor.
	Transaction   *iotasigner.SignedTransaction // The TX for committing the block.
	Block         state.Block                   // The state diff produced.
}

func (r *Result) String() string {
	return fmt.Sprintf(
		"{cons.Result, txDigest=%s, baseAnchor=%v, outBlockHash=%v}",
		lo.Must(r.Transaction.Digest()),
		r.DecidedAnchor,
		r.Block.Hash(),
	)
}

type Consensus struct {
	out                     gpa.OutBuffer
	chainID                 isc.ChainID
	chainStore              state.Store
	edSuite                 suites.Suite    // For signatures.
	blsSuite                suites.Suite    // For randomness only.
	dkShare                 tcrypto.DKShare // The current committee's keys.
	rotateTo                *iotago.Address // If non-nil and differs from the dkShare, then rotation is suggested.
	processorCache          *processors.Config
	nodeIDs                 []gpa.NodeID
	me                      gpa.NodeID
	f                       int
	distributedSignature    *distsign.DistributedSignature
	acs                     *acs.ACS
	subMempool              *SyncMempool              // Mempool.
	subStateMgr             *SyncStateMgr             // StateMgr.
	subNodeconn             *SyncNodeconn             // Synchronization with the NodeConn.
	subDistributedSignature *SyncDistributedSignature // Distributed Schnorr Signature.
	subACS                  *SyncACS                  // Asynchronous Common Subset.
	subRND                  *SyncRND                  // Randomness.
	subVM                   *SyncVM                   // Virtual Machine.
	subTX                   *SyncTX                   // Building final TX.
	term                    *termCondition            // To detect, when this instance can be terminated.
	msgWrapper              *gpa.MsgWrapper
	output                  *Output
	validatorAgentID        isc.AgentID
	log                     log.Logger
}

const (
	subsystemTypeDistributedSignature byte = iota
	subsystemTypeACS
)

var _ gpa.GPA = &Consensus{}

func New(
	chainID isc.ChainID,
	chainStore state.Store,
	me gpa.NodeID,
	mySK *cryptolib.PrivateKey,
	dkShare tcrypto.DKShare,
	rotateTo *iotago.Address,
	processorCache *processors.Config,
	instID []byte,
	nodeIDFromPubKey func(pubKey *cryptolib.PublicKey) gpa.NodeID,
	validatorAgentID isc.AgentID,
	log log.Logger,
) *Consensus {
	edSuite := tcrypto.DefaultEd25519Suite()
	blsSuite := tcrypto.DefaultBLSSuite()

	dkShareNodePubKeys := dkShare.GetNodePubKeys()
	nodeIDs := make([]gpa.NodeID, len(dkShareNodePubKeys))
	nodePKs := map[gpa.NodeID]kyber.Point{}
	for i := range dkShareNodePubKeys {
		var err error
		nodeIDs[i] = nodeIDFromPubKey(dkShareNodePubKeys[i])
		nodePKs[nodeIDs[i]], err = dkShareNodePubKeys[i].AsKyberPoint()
		if err != nil {
			panic(fmt.Errorf("cannot convert nodePK[%v] to kyber.Point: %w", i, err))
		}
	}

	f := len(dkShareNodePubKeys) - int(dkShare.GetT())
	myKyberKeys, err := mySK.AsKyberKeyPair()
	if err != nil {
		panic(fmt.Errorf("cannot convert node's SK to kyber.Scalar: %w", err))
	}
	longTermDKS := dkShare.DSS()
	acsLog := log.NewChildLogger("ACS")
	acsCCInstFunc := func(nodeID gpa.NodeID, round int) cc.CommonCoin {
		var roundBin [4]byte
		roundU32, err := safecast.Convert[uint32](round)
		if err != nil {
			panic("round overflows uint32")
		}
		binary.BigEndian.PutUint32(roundBin[:], roundU32)
		sid := hashing.HashDataBlake2b(instID, nodeID[:], roundBin[:]).Bytes()
		realCC := blssig.New(blsSuite, nodeIDs, dkShare.BLSCommits(), dkShare.BLSPriShare(), int(dkShare.BLSThreshold()), me, sid, acsLog)
		return semi.New(round, realCC)
	}
	c := &Consensus{
		chainID:              chainID,
		chainStore:           chainStore,
		edSuite:              edSuite,
		blsSuite:             blsSuite,
		dkShare:              dkShare,
		rotateTo:             rotateTo,
		processorCache:       processorCache,
		nodeIDs:              nodeIDs,
		me:                   me,
		f:                    f,
		distributedSignature: distsign.New(edSuite, nodeIDs, nodePKs, f, me, myKyberKeys.Private, longTermDKS, log.NewChildLogger("DistributedSignature")),
		acs:                  acs.New(nodeIDs, me, f, acsCCInstFunc, acsLog),
		output:               &Output{Status: Running},
		log:                  log,
		validatorAgentID:     validatorAgentID,
	}
	c.msgWrapper = gpa.NewMsgWrapper(msgTypeWrapped, c.msgWrapperFunc)
	c.subMempool = NewSyncMempool(c)
	c.subStateMgr = NewSyncStateMgr(c)
	c.subNodeconn = NewSyncNodeconn(c)
	c.subDistributedSignature = NewSyncDistributedSignature(c)
	c.subACS = NewSyncACS(c)
	c.subRND = NewSyncRND(int(dkShare.BLSThreshold()), c)
	c.subVM = NewSyncVM(c)
	c.subTX = NewSyncTX(c)
	c.term = newTermCondition(
		c.uponTerminationCondition,
	)
	return c
}

func (c *Consensus) SwapOutBuffer() []gpa.MessageOut {
	return c.out.Swap()
}

// Used to select a target subsystem for a wrapped message received.
func (c *Consensus) msgWrapperFunc(subsystem byte, index int) (gpa.GPA, error) {
	if subsystem == subsystemTypeDistributedSignature {
		if index != 0 {
			return nil, fmt.Errorf("unexpected DistributedSignature index: %v", index)
		}
		return c.distributedSignature, nil
	}
	if subsystem == subsystemTypeACS {
		if index != 0 {
			return nil, fmt.Errorf("unexpected ACS index: %v", index)
		}
		return c.acs, nil
	}
	return nil, fmt.Errorf("unexpected subsystem: %v", subsystem)
}

func (c *Consensus) InputProposal(baseAnchor *isc.StateAnchor) {
	defer c.wrapSubsystemMessages()
	c.log.LogInfof("Consensus started, received %s", baseAnchor)
	c.subNodeconn.HaveInputAnchor(baseAnchor)
	c.subMempool.BaseAnchorReceived(baseAnchor)
	c.subStateMgr.ProposedBaseAnchorReceived(baseAnchor)
	c.subDistributedSignature.InitialInputReceived()
}

func (c *Consensus) InputRotateTo(address *iotago.Address) {
	// We can update the rotation address while consensus is running.
	// New value will be used, if decision has not been made yet.
	c.rotateTo = address
}

func (c *Consensus) InputMempoolProposal(requestRefs []*isc.RequestRef) {
	defer c.wrapSubsystemMessages()
	c.subMempool.ProposalReceived(requestRefs)
}

func (c *Consensus) InputMempoolRequests(requests []isc.Request) {
	defer c.wrapSubsystemMessages()
	c.subMempool.RequestsReceived(requests)
}

func (c *Consensus) InputStateMgrProposalConfirmed() {
	defer c.wrapSubsystemMessages()
	c.subStateMgr.StateProposalConfirmedByStateMgr()
}

func (c *Consensus) InputStateMgrDecidedVirtualState(chainState state.State) {
	defer c.wrapSubsystemMessages()
	c.subStateMgr.DecidedVirtualStateReceived(chainState)
}

func (c *Consensus) InputStateMgrBlockSaved(block state.Block) {
	defer c.wrapSubsystemMessages()
	c.subStateMgr.BlockSaved(block)
}

func (c *Consensus) InputTimeData(timeData time.Time) {
	defer c.wrapSubsystemMessages()
	c.subACS.TimeDataReceived(timeData)
}

func (c *Consensus) InputL1Info(gasCoins []*coin.CoinWithRef, l1params *parameters.L1Params) {
	defer c.wrapSubsystemMessages()
	c.subNodeconn.HaveL1Info(gasCoins, l1params)
}

func (c *Consensus) InputVMResult(task *vm.VMTaskResult) {
	defer c.wrapSubsystemMessages()
	c.subVM.VMResultReceived(task)
}

// Message implements the gpa.GPA interface.
// Here we route all the messages.
func (c *Consensus) Message(msg gpa.MessageIn) {
	defer c.wrapSubsystemMessages()
	switch msgT := msg.Payload.(type) {
	case *msgBLSPartialSig:
		c.subRND.BLSPartialSigReceived(msg.Sender, msgT.partialSig)
	case *gpa.WrappingMsg:
		err := c.msgWrapper.DelegateMessageIn(gpa.AsTypedMessageIn[*gpa.WrappingMsg](msg))
		if err != nil {
			c.log.LogWarnf("unexpected wrapped message: %w", err)
			return
		}
		switch msgT.Subsystem() {
		case subsystemTypeACS:
			c.subACS.ACSOutputReceived(c.acs.Output())
		case subsystemTypeDistributedSignature:
			c.subDistributedSignature.DistributedSignatureReady(c.distributedSignature.Output())
		default:
			c.log.LogWarnf("unexpected subsystem after check: %+v", msg)
			return
		}
	default:
		panic(fmt.Errorf("unexpected message: %v", msg))
	}
}

func (c *Consensus) wrapSubsystemMessages() {
	c.out.PutAll(lo.Must(c.msgWrapper.WrapMessagesOut(subsystemTypeACS, 0)))
	c.out.PutAll(lo.Must(c.msgWrapper.WrapMessagesOut(subsystemTypeDistributedSignature, 0)))
}

func (c *Consensus) Output() *Output {
	return c.output // Always non-nil.
}

func (c *Consensus) StatusString() string {
	// We con't include RND here, maybe that's less important, and visible from the VM status.
	return fmt.Sprintf("{consImpl⟨%v⟩,%v,%v,%v,%v,%v,%v,%v}",
		c.output.Status,
		c.subStateMgr.String(),
		c.subMempool.String(),
		c.subNodeconn.String(),
		c.subDistributedSignature.String(),
		c.subACS.String(),
		c.subVM.String(),
		c.subTX.String(),
	)
}

////////////////////////////////////////////////////////////////////////////////
// MP -- MemPool

func (c *Consensus) uponMempoolProposalInputsReady(baseAnchor *isc.StateAnchor) {
	if baseAnchor == nil {
		// If the base Anchor is nil, we are not going to propose any requests.
		c.subMempool.ProposalReceived([]*isc.RequestRef{})
		return
	}
	c.output.NeedMempoolProposal = baseAnchor
}

func (c *Consensus) uponMempoolProposalReceived(requestRefs []*isc.RequestRef) {
	c.output.NeedMempoolProposal = nil
	c.subACS.MempoolRequestsReceived(requestRefs)
	c.subNodeconn.HaveRequests()
}

func (c *Consensus) uponMempoolRequestsNeeded(requestRefs []*isc.RequestRef) {
	c.output.NeedMempoolRequests = requestRefs
}

func (c *Consensus) uponMempoolRequestsReceived(requests []isc.Request) {
	c.output.NeedMempoolRequests = nil
	c.subVM.RequestsReceived(requests)
}

////////////////////////////////////////////////////////////////////////////////
// SM -- StateManager

func (c *Consensus) uponStateMgrStateProposalQueryInputsReady(baseAnchor *isc.StateAnchor) {
	if baseAnchor == nil {
		// Don't wait for the state if no base Anchor is known.
		c.subStateMgr.StateProposalConfirmedByStateMgr()
		return
	}
	c.output.NeedStateMgrStateProposal = baseAnchor
}

func (c *Consensus) uponStateMgrStateProposalReceived(proposedAnchor *isc.StateAnchor) {
	c.output.NeedStateMgrStateProposal = nil
	c.subACS.StateProposalReceived(proposedAnchor)
	c.subNodeconn.HaveState()
}

func (c *Consensus) uponStateMgrDecidedStateQueryInputsReady(decidedBaseAnchor *isc.StateAnchor) {
	c.output.NeedStateMgrDecidedState = decidedBaseAnchor
}

func (c *Consensus) uponStateMgrDecidedStateReceived(chainState state.State) {
	c.output.NeedStateMgrDecidedState = nil
	c.subVM.DecidedStateReceived(chainState)
}

func (c *Consensus) uponStateMgrSaveProducedBlockInputsReady(producedBlock state.StateDraft) {
	if producedBlock == nil {
		// Don't have a block to save in the case of self-governed rotation.
		// So mark it as saved immediately.
		c.subStateMgr.BlockSaved(nil)
		return
	}
	c.output.NeedStateMgrSaveBlock = producedBlock
}

func (c *Consensus) uponStateMgrSaveProducedBlockDone(block state.Block) {
	c.output.NeedStateMgrSaveBlock = nil
	c.subTX.BlockSaved(block)
}

////////////////////////////////////////////////////////////////////////////////
// NC

func (c *Consensus) uponNodeconnInputsReady(anchor *isc.StateAnchor) {
	if anchor == nil {
		c.log.LogDebugf("ACS got ⊥ as input, no L1 info can be fetched.")
		c.subACS.L1InfoReceived([]*coin.CoinWithRef{}, nil)
		return
	}
	c.output.NeedNodeConnL1Info = anchor
}

func (c *Consensus) uponNodeconnOutputReady(gasCoins []*coin.CoinWithRef, l1params *parameters.L1Params) {
	c.log.LogDebugf("L1 info received, gasCoins=%v, l1Params=%v", gasCoins, l1params)
	c.output.NeedNodeConnL1Info = nil
	c.subACS.L1InfoReceived(gasCoins, l1params)
}

////////////////////////////////////////////////////////////////////////////////
// DistributedSignature

func (c *Consensus) uponDistributedSignatureInitialInputsReady() {
	c.log.LogDebugf("uponDistributedSignatureInitialInputsReady")
	c.distributedSignature.Start()
	c.subDistributedSignature.DistributedSignatureReady(c.distributedSignature.Output())
}

func (c *Consensus) uponDistributedSignatureIndexProposalReady(indexProposal []int) {
	c.log.LogDebugf("uponDistributedSignatureIndexProposalReady")
	c.subACS.DistributedSignatureIndexProposalReceived(indexProposal)
}

func (c *Consensus) uponDistributedSignatureSigningInputsReceived(decidedIndexProposals map[gpa.NodeID][]int, messageToSign []byte) {
	c.log.LogDebugf("uponDistributedSignatureSigningInputsReceived(decidedIndexProposals=%+v, H(messageToSign)=%v)", decidedIndexProposals, hashing.HashDataBlake2b(messageToSign))
	c.distributedSignature.InputDecided(decidedIndexProposals, messageToSign)
	c.subDistributedSignature.DistributedSignatureReady(c.distributedSignature.Output())
}

func (c *Consensus) uponDistributedSignatureOutputReady(signature []byte) {
	c.log.LogDebugf("uponDistributedSignatureOutputReady")
	c.subTX.SignatureReceived(signature)
}

////////////////////////////////////////////////////////////////////////////////
// ACS

func (c *Consensus) uponACSInputsReceived(
	baseAnchor *isc.StateAnchor, // Can be nil.
	requestRefs []*isc.RequestRef,
	distSignIndexProposal []int,
	timeData time.Time,
	gasCoins []*coin.CoinWithRef, // Can be nil.
	l1params *parameters.L1Params, // Can be nil.
) {
	rotateTo := c.rotateTo
	if rotateTo != nil && rotateTo.Equals(*c.dkShare.GetAddress().AsIotaAddress()) {
		// Do not propose to rotate to the existing committee.
		rotateTo = nil
	}
	batchProposal := batchproposal.NewBatchProposal(
		*c.dkShare.GetIndex(),
		baseAnchor, // Will be NIL in the case of ⊥ proposal.
		util.NewFixedSizeBitVector(c.dkShare.GetN()).SetBits(distSignIndexProposal),
		rotateTo,
		timeData,
		c.validatorAgentID,
		requestRefs, // Will be [] in the case of ⊥ proposal.
		gasCoins,    // Will be NIL in the case of ⊥ proposal.
		l1params,    // Will be NIL in the case of ⊥ proposal.
	)
	c.acs.Input(batchProposal.Bytes())
	c.subACS.ACSOutputReceived(c.acs.Output())
}

func (c *Consensus) uponACSOutputReceived(outputValues map[gpa.NodeID][]byte) {
	aggr := batchproposal.AggregateBatchProposals(outputValues, c.nodeIDs, c.f, c.log)
	if aggr.ShouldBeSkipped() {
		// Cannot proceed with such proposals.
		// Have to retry the consensus after some time with the next log index.
		c.log.LogInfof("Terminating consensus with status=Skipped, there is no way to aggregate batch proposal.")
		c.output.Status = Skipped
		c.term.haveOutputProduced()
		return
	}
	bao := aggr.DecidedBaseAnchor()
	baoID := bao.GetObjectRef()
	reqs := aggr.DecidedRequestRefs()
	c.log.LogDebugf("ACS decision: baseAnchor=%v, requests=%v", bao, reqs)
	if aggr.DecidedRotateTo() != nil {
		c.log.LogDebugf("Will rotate to %v", aggr.DecidedRotateTo().ToHex())
		rotationPTB := vmtxbuilder.NewAnchorTransactionBuilder(bao.ISCPackage(), bao, c.dkShare.GetAddress())
		rotationPTB.RotationTransaction(aggr.DecidedRotateTo())
		rotationPTX := rotationPTB.BuildTransactionEssence(bao.GetStateMetadata(), 0)
		rotationTXD := c.makeTransactionData(&rotationPTX, aggr)
		rotationTXB := c.makeTransactionSigningBytes(rotationTXD)
		c.log.LogDebugf("Rotation TxDataBytes=%s", hex.EncodeToString(c.makeTransactionDataBytes(rotationTXD)))
		c.subTX.UnsignedTXReceived(rotationTXD)
		c.subTX.BlockSaved(nil)
		c.subTX.AnchorDecided(bao)
		c.subDistributedSignature.MessageToSignReceived(rotationTXB)
		c.subDistributedSignature.DecidedIndexProposalsReceived(aggr.DecidedDistributedSignatureIndexProposals())
		return
	}
	c.subMempool.RequestsNeeded(reqs)
	c.subStateMgr.DecidedVirtualStateNeeded(bao)
	c.subVM.DecidedBatchProposalsReceived(aggr)
	c.subRND.CanProceed(baoID.Bytes())
	c.subDistributedSignature.DecidedIndexProposalsReceived(aggr.DecidedDistributedSignatureIndexProposals())
}

func (c *Consensus) uponACSTerminated() {
	c.term.haveAcsTerminated()
}

////////////////////////////////////////////////////////////////////////////////
// RND

func (c *Consensus) uponRNDInputsReady(dataToSign []byte) {
	sigShare, err := c.dkShare.BLSSignShare(dataToSign)
	if err != nil {
		panic(fmt.Errorf("cannot sign share for randomness: %w", err))
	}
	for _, nid := range c.nodeIDs {
		c.out.Put(newMsgBLSPartialSig(c.blsSuite, nid, sigShare))
	}
}

func (c *Consensus) uponRNDSigSharesReady(dataToSign []byte, partialSigs map[gpa.NodeID][]byte) bool {
	partialSigArray := make([][]byte, 0, len(partialSigs))
	for nid := range partialSigs {
		partialSigArray = append(partialSigArray, partialSigs[nid])
	}
	sig, err := c.dkShare.BLSRecoverMasterSignature(partialSigArray, dataToSign)
	if err != nil {
		c.log.LogWarnf("Cannot reconstruct BLS signature from %v/%v sigShares: %v", len(partialSigs), c.dkShare.GetN(), err)
		return false // Continue to wait for other sig shares.
	}
	c.subVM.RandomnessReceived(hashing.HashDataBlake2b(sig.Signature.Bytes()))
	return true
}

////////////////////////////////////////////////////////////////////////////////
// VM

func (c *Consensus) uponVMInputsReceived(aggregatedProposals *batchproposal.AggregatedBatchProposals, randomness *hashing.HashValue, requests []isc.Request) {
	decidedBaseAnchor := aggregatedProposals.DecidedBaseAnchor()
	stateAnchor := isc.NewStateAnchor(decidedBaseAnchor.Anchor(), decidedBaseAnchor.ISCPackage())
	gasCoins := aggregatedProposals.AggregatedGasCoins()
	// FIXME we need only one
	if len(gasCoins) != 1 {
		panic("FIXME we support only one gas coin now")
	}
	gasCoin := gasCoins[0]

	c.output.NeedVMResult = &vm.VMTask{
		Processors:           c.processorCache,
		Anchor:               &stateAnchor,
		GasCoin:              gasCoin,
		L1Params:             aggregatedProposals.AggregatedL1Params(),
		Store:                c.chainStore,
		Requests:             aggregatedProposals.OrderedRequests(requests, *randomness),
		Timestamp:            aggregatedProposals.AggregatedTime(),
		Entropy:              *randomness,
		ValidatorFeeTarget:   aggregatedProposals.ValidatorFeeTarget(*randomness),
		EstimateGasMode:      false,
		EnableGasBurnLogging: false,
		Log:                  c.log.NewChildLogger("VM"),
		Migrations:           allmigrations.DefaultScheme,
	}
	c.subTX.AnchorDecided(decidedBaseAnchor)
}

func (c *Consensus) uponVMOutputReceived(vmResult *vm.VMTaskResult, aggregatedProposals *batchproposal.AggregatedBatchProposals) {
	c.output.NeedVMResult = nil
	if len(vmResult.RequestResults) == 0 {
		// No requests were processed, don't have what to do.
		// Will need to retry the consensus with the next log index some time later.
		c.log.LogInfof("Terminating consensus with status=Skipped, 0 requests processed.")
		c.output.Status = Skipped
		c.term.haveOutputProduced()
		return
	}

	// Make sure all the fields in the TX are ordered properly.
	unsignedTX := vmResult.UnsignedTransaction
	txData := c.makeTransactionData(&unsignedTX, aggregatedProposals)
	txBytes := c.makeTransactionSigningBytes(txData)
	c.log.LogDebugf("VM produced TxDataBytes=%s", hex.EncodeToString(c.makeTransactionDataBytes(txData)))
	c.subStateMgr.BlockProduced(vmResult.StateDraft)
	c.subTX.UnsignedTXReceived(txData)
	c.subDistributedSignature.MessageToSignReceived(txBytes)
}

////////////////////////////////////////////////////////////////////////////////
// TX

func (c *Consensus) makeTransactionData(pt *iotago.ProgrammableTransaction, aggregatedProposals *batchproposal.AggregatedBatchProposals) *iotago.TransactionData {
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

func (c *Consensus) makeTransactionDataBytes(txData *iotago.TransactionData) []byte {
	txnBytes, err := bcs.Marshal(txData)
	if err != nil {
		panic(fmt.Errorf("uponVMOutputReceived: cannot serialize the tx: %w", err))
	}
	return txnBytes
}

func (c *Consensus) makeTransactionSigningBytes(txData *iotago.TransactionData) []byte {
	txnBytes := c.makeTransactionDataBytes(txData)
	txnBytes = iotasigner.MessageWithIntent(iotasigner.DefaultIntent(), txnBytes)
	txnBytesHash := blake2b.Sum256(txnBytes)
	return txnBytesHash[:]
}

// Everything is ready for the output TX, produce it.
func (c *Consensus) uponTXInputsReady(decidedAnchor *isc.StateAnchor, unsignedTX *iotago.TransactionData, block state.Block, signature []byte) {
	suiSignature := cryptolib.NewSignature(c.dkShare.GetSharedPublic(), signature).AsIotaSignature()
	signedTX := iotasigner.NewSignedTransaction(unsignedTX, suiSignature)
	c.output.Result = &Result{
		DecidedAnchor: decidedAnchor,
		Transaction:   signedTX,
		Block:         block,
	}
	c.output.Status = Completed
	c.log.LogInfof("Terminating consensus with status=Completed")
	c.term.haveOutputProduced()
}

////////////////////////////////////////////////////////////////////////////////
// TERM

func (c *Consensus) uponTerminationCondition() {
	c.output.Terminated = true
}
