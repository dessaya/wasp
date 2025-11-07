// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Package acss implements "Asynchronous Complete Secret Sharing" as described in
//
//	https://iotaledger.github.io/crypto-tss/talks/async-dkg/slides-async-dkg.html#/5/6
//
// Here is a copy of the pseudo code from the slide mentioned above (just in case):
//
// > // dealer with input s
// > sample random polynomial ϕ such that ϕ(0) = s
// > C, S := VSS.Share(ϕ, f+1, n)
// > E := [PKI.Enc(S[i], pkᵢ) for each party i]
// >
// > // party i (including the dealer)
// > RBC(C||E)
// > sᵢ := PKI.Dec(eᵢ, skᵢ)
// > if decrypt fails or VSS.Verify(C, i, sᵢ) == false:
// >   send <IMPLICATE, i, skᵢ> to all parties
// > else:
// >   send <OK>
// >
// > on receiving <OK> from n-f parties:
// >   send <READY> to all parties
// >
// > on receiving <READY> from f+1 parties:
// >   send <READY> to all parties
// >
// > on receiving <READY> from n-f parties:
// >   if sᵢ is valid:
// >     out = true
// >     output sᵢ
// >
// > on receiving <IMPLICATE, j, skⱼ>:
// >   sⱼ := PKI.Dec(eⱼ, skⱼ)
// >   if decrypt fails or VSS.Verify(C, j, sⱼ) == false:
// >     if out == true:
// >       send <RECOVER, i, skᵢ> to all parties
// >       return
// >
// >     on receiving <RECOVER, j, skⱼ>:
// >       sⱼ := PKI.Dec(eⱼ, skⱼ)
// >       if VSS.Verify(C, j, sⱼ): T = T ∪ {sⱼ}
// >
// >     wait until len(T) >= f+1:
// >       sᵢ = SSS.Recover(T, f+1, n)(i)
// >       out = true
// >       output sᵢ
//
// On the adaptations and sources:
//
// > More details and references to the papers are bellow:
// >
// > Here the references for the Asynchronous Secret-Sharing that I was referring to.
// > It is purely based on (Feldman) Verifiable Secret Sharing and does not rely on any PVSS schemes
// > requiring fancy NIZKP (and thus trades network-complexity vs computational-complexity):
// >
// >   * [1], Section IV. A. we use the ACSS scheme from [2] but replace its Pedersen
// >     commitment with a Feldman polynomial commitment to achieve Homomorphic-Partial-Commitment.
// >
// >   * In [2], Section 5.3. they explain the Pedersen-based hbACSS0 and give some proof sketch.
// >     The complete description and analysis of hbACSS0 can be found in [3]. However, as mentioned
// >     before they use Kate-commitments instead of Feldman/Pedersen. This has better message
// >     complexity especially when multiple secrets are shared at the same time, but in our case
// >     that would need to be replaced with Feldman making it much simpler and not losing any security.
// >     Actually, [3] is just a pre-print, the official published version is [4], but [4] also contains
// >     other, non-relevant, variants like hbACSS1 and hbACSS2 and much more analysis.
// >     So, I found [3] a bit more helpful, although it is just the preliminary version.
// >     They also provide their reference implementation in [5], which is also what the
// >     authors of [1] used for their practical DKG results.
// >
// > [1] Practical Asynchronous Distributed Key Generation https://eprint.iacr.org/2021/1591
// > [2] Asynchronous Data Dissemination and its Applications https://eprint.iacr.org/2021/777
// > [3] Brief Note: Asynchronous Verifiable Secret Sharing with Optimal Resilience and Linear Amortized Overhead https://arxiv.org/pdf/1902.06095.pdf
// > [4] hbACSS: How to Robustly Share Many Secrets https://eprint.iacr.org/2021/159
// > [5] https://github.com/tyurek/hbACSS
//
// A PoC implementation: <https://github.com/Wollac/async.go>.
//
// The Crypto part shown the pseudo-code above is replaced in the implementation with the
// scheme allowing to keep the private keys secret. The scheme implementation is taken
// from the PoC mentioned above. It is described in <https://hackmd.io/@CcRtfCBnRbW82-AdbFJUig/S1qcPiUN5>.
package acss

import (
	"errors"
	"fmt"
	"math"

	"github.com/samber/lo"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"

	bcs "github.com/iotaledger/bcs-go"
	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/gpa/acss/crypto"
	"github.com/iotaledger/wasp/v2/packages/gpa/rbc/bracha"
)

const (
	subsystemRBC byte = iota
)

type Output struct {
	PriShare *share.PriShare // Private share, received by this instance.
	Commits  []kyber.Point   // Feldman's commitment to the shared polynomial.
}

type ACSS struct {
	out           gpa.OutBuffer
	suite         suites.Suite
	n             int
	f             int
	me            gpa.NodeID
	mySK          kyber.Scalar
	myPK          kyber.Point
	myIdx         int
	dealer        gpa.NodeID                                 // A node that is recognized as a dealer.
	dealCB        func(int, []byte) []byte                   // Callback to be called on the encrypted deals (for tests actually).
	peerPKs       map[gpa.NodeID]kyber.Point                 // Peer public keys.
	peerIdx       []gpa.NodeID                               // Particular order of the nodes (position in the polynomial).
	rbc           *bracha.RBC                                // RBC to share `C||E`.
	rbcOut        *crypto.Deal                               // Deal broadcasted by the dealer.
	voteOKRecv    map[gpa.NodeID]bool                        // A set of received OK votes.
	voteREADYRecv map[gpa.NodeID]bool                        // A set of received READY votes.
	voteREADYSent bool                                       // Have we sent our READY vote?
	pendingIRMsgs []gpa.TypedMessageIn[*msgImplicateRecover] // I/R messages are buffered, if the RBC is not completed yet.
	implicateRecv map[gpa.NodeID]bool                        // To check, that implicate only received once from a node.
	recoverRecv   map[gpa.NodeID]*share.PriShare             // Private shares from the RECOVER messages.
	outS          *share.PriShare                            // Our share of the secret (decrypted from rbcOutE).
	output        bool
	msgWrapper    *gpa.MsgWrapper
	log           log.Logger
}

var _ gpa.GPA = &ACSS{}

func New(
	suite suites.Suite, // Ed25519
	peers []gpa.NodeID, // Participating nodes in a specific order.
	peerPKs map[gpa.NodeID]kyber.Point, // Public keys for all the peers.
	f int, // Max number of expected faulty nodes.
	me gpa.NodeID, // ID of this node.
	mySK kyber.Scalar, // Secret Key of this node.
	dealer gpa.NodeID, // The dealer node for this protocol instance.
	dealCB func(int, []byte) []byte, // For tests only: interceptor for the deal to be shared.
	log log.Logger, // A logger to use.
) *ACSS {
	n := len(peers)
	if dealCB == nil {
		dealCB = func(i int, b []byte) []byte { return b }
	}
	a := &ACSS{
		suite:         suite,
		n:             n,
		f:             f,
		me:            me,
		mySK:          mySK,
		myPK:          peerPKs[me],
		myIdx:         -1, // Updated bellow.
		dealer:        dealer,
		dealCB:        dealCB,
		peerPKs:       peerPKs,
		peerIdx:       peers,
		rbc:           bracha.New(peers, f, me, dealer, math.MaxInt, func(b []byte) bool { return true }, log), // TODO: Provide meaningful maxMsgSize
		rbcOut:        nil,                                                                                     // Will be set on output from the RBC.
		voteOKRecv:    map[gpa.NodeID]bool{},
		voteREADYRecv: map[gpa.NodeID]bool{},
		voteREADYSent: false,
		pendingIRMsgs: []gpa.TypedMessageIn[*msgImplicateRecover]{},
		implicateRecv: map[gpa.NodeID]bool{},
		recoverRecv:   map[gpa.NodeID]*share.PriShare{},
		outS:          nil,
		output:        false,
		log:           log,
	}
	a.msgWrapper = gpa.NewMsgWrapper(msgTypeWrapped, func(subsystem byte, index int) (gpa.GPA, error) {
		if subsystem == subsystemRBC {
			if index != 0 {
				return nil, fmt.Errorf("unknown rbc index: %v", index)
			}
			return a.rbc, nil
		}
		return nil, fmt.Errorf("unknown subsystem: %v", subsystem)
	})
	if a.myIdx = a.peerIndex(me); a.myIdx == -1 {
		panic("i'm not in the peer list")
	}
	return a
}

// SwapOutBuffer implements gpa.GPA.
func (a *ACSS) SwapOutBuffer() []gpa.MessageOut {
	return a.out.Swap()
}

// Input for the algorithm is the secret to share.
// It can be provided by the dealer only.
func (a *ACSS) Input(secretToShare kyber.Scalar) {
	if a.me != a.dealer {
		panic(errors.New("only dealer can initiate the sharing"))
	}
	a.handleInput(secretToShare)
}

// Receive all the messages and route them to the appropriate handlers.
func (a *ACSS) Message(msg gpa.MessageIn) {
	switch m := msg.Payload.(type) {
	case *gpa.WrappingMsg:
		switch m.Subsystem() {
		case subsystemRBC:
			a.handleRBCMessage(gpa.AsTypedMessageIn[*gpa.WrappingMsg](msg))
		default:
			a.log.LogWarnf("unexpected wrapped message subsystem: %+v", m)
		}
	case *msgVote:
		switch m.kind {
		case msgVoteOK:
			a.handleVoteOK(gpa.AsTypedMessageIn[*msgVote](msg))
		case msgVoteREADY:
			a.handleVoteREADY(gpa.AsTypedMessageIn[*msgVote](msg))
		default:
			a.log.LogWarnf("unexpected vote message: %+v", m)
		}
	case *msgImplicateRecover:
		a.handleImplicateRecoverReceived(gpa.AsTypedMessageIn[*msgImplicateRecover](msg))
	default:
		panic(fmt.Errorf("unexpected message: %+v", msg))
	}
}

// > // dealer with input s
// > sample random polynomial ϕ such that ϕ(0) = s
// > C, S := VSS.Share(ϕ, f+1, n)
// > E := [PKI.Enc(S[i], pkᵢ) for each party i]
// >
// > // party i (including the dealer)
// > RBC(C||E)
func (a *ACSS) handleInput(secretToShare kyber.Scalar) {
	pubKeys := make([]kyber.Point, 0)
	for _, peerID := range a.peerIdx {
		pubKeys = append(pubKeys, a.peerPKs[peerID])
	}
	deal := crypto.NewDeal(a.suite, pubKeys, secretToShare)
	data, err := deal.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}

	// > RBC(C||E)
	rbcCEPayloadBytes := bcs.MustMarshal(&msgRBCCEPayload{suite: a.suite, data: data})
	a.rbc.Input(rbcCEPayloadBytes)
	a.tryHandleRBCTermination(false)
}

// Delegate received messages to the RBC and handle its output.
//
// > // party i (including the dealer)
// > RBC(C||E)
func (a *ACSS) handleRBCMessage(m gpa.TypedMessageIn[*gpa.WrappingMsg]) {
	wasOut := a.rbc.Output() != nil // To send the msgRBCCEOutput message once (for perf reasons).
	a.rbc.Message(m.Payload.WrappedIn(m.Sender))
	a.tryHandleRBCTermination(wasOut)
}

func (a *ACSS) tryHandleRBCTermination(wasOut bool) {
	msgs, err := a.msgWrapper.WrapMessagesOut(subsystemRBC, 0)
	if err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	a.out.PutAll(msgs)

	if out := a.rbc.Output(); !wasOut && out != nil {
		// Send the result for self as a message (maybe the code will look nicer this way).
		outParsed, err := bcs.UnmarshalInto(out, &msgRBCCEPayload{suite: a.suite})
		if err != nil {
			outParsed = &msgRBCCEPayload{err: err}
		}
		a.handleRBCOutput(outParsed)
	}
}

// Upon receiving the RBC output...
//
// > sᵢ := PKI.Dec(eᵢ, skᵢ)
// > if decrypt fails or VSS.Verify(C, i, sᵢ) == false:
// >   send <IMPLICATE, i, skᵢ> to all parties
// > else:
// >   send <OK>
func (a *ACSS) handleRBCOutput(rbcOutput *msgRBCCEPayload) {
	if a.outS != nil || a.rbcOut != nil {
		// Take the first RBC output only.
		return
	}
	//
	// Store the broadcast result and process pending IMPLICATE/RECOVER messages, if any.
	if rbcOutput.err != nil {
		a.broadcastImplicate(rbcOutput.err)
		return
	}
	deal, err := crypto.DealUnmarshalBinary(a.suite, a.n, rbcOutput.data)
	if err != nil {
		a.broadcastImplicate(errors.New("cannot unmarshal msgRBCCEPayload.data"))
		return
	}
	a.rbcOut = deal
	a.handleImplicateRecoverPending()
	//
	// Process the RBC output, as described above.
	secret := crypto.Secret(a.suite, a.rbcOut.PubKey, a.mySK)
	myShare, err := crypto.DecryptShare(a.suite, a.rbcOut, a.myIdx, secret)
	if err != nil {
		a.broadcastImplicate(err)
		return
	}
	a.outS = myShare
	a.tryOutput() // Maybe the READY messages are already received.
	a.broadcastVote(msgVoteOK)
	a.handleImplicateRecoverPending()
}

// > on receiving <OK> from n-f parties:
// >   send <READY> to all parties
func (a *ACSS) handleVoteOK(msg gpa.TypedMessageIn[*msgVote]) {
	a.voteOKRecv[msg.Sender] = true
	count := len(a.voteOKRecv)
	if !a.voteREADYSent && count >= (a.n-a.f) {
		a.voteREADYSent = true
		a.broadcastVote(msgVoteREADY)
	}
}

// > on receiving <READY> from f+1 parties:
// >   send <READY> to all parties
// >
// > on receiving <READY> from n-f parties:
// >   if sᵢ is valid:
// >     out = true
// >     output sᵢ
func (a *ACSS) handleVoteREADY(msg gpa.TypedMessageIn[*msgVote]) {
	a.voteREADYRecv[msg.Sender] = true
	count := len(a.voteREADYRecv)
	if !a.voteREADYSent && count >= (a.f+1) {
		a.broadcastVote(msgVoteREADY)
		a.voteREADYSent = true
	}
	a.tryOutput()
	a.handleImplicateRecoverPending()
}

// It is possible that we are receiving IMPLICATE/RECOVER messages before our RBC is completed.
// We store these messages for processing after that, if RBC is not done and process it otherwise.
func (a *ACSS) handleImplicateRecoverReceived(msg gpa.TypedMessageIn[*msgImplicateRecover]) {
	if a.rbcOut == nil {
		a.pendingIRMsgs = append(a.pendingIRMsgs, msg)
		return
	}
	switch msg.Payload.kind {
	case msgImplicateRecoverKindIMPLICATE:
		a.handleImplicate(msg)
	case msgImplicateRecoverKindRECOVER:
		a.handleRecover(msg)
	default:
		a.log.LogWarnf("handleImplicateRecoverReceived: unexpected msgImplicateRecover.kind=%v, message: %+v", msg.Payload.kind, msg)
	}
}

func (a *ACSS) handleImplicateRecoverPending() {
	//
	// Only process the IMPLICATE/RECOVER messages, if this node has RBC completed.
	if a.rbcOut == nil {
		return
	}
	postponedIRMsgs := []gpa.TypedMessageIn[*msgImplicateRecover]{}
	for _, m := range a.pendingIRMsgs {
		switch m.Payload.kind {
		case msgImplicateRecoverKindIMPLICATE:
			// Only handle the IMPLICATE messages when output is already produced to implement the following:
			//
			// >     if out == true:
			// >       send <RECOVER, i, skᵢ> to all parties
			// >       return
			//
			if a.output {
				a.handleImplicate(m)
			} else {
				postponedIRMsgs = append(postponedIRMsgs, m)
			}
		case msgImplicateRecoverKindRECOVER:
			a.handleRecover(m)
		default:
			a.log.LogWarnf("handleImplicateRecoverReceived: unexpected msgImplicateRecover.kind=%v, message: %+v", m.Payload.kind, m)
			// Don't return here, we are just dropping incorrect message.
		}
	}
	a.pendingIRMsgs = postponedIRMsgs
}

// Here the RBC is assumed to be completed already, OUT is set and the private key is checked.
//
// > on receiving <IMPLICATE, j, skⱼ>:
// >   sⱼ := PKI.Dec(eⱼ, skⱼ)
// >   if decrypt fails or VSS.Verify(C, j, sⱼ) == false:
// >     if out == true:
// >       send <RECOVER, i, skᵢ> to all parties
// >       return
//
// NOTE: We assume `if out == true:` stands for a wait for such condition.
func (a *ACSS) handleImplicate(msg gpa.TypedMessageIn[*msgImplicateRecover]) {
	peerIndex := a.peerIndex(msg.Sender)
	if peerIndex == -1 {
		a.log.LogWarnf("implicate received from unknown peer: %v", msg.Sender)
		return
	}
	//
	// Check message duplicates.
	if _, ok := a.implicateRecv[msg.Sender]; ok {
		// Received the implicate before, just ignore it.
		return
	}
	a.implicateRecv[msg.Sender] = true
	//
	// Check implicate.
	secret, err := crypto.CheckImplicate(a.suite, a.rbcOut.PubKey, a.peerPKs[msg.Sender], msg.Payload.data)
	if err != nil {
		a.log.LogWarnf("Invalid implication received: %v", err)
		return
	}
	_, err = crypto.DecryptShare(a.suite, a.rbcOut, peerIndex, secret)
	if err == nil {
		// if we are able to decrypt the share, the implication is not correct
		a.log.LogWarn("encrypted share is valid")
		return
	}
	//
	// Create the reveal message.
	a.broadcastRecover()
}

// Here the RBC is assumed to be completed already and the private key is checked.
//
// >     on receiving <RECOVER, j, skⱼ>:
// >       sⱼ := PKI.Dec(eⱼ, skⱼ)
// >       if VSS.Verify(C, j, sⱼ): T = T ∪ {sⱼ}
// >
// >     wait until len(T) >= f+1:
// >       sᵢ = SSS.Recover(T, f+1, n)(i)
// >       out = true
// >       output sᵢ
func (a *ACSS) handleRecover(msg gpa.TypedMessageIn[*msgImplicateRecover]) {
	if a.output {
		// Ignore the RECOVER messages, if we are done with the output.
		return
	}
	peerIndex := a.peerIndex(msg.Sender)
	if peerIndex == -1 {
		a.log.LogWarnf("Recover received from unexpected sender: %v", msg.Sender)
		return
	}
	if _, ok := a.recoverRecv[msg.Sender]; ok {
		a.log.LogWarnf("Recover was already received from %v", msg.Sender)
		return
	}

	peerSecret, err := crypto.DecryptShare(a.suite, a.rbcOut, peerIndex, msg.Payload.data)
	if err != nil {
		a.log.LogWarn("invalid secret revealed")
		return
	}
	a.recoverRecv[msg.Sender] = peerSecret

	// >     wait until len(T) >= f+1:
	// >       sᵢ = SSS.Recover(T, f+1, n)(i)
	// >       out = true
	// >       output sᵢ
	if len(a.recoverRecv) >= a.f+1 {
		priShares := []*share.PriShare{}
		for i := range a.recoverRecv {
			priShares = append(priShares, a.recoverRecv[i])
		}

		myPriShare, err := crypto.InterpolateShare(a.suite, priShares, a.n, a.myIdx)
		if err != nil {
			a.log.LogWarnf("Failed to recover pri-poly: %v", err)
		}
		a.outS = myPriShare
		a.output = true
		return
	}
}

func (a *ACSS) broadcastVote(voteKind msgVoteKind) {
	a.out.PutAll(lo.Map(a.peerIdx, func(peer gpa.NodeID, _ int) gpa.MessageOut {
		return gpa.NewMessageOut(peer, &msgVote{
			kind: voteKind,
		})
	}))
}

func (a *ACSS) broadcastImplicate(reason error) {
	a.log.LogWarnf("Sending implicate because of: %v", reason)
	implicate := crypto.Implicate(a.suite, a.rbcOut.PubKey, a.mySK)
	a.broadcastImplicateRecover(msgImplicateRecoverKindIMPLICATE, implicate)
}

func (a *ACSS) broadcastRecover() {
	secret := crypto.Secret(a.suite, a.rbcOut.PubKey, a.mySK)
	a.broadcastImplicateRecover(msgImplicateRecoverKindRECOVER, secret)
}

func (a *ACSS) broadcastImplicateRecover(kind msgImplicateKind, data []byte) {
	a.out.PutAll(lo.Map(a.peerIdx, func(peer gpa.NodeID, _ int) gpa.MessageOut {
		return gpa.NewMessageOut(peer, &msgImplicateRecover{
			kind: kind,
			i:    a.myIdx,
			data: data,
		})
	}))
}

func (a *ACSS) tryOutput() {
	count := len(a.voteREADYRecv)
	if count >= (a.n-a.f) && a.outS != nil {
		a.output = true
	}
}

func (a *ACSS) peerIndex(peer gpa.NodeID) int {
	for i := range a.peerIdx {
		if a.peerIdx[i] == peer {
			return i
		}
	}
	return -1
}

func (a *ACSS) Output() *Output {
	if a.output {
		return &Output{
			PriShare: a.outS,
			Commits:  a.rbcOut.Commits,
		}
	}
	return nil
}

func (a *ACSS) StatusString() string {
	return fmt.Sprintf("{ACSS, output=%v, rbc=%v}", a.output, a.rbc.StatusString())
}
