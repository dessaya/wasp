package actors

import (
	"fmt"

	"github.com/samber/lo"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"

	"github.com/iotaledger/wasp/v2/packages/gpa/acss/crypto"
)

// ACSS implements "Asynchronous Complete Secret Sharing" as described in
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
// > More details and references to the papers are below:
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
type ACSS struct {
	Actor
	Output  *Output[*ACSSOutput]
	f       int
	suite   suites.Suite
	peerPKs map[NodeID]kyber.Point
	mySK    kyber.Scalar
}

type ACSSOutput struct {
	PriShare *share.PriShare
	Commits  crypto.Commits
}

const (
	acssMsgTypeOk MessageType = iota
	acssMsgTypeReady
	acssMsgTypeImplicate
	acssMsgTypeRecover
)

type msgACSSOk struct{}

func (m *msgACSSOk) MsgType() MessageType { return acssMsgTypeOk }
func (m *msgACSSOk) String() string       { return "OK" }

type msgACSSReady struct{}

func (m *msgACSSReady) MsgType() MessageType { return acssMsgTypeReady }
func (m *msgACSSReady) String() string       { return "READY" }

type msgACSSImplicate struct {
	DLEQProof []byte
}

func (m *msgACSSImplicate) MsgType() MessageType { return acssMsgTypeImplicate }
func (m *msgACSSImplicate) String() string {
	return fmt.Sprintf("IMPLICATE(%q)", lo.Ellipsis(string(m.DLEQProof), 16))
}

type msgACSSRecover struct {
	RecoverySecret []byte
}

func (m *msgACSSRecover) MsgType() MessageType { return acssMsgTypeRecover }
func (m *msgACSSRecover) String() string {
	return fmt.Sprintf("RECOVER(%q)", lo.Ellipsis(string(m.RecoverySecret), 16))
}

// Constructor.
func NewACSS(
	endpoint *Endpoint,
	f int,
	suite suites.Suite,
	peerPKs map[NodeID]kyber.Point,
	mySK kyber.Scalar,
) *ACSS {
	return &ACSS{
		Actor:   NewActor(endpoint),
		Output:  NewOutput[*ACSSOutput](endpoint.Context()),
		f:       f,
		suite:   suite,
		peerPKs: peerPKs,
		mySK:    mySK,
	}
}

func (a *ACSS) MakeDealAndShare(secret kyber.Scalar) {
	a.ShareDeal(a.MakeDealFromSecret(secret))
}

// MakeDealFromSecret creates a new Deal that can be shared with ShareDeal.
func (a *ACSS) MakeDealFromSecret(secret kyber.Scalar) *crypto.Deal {
	// > // dealer with input s
	// > sample random polynomial ϕ such that ϕ(0) = s
	// > C, S := VSS.Share(ϕ, f+1, n)
	// > E := [PKI.Enc(S[i], pkᵢ) for each party i]
	pubKeys := make([]kyber.Point, 0)
	for _, peerID := range a.Endpoint().Router.Peers {
		pubKeys = append(pubKeys, a.peerPKs[peerID])
	}
	return crypto.NewDeal(a.suite, pubKeys, secret)
}

// ShareDeal implements the dealer's part of the ACSS protocol, which shares the
// given secret with all parties.
func (a *ACSS) ShareDeal(deal *crypto.Deal) {
	a.Go(func() {
		data := lo.Must(deal.MarshalBinary())
		if a.Endpoint().N() == 1 {
			// shortcut for n=1
			secret := crypto.Secret(a.suite, deal.PubKey, a.mySK)
			priShare := lo.Must(crypto.DecryptShare(a.suite, deal, a.Endpoint().MyIndex(), secret))
			a.Output.Set(&ACSSOutput{
				PriShare: priShare,
				Commits:  deal.Commits,
			})
			return
		}
		// > RBC(C||E)
		rbcOut := a.runRBC(a.Endpoint().Me(), func(rbc *ReliableBroadcast) {
			rbc.Broadcast(data)
		})
		a.mainLoop(rbcOut)
	})
}

// Receive implements the receiver's part of the ACSS protocol, which receives
// the shared secret from the dealer.
func (a *ACSS) Receive(dealer NodeID) {
	if a.Endpoint().Me() == dealer {
		panic(fmt.Errorf("dealer cannot call Receive"))
	}
	a.Go(func() {
		// > // party i (including the dealer)
		// > RBC(C||E)
		rbcOut := a.runRBC(dealer, func(rbc *ReliableBroadcast) {
			rbc.Receive()
		})
		a.mainLoop(rbcOut)
	})
}

func (a *ACSS) runRBC(dealer NodeID, f func(rbc *ReliableBroadcast)) []byte {
	rbc := NewReliableBroadcast(a.Endpoint().Sub("rbc"), a.f, dealer)
	f(rbc)
	return rbc.Output.Wait()
}

func (a *ACSS) mainLoop(rbcOut []byte) {
	broadcastOk := func() {
		a.Endpoint().SendToAll(&msgACSSOk{})
	}

	readySent := false
	broadcastReady := func() {
		if !readySent {
			readySent = true
			a.Endpoint().SendToAll(&msgACSSReady{})
		}
	}

	broadcastImplicate := func(dealerPublic kyber.Point, err error) {
		a.Log().Warn("ACSS: broadcasting IMPLICATE", "error", err)
		a.Endpoint().SendToAll(&msgACSSImplicate{
			DLEQProof: crypto.Implicate(a.suite, dealerPublic, a.mySK),
		})
	}

	broadcastRecover := func(dealerPublic kyber.Point) {
		a.Endpoint().SendToAll(&msgACSSRecover{
			RecoverySecret: crypto.Secret(a.suite, dealerPublic, a.mySK),
		})
	}

	// > // party i (including the dealer)
	deal := lo.Must(crypto.DealUnmarshalBinary(a.suite, a.Endpoint().N(), rbcOut))

	// > sᵢ := PKI.Dec(eᵢ, skᵢ)
	// > if decrypt fails or VSS.Verify(C, i, sᵢ) == false:
	// >   send <IMPLICATE, i, skᵢ> to all parties
	// > else:
	// >   send <OK>
	secret := crypto.Secret(a.suite, deal.PubKey, a.mySK)
	myShare, err := crypto.DecryptShare(a.suite, deal, a.Endpoint().MyIndex(), secret)
	if err != nil {
		broadcastImplicate(deal.PubKey, err)
	} else {
		broadcastOk()
	}

	okReceived := make(map[NodeID]struct{})
	readyReceived := make(map[NodeID]struct{})
	implicateReceived := make(map[NodeID]struct{})
	recoverReceived := make(map[NodeID]*share.PriShare)

	for {
		msg := a.Endpoint().Receive(func() {
			a.Log().Info("status",
				"output", a.Output.String(),
				"okReceived", len(okReceived),
				"readyReceived", len(readyReceived),
				"implicateReceived", len(implicateReceived),
				"recoverReceived", len(recoverReceived),
			)
		})

		switch m := msg.Payload.(type) {
		case *msgACSSOk:
			if _, ok := okReceived[msg.Sender]; !ok {
				// > on receiving <OK> from n-f parties:
				// >   send <READY> to all parties
				okReceived[msg.Sender] = struct{}{}
				if len(okReceived) >= a.Endpoint().N()-a.f {
					broadcastReady()
				}
			}

		case *msgACSSReady:
			if _, ok := readyReceived[msg.Sender]; !ok {
				// > on receiving <READY> from f+1 parties:
				// >   send <READY> to all parties
				readyReceived[msg.Sender] = struct{}{}
				if len(readyReceived) >= a.f+1 {
					broadcastReady()
				}
				// > on receiving <READY> from n-f parties:
				// >   if sᵢ is valid:
				// >     out = true
				// >     output sᵢ
				if !a.Output.IsReady() && len(readyReceived) >= a.Endpoint().N()-a.f && myShare != nil {
					a.Output.Set(&ACSSOutput{
						PriShare: myShare,
						Commits:  deal.Commits,
					})
				}
			}

		case *msgACSSImplicate:
			// > on receiving <IMPLICATE, j, skⱼ>:
			// >   sⱼ := PKI.Dec(eⱼ, skⱼ)
			// >   if decrypt fails or VSS.Verify(C, j, sⱼ) == false:
			// >     if out == true:
			// >       send <RECOVER, i, skᵢ> to all parties
			// >       return
			if _, ok := implicateReceived[msg.Sender]; !ok {
				peerIndex := lo.IndexOf(a.Endpoint().Router.Peers, msg.Sender)
				if peerIndex < 0 {
					a.Log().Warn("Implication received from unknown peer", "peer", msg.Sender)
					continue
				}
				implicateReceived[msg.Sender] = struct{}{}
				secret, err := crypto.CheckImplicate(a.suite, deal.PubKey, a.peerPKs[msg.Sender], m.DLEQProof)
				if err != nil {
					a.Log().Warn("Invalid implication received", "error", err)
					continue
				}
				_, err = crypto.DecryptShare(a.suite, deal, peerIndex, secret)
				if err == nil {
					// if we are able to decrypt the share, the implication is not correct
					a.Log().Warn("encrypted share is valid")
					continue
				}
				broadcastRecover(deal.PubKey)
			}

		case *msgACSSRecover:
			if a.Output.IsReady() {
				// Ignore the RECOVER messages, if we are done with the output.
				continue
			}
			// >     on receiving <RECOVER, j, skⱼ>:
			// >       sⱼ := PKI.Dec(eⱼ, skⱼ)
			// >       if VSS.Verify(C, j, sⱼ): T = T ∪ {sⱼ}
			// >
			if _, ok := recoverReceived[msg.Sender]; !ok {
				peerIndex := lo.IndexOf(a.Endpoint().Router.Peers, msg.Sender)
				if peerIndex < 0 {
					a.Log().Warn("Recover received from unknown peer", "peer", msg.Sender)
					continue
				}
				peerSecret, err := crypto.DecryptShare(a.suite, deal, peerIndex, m.RecoverySecret)
				if err != nil {
					a.Log().Warn("invalid secret revealed")
					continue
				}
				recoverReceived[msg.Sender] = peerSecret

				// >     wait until len(T) >= f+1:
				// >       sᵢ = SSS.Recover(T, f+1, n)(i)
				// >       out = true
				// >       output sᵢ
				if len(recoverReceived) >= a.f+1 {
					priShares := lo.Values(recoverReceived)
					myShare, err := crypto.InterpolateShare(a.suite, priShares, a.Endpoint().N(), a.Endpoint().MyIndex())
					if err != nil {
						a.Log().Warn("Failed to recover pri-poly: %s", "error", err.Error())
						continue
					}
					a.Output.Set(&ACSSOutput{
						PriShare: myShare,
						Commits:  deal.Commits,
					})
				}
			}
		default:
			a.Log().Warn("ACSS: unexpected message type", "type", msg.Payload.MsgType())
		}
	}
}
