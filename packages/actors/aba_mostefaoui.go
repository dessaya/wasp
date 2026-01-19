package actors

import (
	"fmt"
	"log/slog"

	"github.com/samber/lo"
)

// BinaryAgreement implements the Asynchronous Byzantine Binary Agreement (ABA) consensus algorithm by
// Mostefaoui et al., as described in the HBBFT paper:
//
// > Miller, A., Xia, Y., Croman, K., Shi, E., and Song, D. (2016). The Honey Badger of
// > BFT Protocols. In Proceedings of the 2016 ACM SIGSAC Conference on Computer
// > and Communications Security, CCS ’16, page 31–42, New York, NY, USA.
// > Association for Computing Machinery.
//
// The original paper by Mostefaoui is:
//
// > A. Mostefaoui, H. Moumen, and M. Raynal. Signature-free
// > asynchronous byzantine consensus with t< n/3 and o (n 2)
// > messages. In Proceedings of the 2014 ACM symposium on
// > Principles of distributed computing, pages 2–9. ACM, 2014.
//
// The HBBFT paper presents the algorithm as follows:
//
// > • upon receiving input b_input, set est_0 := b_input and proceed as
// >   follows in consecutive epochs, with increasing labels r:
// >     – multicast BVAL_r(est_r)
// >     – bin_values_r := {}
// >     – upon receiving BVAL_r(b) messages from f + 1 nodes, if
// >       BVAL_r(b) has not been sent, multicast BVAL_r(b)
// >     – upon receiving BVAL_r(b) messages from 2f + 1 nodes,
// >       bin_values_r := bin_values_r ∪ {b}
// >     – wait until bin_values_r != {}, then
// >         ∗ multicast AUX_r(w) where w ∈ bin_values_r
// >         ∗ wait until at least (N − f) AUX_r messages have been
// >           received, such that the set of values carried by these
// >           messages, vals are a subset of bin_values_r (note that
// >           bin_values_r may continue to change as BVAL_r messages
// >           are received, thus this condition may be triggered upon
// >           arrival of either an AUX_r or a BVAL_r message)
// >         ∗ s ← Coin_r.GetCoin()
// >         ∗ if vals = {b}, then
// >             · est_r+1 := b
// >             · if (b = s%2) then output b
// >         ∗ else est_r+1 := s%2
// > • continue looping until both a value b is output in some round r,
// >   and the value Coin_r' = b for some round r' > r.

type MakeCommonCoinFunc func(round int, endpoint *Endpoint) *CommonCoinBLSSig

type BinaryAgreement struct {
	Actor[bool]
	f      int                // maximum faulty nodes
	makeCC MakeCommonCoinFunc // creates the Common Coin actor
}

type (
	abaMsgType byte

	msgABA struct {
		msgType abaMsgType `bcs:"export"`
		round   int        `bcs:"export"`
		b       bool       `bcs:"export"`
	}
)

const (
	abaMsgTypeBVAL abaMsgType = 0
	abaMsgTypeAUX  abaMsgType = 1
)

func (m *msgABA) MsgType() MessageType { return 0 }
func (m *msgABA) String() string {
	switch m.msgType {
	case abaMsgTypeBVAL:
		return fmt.Sprintf("BVAL(r=%d,b=%t)", m.round, m.b)
	case abaMsgTypeAUX:
		return fmt.Sprintf("AUX(r=%d,b=%t)", m.round, m.b)
	default:
		return fmt.Sprintf("UnknownABAType(r=%d,b=%t)", m.round, m.b)
	}
}

// NewBinaryAgreement constructs a new Binary Agreement actor.
func NewBinaryAgreement(
	endpoint *Endpoint,
	f int,
	makeCC MakeCommonCoinFunc,
	log *slog.Logger,
) *BinaryAgreement {
	return &BinaryAgreement{
		Actor:  NewActor[bool](endpoint, log),
		f:      f,
		makeCC: makeCC,
	}
}

func (aba *BinaryAgreement) Run(input bool) {
	aba.Go(func() {
		// special case: if there's only one node, decide immediately
		if aba.Endpoint().N() == 1 {
			aba.SetOutput(input)
			return
		}

		// here we buffer incoming messages per-round; this is necessary
		// since a message for round r' could arrive before all messages for
		// round r have been processed
		incoming := map[int][]MessageIn{}

		// > upon receiving input b_input, set est_0 := b_input and proceed as
		// > follows in consecutive epochs, with increasing labels r:
		est := input
		lastOutputRound := -1
		for r := 0; ; r++ {
			vals := aba.doRound(r, est, incoming)

			// > s ← Coin_r.GetCoin()
			cc := aba.makeCC(r, aba.Endpoint().Router.GetEndpoint(aba.Endpoint().Path.Sub("cc%d", r)))
			cc.Run()
			s := WaitOutput(aba.Context(), cc)

			// > continue looping until both a value b is output in some round r,
			// > and the value Coin_r' = b for some round r' > r.
			if lastOutputRound >= 0 && r > lastOutputRound && aba.Output().IsReady() {
				if s == aba.Output().MustGet() {
					return
				}
			}

			// > if vals = {b}, then
			// >     · est_r+1 := b
			// >     · if (b = s%2) then output b
			// > else est_r+1 := s%2
			if len(vals) == 1 {
				b := vals[0]
				est = b
				if b == s {
					lastOutputRound = r
					aba.SetOutput(b)
				}
			} else {
				est = s
			}
		}
	})
}

func (aba *BinaryAgreement) doRound(r int, est bool, incoming map[int][]MessageIn) []bool {
	sentBVAL := map[bool]struct{}{}
	sendBVALOnce := func(b bool) {
		if _, ok := sentBVAL[b]; ok {
			return
		}
		sentBVAL[b] = struct{}{}
		aba.Endpoint().SendToAll(&msgABA{msgType: abaMsgTypeBVAL, round: r, b: b})
	}

	receivedBVAL := map[bool]map[NodeID]struct{}{}
	markReceivedBVAL := func(b bool, sender NodeID) {
		if receivedBVAL[b] == nil {
			receivedBVAL[b] = map[NodeID]struct{}{}
		}
		receivedBVAL[b][sender] = struct{}{}
	}

	receivedAUX := map[NodeID]bool{}

	// >     – multicast BVAL_r(est_r)
	sendBVALOnce(est)

	// > bin_values_r := {}
	binValues := map[bool]bool{}

	for {
		aba.receiveMessage(incoming)
		// process all pending messages for this round
		msgs := incoming[r]
		incoming[r] = nil
		for _, msg := range msgs {
			m := msg.Payload.(*msgABA)

			switch m.msgType {
			case abaMsgTypeBVAL:
				markReceivedBVAL(m.b, msg.Sender)
				// > upon receiving BVAL_r(b) messages from f + 1 nodes, if
				// > BVAL_r(b) has not been sent, multicast BVAL_r(b)
				if len(receivedBVAL[m.b]) == aba.f+1 {
					sendBVALOnce(m.b)
				}
				// > upon receiving BVAL_r(b) messages from 2f + 1 nodes,
				if len(receivedBVAL[m.b]) == 2*aba.f+1 {
					if len(binValues) == 0 {
						// > wait until bin_values_r != {}, then
						// > multicast AUX_r(w) where w ∈ bin_values_r
						aba.Endpoint().SendToAll(&msgABA{msgType: abaMsgTypeAUX, round: r, b: m.b})
					}
					// > bin_values_r := bin_values_r ∪ {b}
					binValues[m.b] = true
				}

			case abaMsgTypeAUX:
				receivedAUX[msg.Sender] = m.b

			default:
				aba.Log().Warn("Received unknown ABA message type", "type", fmt.Sprintf("%d", m.msgType))
				continue
			}

			// > wait until at least (N − f) AUX_r messages have been
			// > received, such that the set of values carried by these
			// > messages, vals, are a subset of bin_values_r (note that
			// > bin_values_r may continue to change as BVAL_r messages
			// > are received, thus this condition may be triggered upon
			// > arrival of either an AUX_r or a BVAL_r message)
			vals := lo.Uniq(lo.Values(receivedAUX))
			if len(binValues) > 0 && len(receivedAUX) >= aba.Endpoint().N()-aba.f && lo.Every(lo.Keys(binValues), vals) {
				return vals
			}
		}
	}
}

func (aba *BinaryAgreement) receiveMessage(incoming map[int][]MessageIn) {
	msg := aba.Endpoint().Receive()
	switch m := msg.Payload.(type) {
	case *msgABA:
		// classify message per-round
		incoming[m.round] = append(incoming[m.round], msg)
	default:
		aba.Log().Warn("Received unknown message type", "type", fmt.Sprintf("%T", m))
	}
}
