// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package actors

import (
	"encoding/hex"
	"fmt"

	"github.com/samber/lo"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

type CommonCoinBLSSigParams struct {
	T        int
	Suite    pairing.Suite
	PubPoly  *share.PubPoly
	PriShare *share.PriShare
	SID      []byte
}

// CommonCoinBLSSig implements a Common Coin (CC) based on a BLS Threshold signatures as
// described in the Appendix C of
//
// > Andrew Miller, Yu Xia, Kyle Croman, Elaine Shi, and Dawn Song. 2016.
// > The Honey Badger of BFT Protocols. In Proceedings of the 2016 ACM SIGSAC
// > Conference on Computer and Communications Security (CCS '16).
// > Association for Computing Machinery, New York, NY, USA, 31–42.
// > DOI:https://doi.org/10.1145/2976749.2978399
//
// We con't use the DKShare here, because in some cases this CC will be used while
// creating the DKShare.
type CommonCoinBLSSig struct {
	Actor
	blsParams CommonCoinBLSSigParams
	Output    *Output[bool]
}

type msgCCSigShare struct {
	s []byte `bcs:"export"`
}

func (m *msgCCSigShare) MsgType() MessageType { return 0 }
func (m *msgCCSigShare) String() string {
	return fmt.Sprintf("SIG_SHARE(%x)", lo.Ellipsis(string(m.s), 16))
}

// NewCommonCoinBLSSig constructs a new common coin actor.
func NewCommonCoinBLSSig(
	endpoint *Endpoint,
	blsParams CommonCoinBLSSigParams,
) *CommonCoinBLSSig {
	return &CommonCoinBLSSig{
		Actor:     NewActor(endpoint),
		Output:    NewOutput[bool](endpoint.Context()),
		blsParams: blsParams,
	}
}

// Run executes the common coin protocol until a coin value is decided or the
// context is canceled. It returns the decided coin value.
func (cc *CommonCoinBLSSig) Run() {
	cc.Go(func() {
		// make sure session ID is unique per CC instance
		sid := append([]byte(cc.Endpoint().Path), cc.blsParams.SID...)

		cc.Log().Info("Starting CC", "sid", hex.EncodeToString(sid))
		sigShares := make(map[NodeID][]byte)

		// Generate own share and broadcast
		{
			sigShare := lo.Must(tbls.Sign(cc.blsParams.Suite, cc.blsParams.PriShare, sid))
			if cc.Endpoint().N() == 1 {
				// Only one node; decide immediately.
				coin := makeCoin(sigShare)
				cc.Output.Set(coin)
				return
			}
			cc.Endpoint().SendToAllButMe(&msgCCSigShare{s: sigShare})
			sigShares[cc.Endpoint().Me()] = sigShare
		}

		for {
			msg := cc.Endpoint().Receive(func() {
				cc.Log().Info("status", "output", cc.Output.String())
			})
			switch payload := msg.Payload.(type) {
			case *msgCCSigShare:
				if _, exists := sigShares[msg.Sender]; exists {
					// Duplicate share from same sender; ignore.
					continue
				}
				sigShares[msg.Sender] = payload.s
				if !cc.Output.IsReady() && len(sigShares) >= cc.blsParams.T {
					mainSig, err := tbls.Recover(cc.blsParams.Suite, cc.blsParams.PubPoly, sid, lo.Values(sigShares), cc.blsParams.T, cc.Endpoint().N())
					if err != nil {
						cc.Log().Warn("signature recovery failed", "error", err)
						continue
					}
					if err := bdn.Verify(cc.blsParams.Suite, cc.blsParams.PubPoly.Commit(), sid, mainSig); err != nil {
						cc.Log().Warn("signature verification failed", "error", err)
						continue
					}
					// Decided!
					cc.Output.Set(makeCoin(mainSig))
					return
				}
			default:
				cc.Log().Warn("CommonCoinBLSSig: unexpected message",
					"type", msg.Payload.MsgType(),
					"sender", msg.Sender.ShortString(),
				)
			}
		}
	})
}

func makeCoin(b []byte) bool {
	return b[len(b)-1]%2 == 1
}
