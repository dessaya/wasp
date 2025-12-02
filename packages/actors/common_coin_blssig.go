// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package actors

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/samber/lo"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

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
	endpoint *Endpoint
	t        int
	suite    pairing.Suite
	pubPoly  *share.PubPoly
	priShare *share.PriShare
	sid      []byte
	log      *slog.Logger
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
	t int,
	suite pairing.Suite,
	pubPoly *share.PubPoly,
	priShare *share.PriShare,
	sid []byte,
	log *slog.Logger,
) *CommonCoinBLSSig {
	return &CommonCoinBLSSig{
		endpoint: endpoint,
		suite:    suite,
		pubPoly:  pubPoly,
		priShare: priShare,
		t:        t,
		sid:      sid,
		log:      log,
	}
}

func (cc *CommonCoinBLSSig) Endpoint() *Endpoint {
	return cc.endpoint
}

// Run executes the common coin protocol until a coin value is decided or the
// context is canceled. It returns the decided coin value.
func (cc *CommonCoinBLSSig) Run(ctx context.Context) (bool, error) {
	defer cc.endpoint.Close()

	sigShares := make(map[NodeID][]byte)

	// Generate own share and broadcast
	{
		sigShare, err := tbls.Sign(cc.suite, cc.priShare, cc.sid)
		if err != nil {
			return false, fmt.Errorf("cannot create signature share: %w", err)
		}
		if cc.endpoint.N() == 1 {
			// Only one node; decide immediately.
			coin := makeCoin(sigShare)
			return coin, nil
		}
		if err := cc.endpoint.SendToAllButMe(ctx, &msgCCSigShare{s: sigShare}); err != nil {
			return false, err
		}
		sigShares[cc.endpoint.Me()] = sigShare
	}

	for {
		msg, err := cc.endpoint.Receive(ctx)
		if err != nil {
			return false, err
		}
		switch payload := msg.Payload.(type) {
		case *msgCCSigShare:
			if _, exists := sigShares[msg.Sender]; exists {
				// Duplicate share from same sender; ignore.
				continue
			}
			sigShares[msg.Sender] = payload.s
			if len(sigShares) < cc.t {
				// Not enough shares collected yet.
				continue
			}
			mainSig, err := tbls.Recover(cc.suite, cc.pubPoly, cc.sid, lo.Values(sigShares), cc.t, cc.endpoint.N())
			if err != nil {
				cc.log.Warn("CommonCoinBLSSig: signature recovery failed", "error", err)
				continue
			}
			if err := bdn.Verify(cc.suite, cc.pubPoly.Commit(), cc.sid, mainSig); err != nil {
				cc.log.Warn("CommonCoinBLSSig: signature verification failed", "error", err)
				continue
			}
			// Decided!
			return makeCoin(mainSig), nil
		default:
			cc.log.Warn("CommonCoinBLSSig: unexpected message",
				"type", msg.Payload.MsgType(),
				"sender", msg.Sender.ShortString(),
			)
		}
	}
}

func makeCoin(b []byte) bool {
	return b[len(b)-1]%2 == 1
}
