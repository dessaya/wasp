// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"github.com/iotaledger/wasp/v2/packages/isc"
)

type SyncMempool struct {
	c                  *Consensus
	baseAnchor         *isc.StateAnchor
	baseAnchorReceived bool
	proposalReceived   bool
	requestsNeeded     bool
	requestsReceived   bool
}

func NewSyncMempool(
	c *Consensus,
) *SyncMempool {
	return &SyncMempool{
		c: c,
	}
}

func (s *SyncMempool) BaseAnchorReceived(baseAnchor *isc.StateAnchor) {
	if s.baseAnchorReceived {
		return
	}
	s.baseAnchor = baseAnchor
	s.baseAnchorReceived = true
	s.c.uponMempoolProposalInputsReady(s.baseAnchor)
}

func (s *SyncMempool) ProposalReceived(requestRefs []*isc.RequestRef) {
	if s.proposalReceived {
		return
	}
	s.proposalReceived = true
	s.c.uponMempoolProposalReceived(requestRefs)
}

func (s *SyncMempool) RequestsNeeded(requestRefs []*isc.RequestRef) {
	if s.requestsNeeded {
		return
	}
	s.requestsNeeded = true
	s.c.uponMempoolRequestsNeeded(requestRefs)
}

func (s *SyncMempool) RequestsReceived(requests []isc.Request) {
	if s.requestsReceived {
		return
	}
	s.requestsReceived = true
	s.c.uponMempoolRequestsReceived(requests)
}

// String tries to provide useful human-readable compact status.
func (s *SyncMempool) String() string {
	str := "MP"
	if s.proposalReceived && s.requestsReceived {
		return str + statusStrOK
	}
	if s.proposalReceived {
		str += "/proposal=OK"
	} else if !s.baseAnchorReceived {
		str += "/proposal=WAIT[BaseAnchor]"
	} else {
		str += "/proposal=WAIT[RespFromMemPool]"
	}
	if s.requestsReceived {
		str += "/requests=OK"
	} else if !s.requestsNeeded {
		str += "/requests=WAIT[AcsDecision]"
	} else {
		str += "/requests=WAIT[RespFromMemPool]"
	}
	return str
}
