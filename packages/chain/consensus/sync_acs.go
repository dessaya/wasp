// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"fmt"
	"strings"
	"time"

	"github.com/iotaledger/wasp/v2/packages/coin"
	"github.com/iotaledger/wasp/v2/packages/gpa/acs"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/parameters"
)

// > UPON Reception of responses from Mempool, StateMgr and DistributedSignature NonceIndexes:
// >     Produce a batch proposal.
// >     Start the ACS.

type SyncACS struct {
	c *Consensus

	baseStateAnchor                   *isc.StateAnchor
	baseStateAnchorReceived           bool
	RequestRefs                       []*isc.RequestRef
	DistributedSignatureIndexProposal []int
	TimeData                          time.Time
	gasCoins                          []*coin.CoinWithRef
	l1params                          *parameters.L1Params
	l1InfoReceived                    bool

	inputsReady bool
	outputReady bool
	terminated  bool
}

func NewSyncACS(
	c *Consensus,
) *SyncACS {
	return &SyncACS{
		c: c,
	}
}

func (sub *SyncACS) StateProposalReceived(proposedBaseAnchor *isc.StateAnchor) {
	if sub.baseStateAnchorReceived {
		return
	}
	sub.baseStateAnchor = proposedBaseAnchor
	sub.baseStateAnchorReceived = true
	sub.tryCompleteInput()
}

func (sub *SyncACS) MempoolRequestsReceived(requestRefs []*isc.RequestRef) {
	if sub.RequestRefs != nil {
		return
	}
	sub.RequestRefs = requestRefs
	sub.tryCompleteInput()
}

func (sub *SyncACS) DistributedSignatureIndexProposalReceived(distSignIndexProposal []int) {
	if sub.DistributedSignatureIndexProposal != nil {
		return
	}
	sub.DistributedSignatureIndexProposal = distSignIndexProposal
	sub.tryCompleteInput()
}

func (sub *SyncACS) TimeDataReceived(timeData time.Time) {
	if timeData.After(sub.TimeData) {
		sub.TimeData = timeData
		sub.tryCompleteInput()
	}
}

func (sub *SyncACS) L1InfoReceived(gasCoins []*coin.CoinWithRef, l1params *parameters.L1Params) {
	if sub.l1InfoReceived {
		return
	}
	sub.gasCoins = gasCoins
	sub.l1params = l1params
	sub.l1InfoReceived = true
	sub.tryCompleteInput()
}

func (sub *SyncACS) tryCompleteInput() {
	if sub.inputsReady || !sub.baseStateAnchorReceived {
		return
	}
	if sub.RequestRefs == nil || sub.DistributedSignatureIndexProposal == nil || sub.TimeData.IsZero() || !sub.l1InfoReceived {
		return
	}
	sub.inputsReady = true
	sub.c.uponACSInputsReceived(sub.baseStateAnchor, sub.RequestRefs, sub.DistributedSignatureIndexProposal, sub.TimeData, sub.gasCoins, sub.l1params)
}

func (sub *SyncACS) ACSOutputReceived(acsOutput *acs.Output) {
	if acsOutput == nil {
		return
	}
	if !sub.terminated && acsOutput.Terminated {
		sub.terminated = true
		sub.c.uponACSTerminated()
	}
	if sub.outputReady {
		return
	}
	sub.outputReady = true
	sub.c.uponACSOutputReceived(acsOutput.Values)
}

// String tries to provide useful human-readable compact status.
func (sub *SyncACS) String() string {
	str := "ACS"
	if sub.outputReady {
		str += statusStrOK
	} else if sub.inputsReady {
		str += "/WAIT[ACS to complete]"
	} else {
		wait := []string{}
		if !sub.baseStateAnchorReceived {
			wait = append(wait, "BaseStateAnchor")
		}
		if sub.RequestRefs == nil {
			wait = append(wait, "RequestRefs")
		}
		if sub.DistributedSignatureIndexProposal == nil {
			wait = append(wait, "DistributedSignatureIndexProposal")
		}
		if sub.TimeData.IsZero() {
			wait = append(wait, "TimeData")
		}
		if !sub.l1InfoReceived {
			wait = append(wait, "L1Info")
		}
		str += fmt.Sprintf("/WAIT[%v]", strings.Join(wait, ","))
	}
	return str
}
