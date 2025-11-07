// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"fmt"
	"strings"

	"github.com/iotaledger/wasp/v2/packages/chain/consensus/batchproposal"
	"github.com/iotaledger/wasp/v2/packages/hashing"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/state"
	"github.com/iotaledger/wasp/v2/packages/vm"
)

type SyncVM struct {
	c                   *Consensus
	aggregatedProposals *batchproposal.AggregatedBatchProposals
	chainState          state.State
	randomness          *hashing.HashValue
	requests            []isc.Request
	vmResult            *vm.VMTaskResult
	inputsReady         bool
	outputReady         bool
}

func NewSyncVM(
	c *Consensus,
) *SyncVM {
	return &SyncVM{c: c}
}

func (sub *SyncVM) DecidedBatchProposalsReceived(aggregatedProposals *batchproposal.AggregatedBatchProposals) {
	if sub.aggregatedProposals != nil || aggregatedProposals == nil {
		return
	}
	sub.aggregatedProposals = aggregatedProposals
	sub.tryCompleteInputs()
	sub.tryCompleteOutputs()
}

func (sub *SyncVM) DecidedStateReceived(chainState state.State) {
	if sub.chainState != nil {
		return
	}
	sub.chainState = chainState
	sub.tryCompleteInputs()
}

func (sub *SyncVM) RandomnessReceived(randomness hashing.HashValue) {
	if sub.randomness != nil {
		return
	}
	sub.randomness = &randomness
	sub.tryCompleteInputs()
}

func (sub *SyncVM) RequestsReceived(requests []isc.Request) {
	if sub.requests != nil || requests == nil {
		return
	}
	sub.requests = requests
	sub.tryCompleteInputs()
}

func (sub *SyncVM) tryCompleteInputs() {
	if sub.inputsReady || sub.aggregatedProposals == nil || sub.chainState == nil || sub.randomness == nil || sub.requests == nil {
		return
	}
	sub.inputsReady = true
	sub.c.uponVMInputsReceived(sub.aggregatedProposals, sub.randomness, sub.requests)
}

func (sub *SyncVM) tryCompleteOutputs() {
	if sub.vmResult == nil || sub.aggregatedProposals == nil {
		return
	}
	if sub.outputReady {
		return
	}
	sub.outputReady = true
	sub.c.uponVMOutputReceived(sub.vmResult, sub.aggregatedProposals)
}

func (sub *SyncVM) VMResultReceived(vmResult *vm.VMTaskResult) {
	if sub.vmResult != nil || vmResult == nil {
		return
	}
	sub.vmResult = vmResult
	sub.tryCompleteOutputs()
}

// String tries to provide useful human-readable compact status.
func (sub *SyncVM) String() string {
	str := "VM"
	if sub.outputReady {
		str += statusStrOK
	} else if sub.inputsReady {
		str += "/WAIT[VM to complete]"
	} else {
		wait := []string{}
		if sub.aggregatedProposals == nil {
			wait = append(wait, "AggrProposals")
		}
		if sub.chainState == nil {
			wait = append(wait, "StateFromSM")
		}
		if sub.randomness == nil {
			wait = append(wait, "Randomness")
		}
		if sub.requests == nil {
			wait = append(wait, "RequestsFromMP")
		}
		str += fmt.Sprintf("/WAIT[%v]", strings.Join(wait, ","))
	}
	return str
}
