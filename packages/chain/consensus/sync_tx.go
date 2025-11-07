// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"fmt"
	"strings"

	"github.com/iotaledger/wasp/v2/clients/iota-go/iotago"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/state"
)

type SyncTX struct {
	c *Consensus

	decidedAnchor *isc.StateAnchor
	unsignedTX    *iotago.TransactionData
	signature     []byte
	blockSaved    bool
	block         state.Block

	inputsReady bool
}

func NewSyncTX(c *Consensus) *SyncTX {
	return &SyncTX{c: c}
}

func (sub *SyncTX) AnchorDecided(ao *isc.StateAnchor) {
	if sub.decidedAnchor != nil || ao == nil {
		return
	}
	sub.decidedAnchor = ao
	sub.tryCompleteInputs()
}

func (sub *SyncTX) UnsignedTXReceived(unsignedTX *iotago.TransactionData) {
	if sub.unsignedTX != nil || unsignedTX == nil {
		return
	}
	sub.unsignedTX = unsignedTX
	sub.tryCompleteInputs()
}

func (sub *SyncTX) SignatureReceived(signature []byte) {
	if sub.signature != nil || signature == nil {
		return
	}
	sub.signature = signature
	sub.tryCompleteInputs()
}

func (sub *SyncTX) BlockSaved(block state.Block) {
	if sub.blockSaved {
		return
	}
	sub.blockSaved = true
	sub.block = block
	sub.tryCompleteInputs()
}

func (sub *SyncTX) tryCompleteInputs() {
	if sub.inputsReady || sub.decidedAnchor == nil || sub.unsignedTX == nil || sub.signature == nil || !sub.blockSaved {
		return
	}
	sub.inputsReady = true
	sub.c.uponTXInputsReady(sub.decidedAnchor, sub.unsignedTX, sub.block, sub.signature)
}

// String tries to provide useful human-readable compact status.
func (sub *SyncTX) String() string {
	str := "TX"
	if sub.inputsReady {
		str += statusStrOK
	} else {
		wait := []string{}
		if sub.decidedAnchor == nil {
			wait = append(wait, "decidedAnchor")
		}
		if sub.unsignedTX == nil {
			wait = append(wait, "unsignedTX")
		}
		if sub.signature == nil {
			wait = append(wait, "Signature")
		}
		if !sub.blockSaved {
			wait = append(wait, "SavedBlock")
		}
		str += fmt.Sprintf("/WAIT[%v]", strings.Join(wait, ","))
	}
	return str
}
