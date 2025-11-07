package consensus

import (
	"fmt"
	"strings"

	"github.com/iotaledger/wasp/v2/packages/coin"
	"github.com/iotaledger/wasp/v2/packages/isc"
	"github.com/iotaledger/wasp/v2/packages/parameters"
)

type SyncNodeconn struct {
	c *Consensus

	inputProcessed      bool
	inputAnchor         *isc.StateAnchor
	inputAnchorReceived bool
	stateReceived       bool
	requestsReceived    bool

	outputProcessed bool
	gasCoins        []*coin.CoinWithRef
	l1params        *parameters.L1Params
}

func NewSyncNodeconn(c *Consensus) *SyncNodeconn {
	return &SyncNodeconn{c: c}
}

func (s *SyncNodeconn) String() string {
	str := "NC"
	if s.outputProcessed {
		str += statusStrOK
	} else if s.inputProcessed {
		str += "/WAIT[NC to respond]"
	} else {
		wait := []string{}
		if !s.inputAnchorReceived {
			wait = append(wait, "InputAnchor")
		}
		if !s.stateReceived {
			wait = append(wait, "StateProposal")
		}
		if !s.requestsReceived {
			wait = append(wait, "RequestProposals")
		}
		str += fmt.Sprintf("/WAIT[%v]", strings.Join(wait, ","))
	}
	return str
}

func (s *SyncNodeconn) HaveInputAnchor(anchor *isc.StateAnchor) {
	if s.inputAnchorReceived {
		return
	}
	s.inputAnchor = anchor // can be nil.
	s.inputAnchorReceived = true
	s.tryCompleteInputs()
}

func (s *SyncNodeconn) HaveState() {
	if s.stateReceived {
		return
	}
	s.stateReceived = true
	s.tryCompleteInputs()
}

func (s *SyncNodeconn) HaveRequests() {
	if s.requestsReceived {
		return
	}
	s.requestsReceived = true
	s.tryCompleteInputs()
}

func (s *SyncNodeconn) tryCompleteInputs() {
	if !s.inputAnchorReceived || !s.stateReceived || !s.requestsReceived || s.inputProcessed {
		return
	}
	s.inputProcessed = true
	s.c.uponNodeconnInputsReady(s.inputAnchor)
}

func (s *SyncNodeconn) HaveL1Info(gasCoins []*coin.CoinWithRef, l1params *parameters.L1Params) {
	if s.gasCoins == nil && gasCoins != nil {
		s.gasCoins = gasCoins
	}
	if s.l1params == nil && l1params != nil {
		s.l1params = l1params
	}
	s.tryCompleteOutput()
}

func (s *SyncNodeconn) tryCompleteOutput() {
	if s.outputProcessed || s.gasCoins == nil || s.l1params == nil {
		return
	}
	s.outputProcessed = true
	s.c.uponNodeconnOutputReady(s.gasCoins, s.l1params)
}
