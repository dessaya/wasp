package committeelog

import (
	"fmt"
	"maps"

	"github.com/iotaledger/hive.go/log"

	"github.com/iotaledger/wasp/v2/packages/isc"
)

// VarConsInsts implements the algorithm modeled in WaspChainCommitteeLogSUI.tla
type VarConsInsts struct {
	cl          *CommitteeLog
	haveConsOut bool
	lis         map[LogIndex]*isc.StateAnchor
	minLI       LogIndex         // Do not participate in LI lower than this.
	maxLI       LogIndex         // Cleanup all LIs smaller than this - hist.
	lastLI      LogIndex         // Just to wait for lastAnchor, if needed but not provided.
	lastAnchor  *isc.StateAnchor // Last Anchor seen confirmed in L1.
	hist        uint32           // How many instances to keep running.
	delayed     []LogIndex
	log         log.Logger
}

// NewVarConsInsts is a constructor.
func NewVarConsInsts(
	cl *CommitteeLog,
	minLI LogIndex,
	log log.Logger,
) *VarConsInsts {
	vci := &VarConsInsts{
		cl:          cl,
		haveConsOut: false,
		lis: map[LogIndex]*isc.StateAnchor{
			minLI: nil,
		},
		minLI:      minLI,
		maxLI:      minLI,
		lastLI:     NilLogIndex(),
		lastAnchor: nil,
		hist:       3,
		delayed:    make([]LogIndex, 3), // Will wait for 3 time ticks before considering SeenLI.
		log:        log,
	}
	vci.cl.setOutput(maps.Clone(vci.lis))
	return vci
}

// ConsOutputDone - Consensus at LI produced a TX.
func (vci *VarConsInsts) ConsOutputDone(li LogIndex, producedAnchor *isc.StateAnchor) {
	vci.haveConsOut = true
	vci.trySet(li.Next(), producedAnchor)
}

// ConsOutputSkip - Consensus at LI terminate with a SKIP/⊥ decision.
func (vci *VarConsInsts) ConsOutputSkip(li LogIndex) {
	vci.haveConsOut = true
	if vci.lastAnchor == nil {
		vci.lastLI = li.Next() // Will be set in LatestL1Anchor.
		return
	}
	vci.trySet(li.Next(), vci.lastAnchor)
}

// ConsOutputTimeout - Consensus at LI indicated a timeout.
func (vci *VarConsInsts) ConsOutputTimeout(li LogIndex) {
	vci.trySet(li.Next(), nil)
}

// LatestSeenLI - If we see consensus proposals from F+1 nodes at seenLI...
func (vci *VarConsInsts) LatestSeenLI(seenLI LogIndex) {
	vci.trySet(seenLI.Prev(), nil)
	if !vci.haveConsOut {
		// Still don't have the initial round succeeded, thus keep proposing the NIL.
		// A race condition is possible between receiving the next LI from the VarLogIndex,
		// and receiving the consensus output. While the actual convergence at runtime
		// happens anyway, we delay reaction to the VarLogIndex output to some delay to make
		// the test-cases more deterministic.
		vci.delayed[0] = MaxLogIndex(vci.delayed[0], seenLI)
	}
}

// LatestL1Anchor - Here we get the latest L1 state.
func (vci *VarConsInsts) LatestL1Anchor(ao *isc.StateAnchor) {
	vci.lastAnchor = ao
	vci.trySet(vci.lastLI, ao) // Finish ConsOutputSkipBase, if pending.
}

func (vci *VarConsInsts) Tick() {
	n := len(vci.delayed)
	last := vci.delayed[n-1]
	for i := n - 1; i > 0; i-- {
		vci.delayed[i] = vci.delayed[i-1]
	}
	vci.delayed[0] = NilLogIndex()
	if last.IsNil() {
		return
	}
	vci.trySet(last, nil)
}

func (vci *VarConsInsts) trySet(li LogIndex, ao *isc.StateAnchor) {
	//
	// Is it outdated?
	if li < vci.minLI {
		return
	}
	//
	// Is it already proposed?
	if _, ok := vci.lis[li]; ok {
		return
	}
	//
	// Propose it.
	vci.lis[li] = ao
	//
	// Track the max.
	if li > vci.maxLI {
		vci.cl.persistLI(li)
		vci.maxLI = li
		vci.minLI = MaxLogIndex(vci.minLI, vci.maxLI.Sub(vci.hist))
		vci.cl.varLogIndex.ConsensusStarted(li)
	}
	//
	// Cleanup old instances.
	for i := range vci.lis {
		if i < vci.minLI {
			vci.log.LogDebugf("Cleaning up LI=%v, minLI=%v, maxLI=%v", i, vci.minLI, vci.maxLI)
			delete(vci.lis, i)
			continue
		}
	}
	//
	// Set all non-last positions to ⊥, if not set yet.
	for li := vci.minLI; li < vci.maxLI; li = li.Next() {
		if _, ok := vci.lis[li]; !ok {
			vci.lis[li] = nil
		}
	}
	//
	// Notify updated state.
	vci.cl.setOutput(maps.Clone(vci.lis))
}

func (vci *VarConsInsts) StatusString() string {
	buf := ""
	for li := vci.minLI; li <= vci.maxLI; li = li.Next() {
		ao, ok := vci.lis[li]
		if !ok {
			buf += fmt.Sprintf(" LI#%d=…", li)
		} else if ao == nil {
			buf += fmt.Sprintf(" LI#%d=⊥", li)
		} else {
			buf += fmt.Sprintf(" LI#%d=%s", li, ao.Anchor().String())
		}
	}
	return fmt.Sprintf("{varConsInsts: minLI=%v,%s}", vci.minLI, buf)
}
