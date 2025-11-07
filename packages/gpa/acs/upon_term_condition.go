// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package acs

import "github.com/iotaledger/wasp/v2/packages/gpa"

// Here we track the termination condition.
type uponTermCondition struct {
	acs  *ACS
	term map[gpa.NodeID]bool
	done bool
}

func newUponTermCondition(acs *ACS) *uponTermCondition {
	return &uponTermCondition{
		acs:  acs,
		term: map[gpa.NodeID]bool{},
		done: false,
	}
}

func (u *uponTermCondition) abaTerminated(nodeID gpa.NodeID) {
	if u.done {
		return
	}
	if ok := u.term[nodeID]; ok {
		return
	}
	u.term[nodeID] = true
	if len(u.term) == u.acs.n {
		u.done = true
		u.acs.uponTermCondition()
	}
}

func (u *uponTermCondition) canTerminate() bool {
	return u.done
}
