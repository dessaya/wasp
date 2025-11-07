// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Package semi implements a Common Coin (CC) that produces deterministic
// values only for some of the rounds. I.e. only every 5th round will give a
// real non-deterministic CC.
package semi

import (
	"fmt"

	"github.com/iotaledger/wasp/v2/packages/gpa"
	"github.com/iotaledger/wasp/v2/packages/gpa/cc/blssig"
)

type CommonCoin struct {
	target *blssig.CommonCoin
	index  int
	output *bool
}

var _ gpa.GPA = &CommonCoin{}

func New(index int, target *blssig.CommonCoin) *CommonCoin {
	return &CommonCoin{index: index, target: target}
}

func (cc *CommonCoin) SwapOutBuffer() []gpa.MessageOut {
	if cc.index%5 < 4 {
		return nil
	}
	return cc.target.SwapOutBuffer()
}

func (cc *CommonCoin) Input() {
	mod5 := cc.index % 5
	if mod5 < 2 {
		coin := true
		cc.output = &coin
		return
	}
	if mod5 < 4 {
		coin := false
		cc.output = &coin
		return
	}
	cc.target.Input()
}

func (cc *CommonCoin) Message(msg gpa.MessageIn) {
	if cc.output != nil {
		return
	}
	cc.target.Message(msg)
}

func (cc *CommonCoin) Output() *bool {
	if cc.index%5 < 4 {
		return cc.output
	}
	return cc.target.Output()
}

func (cc *CommonCoin) StatusString() string {
	if cc.output != nil {
		// Try produce compact output.
		return fmt.Sprintf("{CC:semi, index=%v, output=%v}", cc.index, *cc.output)
	}
	return fmt.Sprintf("{CC:semi, index=%v, output=%v, target=%v}", cc.index, cc.output, cc.target.StatusString())
}

func (cc *CommonCoin) UnmarshalPayload(data []byte) (gpa.MessagePayload, error) {
	return cc.target.UnmarshalPayload(data)
}
