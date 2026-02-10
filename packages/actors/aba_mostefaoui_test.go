package actors_test

// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import (
	"fmt"
	"log/slog"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotaledger/wasp/v2/packages/actors"
	"github.com/iotaledger/wasp/v2/packages/actors/actorstest"
	"github.com/iotaledger/wasp/v2/packages/tcrypto"
	"github.com/iotaledger/wasp/v2/packages/testutil/testpeers"
)

func TestABA_Mostefaoui(t *testing.T) {
	valueRand := func() bool { return rand.Int()%2 == 1 }
	valueTrue := func() bool { return true }
	valueFalse := func() bool { return false }

	expectedTrue := true
	expectedFalse := false

	for _, tc := range []struct {
		n         int // total nodes
		f         int // max faulty nodes
		silent    int // number of silent nodes
		inputType string
		input     func() bool
		expected  *bool
	}{
		// Basic tests with random inputs:
		{1, 0, 0, "r", valueRand, nil},
		{2, 0, 0, "r", valueRand, nil},
		{3, 0, 0, "r", valueRand, nil},
		{4, 1, 0, "r", valueRand, nil},
		{10, 3, 0, "r", valueRand, nil},
		{31, 10, 0, "r", valueRand, nil},
		// Uniform inputs:
		{1, 0, 0, "t", valueTrue, &expectedTrue},
		{1, 0, 0, "f", valueFalse, &expectedFalse},
		{2, 0, 0, "t", valueTrue, &expectedTrue},
		{2, 0, 0, "f", valueFalse, &expectedFalse},
		{3, 0, 0, "t", valueTrue, &expectedTrue},
		{3, 0, 0, "f", valueFalse, &expectedFalse},
		{4, 1, 0, "t", valueTrue, &expectedTrue},
		{4, 1, 0, "f", valueFalse, &expectedFalse},
		// Silent nodes:
		{4, 1, 1, "r", valueRand, nil},
		{10, 3, 3, "r", valueRand, nil},
		{31, 10, 10, "r", valueRand, nil},
	} {
		t.Run(fmt.Sprintf("N=%d,F=%d,I=%s,S=%d", tc.n, tc.f, tc.inputType, tc.silent), func(t *testing.T) {
			testABA(t, tc.n, tc.f, tc.silent, tc.input, tc.expected)
		})
	}
}

func testABA(t *testing.T, n, f int, silent int, input func() bool, expected *bool) {
	// Common Coin threshold:
	threshold := f + 1
	active := n - silent

	ctx, stop, peers, routers := actorstest.MakeRouters(t, n, true)
	defer stop()

	suite := tcrypto.DefaultBLSSuite()
	_, pubPoly, priShares := testpeers.MakeSharedSecret(suite, n, threshold)

	// Actor paths:
	const abaPath actors.Path = "aba"
	// Common coin path will be abaPath.Sub("cc%d", r) per round

	// Prepare ABA actors and start them.
	abaOutputs := make(map[actors.NodeID]*actors.Output[bool])
	for i, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(abaPath)
		if i < active {
			// fair node
			makeCC := func(endpoint *actors.Endpoint, sid string) *actors.CommonCoinBLSSig {
				return actors.NewCommonCoinBLSSig(
					endpoint,
					threshold,
					suite,
					pubPoly,
					priShares[i],
					[]byte(sid),
					slog.Default(),
				)
			}
			aba := actors.NewBinaryAgreement(
				endpoint,
				f,
				makeCC,
				slog.Default(),
			)
			aba.Run(input())
			abaOutputs[nodeID] = aba.Output
		} else {
			// silent node
			actorstest.NewSilent(endpoint).Run()
		}
	}

	actorstest.Start(t, ctx, routers)

	// Collect outputs from all active nodes.
	done := actors.OutputsReadyChan(ctx, abaOutputs)
	results := make(map[actors.NodeID]bool, active)
	var refVal bool
	for range active {
		nodeID := <-done
		results[nodeID] = abaOutputs[nodeID].MustGet()
		refVal = results[nodeID]
	}
	if expected != nil {
		require.Equal(t, *expected, refVal, "ABA result does not match expected uniform input")
	}
	for nodeID, val := range results {
		require.Equalf(t, refVal, val, "node %s disagreed on ABA result", nodeID.ShortString())
	}
}
