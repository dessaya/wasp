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

	peers, routers := actorstest.MakeRouters(t, n)

	suite := tcrypto.DefaultBLSSuite()
	_, pubPoly, priShares := testpeers.MakeSharedSecret(suite, n, threshold)

	// Actor paths:
	const abaPath actors.Path = "aba"
	// Common coin path will be abaPath.Sub("cc%d", r) per round

	// Prepare ABA actors and start them.
	outputs := make(chan struct {
		node actors.NodeID
		val  bool
	}, active)

	for i, nodeID := range peers {
		endpoint := routers[nodeID].GetEndpoint(abaPath)
		if i >= active {
			// silent node
			s := actorstest.NewSilent(endpoint)
			go func() {
				_ = s.Run(t.Context())
			}()
		} else {
			// fair node
			makeCC := func(round int, endpoint *actors.Endpoint) *actors.CommonCoinBLSSig {
				return actors.NewCommonCoinBLSSig(
					endpoint,
					threshold,
					suite,
					pubPoly,
					priShares[i],
					[]byte{1, 2, 3, byte(round)},
					slog.Default(),
				)
			}
			aba := actors.NewBinaryAgreement(
				endpoint,
				f,
				makeCC,
				slog.Default(),
			)
			go func(nodeID actors.NodeID, aba *actors.BinaryAgreement, input func() bool) {
				val, err := aba.Run(t.Context(), input())
				require.NoError(t, err)
				t.Logf("node %s ABA terminated with value %t", nodeID.ShortString(), val)
				outputs <- struct {
					node actors.NodeID
					val  bool
				}{node: nodeID, val: val}
			}(nodeID, aba, input)
		}
	}

	// Execute message delivery until all endpoints are closed.
	stats, err := actorstest.Execute(t, routers)
	require.NoError(t, err)
	t.Logf("delivered %d messages", stats.Delivered)

	// Collect outputs from all active nodes.
	results := make(map[actors.NodeID]bool, active)
	var refVal bool
	for range active {
		select {
		case out := <-outputs:
			results[out.node] = out.val
			refVal = out.val
		case <-t.Context().Done():
			t.Fatalf("context closed while waiting for ABA outputs: %v", t.Context().Err())
		}
	}
	if expected != nil {
		require.Equal(t, *expected, refVal, "ABA result does not match expected uniform input")
	}
	for nodeID, val := range results {
		require.Equalf(t, refVal, val, "node %s disagreed on ABA result", nodeID.ShortString())
	}
}
