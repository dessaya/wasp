// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package bp

import (
	"time"

	"golang.org/x/xerrors"

	"github.com/iotaledger/hive.go/core/marshalutil"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/wasp/packages/isc"
	"github.com/iotaledger/wasp/packages/state"
	"github.com/iotaledger/wasp/packages/util"
)

type BatchProposal struct {
	nodeIndex        uint16              // Just for a double-check.
	stateOutputID    *iotago.UTXOInput   // Proposed Base AliasOutput to use.
	stateCommitment  *state.L1Commitment // State commitment of the proposed base AliasOutput.
	dssIndexProposal util.BitVector      // DSS Index proposal.
	timeData         time.Time           // Our view of time.
	feeDestination   isc.AgentID         // Proposed destination for fees.
	requestRefs      []*isc.RequestRef   // Requests we propose to include into the execution.
}

func NewBatchProposal(
	nodeIndex uint16,
	stateOutput *isc.AliasOutputWithID,
	dssIndexProposal util.BitVector,
	timeData time.Time,
	feeDestination isc.AgentID,
	requestRefs []*isc.RequestRef,
) *BatchProposal {
	stateCommitment, err := state.L1CommitmentFromAliasOutput(stateOutput.GetAliasOutput())
	if err != nil {
		panic(xerrors.Errorf("cannot get L1Commitment from AliasOutput: %w", err))
	}
	stateOutput.GetStateMetadata()
	return &BatchProposal{
		nodeIndex:        nodeIndex,
		stateOutputID:    stateOutput.ID(),
		stateCommitment:  stateCommitment,
		dssIndexProposal: dssIndexProposal,
		timeData:         timeData,
		feeDestination:   feeDestination,
		requestRefs:      requestRefs,
	}
}

func batchProposalFromBytes(data []byte) (*BatchProposal, error) {
	return batchProposalFromMarshalUtil(marshalutil.New(data))
}

func batchProposalFromMarshalUtil(mu *marshalutil.MarshalUtil) (*BatchProposal, error) {
	errFmt := "batchProposalFromMarshalUtil: %w"
	ret := &BatchProposal{}
	var err error
	ret.nodeIndex, err = mu.ReadUint16()
	if err != nil {
		return nil, xerrors.Errorf(errFmt, err)
	}
	ret.stateOutputID, err = isc.UTXOInputFromMarshalUtil(mu)
	if err != nil {
		return nil, xerrors.Errorf(errFmt, err)
	}
	ret.stateCommitment, err = state.L1CommitmentFromMarshalUtil(mu)
	if err != nil {
		return nil, xerrors.Errorf(errFmt, err)
	}
	if ret.dssIndexProposal, err = util.NewFixedSizeBitVectorFromMarshalUtil(mu); err != nil {
		return nil, xerrors.Errorf(errFmt, err)
	}
	ret.timeData, err = mu.ReadTime()
	if err != nil {
		return nil, xerrors.Errorf(errFmt, err)
	}
	ret.feeDestination, err = isc.AgentIDFromMarshalUtil(mu)
	if err != nil {
		return nil, xerrors.Errorf(errFmt, err)
	}
	requestCount, err := mu.ReadUint16()
	if err != nil {
		return nil, xerrors.Errorf(errFmt, err)
	}
	ret.requestRefs = make([]*isc.RequestRef, requestCount)
	for i := range ret.requestRefs {
		ret.requestRefs[i] = &isc.RequestRef{}
		ret.requestRefs[i].ID, err = isc.RequestIDFromMarshalUtil(mu)
		if err != nil {
			return nil, xerrors.Errorf(errFmt, err)
		}
		hashBytes, err := mu.ReadBytes(32)
		copy(ret.requestRefs[i].Hash[:], hashBytes)
		if err != nil {
			return nil, xerrors.Errorf(errFmt, err)
		}
	}
	return ret, nil
}

func (b *BatchProposal) Bytes() []byte {
	mu := marshalutil.New()
	stateOutputID := b.stateOutputID.ID()
	stateCommitmentBytes := b.stateCommitment.Bytes()
	mu.WriteUint16(b.nodeIndex).
		WriteBytes(stateOutputID[:]).
		WriteUint16(uint16(len(stateCommitmentBytes))).
		WriteBytes(stateCommitmentBytes).
		Write(b.dssIndexProposal).
		WriteTime(b.timeData).
		Write(b.feeDestination).
		WriteUint16(uint16(len(b.requestRefs)))
	for i := range b.requestRefs {
		mu.Write(b.requestRefs[i].ID)
		mu.WriteBytes(b.requestRefs[i].Hash[:])
	}
	return mu.Bytes()
}