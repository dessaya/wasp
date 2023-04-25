package transaction

import (
	"fmt"

	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/wasp/packages/state"
	"github.com/iotaledger/wasp/packages/vm/gas"
	"github.com/iotaledger/wasp/packages/wbf"
)

const (
	// L1Commitment calculation has changed from version 0 to version 1.
	// The structure is actually the same, but the L1 commitment in V0
	// refers to an empty state, and in V1 refers to the first initialized
	// state.
	StateMetadataSupportedVersion byte = 1
)

type StateMetadata struct {
	Version        byte
	SchemaVersion  uint32
	L1Commitment   *state.L1Commitment
	GasFeePolicy   *gas.FeePolicy
	CustomMetadata []byte `wbf:"u16size"`
}

func NewStateMetadata(
	l1Commitment *state.L1Commitment,
	gasFeePolicy *gas.FeePolicy,
	schemaVersion uint32,
	customMetadata []byte,
) *StateMetadata {
	return &StateMetadata{
		Version:        StateMetadataSupportedVersion,
		L1Commitment:   l1Commitment,
		GasFeePolicy:   gasFeePolicy,
		SchemaVersion:  schemaVersion,
		CustomMetadata: customMetadata,
	}
}

func (s *StateMetadata) Bytes() []byte {
	if s.Version != StateMetadataSupportedVersion {
		panic(fmt.Sprintf("cannot serialize state metadata: unsupported version %d", s.Version))
	}
	return wbf.MustMarshal(s)
}

func StateMetadataFromBytes(data []byte) (*StateMetadata, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("unable to parse state metadata version: EOF")
	}
	if data[0] > StateMetadataSupportedVersion {
		return nil, fmt.Errorf("unsupported state metadata version: %d", data[0])
	}
	ret := StateMetadata{}
	err := wbf.Unmarshal(&ret, data)
	return &ret, err
}

func L1CommitmentFromAliasOutput(ao *iotago.AliasOutput) (*state.L1Commitment, error) {
	s, err := StateMetadataFromBytes(ao.StateMetadata)
	if err != nil {
		return nil, err
	}
	return s.L1Commitment, nil
}

func MustL1CommitmentFromAliasOutput(ao *iotago.AliasOutput) *state.L1Commitment {
	l1c, err := L1CommitmentFromAliasOutput(ao)
	if err != nil {
		panic(err)
	}
	return l1c
}
