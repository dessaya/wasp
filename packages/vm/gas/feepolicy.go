package gas

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/iotaledger/hive.go/serializer/v2"
	"github.com/iotaledger/wasp/packages/util"
	"github.com/iotaledger/wasp/packages/wbf"
)

// By default each token pays for 100 units of gas
var DefaultGasPerToken = util.Ratio32{A: 100, B: 1}

// GasPerToken + ValidatorFeeShare + EVMGasRatio
const GasPolicyByteSize = util.RatioByteSize + serializer.OneByte + util.RatioByteSize

type FeePolicy struct {
	// GasPerToken specifies how many gas units are paid for each token.
	GasPerToken util.Ratio32 `json:"gasPerToken" swagger:"desc(The gas per token ratio (A/B) (gas/token)),required"`

	// ValidatorFeeShare Validator/Governor fee split: percentage of fees which goes to Validator
	// 0 mean all goes to Governor
	// >=100 all goes to Validator
	ValidatorFeeShare uint8 `json:"validatorFeeShare" swagger:"desc(The validator fee share.),required"`

	// EVMGasRatio expresses the ratio at which EVM gas is converted to ISC gas
	// X = ISC gas, Y = EVM gas => ISC gas = EVM gas * A/B
	EVMGasRatio util.Ratio32 `json:"evmGasRatio" swagger:"desc(The EVM gas ratio (ISC gas = EVM gas * A/B)),required"`
}

// FeeFromGasBurned calculates the how many tokens to take and where
// to deposit them.
func (p *FeePolicy) FeeFromGasBurned(gasUnits, availableTokens uint64) (sendToOwner, sendToValidator uint64) {
	var fee uint64

	// round up
	fee = p.FeeFromGas(gasUnits)
	fee = util.MinUint64(fee, availableTokens)

	validatorPercentage := p.ValidatorFeeShare
	if validatorPercentage > 100 {
		validatorPercentage = 100
	}
	// safe arithmetics
	if fee >= 100 {
		sendToValidator = (fee / 100) * uint64(validatorPercentage)
	} else {
		sendToValidator = (fee * uint64(validatorPercentage)) / 100
	}
	return fee - sendToValidator, sendToValidator
}

func FeeFromGas(gasUnits uint64, gasPerToken util.Ratio32) uint64 {
	return gasPerToken.YCeil64(gasUnits)
}

func (p *FeePolicy) FeeFromGas(gasUnits uint64) uint64 {
	return FeeFromGas(gasUnits, p.GasPerToken)
}

func (p *FeePolicy) MinFee() uint64 {
	return p.FeeFromGas(BurnCodeMinimumGasPerRequest1P.Cost())
}

func (p *FeePolicy) IsEnoughForMinimumFee(availableTokens uint64) bool {
	return availableTokens >= p.MinFee()
}

func (p *FeePolicy) GasBudgetFromTokens(availableTokens uint64) uint64 {
	return p.GasPerToken.XFloor64(availableTokens)
}

func DefaultFeePolicy() *FeePolicy {
	return &FeePolicy{
		GasPerToken:       DefaultGasPerToken,
		ValidatorFeeShare: 0, // by default all goes to the governor
		EVMGasRatio:       DefaultEVMGasRatio,
	}
}

func MustFeePolicyFromBytes(data []byte) *FeePolicy {
	ret, err := FeePolicyFromBytes(data)
	if err != nil {
		panic(err)
	}
	return ret
}

var ErrInvalidRatio = errors.New("ratio must have both components != 0")

func FeePolicyFromBytes(data []byte) (*FeePolicy, error) {
	return FeePolicyFromReader(bytes.NewReader(data))
}

func FeePolicyFromReader(r io.Reader) (*FeePolicy, error) {
	var f FeePolicy
	err := wbf.ReadValue(&f, r)
	if f.EVMGasRatio.HasZeroComponent() || f.GasPerToken.HasZeroComponent() {
		return nil, ErrInvalidRatio
	}
	return &f, err
}

func (p *FeePolicy) Bytes() []byte {
	return wbf.MustMarshal(p)
}

func (p *FeePolicy) String() string {
	return fmt.Sprintf(`
	GasPerToken %s
	EVMGasRatio %s
	ValidatorFeeShare %d
	`,
		p.GasPerToken,
		p.EVMGasRatio,
		p.ValidatorFeeShare,
	)
}
