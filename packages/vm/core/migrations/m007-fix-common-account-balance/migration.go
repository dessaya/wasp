package m007

import (
	"github.com/iotaledger/hive.go/log"
	"github.com/iotaledger/wasp/packages/isc"
	"github.com/iotaledger/wasp/packages/kv"
	"github.com/iotaledger/wasp/packages/vm/core/accounts"
	"github.com/iotaledger/wasp/packages/vm/core/migrations"
)

var toDebit = isc.NewCoinBalances().AddBaseTokens(1000)

var FixCommonAccountBalance = migrations.Migration{
	Apply: func(contractState kv.KVStore, log log.Logger) error {
		accounts.NewStateWriter(migrations.LatestSchemaVersion, contractState).
			DebitFromAccount(accounts.CommonAccount(), toDebit)
		return nil
	},
	Contract: accounts.Contract,
}
