package util

import iotago "github.com/iotaledger/iota.go/v4"

func AnchorIDFromAnchorOutput(out *iotago.AnchorOutput, outID iotago.OutputID) iotago.AnchorID {
	if out.AnchorID.Empty() {
		// NFT outputs might not have an NFTID defined yet (when initially minted, the NFTOutput will have an empty NFTID, so we need to compute it)
		return iotago.AnchorIDFromOutputID(outID)
	}
	return out.AnchorID
}

func AccountIDFromAccountOutput(out *iotago.AccountOutput, outID iotago.OutputID) iotago.AccountID {
	if out.AccountID.Empty() {
		// NFT outputs might not have an NFTID defined yet (when initially minted, the NFTOutput will have an empty NFTID, so we need to compute it)
		return iotago.AccountIDFromOutputID(outID)
	}
	return out.AccountID
}