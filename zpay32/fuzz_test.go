package zpay32

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/channeldb/migration_01_to_11/zpay32"
)

// Fuzz_decode is used by go-fuzz.
func Fuzz_decode(data []byte) int {
	inv, err := zpay32.Decode(string(data), &chaincfg.TestNet3Params)
	if err != nil {
		return 1
	}

	// Call these functions as a sanity check to make sure the invoice
	// is well-formed.
	_ = inv.MinFinalCLTVExpiry()
	_ = inv.Expiry()
	return 1
}

// Fuzz_decode is used by go-fuzz.
func Fuzz_decode(data []byte) int {
	inv, err := zpay32.Decode(string(data), &chaincfg.TestNet3Params)
	if err != nil {
		return 1
	}

	// Call these functions as a sanity check to make sure the invoice
	// is well-formed.
	_ = inv.MinFinalCLTVExpiry()
	_ = inv.Expiry()
	return 1
}
