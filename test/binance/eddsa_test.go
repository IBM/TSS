package binance_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	eddsa_scheme "github.com/IBM/TSS/mpc/binance/eddsa"
	"github.com/IBM/TSS/threshold"
	. "github.com/IBM/TSS/types"
	"github.com/stretchr/testify/assert"
)

func TestThresholdBinanceEdDSA(t *testing.T) {
	n := 4

	var verifySig signatureVerifyFunc

	var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

	verifySig = verifySignatureEdDSA
	signatureAlgorithms = eddsaKeygenAndSign

	threshold.SyncInterval = time.Millisecond * 50

	testScheme(t, n, signatureAlgorithms, verifySig, false)
}

func TestFastThresholdBinanceEdDSA(t *testing.T) {
	n := 4

	var verifySig signatureVerifyFunc

	var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

	verifySig = verifySignatureEdDSA
	signatureAlgorithms = eddsaKeygenAndSign

	testScheme(t, n, signatureAlgorithms, verifySig, true)
}

func eddsaKeygenAndSign(loggers []*commLogger) (func(id uint16) KeyGenerator, func(id uint16) Signer) {
	kgf := func(id uint16) KeyGenerator {
		return eddsa_scheme.NewParty(id, loggers[id-1])
	}

	sf := func(id uint16) Signer {
		return eddsa_scheme.NewParty(id, loggers[id-1])
	}
	return kgf, sf
}

func verifySignatureEdDSA(pkBytes []byte, t *testing.T, msg string, signature []byte) {
	assert.True(t, ed25519.Verify(pkBytes, sha256Digest([]byte(msg)), signature))
}
