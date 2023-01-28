package binance_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.ibm.com/fabric-security-research/tss/threshold"

	eddsa_scheme "github.ibm.com/fabric-security-research/tss/mpc/binance/eddsa"

	"github.com/stretchr/testify/assert"
	. "github.ibm.com/fabric-security-research/tss/types"
)

func TestThresholdBinanceEdDSA(t *testing.T) {
	n := 4

	var verifySig signatureVerifyFunc

	var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

	verifySig = verifySignatureEdDSA
	signatureAlgorithms = eddsaKeygenAndSign

	threshold.SyncInterval = time.Millisecond * 50

	testScheme(t, n, signatureAlgorithms, verifySig)
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
