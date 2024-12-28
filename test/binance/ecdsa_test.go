package binance_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	ecdsa_scheme "github.com/IBM/TSS/mpc/binance/ecdsa"

	. "github.com/IBM/TSS/types"

	"github.com/stretchr/testify/assert"
)

func TestThresholdBinanceECDSA(t *testing.T) {
	n := 4

	var verifySig signatureVerifyFunc

	var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

	verifySig = verifySignatureECDSA
	signatureAlgorithms = func(loggers []*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer) {
		return ecdsaKeygenAndSign(elliptic.P256(), loggers)
	}

	testScheme(t, n, signatureAlgorithms, verifySig, false)
}

func TestFastThresholdBinanceECDSA(t *testing.T) {
	n := 4

	var verifySig signatureVerifyFunc

	var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

	verifySig = verifySignatureECDSA
	signatureAlgorithms = func(loggers []*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer) {
		return ecdsaKeygenAndSign(elliptic.P256(), loggers)
	}

	testScheme(t, n, signatureAlgorithms, verifySig, true)
}

func ecdsaKeygenAndSign(curve elliptic.Curve, loggers []*commLogger) (func(id uint16) KeyGenerator, func(id uint16) Signer) {
	kgf := func(id uint16) KeyGenerator {
		return ecdsa_scheme.NewParty(id, curve, loggers[id-1])
	}

	sf := func(id uint16) Signer {
		return ecdsa_scheme.NewParty(id, curve, loggers[id-1])
	}
	return kgf, sf
}

func verifySignatureECDSA(pkBytes []byte, t *testing.T, msg string, signature []byte) {
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	assert.NoError(t, err)

	assert.True(t, ecdsa.VerifyASN1(pk.(*ecdsa.PublicKey), sha256Digest([]byte(msg)), signature))
}
