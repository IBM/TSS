package binance_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	ecdsa_scheme "github.com/IBM/TSS/mpc/binance/ecdsa"
	. "github.com/IBM/TSS/types"
	s256k1 "github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/stretchr/testify/assert"
)

func TestThresholdBinanceECDSA(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		s256k1.S256(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			n := 4

			var verifySig signatureVerifyFunc
			var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

			verifySig = getVerifySignature(curve)
			signatureAlgorithms = func(loggers []*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer) {
				return ecdsaKeygenAndSign(curve, loggers)
			}

			testScheme(t, n, signatureAlgorithms, verifySig, false)
		})
	}
}

func TestFastThresholdBinanceECDSA(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		s256k1.S256(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			n := 4

			var verifySig signatureVerifyFunc
			var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

			verifySig = getVerifySignature(curve)
			signatureAlgorithms = func(loggers []*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer) {
				return ecdsaKeygenAndSign(curve, loggers)
			}

			testScheme(t, n, signatureAlgorithms, verifySig, true)
		})
	}
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

func getVerifySignature(curve elliptic.Curve) func(pkBytes []byte, t *testing.T, msg string, signature []byte) {
	switch curve.Params().Name {
	case s256k1.S256().Params().Name:
		return verifySignatureSecp256k1
	default:
		return verifySignatureECDSA
	}
}

func verifySignatureSecp256k1(pkBytes []byte, t *testing.T, msg string, signature []byte) {
	pk, err := s256k1.ParsePubKey(pkBytes)
	assert.NoError(t, err)

	sig, err := btcecdsa.ParseDERSignature(signature)
	assert.NoError(t, err)

	assert.True(t, sig.Verify(sha256Digest([]byte(msg)), pk))
}

func verifySignatureECDSA(pkBytes []byte, t *testing.T, msg string, signature []byte) {
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	assert.NoError(t, err)

	assert.True(t, ecdsa.VerifyASN1(pk.(*ecdsa.PublicKey), sha256Digest([]byte(msg)), signature))
}
