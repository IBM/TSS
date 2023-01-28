package binance_test

import (
	"encoding/asn1"
	"github.ibm.com/fabric-security-research/tss/threshold"
	"math/big"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
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
	type PK struct {
		X, Y *big.Int
	}

	publicKey := &PK{}

	_, err := asn1.Unmarshal(pkBytes, publicKey)
	assert.NoError(t, err)

	r, s := unmarshalSignature(t, signature)
	assert.True(t, edwards.Verify(&edwards.PublicKey{
		X:     publicKey.X,
		Y:     publicKey.Y,
		Curve: tss.Edwards(),
	}, sha256Digest([]byte(msg)), r, s))
}

func unmarshalSignature(t *testing.T, rawSig []byte) (R *big.Int, S *big.Int) {
	type sig struct {
		R, S *big.Int
	}

	signature := &sig{}

	_, err := asn1.Unmarshal(rawSig, signature)
	assert.NoError(t, err)

	return signature.R, signature.S
}
