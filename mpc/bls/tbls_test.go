package bls

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func TestBLS(t *testing.T) {
	sk := c.NewZrFromInt(2)
	pk := c.GenG2.Copy().Mul(sk)

	h := sha256.New()
	h.Write([]byte("the little fox jumps over the lazy dog"))
	digest := h.Sum(nil)

	signature := c.HashToG1(digest).Mul(sk)

	left := c.Pairing(c.GenG2.Copy(), signature)
	left = c.FExp(left)
	right := c.Pairing(pk, c.HashToG1(digest))
	right = c.FExp(right)

	assert.True(t, left.Equals(right))
}

func TestLocalSignVerify(t *testing.T) {
	sk := c.NewRandomZr(rand.Reader)

	h := sha256.New()
	h.Write([]byte("the little fox jumps over the lazy dog"))
	digest := h.Sum(nil)

	sig := localSign(sk, digest)
	pk := c.GenG2.Copy().Mul(sk)
	assert.NoError(t, localVerify(pk, digest, sig))

	h = sha256.New()
	h.Write([]byte("the little fox hops over the lazy dog"))
	digest2 := h.Sum(nil)

	assert.EqualError(t, localVerify(pk, digest2, sig), "signature mismatch")

	sig2 := localSign(sk, digest2)

	assert.EqualError(t, localVerify(pk, digest, sig2), "signature mismatch")
}

func TestLocalThresholdBLS(t *testing.T) {
	shares := localGen(3, 2)
	pks := localCreatePublicKeys(shares)

	digest := sha256.Sum256([]byte("the little fox jumps over the lazy dog"))

	var signatures []*math.G1
	for i := 0; i < len(shares); i++ {
		signatures = append(signatures, localSign(shares[i], digest[:]))
	}

	for i := 0; i < len(shares); i++ {
		assert.NoError(t, localVerify(pks[i], digest[:], signatures[i]))
	}

	thresholdSignature := localAggregateSignatures(signatures[:2], 1, 2)
	thresholdPK := localAggregatePublicKeys(pks, 1, 2)

	assert.NoError(t, localVerify(thresholdPK, digest[:], thresholdSignature))
}
