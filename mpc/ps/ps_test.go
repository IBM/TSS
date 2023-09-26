/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"crypto/rand"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func TestBlindCorrectFormProof(t *testing.T) {
	c := math.Curves[1]

	msgLen := 10

	pp := Setup(c, msgLen)

	msg := make([]*math.Zr, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = c.NewRandomZr(rand.Reader)
	}

	hExp := c.NewRandomZr(rand.Reader)
	h := pp.g.Mul(hExp)

	z := c.NewRandomZr(rand.Reader)
	u := pp.g.Mul(z)

	a, b, r := encrypt(&pp, c, msg, h, u)

	rcm := c.NewRandomZr(rand.Reader)
	cm := commit(&pp, rcm, msg)

	ξ := proveBlindingIsWellFormed(c, msg, r, a, b, rcm, pp.g, pp.g0, h, u, cm, pp.gs)
	err := ξ.Verify(c, len(msg), a, b, cm, pp.g, pp.g0, h, u, pp.gs)
	assert.NoError(t, err)

	rawProof := ξ.Bytes()
	var ξ2 BlindCorrectFormProof
	err = ξ2.fromBytes(rawProof, c)
	assert.NoError(t, err)
	assert.Equal(t, ξ2, ξ)
}

func TestProveKnowledgeOfSignature(t *testing.T) {
	c := math.Curves[1]

	msgLen := 10

	pp := Setup(c, msgLen)

	_, pk := LocalKeyGen(pp)

	msg := make([]*math.Zr, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = c.NewRandomZr(rand.Reader)
	}

	δ := c.NewRandomZr(rand.Reader)

	ε := c.NewRandomZr(rand.Reader)
	hε := pp.g.Mul(ε)
	ν := hε.Mul(δ)
	X := pk.X
	Y := pk.Y

	κ := X.Copy()
	for i := 0; i < len(msg); i++ {
		κ.Add(Y[i].Mul(msg[i]))
	}
	κ.Add(pp.g2.Mul(δ))

	ψ := proveProofOfKnowledgeOfSignatureIsCorrectlyFormed(c, msg, δ, ν, hε, κ, pp.g2, X, Y)
	err := ψ.Verify(c, ν, hε, pp.g2, X, κ, Y)
	assert.NoError(t, err)
}

func TestBlindSignaturePoK(t *testing.T) {
	c := math.Curves[1]

	msgLen := 10

	pp := Setup(c, msgLen)

	msg := make([]*math.Zr, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = c.NewRandomZr(rand.Reader)
	}

	σ, secret := Blind(&pp, c, msg)

	sk, pk := LocalKeyGen(pp)

	sig, err := SignBlindSignature(&pp, σ, sk)
	assert.NoError(t, err)

	hPrime, err := UnBlind(&pp, pk, sig, secret.h, secret.msg, secret.z)
	assert.NoError(t, err)

	sigPoK := PoKofSig(&pp, pk, secret.h, hPrime, secret.msg)
	err = sigPoK.Verify(&pp, pk)
	assert.NoError(t, err)
}
