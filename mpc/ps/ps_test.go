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
	//sk, pk := LocalKeyGen(pp)

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
}
