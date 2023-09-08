/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPS(t *testing.T) {
	sk, pk := Gen()
	m := c.NewRandomZr(rand.Reader)

	blindedMsg, blindingFactor, proof := Blind(&pk, rand.Reader, m)
	err := proof.Verify(blindedMsg, &pk.Y1, g1)
	assert.NoError(t, err)

	blindedSig := sk.Sign(rand.Reader, blindedMsg)
	signature := blindedSig.UnBlind(blindingFactor)
	err = signature.Verify(&pk, m)
	assert.NoError(t, err)
}
