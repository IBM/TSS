/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"crypto/rand"
	"fmt"
	math "github.com/IBM/mathlib"
)

func localGen(n, t int) Shares {
	_, shares := (&SSS{Threshold: t}).Gen(n, rand.Reader)
	return shares
}

func localCreatePublicKeys(shares Shares) []*math.G2 {
	publicKeys := make([]*math.G2, len(shares))
	for i := 0; i < len(shares); i++ {
		publicKeys[i] = c.GenG2.Copy().Mul(shares[i])
	}

	return publicKeys
}

func localAggregatePublicKeys(pks []*math.G2, evaluationPoints ...int64) *math.G2 {
	zero := c.GenG2.Copy()
	zero.Sub(c.GenG2)

	sum := zero

	for i := 0; i < len(evaluationPoints); i++ {
		sum.Add(pks[evaluationPoints[i]-1].Mul(lagrangeCoefficient(evaluationPoints[i], evaluationPoints...)))
	}

	return sum
}

func localAggregateSignatures(signatures []*math.G1, evaluationPoints ...int64) *math.G1 {
	zero := c.GenG1.Copy()
	zero.Sub(zero)

	sum := zero

	for _, evaluationPoint := range evaluationPoints {
		sum.Add(signatures[evaluationPoint-1].Mul(lagrangeCoefficient(evaluationPoint, evaluationPoints...)))
	}

	return sum
}

func localSign(sk *math.Zr, digest []byte) *math.G1 {
	return c.HashToG1(digest).Mul(sk)
}

func localVerify(pk *math.G2, digest []byte, sig *math.G1) error {
	left := c.Pairing(c.GenG2.Copy(), sig)
	left = c.FExp(left)
	right := c.Pairing(pk, c.HashToG1(digest))
	right = c.FExp(right)
	if left.Equals(right) {
		return nil
	}

	return fmt.Errorf("signature mismatch")
}
