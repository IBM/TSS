/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

var (
	g2 bn254.G2Affine
)

func init() {
	_, _, _, g2 = bn254.Generators()

}

func localGen(n, t int) Shares {
	_, shares := (&SSS{Threshold: t}).Gen(n)
	return shares
}

func makePublicKey(sk *big.Int) *bn254.G2Affine {
	var pk bn254.G2Affine
	pk.ScalarMultiplication(&g2, sk)
	return &pk
}

func localCreatePublicKeys(shares Shares) []bn254.G2Affine {
	publicKeys := make([]bn254.G2Affine, len(shares))
	for i := 0; i < len(shares); i++ {
		publicKeys[i].ScalarMultiplication(&g2, shares[i])
	}

	return publicKeys
}

func localAggregatePublicKeys(pks []bn254.G2Affine, evaluationPoints ...int64) *bn254.G2Affine {
	var zero bn254.G2Affine
	zero.X.SetZero()
	zero.Y.SetZero()

	sum := zero

	for i := 0; i < len(evaluationPoints); i++ {
		var mul bn254.G2Affine
		mul.ScalarMultiplication(&pks[evaluationPoints[i]-1], lagrangeCoefficient(evaluationPoints[i], evaluationPoints...))
		sum.Add(&sum, &mul)
	}

	return &sum
}

func localAggregateSignatures(signatures []bn254.G1Affine, evaluationPoints ...int64) *bn254.G1Affine {
	var zero bn254.G1Affine
	zero.X.SetZero()
	zero.Y.SetZero()

	sum := zero

	var signatureIndex int
	for _, evaluationPoint := range evaluationPoints {
		var mul bn254.G1Affine
		mul.ScalarMultiplication(&signatures[signatureIndex], lagrangeCoefficient(evaluationPoint, evaluationPoints...))
		sum.Add(&sum, &mul)
		signatureIndex++
	}

	return &sum
}

func localSign(sk *big.Int, digest []byte) *bn254.G1Affine {
	g1h, err := bn254.HashToG1(digest, []byte("BLS"))
	if err != nil {
		panic(err)
	}
	return g1h.ScalarMultiplication(&g1h, sk)
}

func localVerify(pk *bn254.G2Affine, digest []byte, sig *bn254.G1Affine) error {

	g1h, err := bn254.HashToG1(digest, []byte("BLS"))
	if err != nil {
		panic(err)
	}

	left, err := bn254.Pair([]bn254.G1Affine{*sig}, []bn254.G2Affine{g2})
	if err != nil {
		return fmt.Errorf("cannot pair G2 with signature: %v", err)
	}

	right, err := bn254.Pair([]bn254.G1Affine{g1h}, []bn254.G2Affine{*pk})
	if err != nil {
		return fmt.Errorf("cannot pair public key with digest: %v", err)
	}

	if (&left).Equal(&right) {
		return nil
	}

	return fmt.Errorf("signature mismatch")
}
