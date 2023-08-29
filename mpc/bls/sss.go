/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type SSS struct {
	Threshold int
}

type Polynomial []*big.Int

func (p Polynomial) ValueAt(x int) *big.Int {
	X := big.NewInt(int64(x))
	sum := big.NewInt(0)
	for i := 0; i < len(p); i++ {
		exp := big.NewInt(int64(i))
		xExp := big.NewInt(int64(0)).Exp(X, exp, fr.Modulus())
		y := big.NewInt(0).Mul(xExp, p[i])
		y.Mod(y, fr.Modulus())
		sum.Add(sum, y)
	}

	sum.Mod(sum, fr.Modulus())

	return sum
}

func (s Shares) reconstruct(evaluationPoints ...int64) *big.Int {
	sum := big.NewInt(0)

	for _, x := range evaluationPoints {
		sum.Add(sum, big.NewInt(0).Mul(s[x-1], lagrangeCoefficient(x, evaluationPoints...)))
		sum.Mod(sum, fr.Modulus())
	}

	return sum
}

type Shares []*big.Int

// Gen receives as input a number of shares to output,
// and outputs a mapping from evaluation point to point.
// The evaluation points are numbered {1, ..., n}
func (sss *SSS) Gen(n int) (Polynomial, Shares) {
	// Create a random polynomial

	polynomial := make(Polynomial, sss.Threshold)

	for i := 0; i < sss.Threshold; i++ {
		polynomial[i] = randomFE()
	}

	// Create the shares
	shares := make([]*big.Int, n)
	for evaluationPoint := 1; evaluationPoint <= n; evaluationPoint++ {
		shares[evaluationPoint-1] = polynomial.ValueAt(evaluationPoint)
	}

	return polynomial, shares
}

func lagrangeCoefficient(evaluatedAt int64, evaluationPoints ...int64) *big.Int {
	var prodElements []*big.Int

	iScalar := big.NewInt(evaluatedAt)

	for _, j := range evaluationPoints {
		if evaluatedAt == j {
			continue
		}

		jScalar := big.NewInt(j)

		nominator := jScalar // j

		n := big.NewInt(0)
		n.Sub(jScalar, iScalar) // j-i
		denominator := n.Mod(n, fr.Modulus())

		denominator.ModInverse(denominator, fr.Modulus())

		division := nominator.Mul(nominator, denominator) // j / (j-i)

		prodElements = append(prodElements, division)
	}

	if len(prodElements) == 0 {
		panic("empty lagrange coefficient vector")
	}

	prod := prodElements[0]
	for i := 1; i < len(prodElements); i++ {
		prod = prod.Mul(prod, prodElements[i])
	}

	return prod
}

func randomFE() *big.Int {
	res := new(big.Int)
	v := &fr.Element{}
	_, err := v.SetRandom()
	if err != nil {
		panic(err)
	}

	return v.ToBigIntRegular(res)
}
