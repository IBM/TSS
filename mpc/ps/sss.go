/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"io"

	math "github.com/IBM/mathlib"
)

type SSS struct {
	Threshold int
}

var (
	c = math.Curves[1]
)

type Polynomial []*math.Zr

func (p Polynomial) ValueAt(x int) *math.Zr {
	sum := c.NewZrFromInt(0)
	for i := 0; i < len(p); i++ {
		exp := c.NewZrFromInt(int64(i))
		sum = sum.Plus(c.NewZrFromInt(int64(x)).PowMod(exp).Mul(p[i]))
	}
	sum.Mod(c.GroupOrder)
	return sum
}

func (s Shares) reconstruct(evaluationPoints ...int64) *math.Zr {
	sum := c.NewZrFromInt(0)
	for _, x := range evaluationPoints {
		sum = sum.Plus(s[x-1].Mul(lagrangeCoefficient(x, evaluationPoints...)))
		sum.Mod(c.GroupOrder)
	}

	return sum
}

type Shares []*math.Zr

// Gen receives as input a number of shares to output,
// and outputs a mapping from evaluation point to point.
// The evaluation points are numbered {1, ..., n}
func (sss *SSS) Gen(n int, rand io.Reader) (Polynomial, Shares) {
	// Create a random polynomial

	polynomial := make(Polynomial, sss.Threshold)

	for i := 0; i < sss.Threshold; i++ {
		polynomial[i] = c.NewRandomZr(rand)
	}

	// Create the shares
	shares := make([]*math.Zr, n)
	for evaluationPoint := 1; evaluationPoint <= n; evaluationPoint++ {
		shares[evaluationPoint-1] = polynomial.ValueAt(evaluationPoint)
	}

	return polynomial, shares
}

func lagrangeCoefficient(evaluatedAt int64, evaluationPoints ...int64) *math.Zr {
	var prodElements []*math.Zr

	for _, j := range evaluationPoints {
		if evaluatedAt == j {
			continue
		}

		iScalar := c.NewZrFromInt(evaluatedAt)
		jScalar := c.NewZrFromInt(j)

		nominator := jScalar.Copy() // j

		denominator := c.ModSub(jScalar, iScalar, c.GroupOrder) // j-i

		denominator.InvModP(c.GroupOrder)
		division := nominator.Mul(denominator) // j / (j-i)

		prodElements = append(prodElements, division)
	}

	if len(prodElements) == 0 {
		panic("empty lagrange coefficient vector")
	}

	prod := prodElements[0].Copy()
	for i := 1; i < len(prodElements); i++ {
		prod = prod.Mul(prodElements[i])
	}

	return prod
}
