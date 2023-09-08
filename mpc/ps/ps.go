/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	math "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"io"
)

// This is an implementation algorithm 6.1 from the paper:
// "Short Randomizable Signatures"
// By David Pointcheval and Olivier Sanders
// https://eprint.iacr.org/2015/525.pdf

var (
	c     = math.Curves[1]
	g1    = c.HashToG1([]byte("PS G1"))
	g2    = psuedoRandomG2()
	unity = c.GenG1.Copy().Mul(c.GroupOrder)
)

type SK math.G1

func (sk SK) Sign(rand io.Reader, blindedM *math.G1) BlindSignature {
	u := c.NewRandomZr(rand)

	XC := (math.G1)(sk)
	XC.Add(blindedM)

	return BlindSignature{
		R: g1.Mul(u),
		S: XC.Mul(u),
	}
}

type PK struct {
	Y1     math.G1
	X2, Y2 math.G2
}

type Signature struct {
	R *math.G1
	S *math.G1
}

func (s *Signature) Verify(pk *PK, m *math.Zr) error {
	if s.R.Equals(unity) {
		return fmt.Errorf("σ1 is 1")
	}

	XYm := pk.X2.Copy()
	XYm.Add((&pk.Y2).Mul(m))

	left := c.Pairing(XYm, s.R)
	c.FExp(left)

	right := c.Pairing(g2, s.S)
	c.FExp(right)

	if left.Equals(right) {
		return nil
	}

	return fmt.Errorf("invalid signature")
}

type BlindSignature struct {
	R *math.G1
	S *math.G1
}

func (bs *BlindSignature) UnBlind(blindingFactor *math.Zr) Signature {
	S := bs.S.Copy()
	S.Add(neg(bs.R.Mul(blindingFactor)))

	return Signature{
		R: bs.R,
		S: S,
	}
}

func Gen() (SK, PK) {
	x, y := c.NewRandomZr(rand.Reader), c.NewRandomZr(rand.Reader)
	X1, Y1 := g1.Mul(x), g1.Mul(y)
	X2, Y2 := g2.Mul(x), g2.Mul(y)
	return SK(*X1), PK{Y1: *Y1, X2: *X2, Y2: *Y2}
}

func Blind(pk *PK, rand io.Reader, m *math.Zr) (*math.G1, *math.Zr, ProofOfOpening) {
	t := c.NewRandomZr(rand)
	C := g1.Mul(t)
	C.Add(pk.Y1.Mul(m))
	com := commitment{x: m, r: t}
	return C, t, com.prove(rand, &pk.Y1, g1)
}

type commitment struct {
	x, r *math.Zr
}

type ProofOfOpening struct {
	U, V *math.Zr
	D    *math.G1
}

func (pop ProofOfOpening) Verify(com, g, h *math.G1) error {
	e := HVZKChallenge(pop.D, g, h)
	r := com.Mul(e)
	r.Add(pop.D)

	l := g.Mul(pop.U)
	l.Add(h.Mul(pop.V))

	if l.Equals(r) {
		return nil
	}

	return fmt.Errorf("invalid proof of opening")
}

func (com commitment) prove(rand io.Reader, g, h *math.G1) ProofOfOpening {
	y, s := c.NewRandomZr(rand), c.NewRandomZr(rand)
	d1 := g.Mul(y)
	d2 := h.Mul(s)
	d := d1
	d.Add(d2)

	e := HVZKChallenge(d, g, h)

	u := y.Plus(e.Mul(com.x))
	v := s.Plus(e.Mul(com.r))

	return ProofOfOpening{
		U: u,
		V: v,
		D: d,
	}

}

func HVZKChallenge(d, g, h *math.G1) *math.Zr {
	// Public parameters and 'd' go into the random oracle

	gBytes := g.Bytes()
	hBytes := h.Bytes()
	dBytes := d.Bytes()

	preimage := make([]byte, 0, len(gBytes)+len(hBytes)+len(dBytes))
	preimage = append(preimage, gBytes...)
	preimage = append(preimage, hBytes...)
	preimage = append(preimage, dBytes...)

	return c.HashToZr(hash(preimage))
}

func hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

func psuedoRandomG2() *math.G2 {
	g2, err := bn254.HashToG2([]byte("PS"), []byte("G2"))
	if err != nil {
		panic(err)
	}

	bytes := g2.Bytes()
	g, err := c.NewG2FromBytes(bytes[:])
	if err != nil {
		panic(err)
	}

	return g
}

func neg(in *math.G1) *math.G1 {
	zero := c.GenG1.Copy()
	zero.Sub(zero)

	zero.Sub(in)
	return zero
}
