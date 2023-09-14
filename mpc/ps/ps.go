/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	math "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// This is an implementation of a threshold blind signature scheme and zero knowledge proof of knowledge of such signature.
// The notation follows appendix C from "Privacy-preserving auditable token payments in a permissioned blockchain system" - https://eprint.iacr.org/2019/1058.pdf
// but the actual algorithm closely follows Appendix B from
// the paper: "Coconut: Threshold Issuance Selective Disclosure  Credentials with Applications to Distributed Ledgers" - https://arxiv.org/pdf/1802.07344.pdf
// with a slight deviation where we add an extra message m' as in section 4.2 in "Reassessing Security of Randomizable Signatures" - https://eprint.iacr.org/2017/1197.pdf

type PP struct {
	c  *math.Curve
	g2 *math.G2
	g0 *math.G1
	g  *math.G1
	gs []*math.G1
	n  int // |m|+1
}

func Setup(c *math.Curve, messageLength int) PP {
	return PP{
		n:  messageLength + 1,
		c:  c,
		g2: psuedoRandomG2(c),
		g0: psuedoRandomG1s(c, 1, "G0")[0],
		g:  psuedoRandomG1s(c, 1, "G")[0],
		gs: psuedoRandomG1s(c, messageLength+1, "Gs"),
	}
}

type SK struct {
	x  *math.Zr
	ys []*math.Zr
}

type PK struct {
	X  *math.G2
	Ys []*math.G2
}

func LocalKeyGen(pp PP) (SK, PK) {
	sk := SK{
		ys: make([]*math.Zr, pp.n+1),
	}

	sk.x = pp.c.NewRandomZr(rand.Reader)
	for i := 0; i < len(sk.ys); i++ {
		sk.ys[i] = pp.c.NewRandomZr(rand.Reader)
	}

	pk := PK{
		X: pp.g2.Mul(sk.x),
	}

	for i := 0; i < len(sk.ys); i++ {
		pk.Ys[i] = pp.g2.Mul(sk.ys[i])
	}

	return sk, pk
}

func Blind(pp *PP, c *math.Curve, m []*math.Zr) {
	if len(m)+1 != pp.n {
		panic(fmt.Sprintf("expected message to be of length %d but was of length %d", pp.n-1, len(m)))
	}
	rcm := c.NewRandomZr(rand.Reader)

	// private key for ElGamal
	z := c.NewRandomZr(rand.Reader)

	// public key for ElGamal
	u := pp.g.Mul(z)

	// commitment to 'm'
	cm := commit(pp, rcm, m)

	mPrime := pp.c.HashToZr(hash(cm.Bytes()))

	// Add m' to commitment
	cm.Add(pp.gs[len(m)].Mul(mPrime))

	// Update 'h' with final commitment
	h := pp.c.HashToG1(cm.Bytes())

	msg := make([]*math.Zr, pp.n)
	copy(msg, m)
	msg[len(msg)-1] = mPrime
	a, b, r := encrypt(pp, c, msg, h, u)

	_ = a

	// Last element of b vector is encryption of m'
	lastBi := h.Mul(mPrime)
	lastBi.Add(u.Mul(r[len(r)-1]))
	b[len(b)-1] = lastBi
}

func commit(pp *PP, rcm *math.Zr, m []*math.Zr) *math.G1 {
	cm := pp.g0.Mul(rcm)
	for i := 0; i < len(m); i++ {
		cm.Add(pp.gs[i].Mul(m[i]))
	}
	return cm
}

func encrypt(pp *PP, c *math.Curve, m []*math.Zr, h *math.G1, u *math.G1) ([]*math.G1, []*math.G1, []*math.Zr) {
	r := make([]*math.Zr, len(m))
	for i := 0; i < len(r); i++ {
		r[i] = c.NewRandomZr(rand.Reader)
	}

	a := make([]*math.G1, len(m))
	for i := 0; i < len(a); i++ {
		a[i] = pp.g.Mul(r[i])
	}

	b := make([]*math.G1, len(m))
	for i := 0; i < len(m); i++ {
		bi := h.Mul(m[i])
		bi.Add(u.Mul(r[i]))
		b[i] = bi
	}
	return a, b, r
}

func proveBlindingIsWellFormed(c *math.Curve, m []*math.Zr, r []*math.Zr, a, b []*math.G1, rcm *math.Zr, g, g0, h, u, cm *math.G1, gs []*math.G1) BlindCorrectFormProof {
	n := len(m)

	α := make([]*math.Zr, n)
	for i := 0; i < n; i++ {
		α[i] = c.NewRandomZr(rand.Reader)
	}

	β := make([]*math.Zr, n)
	for i := 0; i < n; i++ {
		β[i] = c.NewRandomZr(rand.Reader)
	}

	γ := c.NewRandomZr(rand.Reader)

	d := make([]*math.G1, n)
	f := make([]*math.G1, n)

	s := g0.Mul(γ)
	for i := 0; i < n; i++ {
		s.Add(gs[i].Mul(β[i]))
		d[i] = h.Mul(β[i])
		d[i].Add(u.Mul(α[i]))

		f[i] = g.Mul(α[i])
	}

	digest := randomOracleForBlindingProof(n, d, f, s, a, b, cm, g, g0, h, u, gs)
	e := c.HashToZr(digest)

	z := γ.Plus(e.Mul(rcm))
	x := make([]*math.Zr, n)
	y := make([]*math.Zr, n)
	for i := 0; i < n; i++ {
		x[i] = α[i].Plus(e.Mul(r[i]))
		y[i] = β[i].Plus(e.Mul(m[i]))
	}

	return BlindCorrectFormProof{
		x: x,
		y: y,
		s: s,
		f: f,
		d: d,
		z: z,
	}
}

func randomOracleForBlindingProof(n int, d []*math.G1, f []*math.G1, s *math.G1, a, b []*math.G1, cm *math.G1, g *math.G1, g0 *math.G1, h *math.G1, u *math.G1, gs []*math.G1) []byte {
	hash := sha256.New()
	for i := 0; i < n; i++ {
		hash.Write(d[i].Bytes())
		hash.Write(f[i].Bytes())
		hash.Write(a[i].Bytes())
		hash.Write(b[i].Bytes())
	}
	hash.Write(s.Bytes())
	hash.Write(cm.Bytes())

	hash.Write(g.Bytes())
	hash.Write(g0.Bytes())
	hash.Write(h.Bytes())
	hash.Write(u.Bytes())
	for i := 0; i < n; i++ {
		gs[i].Bytes()
	}
	digest := hash.Sum(nil)
	return digest
}

type BlindCorrectFormProof struct {
	x, y []*math.Zr
	s    *math.G1
	z    *math.Zr
	d, f []*math.G1
}

func (ξ BlindCorrectFormProof) Verify(c *math.Curve, n int, a, b []*math.G1, cm *math.G1, g *math.G1, g0 *math.G1, h *math.G1, u *math.G1, gs []*math.G1) error {
	digest := randomOracleForBlindingProof(n, ξ.d, ξ.f, ξ.s, a, b, cm, g, g0, h, u, gs)
	e := c.HashToZr(digest)

	for i := 0; i < n; i++ {
		left := u.Mul(ξ.x[i])
		left.Add(h.Mul(ξ.y[i]))
		right := ξ.d[i]
		right.Add(b[i].Mul(e))
		if !left.Equals(right) {
			return fmt.Errorf("u^{x%d}h^{y%d} != d%db%d^e", i, i, i, i)
		}
	}

	for i := 0; i < n; i++ {
		left := g.Mul(ξ.x[i])
		right := ξ.f[i].Copy()
		right.Add(a[i].Mul(e))
		if !left.Equals(right) {
			return fmt.Errorf("g^{x%d} != f%da%d^e", i, i, i)
		}
	}

	left := cm.Mul(e)
	left.Add(ξ.s)
	right := g0.Mul(ξ.z)
	for i := 0; i < n; i++ {
		right.Add(gs[i].Mul(ξ.y[i]))
	}
	if !left.Equals(right) {
		return fmt.Errorf("cm^e*s != g0^z * \\prod{gi^yi}")
	}

	return nil
}

func hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

func psuedoRandomG1s(c *math.Curve, count int, label string) []*math.G1 {
	res := make([]*math.G1, count)
	for i := 0; i < count; i++ {
		buff := make([]byte, 0, 20)
		buff = append(buff, []byte("PS")...)
		buff = append(buff, []byte(label)...)
		n := make([]byte, 2)
		binary.BigEndian.PutUint16(n, uint16(i))
		buff = append(buff, n...)
		res[i] = c.HashToG1(hash(buff))
	}
	return res
}

func psuedoRandomG2(c *math.Curve) *math.G2 {
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

/*
func neg(in *math.G1) *math.G1 {
	zero := c.GenG1.Copy()
	zero.Sub(zero)

	zero.Sub(in)
	return zero
}
*/
