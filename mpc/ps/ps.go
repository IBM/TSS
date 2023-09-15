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
	X *math.G2
	Y []*math.G2
}

func LocalKeyGen(pp PP) (SK, PK) {
	sk := SK{
		ys: make([]*math.Zr, pp.n),
	}

	sk.x = pp.c.NewRandomZr(rand.Reader)
	for i := 0; i < len(sk.ys); i++ {
		sk.ys[i] = pp.c.NewRandomZr(rand.Reader)
	}

	pk := PK{
		X: pp.g2.Mul(sk.x),
		Y: make([]*math.G2, len(sk.ys)),
	}

	for i := 0; i < len(sk.ys); i++ {
		pk.Y[i] = pp.g2.Mul(sk.ys[i])
	}

	return sk, pk
}

type BlindSignature struct {
	ξ      BlindCorrectFormProof
	cm     *math.G1
	mPrime *math.Zr
	u      *math.G1
	a, b   []*math.G1
}

type UnblindingSecret struct {
	msg []*math.Zr
	z   *math.Zr
	h   *math.G1
}

func Blind(pp *PP, c *math.Curve, m []*math.Zr) (BlindSignature, UnblindingSecret) {
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

	oldCM := cm.Copy()

	mPrime := pp.c.HashToZr(hash(cm.Bytes()))

	// Add m' to commitment
	cm.Add(pp.gs[len(pp.gs)-1].Mul(mPrime))

	// Update 'h' with final commitment
	h := pp.c.HashToG1(cm.Bytes())

	msg := make([]*math.Zr, pp.n)
	copy(msg, m)
	msg[len(msg)-1] = mPrime
	a, b, r := encrypt(pp, c, msg, h, u)

	ξ := proveBlindingIsWellFormed(c, msg, r, a, b, rcm, pp.g, pp.g0, h, u, cm, pp.gs)

	return BlindSignature{
			mPrime: mPrime,
			cm:     oldCM,
			u:      u,
			ξ:      ξ,
			a:      a,
			b:      b,
		}, UnblindingSecret{
			h:   h,
			z:   z,
			msg: msg,
		}
}

type Signature struct {
	A, B *math.G1
}

func SignBlindSignature(pp *PP, σ BlindSignature, sk SK) (*Signature, error) {
	mPrime := pp.c.HashToZr(hash(σ.cm.Bytes()))
	cm := σ.cm.Copy()
	cm.Add(pp.gs[len(pp.gs)-1].Mul(mPrime))

	h := pp.c.HashToG1(cm.Bytes())

	// Verify blind signature is well formed
	err := σ.ξ.Verify(pp.c, len(pp.gs), σ.a, σ.b, cm, pp.g, pp.g0, h, σ.u, pp.gs)
	if err != nil {
		return nil, err
	}

	// initialize a to be zero
	a := pp.c.GenG1.Copy()
	a.Sub(a)

	for i := 0; i < len(pp.gs); i++ {
		a.Add(σ.a[i].Mul(sk.ys[i]))
	}

	b := h.Mul(sk.x)

	for i := 0; i < len(pp.gs); i++ {
		b.Add(σ.b[i].Mul(sk.ys[i]))
	}

	return &Signature{A: a, B: b}, nil
}

func UnBlind(pp *PP, pk PK, σ *Signature, h *math.G1, msg []*math.Zr, z *math.Zr) (*math.G1, error) {
	negZ := pp.c.ModNeg(z, pp.c.GroupOrder)
	hPrime := σ.B.Copy()
	hPrime.Add(σ.A.Mul(negZ))

	right := pp.c.Pairing(pp.g2, hPrime)
	right = pp.c.FExp(right)

	E := pk.X.Copy()
	for i := 0; i < len(msg); i++ {
		E.Add(pk.Y[i].Mul(msg[i]))
	}

	left := pp.c.Pairing(E, h)
	left = pp.c.FExp(left)

	if !right.Equals(left) {
		return nil, fmt.Errorf("unblinded signature is incorrect")
	}

	return hPrime, nil
}

type SigPoK struct {
	ψ       PoKofSignaturePoCorrectForm
	hε      *math.G1
	hPrimeε *math.G1
	ν       *math.G1
	κ       *math.G2
}

func (sigPoK SigPoK) Verify(pp *PP, pk PK) error {
	if err := sigPoK.ψ.Verify(pp.c, sigPoK.ν, sigPoK.hε, pp.g2, pk.X, sigPoK.κ, pk.Y); err != nil {
		return fmt.Errorf("pairing argument is not well formed: %v", err)
	}

	zero := pp.c.GenG1.Copy()
	zero.Sub(zero)

	if zero.Equals(sigPoK.hε) {
		return fmt.Errorf("h^ε is 0")
	}

	left := pp.c.Pairing(sigPoK.κ, sigPoK.hε)
	left = pp.c.FExp(left)

	hPrimeεν := sigPoK.hPrimeε.Copy()
	hPrimeεν.Add(sigPoK.ν)

	right := pp.c.Pairing(pp.g2, hPrimeεν)
	right = pp.c.FExp(right)

	if !left.Equals(right) {
		return fmt.Errorf("pairing condition unsatisfied")
	}

	return nil
}

func PoKofSig(pp *PP, pk PK, h, hPrime *math.G1, msg []*math.Zr) SigPoK {
	ε, δ := pp.c.NewRandomZr(rand.Reader), pp.c.NewRandomZr(rand.Reader)
	κ := pk.X.Copy()
	for i := 0; i < len(pk.Y); i++ {
		κ.Add(pk.Y[i].Mul(msg[i]))
	}
	κ.Add(pp.g2.Mul(δ))

	hε := h.Mul(ε)
	ν := hε.Mul(δ)
	hPrimeε := hPrime.Mul(ε)

	ψ := proveProofOfKnowledgeOfSignatureIsCorrectlyFormed(pp.c, msg, δ, ν, hε, κ, pp.g2, pk.X, pk.Y)

	return SigPoK{
		hPrimeε: hPrimeε,
		κ:       κ,
		hε:      hε,
		ν:       ν,
		ψ:       ψ,
	}
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

type PoKofSignaturePoCorrectForm struct {
	x []*math.Zr
	y *math.Zr
	Γ *math.G2
	Φ *math.G1
}

func (ψ PoKofSignaturePoCorrectForm) Verify(c *math.Curve, ν, hε *math.G1, g2, X, κ *math.G2, Y []*math.G2) error {

	digest := randomOracleForPoKofSignature(ψ.Γ, ψ.Φ, ν, hε, g2, X, κ, Y)
	e := c.HashToZr(digest)

	if err := ψ.checkcommitmentForm(c, e, g2, X, κ, Y); err != nil {
		return err
	}

	left := hε.Copy().Mul(ψ.y)
	right := ν.Mul(e)
	right.Add(ψ.Φ)

	if !left.Equals(right) {
		return fmt.Errorf("ν is not well formed")
	}

	return nil
}

func (ψ PoKofSignaturePoCorrectForm) checkcommitmentForm(c *math.Curve, e *math.Zr, g2 *math.G2, X *math.G2, κ *math.G2, Y []*math.G2) error {
	left := g2.Mul(ψ.y)
	for i := 0; i < len(ψ.x); i++ {
		left.Add(Y[i].Mul(ψ.x[i]))
	}

	right := ψ.Γ.Copy()
	κ = κ.Copy()
	κ.Add(neg(c, X))
	κ = κ.Mul(e)
	right.Add(κ)

	if !left.Equals(right) {
		return fmt.Errorf("κ is not well formed")
	}

	return nil
}

func randomOracleForPoKofSignature(Γ *math.G2, Φ *math.G1, ν, hε *math.G1, g2, X, κ *math.G2, Y []*math.G2) []byte {
	hash := sha256.New()

	for i := 0; i < len(Y); i++ {
		hash.Write(Y[i].Bytes())
	}
	hash.Write(X.Bytes())
	hash.Write(g2.Bytes())

	hash.Write(Γ.Bytes())
	hash.Write(Φ.Bytes())
	hash.Write(ν.Bytes())
	hash.Write(hε.Bytes())
	hash.Write(κ.Bytes())

	return hash.Sum(nil)
}

func proveProofOfKnowledgeOfSignatureIsCorrectlyFormed(c *math.Curve, m []*math.Zr, δ *math.Zr, ν, hε *math.G1, κ, g2, X *math.G2, Y []*math.G2) PoKofSignaturePoCorrectForm {
	μ := c.NewRandomZr(rand.Reader)
	n := len(m)
	γ := make([]*math.Zr, n)
	for i := 0; i < n; i++ {
		γ[i] = c.NewRandomZr(rand.Reader)
	}

	Γ := g2.Mul(μ)
	for i := 0; i < n; i++ {
		Γ.Add(Y[i].Mul(γ[i]))
	}

	Φ := hε.Mul(μ)

	e := c.HashToZr(randomOracleForPoKofSignature(Γ, Φ, ν, hε, g2, X, κ, Y))

	x := make([]*math.Zr, len(m))

	for i := 0; i < len(m); i++ {
		x[i] = γ[i].Plus(e.Mul(m[i]))
	}

	y := μ.Plus(e.Mul(δ))

	return PoKofSignaturePoCorrectForm{
		x: x,
		y: y,
		Γ: Γ,
		Φ: Φ,
	}
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

func neg(c *math.Curve, in *math.G2) *math.G2 {
	zero := c.GenG2.Copy()
	zero.Sub(zero)

	zero.Sub(in)
	return zero
}
