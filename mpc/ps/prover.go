/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"encoding/asn1"
	"fmt"
	math "github.com/IBM/mathlib"
)

type Prover struct {
	// Config
	Logger Logger

	// State
	tpk                 PK
	publicKeysOfParties map[uint16]PK
	c                   *math.Curve
	msgLen              int
	pp                  PP
}

func (p *Prover) Init(curve *math.Curve, msgLen int, thresholdPK []byte, parties []uint16) error {
	p.c = curve
	p.msgLen = msgLen
	p.pp = Setup(p.c, p.msgLen)

	var tpk ThresholdPK
	if _, err := asn1.Unmarshal(thresholdPK, &tpk); err != nil {
		return err
	}

	p.publicKeysOfParties = make(map[uint16]PK)

	for i, party := range parties {
		var pk PK
		if err := pk.fromBytes(p.c, tpk.PublicKeys[i]); err != nil {
			return err
		}

		p.publicKeysOfParties[party] = pk
	}

	if err := p.tpk.fromBytes(curve, tpk.TPK); err != nil {
		return err
	}

	return nil
}

func (p *Prover) Blind(msg [][]byte) (BlindSignature, UnblindingSecret) {
	if len(msg) != p.msgLen {
		panic(fmt.Sprintf("requested to blind a message of length %d but initialized for messages of length %d", len(msg), p.msgLen))
	}

	m := make([]*math.Zr, len(msg))
	for i := 0; i < len(m); i++ {
		m[i] = p.c.HashToZr(msg[i])
	}

	return Blind(&p.pp, p.c, m)
}

type SignatureWitness math.G1

func (p *Prover) UnBlind(party uint16, blindedSig []byte, secret *UnblindingSecret) (SignatureWitness, error) {
	var rs RawSignature
	if _, err := asn1.Unmarshal(blindedSig, &rs); err != nil {
		return SignatureWitness{}, err
	}

	σ, err := p.parseSignature(rs)
	if err != nil {
		return SignatureWitness{}, err
	}

	hPrime, err := UnBlind(&p.pp, p.publicKeysOfParties[party], &σ, secret.h, secret.msg, secret.z)
	if err != nil {
		return SignatureWitness{}, err
	}

	w := SignatureWitness(*hPrime)

	return w, nil
}

func (p *Prover) ProveKnowledgeOfSignature(us *UnblindingSecret, signers []uint16, witnesses []SignatureWitness) SigPoK {
	if len(signers) != len(witnesses) {
		panic(fmt.Sprintf("attempted to prove with %d signers but %d witnesses", len(signers), len(witnesses)))
	}

	evaluationPoints := make([]int64, len(signers))
	for i, signer := range signers {
		evaluationPoints[i] = int64(signer)
	}

	// initialize hPrime to be zero
	hPrime := p.c.GenG1.Copy()
	hPrime.Sub(hPrime)

	// Combine all witnesses into a single one with the lagrange coefficients
	for i, signer := range signers {
		l := lagrangeCoefficient(int64(signer), evaluationPoints...)
		w := math.G1(witnesses[i])
		hPrime.Add(w.Mul(l))
	}

	return PoKofSig(&p.pp, p.tpk, us.h, hPrime, us.msg)
}

func (p *Prover) parseSignature(rs RawSignature) (Signature, error) {
	var σ Signature
	var err error
	σ.a, err = p.c.NewG1FromBytes(rs.A)
	if err != nil {
		return Signature{}, err
	}

	σ.b, err = p.c.NewG1FromBytes(rs.B)
	if err != nil {
		return Signature{}, err
	}
	return σ, nil
}
