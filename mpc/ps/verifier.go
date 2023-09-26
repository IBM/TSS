/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"encoding/asn1"
	math "github.com/IBM/mathlib"
)

type Verifier struct {
	// State
	tpk    PK
	c      *math.Curve
	msgLen int
	pp     PP
}

func (v *Verifier) Init(curve *math.Curve, msgLen int, thresholdPK []byte) error {
	v.c = curve
	v.msgLen = msgLen
	v.pp = Setup(v.c, v.msgLen)

	var tpk ThresholdPK
	if _, err := asn1.Unmarshal(thresholdPK, &tpk); err != nil {
		return err
	}

	if err := v.tpk.fromBytes(curve, tpk.TPK); err != nil {
		return err
	}

	return nil
}

func (v *Verifier) Verify(proof []byte) error {
	var π SigPoK
	if err := π.fromBytes(v.c, proof); err != nil {
		return err
	}

	return π.Verify(&v.pp, v.tpk)
}
