/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSS(t *testing.T) {
	s := SSS{
		Threshold: 2,
	}

	polynomial, shares := s.Gen(5)

	zeroValue := shares.reconstruct(2, 3)
	assert.Equal(t, polynomial.ValueAt(0), zeroValue)
}
