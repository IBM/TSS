/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNChooseK(t *testing.T) {
	for _, tst := range []struct {
		n int
		k int
	}{
		{n: 1, k: 1},
		{n: 2, k: 2},
		{n: 3, k: 3},
		{n: 5, k: 3},
		{n: 10, k: 5},
	} {
		t.Run(fmt.Sprintf("%d choose %d", tst.n, tst.k), func(t *testing.T) {
			s := make(map[string]struct{})
			permutations := (&big.Int{}).Binomial(int64(tst.n), int64(tst.k))
			var count int
			chooseKoutOfN(tst.n, tst.k, func(a []int64) {
				count++
				s[fmt.Sprintf("%v", a)] = struct{}{}
			})
			assert.Len(t, s, int(permutations.Int64()))
			assert.Equal(t, int(permutations.Int64()), count)
		})
	}
}
