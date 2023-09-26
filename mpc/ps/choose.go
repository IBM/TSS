/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

func chooseKoutOfN(n, k int, f func([]int64)) {
	choose(n, k, 0, nil, f)
}

func choose(n int, targetAmount int, i int, currentSubGroup []int64, f func([]int64)) {
	// Check if we have enough elements in our current subgroup
	if len(currentSubGroup) == targetAmount {
		f(currentSubGroup)
		return
	}
	// Return early if not enough remaining candidates to pick from
	itemsLeftToPick := n - i
	if targetAmount-len(currentSubGroup) > itemsLeftToPick {
		return
	}
	// We either pick the current element
	choose(n, targetAmount, i+1, concatInts(currentSubGroup, int64(i+1)), f)
	// Or don't pick it
	choose(n, targetAmount, i+1, currentSubGroup, f)
}

func concatInts(a []int64, elements ...int64) []int64 {
	var res []int64
	res = append(res, a...)
	res = append(res, elements...)
	return res
}
