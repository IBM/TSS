/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestThresholdBLS(t *testing.T) {
	var thresholdPK []byte
	shares := make([][]byte, 3)
	signatures := make([][]byte, 3)

	msg := []byte("The truth is not for all men but only for those who seek it.")
	digest := sha256.Sum256(msg)

	t.Run("KeyGen", func(t *testing.T) {
		p1 := makeParty(t, 1)
		p2 := makeParty(t, 2)
		p3 := makeParty(t, 3)

		parties := []*TBLS{p1, p2, p3}

		initP1(p1, parties)
		initP2(p2, parties)
		initP3(p3, parties)

		var wg sync.WaitGroup
		wg.Add(3)

		for i, p := range parties {
			go func(i int, p *TBLS) {
				defer wg.Done()
				share, err := p.KeyGen(context.Background())
				assert.NoError(t, err)

				// Save the share for later use
				shares[i] = share
			}(i, p)
		}

		wg.Wait()

		// Ensure all parties now output the same threshold public key
		for _, p := range parties {
			tpk, err := p.ThresholdPK()
			assert.NoError(t, err)

			if thresholdPK == nil {
				thresholdPK = tpk
			} else {
				assert.Equal(t, thresholdPK, tpk)
			}
		}
	})

	// Next, proceed to signing and verifying a threshold message

	t.Run("Sign", func(t *testing.T) {
		p1 := makeParty(t, 1)
		p2 := makeParty(t, 2)
		p3 := makeParty(t, 3)

		parties := []*TBLS{p1, p2, p3}

		initP1(p1, parties)
		initP2(p2, parties)
		initP3(p3, parties)

		for i, p := range parties {
			p.SetShareData(shares[i])
		}

		for i, p := range parties {
			sig, err := p.Sign(context.Background(), digest[:])
			assert.NoError(t, err)

			signatures[i] = sig
		}
	})

	t.Run("Verify", func(t *testing.T) {
		var v Verifier
		assert.NoError(t, v.Init(thresholdPK))

		thresholdSignature, err := v.AggregateSignatures(signatures[:2], []uint16{1, 2})
		assert.NoError(t, err)
		assert.NoError(t, v.Verify(digest[:], thresholdSignature))

		thresholdSignature, err = v.AggregateSignatures(signatures[1:], []uint16{2, 3})
		assert.NoError(t, err)

		assert.NoError(t, v.Verify(digest[:], thresholdSignature))
	})
}

func initP3(p3 *TBLS, parties []*TBLS) {
	p3.Init([]uint16{1, 2, 3}, 2, func(msg []byte, isBroadcast bool, to uint16) {
		if isBroadcast {
			parties[0].OnMsg(msg, 3, isBroadcast)
			parties[1].OnMsg(msg, 3, isBroadcast)
		} else {
			parties[int(to)-1].OnMsg(msg, 3, isBroadcast)
		}
	})
}

func initP2(p2 *TBLS, parties []*TBLS) {
	p2.Init([]uint16{1, 2, 3}, 2, func(msg []byte, isBroadcast bool, to uint16) {
		if isBroadcast {
			parties[0].OnMsg(msg, 2, isBroadcast)
			parties[2].OnMsg(msg, 2, isBroadcast)
		} else {
			parties[int(to)-1].OnMsg(msg, 2, isBroadcast)
		}
	})
}

func initP1(p1 *TBLS, parties []*TBLS) {
	p1.Init([]uint16{1, 2, 3}, 2, func(msg []byte, isBroadcast bool, to uint16) {
		if isBroadcast {
			parties[1].OnMsg(msg, 1, isBroadcast)
			parties[2].OnMsg(msg, 1, isBroadcast)
		} else {
			parties[int(to)-1].OnMsg(msg, 1, isBroadcast)
		}
	})
}

func makeParty(t *testing.T, id int) *TBLS {
	party := &TBLS{
		Logger: logger(fmt.Sprintf("p%d", id), t.Name()),
		Party:  uint16(id),
	}
	return party
}

func logger(id string, testName string) Logger {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	logger = logger.With(zap.String("t", testName)).With(zap.String("id", id))
	return logger.Sugar()
}
