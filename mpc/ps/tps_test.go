/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"context"
	"fmt"
	math "github.com/IBM/mathlib"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestDKG(t *testing.T) {
	pp := Setup(math.Curves[1], 3)
	xShares1 := secretShare(3, 2)
	xShares2 := secretShare(3, 2)

	xShares := make(Shares, len(xShares1))
	for i := 0; i < len(xShares); i++ {
		xShares[i] = xShares1[i].Plus(xShares2[i])
	}

	var xPK []*math.G2
	for i := 0; i < len(xShares); i++ {
		xPK = append(xPK, pp.g2.Mul(xShares[i]))
	}

	pk1 := localAggregateECPoints(xPK, []int64{1, 2}...)
	pk2 := localAggregateECPoints(xPK, []int64{2, 3}...)
	pk3 := localAggregateECPoints(xPK, []int64{1, 3}...)

	fmt.Println(pk1.Equals(pk2))
	fmt.Println(pk2.Equals(pk3))

}

func TestTPS(t *testing.T) {
	var thresholdPK []byte
	shares := make([][]byte, 3)
	msg := [][]byte{
		[]byte(`“Would you tell me, please, which way I ought to go from here?”`),
		[]byte(`“That depends a good deal on where you want to get to,” said the Cat.`),
		[]byte(`“I don’t much care where—” said Alice.`),
		[]byte(`“Then it doesn’t matter which way you go,” said the Cat.`),
		[]byte(`“—so long as I get somewhere,” Alice added as an explanation.`),
		[]byte(`“Oh, you’re sure to do that,” said the Cat, “if you only walk long enough.”`),
	}

	_ = msg

	/*digest := sha256.Sum256(msg)
	_ = digest*/

	t.Run("KeyGen", func(t *testing.T) {
		p1 := makeParty(t, 1, len(msg))
		p2 := makeParty(t, 2, len(msg))
		p3 := makeParty(t, 3, len(msg))

		parties := []*TPS{p1, p2, p3}

		initP1(p1, parties)
		initP2(p2, parties)
		initP3(p3, parties)

		var wg sync.WaitGroup
		wg.Add(3)

		for i, p := range parties {
			go func(i int, p *TPS) {
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
}

func initP3(p3 *TPS, parties []*TPS) {
	p3.Init([]uint16{1, 2, 3}, 2, func(msg []byte, isBroadcast bool, to uint16) {
		if isBroadcast {
			parties[0].OnMsg(msg, 3, isBroadcast)
			parties[1].OnMsg(msg, 3, isBroadcast)
		} else {
			parties[int(to)-1].OnMsg(msg, 3, isBroadcast)
		}
	})
}

func initP2(p2 *TPS, parties []*TPS) {
	p2.Init([]uint16{1, 2, 3}, 2, func(msg []byte, isBroadcast bool, to uint16) {
		if isBroadcast {
			parties[0].OnMsg(msg, 2, isBroadcast)
			parties[2].OnMsg(msg, 2, isBroadcast)
		} else {
			parties[int(to)-1].OnMsg(msg, 2, isBroadcast)
		}
	})
}

func initP1(p1 *TPS, parties []*TPS) {
	p1.Init([]uint16{1, 2, 3}, 2, func(msg []byte, isBroadcast bool, to uint16) {
		if isBroadcast {
			parties[1].OnMsg(msg, 1, isBroadcast)
			parties[2].OnMsg(msg, 1, isBroadcast)
		} else {
			parties[int(to)-1].OnMsg(msg, 1, isBroadcast)
		}
	})
}

func makeParty(t *testing.T, id int, msgLength int) *TPS {
	party := &TPS{
		MessageLength: msgLength,
		Curve:         math.Curves[1],
		Logger:        logger(fmt.Sprintf("p%d", id), t.Name()),
		Party:         uint16(id),
	}
	return party
}

func logger(id string, testName string) Logger {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	logger = logger.With(zap.String("t", testName)).With(zap.String("id", id))
	return logger.Sugar()
}
