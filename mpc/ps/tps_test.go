/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"context"
	"fmt"
	"sync"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

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

	var prover Prover
	prover.Logger = logger("prover", t.Name())
	err := prover.Init(math.Curves[1], len(msg), thresholdPK, []uint16{1, 2, 3})
	assert.NoError(t, err)

	var blindSig []byte
	var unblindingSecret *UnblindingSecret

	t.Run("Blind", func(t *testing.T) {
		σ, secret := prover.Blind(msg)
		blindSig = σ.Bytes()
		unblindingSecret = &secret
	})

	signatures := make([][]byte, 3)

	t.Run("Sign", func(t *testing.T) {
		// Create the parties again, and initialize them out of their share data
		p1 := makeParty(t, 1, len(msg))
		p2 := makeParty(t, 2, len(msg))
		p3 := makeParty(t, 3, len(msg))

		parties := []*TPS{p1, p2, p3}

		initP1(p1, parties)
		initP2(p2, parties)
		initP3(p3, parties)

		err := p1.SetShareData(shares[0])
		assert.NoError(t, err)
		err = p2.SetShareData(shares[1])
		assert.NoError(t, err)
		err = p3.SetShareData(shares[2])
		assert.NoError(t, err)

		p1.ThresholdPK()

		σ1, err := p1.Sign(context.Background(), blindSig)
		assert.NoError(t, err)

		σ2, err := p2.Sign(context.Background(), blindSig)
		assert.NoError(t, err)

		σ3, err := p3.Sign(context.Background(), blindSig)
		assert.NoError(t, err)

		signatures[0] = σ1
		signatures[1] = σ2
		signatures[2] = σ3
	})

	signatureWitnesses := make([]SignatureWitness, 3)

	t.Run("UnBlind", func(t *testing.T) {
		w1, err := prover.UnBlind(1, signatures[0], unblindingSecret)
		assert.NoError(t, err)

		w2, err := prover.UnBlind(2, signatures[1], unblindingSecret)
		assert.NoError(t, err)

		w3, err := prover.UnBlind(3, signatures[2], unblindingSecret)
		assert.NoError(t, err)

		signatureWitnesses[0] = w1
		signatureWitnesses[1] = w2
		signatureWitnesses[2] = w3
	})

	proofs := make([][]byte, 3)

	t.Run("Prove Knowledge Of Signature", func(t *testing.T) {
		π := prover.ProveKnowledgeOfSignature(unblindingSecret, []uint16{1, 2}, []SignatureWitness{signatureWitnesses[0], signatureWitnesses[1]})
		proofs[0] = π.Bytes()

		π = prover.ProveKnowledgeOfSignature(unblindingSecret, []uint16{2, 3}, []SignatureWitness{signatureWitnesses[1], signatureWitnesses[2]})
		proofs[1] = π.Bytes()

		π = prover.ProveKnowledgeOfSignature(unblindingSecret, []uint16{1, 3}, []SignatureWitness{signatureWitnesses[0], signatureWitnesses[2]})
		proofs[2] = π.Bytes()
	})

	t.Run("Verify PoK of signature", func(t *testing.T) {
		var v Verifier
		err := v.Init(math.Curves[1], len(msg), thresholdPK)
		assert.NoError(t, err)

		err = v.Verify(proofs[0])
		assert.NoError(t, err)

		err = v.Verify(proofs[1])
		assert.NoError(t, err)

		err = v.Verify(proofs[2])
		assert.NoError(t, err)
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
