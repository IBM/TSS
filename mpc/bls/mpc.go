/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"sync"

	math "github.com/IBM/mathlib"
)

const (
	unefined uint8 = iota
	shareDistribution
	commitPK
	revealPK
)

type Logger interface {
	Debugf(format string, a ...interface{})
	Infof(format string, a ...interface{})
	Warnf(format string, a ...interface{})
	Errorf(format string, a ...interface{})
}

type TBLS struct {
	Party     uint16
	Logger    Logger
	id        int
	sendMsg   func(msg []byte, isBroadcast bool, to uint16)
	parties   []uint16
	threshold int
	sk        *math.Zr

	lock                sync.Mutex
	init                bool
	signal              sync.Cond
	shares              map[uint16]*math.Zr
	commitments         map[uint16][]byte
	publicKeysOfParties map[uint16][]byte

	sd *StoredData
}

type StoredData struct {
	Sk          []byte
	PublicKeys  [][]byte
	ThresholdPK []byte
}

func (tbls *TBLS) ThresholdPK() ([]byte, error) {
	if tbls.sd == nil {
		panic("invoke SetShareData() or KeyGen() before invoking ThresholdPK()")
	}

	if len(tbls.parties) == 0 {
		panic("invoke Init() before calling ThresholdPK()")
	}

	return asn1.Marshal(PublicParams{
		PublicKeys:  tbls.sd.PublicKeys,
		ThresholdPK: tbls.sd.ThresholdPK,
		Parties:     uint16ToIntSlice(tbls.parties),
	})
}

func (tbls *TBLS) SetShareData(shareData []byte) error {
	sd := &StoredData{}
	if _, err := asn1.Unmarshal(shareData, sd); err != nil {
		return err
	}
	tbls.sd = sd
	tbls.sk = c.NewZrFromBytes(tbls.sd.Sk)
	return nil
}

func (tbls *TBLS) Sign(_ context.Context, msgHash []byte) ([]byte, error) {
	if tbls.sk == nil {
		panic("invoke SetShareData() or KeyGen() before invoking Sign()")
	}

	return localSign(tbls.sk, msgHash).Bytes(), nil
}

func (tbls *TBLS) ClassifyMsg(msgBytes []byte) (uint8, bool, error) {
	switch msgBytes[0] {
	case shareDistribution:
		return shareDistribution, false, nil
	case commitPK:
		return commitPK, true, nil
	case revealPK:
		return commitPK, true, nil
	default:
		return 0, false, fmt.Errorf("invalid prefix: %d", msgBytes[0])
	}
}

func (tbls *TBLS) Init(parties []uint16, threshold int, sendMsg func(msg []byte, isBroadcast bool, to uint16)) {
	party2ID := make(map[uint16]int)
	for i := 0; i < len(parties); i++ {
		party2ID[parties[i]] = i + 1
		if parties[i] == tbls.Party {
			tbls.id = i + 1
		}
	}
	tbls.sk = nil
	tbls.parties = parties
	tbls.threshold = threshold
	tbls.sendMsg = sendMsg
	tbls.shares = make(map[uint16]*math.Zr)
	tbls.commitments = make(map[uint16][]byte)
	tbls.publicKeysOfParties = make(map[uint16][]byte)
	tbls.signal = sync.Cond{L: &tbls.lock}
	tbls.init = true
}

func (tbls *TBLS) OnMsg(msgBytes []byte, from uint16, _ bool) {
	tbls.lock.Lock()
	defer tbls.lock.Unlock()

	switch msgBytes[0] {
	case shareDistribution:
		tbls.Logger.Infof("Got share distribution from %d", from)
		if _, exists := tbls.shares[from]; exists {
			tbls.Logger.Warnf("Already got share from %d", from)
			return
		}

		tbls.shares[from] = c.NewZrFromBytes(msgBytes[1:])
		tbls.signal.Signal()
	case commitPK:
		tbls.Logger.Infof("Got commitment from %d", from)
		if _, exists := tbls.commitments[from]; exists {
			tbls.Logger.Warnf("Already got commitment from %d", from)
			return
		}

		tbls.commitments[from] = msgBytes[1:]
		tbls.signal.Signal()
	case revealPK:
		if _, exists := tbls.publicKeysOfParties[from]; exists {
			tbls.Logger.Warnf("Already got public key from %d", from)
			return
		}

		if _, err := c.NewG2FromBytes(msgBytes[1:]); err != nil {
			tbls.Logger.Warnf("Public key %s of party %d is malformed: %v",
				base64.StdEncoding.EncodeToString(msgBytes[1:]), from, err)
			return
		}

		tbls.publicKeysOfParties[from] = msgBytes[1:]
		expectedCommitment := sha256.Sum256(tbls.publicKeysOfParties[from])
		tbls.Logger.Infof("Got public key from %d: %s, expecting to receive commitment %s",
			from, base64.StdEncoding.EncodeToString(msgBytes[1:]), base64.StdEncoding.EncodeToString(expectedCommitment[:]))
		tbls.signal.Signal()
	default:
		tbls.Logger.Warnf("Got message with invalid tag (%d) from %d", msgBytes[0], from)
	}
}

func (tbls *TBLS) monitorContextTimeout(ctx context.Context) func() {
	keygenFinished := make(chan struct{})

	go func() {
		select {
		case <-keygenFinished:
			return
		case <-ctx.Done():
			tbls.lock.Lock()
			tbls.signal.Signal()
			tbls.lock.Unlock()
		}
	}()

	return func() {
		close(keygenFinished)
	}
}

func (tbls *TBLS) KeyGen(ctx context.Context) ([]byte, error) {
	tbls.ensureInitOrPanic()
	defer tbls.monitorContextTimeout(ctx)()

	// We first generate a polynomial P(x) of 'threshold - 1' degree,
	// and evaluate 'len(parties)' points on it, one point for each party.
	shares := localGen(len(tbls.parties), tbls.threshold)

	// We then distribute the polynomial evaluations (shares) to all parties.
	// Each party 'i' gets P(i).
	tbls.shareDistribution(ctx, shares)

	// Having received all shares, we combine all shares received from all parties by adding them.
	// Now, the private key of each party 'i' is defined to be:
	// Sk = P1(i) + P2(i) + ... Pn(i)
	pk := tbls.combineShares()

	// Our public key 'pk' is now Sk * G2 and will be used whenever anyone validates a signature from us.
	// However, we do not expose this public key just yet.
	// Instead, we commit to it and send our commitment to everyone,
	// and wait for commitments from everyone else.
	tbls.commitPhase(ctx, pk)

	// Now we de-commit, and wait for everyone else to de-commit thus revealing their public key.
	tbls.revealPhase(ctx, pk)
	// Next, we ensure the commitments we received match the de-commitments
	if err := tbls.validateCommitments(); err != nil {
		return nil, err
	}

	// Finally, we ensure that we get the same threshold public key
	// not matter which combination of (len(parties) choose threshold) parties is chosen
	// There is no need to validate with the other parties, as the reliable broadcast ensures us
	// that everyone else received the same public keys as us.
	thresholdPublicKeyCombinations, thresholdPublicKey := tbls.assembleThresholdPublicKey()

	// Ensure there is only a single threshold public key
	if len(thresholdPublicKeyCombinations) > 1 {
		return nil, fmt.Errorf("got %d different threshold public keys", len(thresholdPublicKeyCombinations))
	}

	tbls.sd = &StoredData{
		ThresholdPK: thresholdPublicKey.Bytes(),
		PublicKeys:  tbls.flattenPublicKeys(),
		Sk:          tbls.sk.Bytes(),
	}
	return asn1.Marshal(*tbls.sd)
}

func (tbls *TBLS) ensureInitOrPanic() {
	if !tbls.init {
		panic("Init() must be called before using KeyGen()")
	}
}

func (tbls *TBLS) flattenPublicKeys() [][]byte {
	publicKeys := make([][]byte, len(tbls.parties))
	for i, p := range tbls.parties {
		rawPK, exists := tbls.publicKeysOfParties[p]
		if !exists {
			panic(fmt.Sprintf("programming error: public key of party %d was not found", p))
		}

		publicKeys[i] = rawPK
	}
	return publicKeys
}

func (tbls *TBLS) assembleThresholdPublicKey() (map[string]*math.G2, *math.G2) {
	thresholdPublicKeys := make(map[string]*math.G2)
	var thresholdPublicKey *math.G2
	chooseKoutOfN(len(tbls.parties), tbls.threshold, func(evaluationPoints []int64) {
		var publicKeys []*math.G2
		// For each party, get its announced public key
		for _, p := range tbls.parties {
			rawPK, exists := tbls.publicKeysOfParties[p]
			if !exists {
				panic(fmt.Sprintf("programming error: public key of party %d was not found", p))
			}

			pk, err := c.NewG2FromBytes(rawPK)
			if err != nil {
				panic(fmt.Sprintf("programming error: public key of party %d is malformed", p))
			}
			publicKeys = append(publicKeys, pk)
		}

		// Now create the threshold public key
		thresholdPublicKey = localAggregatePublicKeys(publicKeys, evaluationPoints...)
		thresholdPublicKeys[thresholdPublicKey.String()] = thresholdPublicKey
	})
	return thresholdPublicKeys, thresholdPublicKey
}

func (tbls *TBLS) validateCommitments() error {
	tbls.lock.Lock()
	defer tbls.lock.Unlock()

	if len(tbls.publicKeysOfParties) != len(tbls.parties) {
		fmt.Sprintf("programming error: received only %d decommitments from %d parties", len(tbls.publicKeysOfParties)-1, len(tbls.parties))
	}

	for party, pk := range tbls.publicKeysOfParties {
		if tbls.Party == party {
			// No point validating ourselves
			continue
		}
		commitment, exists := tbls.commitments[party]
		if !exists {
			panic(fmt.Sprintf("programming error: decommitment of party %d was not found", party))
		}

		h := sha256.New()
		h.Write(pk)
		expected := h.Sum(nil)

		if bytes.Equal(expected, commitment) {
			continue
		}

		return fmt.Errorf("party %d received public key from party %d: %s, but its commitment mismatches: %s",
			tbls.Party, party, base64.StdEncoding.EncodeToString(pk), base64.StdEncoding.EncodeToString(commitment))
	}

	return nil
}

func (tbls *TBLS) contextTimedOut(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (tbls *TBLS) shareDistribution(ctx context.Context, shares Shares) {
	for i := 0; i < len(tbls.parties); i++ {
		// My party
		if i+1 == tbls.id {
			tbls.sk = shares[i]
			continue
		}
		tbls.sendMsg(encodeMsg(shareDistribution, shares[i].Bytes()), false, tbls.parties[i])
	}

	tbls.waitForShareDistribution(ctx)
}

func (tbls *TBLS) revealPhase(ctx context.Context, pk []byte) {
	tbls.Logger.Infof("Broadcasting public key: %s", base64.StdEncoding.EncodeToString(pk))
	tbls.sendMsg(encodeMsg(revealPK, pk), true, 0)

	tbls.waitForDeCommitmentDistribution(ctx)
}

func (tbls *TBLS) commitPhase(ctx context.Context, pk []byte) {
	digest := sha256.Sum256(pk)
	commitment := digest[:]

	tbls.Logger.Infof("Broadcasting commitment: %s", base64.StdEncoding.EncodeToString(commitment))

	tbls.sendMsg(encodeMsg(commitPK, commitment), true, 0)

	tbls.waitForCommitmentDistribution(ctx)
}

func (tbls *TBLS) combineShares() []byte {
	for _, party := range tbls.parties {
		if party == tbls.Party {
			continue
		}

		share := tbls.shares[party]
		tbls.sk = tbls.sk.Plus(share)
	}

	pk := c.GenG2.Mul(tbls.sk).Bytes()
	tbls.publicKeysOfParties[tbls.Party] = pk
	return pk
}

func (tbls *TBLS) waitForShareDistribution(ctx context.Context) {
	tbls.lock.Lock()
	defer tbls.lock.Unlock()

	for !tbls.contextTimedOut(ctx) {
		if len(tbls.shares) == len(tbls.parties)-1 {
			return
		}

		tbls.signal.Wait()
	}
}

func (tbls *TBLS) waitForCommitmentDistribution(ctx context.Context) {
	tbls.lock.Lock()
	defer tbls.lock.Unlock()

	for !tbls.contextTimedOut(ctx) {
		if len(tbls.commitments) == len(tbls.parties)-1 {
			return
		}

		tbls.signal.Wait()
	}
}

func (tbls *TBLS) waitForDeCommitmentDistribution(ctx context.Context) {
	tbls.lock.Lock()
	defer tbls.lock.Unlock()

	for !tbls.contextTimedOut(ctx) {
		if len(tbls.publicKeysOfParties) == len(tbls.parties) {
			return
		}

		tbls.signal.Wait()
	}
}

func encodeMsg(msgType uint8, payload []byte) []byte {
	buff := make([]byte, len(payload)+1)
	copy(buff[1:], payload)
	buff[0] = msgType
	return buff
}

func uint16ToIntSlice(in []uint16) []int {
	res := make([]int, len(in))
	for i := 0; i < len(in); i++ {
		res[i] = int(in[i])
	}
	return res
}
