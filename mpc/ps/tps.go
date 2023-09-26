/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ps

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
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

type TPS struct {
	// Config
	Curve         *math.Curve
	Party         uint16
	Logger        Logger
	MessageLength int
	// State
	pp                  PP
	id                  int
	sendMsg             func(msg []byte, isBroadcast bool, to uint16)
	parties             []uint16
	threshold           int
	msgLength           int
	sk                  SK
	lock                sync.Mutex
	init                bool
	signal              sync.Cond
	sharesProcessed     int
	shares              map[uint16]SK
	PKs                 []PK
	commitments         map[uint16][]byte
	publicKeysOfParties map[uint16][]byte
	storedData          *StoredData
}

func (tps *TPS) SetShareData(shareData []byte) error {
	tps.storedData = &StoredData{}
	if _, err := asn1.Unmarshal(shareData, tps.storedData); err != nil {
		return fmt.Errorf("share data is malformed: %v", err)
	}

	tps.sk = SK{}
	if err := tps.sk.fromBytes(tps.Curve, tps.storedData.Sk); err != nil {
		return err
	}

	tps.publicKeysOfParties = make(map[uint16][]byte)

	for i, p := range tps.parties {
		tps.publicKeysOfParties[p] = tps.storedData.PublicKeys[i]
	}

	return nil

}

func (tps *TPS) Sign(_ context.Context, msg []byte) ([]byte, error) {
	bs := BlindSignature{}
	if err := bs.fromBytes(msg, tps.Curve); err != nil {
		return nil, fmt.Errorf("blind signature malformed: %v", err)
	}

	σ, err := SignBlindSignature(&tps.pp, bs, tps.sk)
	if err != nil {
		return nil, fmt.Errorf("failed signing: %v", err)
	}

	return σ.Bytes(), nil
}

type StoredData struct {
	Sk          []byte
	PublicKeys  [][]byte
	ThresholdPK []byte
}

func (tps *TPS) ClassifyMsg(msgBytes []byte) (uint8, bool, error) {
	switch msgBytes[0] {
	case shareDistribution:
		return shareDistribution, false, nil
	case commitPK:
		return commitPK, true, nil
	case revealPK:
		return revealPK, true, nil
	default:
		return 0, false, fmt.Errorf("invalid prefix: %d", msgBytes[0])
	}
}

func (tps *TPS) Init(parties []uint16, threshold int, sendMsg func(msg []byte, isBroadcast bool, to uint16)) {
	party2ID := make(map[uint16]int)
	for i := 0; i < len(parties); i++ {
		party2ID[parties[i]] = i + 1
		if parties[i] == tps.Party {
			tps.id = i + 1
		}
	}
	tps.parties = parties
	tps.threshold = threshold
	tps.sendMsg = sendMsg
	tps.shares = make(map[uint16]SK)
	tps.commitments = make(map[uint16][]byte)
	tps.publicKeysOfParties = make(map[uint16][]byte)
	tps.signal = sync.Cond{L: &tps.lock}
	tps.init = true

	// Generate public parameters
	tps.pp = Setup(tps.Curve, tps.MessageLength)
}

func (tps *TPS) KeyGen(ctx context.Context) ([]byte, error) {
	defer tps.monitorContextTimeout(ctx)()

	// For each private key scalar be it x or Y1...Yn,
	// we first generate a polynomial P(x) of 'threshold - 1' degree,
	// and evaluate 'len(parties)' points on it, one point for each party.
	xShares := secretShare(len(tps.parties), tps.threshold)
	yShares := make([]Shares, tps.pp.n)
	for i := 0; i < len(yShares); i++ {
		yShares[i] = secretShare(len(tps.parties), tps.threshold)
	}

	// We then distribute the polynomial evaluations (shares) to all parties.
	// Each party 'i' gets P(i).
	tps.shareDistribution(ctx, xShares, yShares)

	// Having received all shares, we combine all shares received from all parties by adding them.
	pk := tps.combineShares()
	pkBytes := pk.Bytes()

	tps.commitPhase(ctx, pkBytes)

	// Now we de-commit, and wait for everyone else to de-commit thus revealing their public key.
	tps.revealPhase(ctx, pkBytes)
	// Next, we ensure the commitments we received match the de-commitments
	if err := tps.validateCommitments(); err != nil {
		return nil, err
	}

	// Finally, we ensure that we get the same threshold public key
	// not matter which combination of (len(parties) choose threshold) parties is chosen
	// There is no need to validate with the other parties, as the reliable broadcast ensures us
	// that everyone else received the same public keys as us.
	thresholdPublicKeyCombinations, thresholdPublicKey := tps.assembleThresholdPublicKey()

	// Ensure there is only a single threshold public key
	if len(thresholdPublicKeyCombinations) > 1 {
		return nil, fmt.Errorf("got %d different threshold public keys", len(thresholdPublicKeyCombinations))
	}

	tps.storedData = &StoredData{
		ThresholdPK: thresholdPublicKey.Bytes(),
		PublicKeys:  tps.flattenPublicKeys(),
		Sk:          tps.sk.Bytes(),
	}
	return asn1.Marshal(*tps.storedData)
}

type ThresholdPK struct {
	TPK        []byte
	PublicKeys [][]byte
}

func (tps *TPS) ThresholdPK() ([]byte, error) {
	pkwpp := ThresholdPK{
		TPK:        tps.storedData.ThresholdPK,
		PublicKeys: tps.flattenPublicKeys(),
	}

	return asn1.Marshal(pkwpp)
}

func (tps *TPS) OnMsg(msgBytes []byte, from uint16, _ bool) {
	tps.lock.Lock()
	defer tps.lock.Unlock()

	switch msgBytes[0] {
	case shareDistribution:
		tps.Logger.Infof("Got share distribution from %d", from)
		if _, exists := tps.shares[from]; exists {
			tps.Logger.Warnf("Already got share from %d", from)
			return
		}

		sk, err := unmarshalShare(tps.pp.c, msgBytes[1:])
		if err != nil {
			tps.Logger.Warnf("Received malformed share from %d: %v", from, err)
			return
		}

		tps.sharesProcessed++
		tps.shares[from] = *sk

		tps.signal.Signal()
	case commitPK:
		tps.Logger.Infof("Got commitment from %d", from)
		if _, exists := tps.commitments[from]; exists {
			tps.Logger.Warnf("Already got commitment from %d", from)
			return
		}

		tps.commitments[from] = msgBytes[1:]
		tps.signal.Signal()
	case revealPK:
		if _, exists := tps.publicKeysOfParties[from]; exists {
			tps.Logger.Warnf("Already got public key from %d", from)
			return
		}

		if _, err := unmarshalPK(tps.pp.c, msgBytes[1:]); err != nil {
			tps.Logger.Warnf("Public key %s of party %d is malformed: %v",
				base64.StdEncoding.EncodeToString(msgBytes[1:]), from, err)
			return
		}

		tps.publicKeysOfParties[from] = msgBytes[1:]
		expectedCommitment := sha256.Sum256(tps.publicKeysOfParties[from])
		tps.Logger.Infof("Got public key from %d: %s, expecting to receive commitment %s",
			from, base64.StdEncoding.EncodeToString(msgBytes[1:]), base64.StdEncoding.EncodeToString(expectedCommitment[:]))
		tps.signal.Signal()
	default:
		tps.Logger.Warnf("Got message with invalid tag (%d) from %d", msgBytes[0], from)
	}
}

func (tps *TPS) flattenPublicKeys() [][]byte {
	publicKeys := make([][]byte, len(tps.parties))
	for i, p := range tps.parties {
		rawPK, exists := tps.publicKeysOfParties[p]
		if !exists {
			panic(fmt.Sprintf("programming error: public key of party %d was not found", p))
		}

		publicKeys[i] = rawPK
	}
	return publicKeys
}

func (tps *TPS) assembleThresholdPublicKey() (map[string]PK, PK) {
	thresholdPublicKeys := make(map[string]PK)
	var thresholdPublicKey PK
	chooseKoutOfN(len(tps.parties), tps.threshold, func(evaluationPoints []int64) {
		var publicKeys []PK
		// For each party, get its announced public key
		for _, p := range tps.parties {
			rawPK, exists := tps.publicKeysOfParties[p]
			if !exists {
				panic(fmt.Sprintf("programming error: public key of party %d was not found", p))
			}

			pk, err := unmarshalPK(tps.pp.c, rawPK)
			if err != nil {
				panic(fmt.Sprintf("programming error: public key of party %d is malformed", p))
			}
			publicKeys = append(publicKeys, *pk)
		}

		// Now create the threshold public key
		thresholdPublicKey = localAggregatePublicKeys(tps.pp.n, publicKeys, evaluationPoints...)

		thresholdPublicKeys[hex.EncodeToString(thresholdPublicKey.Bytes())] = thresholdPublicKey
	})
	return thresholdPublicKeys, thresholdPublicKey
}

func (tps *TPS) validateCommitments() error {
	tps.lock.Lock()
	defer tps.lock.Unlock()

	if len(tps.publicKeysOfParties) != len(tps.parties) {
		fmt.Sprintf("programming error: received only %d decommitments from %d parties", len(tps.publicKeysOfParties)-1, len(tps.parties))
	}

	for party, pk := range tps.publicKeysOfParties {
		if tps.Party == party {
			// No point validating ourselves
			continue
		}
		commitment, exists := tps.commitments[party]
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
			tps.Party, party, base64.StdEncoding.EncodeToString(pk), base64.StdEncoding.EncodeToString(commitment))
	}

	return nil
}

func localAggregatePublicKeys(n int, pks PKs, evaluationPoints ...int64) PK {
	var pk PK
	pk.X = localAggregateECPoints(pks.XPoints(), evaluationPoints...)

	pk.Y = make([]*math.G2, n)
	for i := 0; i < n; i++ {
		pk.Y[i] = localAggregateECPoints(pks.YPoints(i), evaluationPoints...)
	}

	return pk
}

func localAggregateECPoints(points []*math.G2, evaluationPoints ...int64) *math.G2 {
	zero := c.GenG2.Copy()
	zero.Sub(c.GenG2)

	sum := zero

	for i := 0; i < len(evaluationPoints); i++ {
		sum.Add(points[evaluationPoints[i]-1].Mul(lagrangeCoefficient(evaluationPoints[i], evaluationPoints...)))
	}

	return sum
}

func (tps *TPS) commitPhase(ctx context.Context, pk []byte) {
	digest := sha256.Sum256(pk)
	commitment := digest[:]

	tps.Logger.Infof("Broadcasting commitment: %s", base64.StdEncoding.EncodeToString(commitment))

	tps.sendMsg(encodeMsg(commitPK, commitment), true, 0)

	tps.waitForCommitmentDistribution(ctx)
}

func (tps *TPS) revealPhase(ctx context.Context, pk []byte) {
	tps.Logger.Infof("Broadcasting public key: %s", base64.StdEncoding.EncodeToString(pk))
	tps.sendMsg(encodeMsg(revealPK, pk), true, 0)

	tps.waitForDeCommitmentDistribution(ctx)
}

func secretShare(n, t int) Shares {
	_, shares := (&SSS{Threshold: t}).Gen(n, rand.Reader)
	return shares
}

func (tps *TPS) waitForCommitmentDistribution(ctx context.Context) {
	tps.lock.Lock()
	defer tps.lock.Unlock()

	for !tps.contextTimedOut(ctx) {
		if len(tps.commitments) == len(tps.parties)-1 {
			return
		}

		tps.signal.Wait()
	}
}

func (tps *TPS) waitForDeCommitmentDistribution(ctx context.Context) {
	tps.lock.Lock()
	defer tps.lock.Unlock()

	for !tps.contextTimedOut(ctx) {
		if len(tps.publicKeysOfParties) == len(tps.parties) {
			return
		}

		tps.signal.Wait()
	}
}

func (tps *TPS) combineShares() PK {
	for _, party := range tps.parties {
		if party == tps.Party {
			continue
		}

		share := tps.shares[party]
		tps.sk.x = tps.sk.x.Plus(share.x)
		for i := 0; i < len(tps.sk.ys); i++ {
			tps.sk.ys[i] = tps.sk.ys[i].Plus(share.ys[i])
		}
	}

	pk := PK{
		X: tps.pp.g2.Mul(tps.sk.x),
		Y: make([]*math.G2, len(tps.sk.ys)),
	}

	for i := 0; i < len(tps.sk.ys); i++ {
		pk.Y[i] = tps.pp.g2.Mul(tps.sk.ys[i])
	}

	tps.publicKeysOfParties[tps.Party] = pk.Bytes()

	return pk
}

func (tps *TPS) shareDistribution(ctx context.Context, xShares Shares, yShares []Shares) {
	tps.sk = SK{
		ys: make([]*math.Zr, tps.pp.n),
		x:  xShares[tps.id-1],
	}

	for j := 0; j < len(tps.sk.ys); j++ {
		tps.sk.ys[j] = yShares[j][tps.id-1]
	}

	for i := 0; i < len(tps.parties); i++ {
		// My party
		if i+1 == tps.id {
			continue
		}
		tps.sendMsg(encodeMsg(shareDistribution, marshalShare(xShares[i], yShares, i+1, tps.pp.n)), false, tps.parties[i])
	}

	tps.waitForShareDistribution(ctx)
}

func (tps *TPS) waitForShareDistribution(ctx context.Context) {
	tps.lock.Lock()
	defer tps.lock.Unlock()

	for !tps.contextTimedOut(ctx) {
		if tps.sharesProcessed == len(tps.parties)-1 {
			return
		}

		tps.signal.Wait()
	}
}

func (tps *TPS) contextTimedOut(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (tps *TPS) monitorContextTimeout(ctx context.Context) func() {
	keygenFinished := make(chan struct{})

	go func() {
		select {
		case <-keygenFinished:
			return
		case <-ctx.Done():
			tps.lock.Lock()
			tps.signal.Signal()
			tps.lock.Unlock()
		}
	}()

	return func() {
		close(keygenFinished)
	}
}

func unmarshalPK(c *math.Curve, bytes []byte) (*PK, error) {
	var xys XYs
	if _, err := asn1.Unmarshal(bytes, &xys); err != nil {
		return nil, err
	}

	var pk PK

	X, err := c.NewG2FromBytes(xys.X)
	if err != nil {
		return nil, err
	}

	pk.X = X

	for i := 0; i < len(xys.Ys); i++ {
		y, err := c.NewG2FromBytes(xys.Ys[i])
		if err != nil {
			return nil, err
		}

		pk.Y = append(pk.Y, y)
	}

	return &pk, nil
}

func unmarshalShare(c *math.Curve, bytes []byte) (*SK, error) {
	var xys XYs
	if _, err := asn1.Unmarshal(bytes, &xys); err != nil {
		return nil, err
	}

	var sk SK

	sk.x = c.NewZrFromBytes(xys.X)
	for i := 0; i < len(xys.Ys); i++ {
		sk.ys = append(sk.ys, c.NewZrFromBytes(xys.Ys[i]))
	}

	return &sk, nil
}

func marshalShare(x *math.Zr, y []Shares, party, n int) []byte {
	ys := make([]*math.Zr, n)

	for i := 0; i < n; i++ {
		ys[i] = y[i][party-1]
	}

	xys := XYs{
		X:  x.Bytes(),
		Ys: make([][]byte, n),
	}

	for i := 0; i < len(y); i++ {
		xys.Ys[i] = ys[i].Bytes()
	}

	bytes, err := asn1.Marshal(xys)
	if err != nil {
		panic(err)
	}

	return bytes
}

func encodeMsg(msgType uint8, payload []byte) []byte {
	buff := make([]byte, len(payload)+1)
	copy(buff[1:], payload)
	buff[0] = msgType
	return buff
}
