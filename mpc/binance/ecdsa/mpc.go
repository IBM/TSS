/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
)

const (
	// defaultSafePrimeGenTimeout is the default time allocated for the library to sample the Paillier public key
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

func init() {
	tss.SetCurve(elliptic.P256())
	tss.RegisterCurve("elliptic.p256Curve", elliptic.P256())
}

var (
	msgURL2Round = map[string]uint8{
		// DKG
		"type.googleapis.com/binance.tsslib.ecdsa.keygen.KGRound1Message":  1,
		"type.googleapis.com/binance.tsslib.ecdsa.keygen.KGRound2Message1": 2,
		"type.googleapis.com/binance.tsslib.ecdsa.keygen.KGRound2Message2": 3,
		"type.googleapis.com/binance.tsslib.ecdsa.keygen.KGRound3Message":  4,

		// Signing
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound1Message1": 5,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound1Message2": 6,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound2Message":  7,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound3Message":  8,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound4Message":  9,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound5Message":  10,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound6Message":  11,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound7Message":  12,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound8Message":  13,
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound9Message":  14,
	}

	broadcastMessages = map[string]struct{}{
		// DKG
		"type.googleapis.com/binance.tsslib.ecdsa.keygen.KGRound1Message":  {},
		"type.googleapis.com/binance.tsslib.ecdsa.keygen.KGRound2Message2": {},
		"type.googleapis.com/binance.tsslib.ecdsa.keygen.KGRound3Message":  {},

		// Signing
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound1Message2": {},
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound3Message":  {},
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound4Message":  {},
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound5Message":  {},
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound6Message":  {},
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound7Message":  {},
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound8Message":  {},
		"type.googleapis.com/binance.tsslib.ecdsa.signing.SignRound9Message":  {},
	}
)

type Sender func(msg []byte, isBroadcast bool, to uint16)

type parties []*party

func (parties parties) numericIDs() []uint16 {
	var res []uint16
	for _, p := range parties {
		res = append(res, uint16(big.NewInt(0).SetBytes(p.id.Key).Uint64()))
	}

	return res
}

type Logger interface {
	Debugf(format string, a ...interface{})
	Warnf(format string, a ...interface{})
	Errorf(format string, a ...interface{})
}

type party struct {
	logger    Logger
	sendMsg   Sender
	id        *tss.PartyID
	params    *tss.Parameters
	out       chan tss.Message
	in        chan tss.Message
	shareData *keygen.LocalPartySaveData
	closeChan chan struct{}
}

func NewParty(id uint16, logger Logger) *party {
	return &party{
		logger: logger,
		id:     tss.NewPartyID(fmt.Sprintf("%d", id), "", big.NewInt(int64(id))),
		out:    make(chan tss.Message, 1000),
		in:     make(chan tss.Message, 1000),
	}
}

func (p *party) ID() *tss.PartyID {
	return p.id
}

func (p *party) locatePartyIndex(id *tss.PartyID) int {
	for index, p := range p.params.Parties().IDs() {
		if bytes.Equal(p.Key, id.Key) {
			return index
		}
	}

	return -1
}

func (p *party) ClassifyMsg(msgBytes []byte) (uint8, bool, error) {
	msg := &any.Any{}
	if err := proto.Unmarshal(msgBytes, msg); err != nil {
		p.logger.Warnf("Received invalid message: %v", err)
		return 0, false, err
	}

	_, isBroadcast := broadcastMessages[msg.TypeUrl]

	round := msgURL2Round[msg.TypeUrl]
	if round > 4 {
		round = round - 4
	}
	return round, isBroadcast, nil
}

func (p *party) OnMsg(msgBytes []byte, from uint16, broadcast bool) {
	id := tss.NewPartyID(fmt.Sprintf("%d", from), "", big.NewInt(int64(from)))
	id.Index = p.locatePartyIndex(id)
	msg, err := tss.ParseWireMessage(msgBytes, id, broadcast)
	if err != nil {
		p.logger.Warnf("Received invalid message (%s) of %d bytes from %d: %v", base64.StdEncoding.EncodeToString(msgBytes), len(msgBytes), from, err)
		return
	}

	key := msg.GetFrom().KeyInt()
	if key == nil || key.Cmp(big.NewInt(int64(math.MaxUint16))) >= 0 {
		p.logger.Warnf("Message received from invalid key: %v", key)
		return
	}

	claimedFrom := uint16(key.Uint64())
	if claimedFrom != from {
		p.logger.Warnf("Message claimed to be from %d but was received from %d", claimedFrom, from)
		return
	}

	p.in <- msg
}

func (p *party) TPubKey() (*ecdsa.PublicKey, error) {
	if p.shareData == nil {
		return nil, fmt.Errorf("must call SetShareData() before attempting to sign")
	}

	pk := p.shareData.ECDSAPub

	return &ecdsa.PublicKey{
		Curve: pk.Curve(),
		X:     pk.X(),
		Y:     pk.Y(),
	}, nil
}

func (p *party) ThresholdPK() ([]byte, error) {
	pk, err := p.TPubKey()
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pk)
}

func (p *party) SetShareData(shareData []byte) error {
	var localSaveData keygen.LocalPartySaveData
	err := json.Unmarshal(shareData, &localSaveData)
	if err != nil {
		return fmt.Errorf("failed deserializing shares: %w", err)
	}
	localSaveData.ECDSAPub.SetCurve(elliptic.P256())
	for _, xj := range localSaveData.BigXj {
		xj.SetCurve(elliptic.P256())
	}
	p.shareData = &localSaveData
	return nil
}

func (p *party) Init(parties []uint16, threshold int, sendMsg func(msg []byte, isBroadcast bool, to uint16)) {
	partyIDs := partyIDsFromNumbers(parties)
	ctx := tss.NewPeerContext(partyIDs)
	p.params = tss.NewParameters(elliptic.P256(), ctx, p.id, len(parties), threshold)
	p.id.Index = p.locatePartyIndex(p.id)
	p.sendMsg = sendMsg
	p.closeChan = make(chan struct{})
	go p.sendMessages()
}

func partyIDsFromNumbers(parties []uint16) []*tss.PartyID {
	var partyIDs []*tss.PartyID
	for _, p := range parties {
		pID := tss.NewPartyID(fmt.Sprintf("%d", p), "", big.NewInt(int64(p)))
		partyIDs = append(partyIDs, pID)
	}
	return tss.SortPartyIDs(partyIDs)
}

func (p *party) Sign(ctx context.Context, msgHash []byte) ([]byte, error) {
	if p.shareData == nil {
		return nil, fmt.Errorf("must call SetShareData() before attempting to sign")
	}
	p.logger.Debugf("Starting signing")
	defer p.logger.Debugf("Finished signing")

	defer close(p.closeChan)

	end := make(chan common.SignatureData, 1)

	msgToSign := hashToInt(msgHash, elliptic.P256())
	party := signing.NewLocalParty(msgToSign, p.params, *p.shareData, p.out, end)

	var endWG sync.WaitGroup
	endWG.Add(1)

	go func() {
		defer endWG.Done()
		err := party.Start()
		if err != nil {
			p.logger.Errorf("Failed signing: %v", err)
		}
	}()

	defer endWG.Wait()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("signing timed out: %w", ctx.Err())
		case sigOut := <-end:
			if !bytes.Equal(sigOut.M, msgToSign.Bytes()) {
				return nil, fmt.Errorf("message we requested to sign is %s but actual message signed is %s",
					base64.StdEncoding.EncodeToString(msgHash),
					base64.StdEncoding.EncodeToString(sigOut.M))
			}
			var sig struct {
				R, S *big.Int
			}
			sig.R = big.NewInt(0)
			sig.S = big.NewInt(0)
			sig.R.SetBytes(sigOut.R)
			sig.S.SetBytes(sigOut.S)

			sigRaw, err := asn1.Marshal(sig)
			if err != nil {
				return nil, fmt.Errorf("failed marshaling ECDSA signature: %w", err)
			}
			return sigRaw, nil
		case msg := <-p.in:
			raw, routing, err := msg.WireBytes()
			if err != nil {
				p.logger.Warnf("Received error when serializing message: %v", err)
				continue
			}
			p.logger.Debugf("%s Got message from %s", p.id.Id, routing.From.Id)
			ok, err := party.UpdateFromBytes(raw, routing.From, routing.IsBroadcast)
			if !ok {
				p.logger.Warnf("Received error when updating party: %v", err.Error())
				continue
			}
		}
	}
}

func (p *party) KeyGen(ctx context.Context) ([]byte, error) {
	p.logger.Debugf("Starting DKG")
	defer p.logger.Debugf("Finished DKG")

	defer close(p.closeChan)

	preParamGenTimeout := defaultSafePrimeGenTimeout

	deadline, deadlineExists := ctx.Deadline()
	if deadlineExists {
		preParamGenTimeout = deadline.Sub(time.Now())
	}
	preParams, err := keygen.GeneratePreParams(preParamGenTimeout)
	if err != nil {
		panic(err)
	}

	end := make(chan keygen.LocalPartySaveData, 1)
	party := keygen.NewLocalParty(p.params, p.out, end, *preParams)

	var endWG sync.WaitGroup
	endWG.Add(1)

	go func() {
		defer endWG.Done()
		err := party.Start()
		if err != nil {
			p.logger.Errorf("Failed generating key: %v", err)
		}
	}()

	defer endWG.Wait()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("DKG timed out: %w", ctx.Err())
		case dkgOut := <-end:
			dkgRawOut, err := json.Marshal(dkgOut)
			if err != nil {
				return nil, fmt.Errorf("failed serializing DKG output: %w", err)
			}
			return dkgRawOut, nil
		case msg := <-p.in:
			raw, routing, err := msg.WireBytes()
			if err != nil {
				p.logger.Warnf("Received error when serializing message: %v", err)
				continue
			}
			p.logger.Debugf("%s Got message from %s", p.id.Id, routing.From.Id)
			ok, err := party.UpdateFromBytes(raw, routing.From, routing.IsBroadcast)
			if !ok {
				p.logger.Warnf("Received error when updating party: %v", err.Error())
				continue
			}
		}
	}
}

func (p *party) sendMessages() {
	for {
		select {
		case <-p.closeChan:
			return
		case msg := <-p.out:
			msgBytes, routing, err := msg.WireBytes()
			if err != nil {
				p.logger.Warnf("Failed marshaling message: %v", err)
				continue
			}
			if routing.IsBroadcast {
				p.sendMsg(msgBytes, routing.IsBroadcast, 0)
			} else {
				for _, to := range msg.GetTo() {
					p.sendMsg(msgBytes, routing.IsBroadcast, uint16(big.NewInt(0).SetBytes(to.Key).Uint64()))
				}
			}
		}
	}
}

// hashToInt is taken as-is from the Go ECDSA standard library
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func digest(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}
