/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package threshold

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	discovery "github.com/IBM/TSS/disc"
	"github.com/IBM/TSS/rbc"
	. "github.com/IBM/TSS/types"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestRBCEncoding(t *testing.T) {
	encoding := newRBCEncoding("digest", 8, 2)
	digest, sender, round, err := encoding.Ack()
	assert.NoError(t, err)
	assert.Equal(t, []byte("digest"), digest)
	assert.Equal(t, uint16(8), sender)
	assert.Equal(t, uint8(2), round)
}

func TestThresholdNaive(t *testing.T) {
	n := 4

	var members []uint16
	var schemes []*Scheme
	var msgsQueues []chan *IncMessage

	stop := make(chan struct{})
	defer close(stop)

	for id := 1; id <= n; id++ {
		id := id
		l := logger(id, t.Name())
		members = append(members, uint16(id))

		s := &Scheme{
			SelfID:    UniversalID(id),
			Logger:    l,
			Threshold: n - 1,
			Membership: func() map[UniversalID]PartyID {
				return map[UniversalID]PartyID{
					1: 1,
					2: 2,
					3: 3,
					4: 4,
				}
			},
			RBF: func(bcast BroadcastFunc, fwd ForwardFunc, n int) ReliableBroadcast {
				r := &rbc.Receiver{
					SelfID: uint16(id),
					Logger: l,
					BroadcastAck: func(digest string, sender uint16, msgRound uint8) {
						bcast(digest, sender, msgRound)
					},
					ForwardToBackend: func(msg interface{}, from uint16) {
						fwd(msg, from)
					},
					N: n,
				}
				return &receiver{Receiver: r}
			},

			SyncFactory: func(members []uint16, broadcast func(msg []byte), send func(msg []byte, to uint16)) Synchronizer {
				return &discovery.Member{
					Membership: members,
					Logger:     l,
					ID:         uint16(id),
					Broadcast:  broadcast,
					Send:       send,
				}
			},
		}

		schemes = append(schemes, s)

		msgQueue := make(chan *IncMessage, 100)
		msgsQueues = append(msgsQueues, msgQueue)

		go func() {
			for {
				select {
				case <-stop:
					return
				case msg := <-msgQueue:
					s.HandleMessage(msg)
				}
			}
		}()

	}

	for id := 1; id <= n; id++ {
		id := id
		s := schemes[id-1]
		s.KeyGenFactory = func(id uint16) KeyGenerator {
			return &naiveInsecureEphemeralGen{}
		}
		s.SignerFactory = func(id uint16) Signer {
			return &naiveInsecureEphemeralSigner{id: id}
		}
		s.Send = func(msgType uint8, topic []byte, msg []byte, to ...UniversalID) {
			for _, dst := range to {
				if int(dst) == id {
					continue
				}
				msgsQueues[int(dst)-1] <- &IncMessage{
					Source:  uint16(id),
					Data:    msg,
					Topic:   topic,
					MsgType: msgType,
				}
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(n)

	for id := 1; id <= n; id++ {
		id := id
		go func(s *Scheme) {
			defer wg.Done()
			share, err := s.KeyGen(context.Background(), n, n-1)
			assert.NoError(t, err)
			assert.NotEmpty(t, share)
			schemes[id-1].StoredData = share
		}(schemes[id-1])
	}

	wg.Wait()

	t.Logf("DKG finished")
	t.Logf("Signing message")

	rawPK, err := schemes[0].ThresholdPK()
	assert.NoError(t, err)

	x, y := elliptic.Unmarshal(elliptic.P256(), rawPK)
	pk := &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: elliptic.P256(),
	}

	msgToSign := digest([]byte("You can avoid reality, but you cannot avoid the consequences of avoiding reality"))

	wg.Add(n)

	for id := 1; id <= n; id++ {
		go func(s *Scheme) {
			defer wg.Done()
			signature, err := s.Sign(context.Background(), msgToSign, "topic")
			assert.NoError(t, err)

			assert.True(t, ecdsa.VerifyASN1(pk, msgToSign, signature))
		}(schemes[id-1])
	}

	wg.Wait()
}

func TestNaiveInsecureEphemeralTSS(t *testing.T) {
	g1, g2, g3, g4 := &naiveInsecureEphemeralGen{
		parties: []uint16{1, 2, 3, 4},
	}, &naiveInsecureEphemeralGen{
		parties: []uint16{1, 2, 3, 4},
	}, &naiveInsecureEphemeralGen{
		parties: []uint16{1, 2, 3, 4},
	}, &naiveInsecureEphemeralGen{
		parties: []uint16{1, 2, 3, 4},
	}

	broadcastForParty := func(id uint16) func([]byte, bool, uint16) {
		parties := []*naiveInsecureEphemeralGen{g1, g2, g3, g4}
		return func(msg []byte, bcast bool, _ uint16) {
			for _, dest := range []uint16{1, 2, 3, 4} {
				if dest == id {
					continue
				}

				parties[dest-1].OnMsg(msg, id, bcast)
			}
		}
	}

	g1.Init([]uint16{1, 2, 3, 4}, 3, broadcastForParty(1))
	g2.Init([]uint16{1, 2, 3, 4}, 3, broadcastForParty(2))
	g3.Init([]uint16{1, 2, 3, 4}, 3, broadcastForParty(3))
	g4.Init([]uint16{1, 2, 3, 4}, 3, broadcastForParty(4))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shares := make([][]byte, 4)

	var wg sync.WaitGroup
	wg.Add(4)

	for i, party := range []*naiveInsecureEphemeralGen{g1, g2, g3, g4} {
		go func(p *naiveInsecureEphemeralGen, i int) {
			defer wg.Done()
			share, err := p.KeyGen(ctx)
			assert.NoError(t, err)

			shares[i] = share
		}(party, i)
	}

	wg.Wait()

	// ---------------------- sign ------------------------------

	s1, s2, s3, s4 := &naiveInsecureEphemeralSigner{
		id:      1,
		parties: []uint16{1, 2, 3, 4},
	}, &naiveInsecureEphemeralSigner{
		id:      2,
		parties: []uint16{1, 2, 3, 4},
	}, &naiveInsecureEphemeralSigner{
		id:      3,
		parties: []uint16{1, 2, 3, 4},
	}, &naiveInsecureEphemeralSigner{
		id:      4,
		parties: []uint16{1, 2, 3, 4},
	}

	broadcastOrSend := func(id uint16) func([]byte, bool, uint16) {
		parties := []*naiveInsecureEphemeralSigner{s1, s2, s3, s4}
		return func(msg []byte, bcast bool, dest uint16) {
			if !bcast {
				parties[dest-1].OnMsg(msg, id, bcast)
				return
			}
			for _, dest := range []uint16{1, 2, 3, 4} {
				if dest == id {
					continue
				}

				parties[dest-1].OnMsg(msg, id, bcast)
			}
		}
	}

	s1.Init([]uint16{1, 2, 3, 4}, 4, broadcastOrSend(1))
	s2.Init([]uint16{1, 2, 3, 4}, 4, broadcastOrSend(2))
	s3.Init([]uint16{1, 2, 3, 4}, 4, broadcastOrSend(3))
	s4.Init([]uint16{1, 2, 3, 4}, 4, broadcastOrSend(4))

	s1.SetShareData(shares[0])
	s2.SetShareData(shares[1])
	s3.SetShareData(shares[2])
	s4.SetShareData(shares[3])

	rawPK, err := s1.ThresholdPK()
	assert.NoError(t, err)

	x, y := elliptic.Unmarshal(elliptic.P256(), rawPK)
	pk := &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: elliptic.P256(),
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	wg.Add(4)

	msgToSign := digest([]byte("The quick brown fox jumps over the lazy dog"))

	for i, party := range []*naiveInsecureEphemeralSigner{s1, s2, s3, s4} {
		go func(p *naiveInsecureEphemeralSigner, i int) {
			defer wg.Done()

			sig, err := p.Sign(ctx, msgToSign)
			assert.NoError(t, err)

			assert.True(t, ecdsa.VerifyASN1(pk, msgToSign, sig))
		}(party, i)
	}

	wg.Wait()
}

type naiveInsecureEphemeralGen struct {
	msgs    chan []byte
	parties []uint16
	sendMsg func(msg []byte, isBroadcast bool, to uint16)
}

func (n *naiveInsecureEphemeralGen) ClassifyMsg(_ []byte) (uint8, bool, error) {
	return 1, true, nil
}

func (n *naiveInsecureEphemeralGen) Init(parties []uint16, _ int, sendMsg func(msg []byte, isBroadcast bool, to uint16)) {
	n.parties = parties
	n.sendMsg = sendMsg
	n.msgs = make(chan []byte, len(parties))
}

func (n *naiveInsecureEphemeralGen) OnMsg(msgBytes []byte, _ uint16, _ bool) {
	select {
	case n.msgs <- msgBytes:
	default:
		panic("nil channel")
	}
}

type SaveData struct {
	ThresholdPK []byte
	Share       []byte
}

func (n *naiveInsecureEphemeralGen) KeyGen(ctx context.Context) ([]byte, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	skBytes, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		return nil, err
	}

	n.sendMsg(skBytes, true, math.MaxUint16)
	// Send the message to yourself
	n.msgs <- skBytes

	thresholdSK := big.NewInt(0)

	for i := 0; i < cap(n.msgs); i++ {
		select {
		case msg := <-n.msgs:
			x, err := x509.ParseECPrivateKey(msg)
			if err != nil {
				return nil, err
			}

			thresholdSK.Add(thresholdSK, x.D)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	thresholdSK.Mod(thresholdSK, elliptic.P256().Params().N)

	x, y := elliptic.P256().ScalarBaseMult(thresholdSK.Bytes())
	thresholdPK := elliptic.Marshal(elliptic.P256(), x, y)

	sd := SaveData{
		ThresholdPK: thresholdPK,
		Share:       skBytes,
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	return sdBytes, nil
}

type naiveInsecureEphemeralSigner struct {
	id       uint16
	share    []byte
	tpk      []byte
	parties  []uint16
	msgs     chan []byte
	sendMsg  func(msg []byte, isBroadcast bool, to uint16)
	signFunc func(ctx context.Context, msg []byte) ([]byte, error)
}

func (n *naiveInsecureEphemeralSigner) ClassifyMsg(msgBytes []byte) (uint8, bool, error) {
	if len(msgBytes) < 100 {
		return 3, true, nil
	}
	return 2, false, nil
}

func (n *naiveInsecureEphemeralSigner) Init(parties []uint16, _ int, sendMsg func(msg []byte, isBroadcast bool, to uint16)) {
	n.sendMsg = sendMsg
	n.parties = parties
	n.msgs = make(chan []byte, len(parties))

	aggregator := n.min()
	if n.id == aggregator {
		n.signFunc = n.signAsAggregator
	} else {
		n.signFunc = n.signAsNonAggregator
	}
}

func (n *naiveInsecureEphemeralSigner) OnMsg(msgBytes []byte, from uint16, _ bool) {
	if n.msgs == nil {
		panic("nil channel")
	}
	n.msgs <- msgBytes
}

func (n *naiveInsecureEphemeralSigner) SetShareData(shareData []byte) error {
	sd := &SaveData{}
	if _, err := asn1.Unmarshal(shareData, sd); err != nil {
		return err
	}

	n.tpk = sd.ThresholdPK
	n.share = sd.Share

	return nil
}

func (n *naiveInsecureEphemeralSigner) ThresholdPK() ([]byte, error) {
	if n.share == nil {
		return nil, fmt.Errorf("please call Init() before calling ThresholdPK()")
	}
	return n.tpk, nil
}

func (n *naiveInsecureEphemeralSigner) Sign(ctx context.Context, msgHash []byte) ([]byte, error) {
	return n.signFunc(ctx, msgHash)
}

func (n *naiveInsecureEphemeralSigner) signAsAggregator(ctx context.Context, msgHash []byte) ([]byte, error) {
	// Prepare a share from yourself
	n.msgs <- n.share

	sk, err := n.reconstructEphemeralSK(ctx)
	if err != nil {
		return nil, err
	}

	sig, err := n.signLocally(msgHash, err, sk)
	if err != nil {
		return nil, err
	}

	// Sanity test: check signature
	x, y := elliptic.Unmarshal(elliptic.P256(), n.tpk)
	pk := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	if !ecdsa.VerifyASN1(pk, msgHash, sig) {
		panic("bad signature")
	}

	// Broadcast signature
	n.sendMsg(sig, true, math.MaxUint16)

	return sig, nil
}

func (n *naiveInsecureEphemeralSigner) signLocally(msgHash []byte, err error, sk *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, sk, msgHash)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (n *naiveInsecureEphemeralSigner) reconstructEphemeralSK(ctx context.Context) (*ecdsa.PrivateKey, error) {
	tSK := big.NewInt(0)

	for i := 0; i < cap(n.msgs); i++ {
		select {
		case msg := <-n.msgs:
			x, err := x509.ParseECPrivateKey(msg)
			if err != nil {
				return nil, err
			}
			tSK.Add(tSK, x.D)
			tSK.Mod(tSK, elliptic.P256().Params().N)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), n.tpk)

	sk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: tSK,
	}
	return sk, nil
}

func (n *naiveInsecureEphemeralSigner) signAsNonAggregator(ctx context.Context, _ []byte) ([]byte, error) {
	n.sendMsg(n.share, false, n.min())

	select {
	case sig := <-n.msgs:
		return sig, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *naiveInsecureEphemeralSigner) min() uint16 {
	var a []int

	for _, id := range n.parties {
		a = append(a, int(id))
	}

	sort.Ints(a)
	return uint16(a[0])
}

func digest(b ...[]byte) []byte {
	hash := sha256.New()
	for _, bytes := range b {
		hash.Write(bytes)
	}
	return hash.Sum(nil)
}

type muteableLogger struct {
	conf *zap.Config
	Logger
}

func (l *muteableLogger) mute() {
	l.conf.Level.SetLevel(zapcore.WarnLevel)
}

func (*muteableLogger) DebugEnabled() bool {
	return false
}

func logger(id int, testName string) *muteableLogger {
	logConfig := zap.NewDevelopmentConfig()
	baseLogger, _ := logConfig.Build()
	logger := baseLogger.With(zap.String("t", testName)).With(zap.String("id", fmt.Sprintf("%d", id)))
	return &muteableLogger{Logger: &loggerWithDebug{SugaredLogger: logger.Sugar()}, conf: &logConfig}
}

type loggerWithDebug struct {
	*zap.SugaredLogger
}

func (lwd *loggerWithDebug) DebugEnabled() bool {
	return false
}
