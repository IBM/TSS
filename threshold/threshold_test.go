/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package threshold

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	discovery "github.ibm.com/fabric-security-research/tss/disc"
	"github.ibm.com/fabric-security-research/tss/mpc/binance"
	comm "github.ibm.com/fabric-security-research/tss/net"
	"github.ibm.com/fabric-security-research/tss/rbc"
	"github.ibm.com/fabric-security-research/tss/testutil/tlsgen"
	. "github.ibm.com/fabric-security-research/tss/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestThreshold(t *testing.T) {
	n := 4

	var members []uint16
	for i := 1; i <= n; i++ {
		members = append(members, uint16(i))
	}

	ca, err := tlsgen.NewCA()
	assert.NoError(t, err)

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca.CertBytes())

	tlsCert, err := ca.NewServerCertKeyPair("127.0.0.1")
	assert.NoError(t, err)

	var commParties []*comm.Party
	var signers []*tlsgen.CertKeyPair
	var loggers []*commLogger
	var listeners []net.Listener
	var stopFuncs []func()

	membership := make(map[UniversalID]PartyID)

	for id := 1; id <= n; id++ {
		l := logger(id, t.Name())
		if id > 2 {
			l.mute()
		}
		loggers = append(loggers, l)

		s := newSigner(ca, t)
		signers = append(signers, s)

		lsnr := comm.Listen("127.0.0.1:0", tlsCert.Cert, tlsCert.Key)
		listeners = append(listeners, lsnr)

		commParties = append(commParties, &comm.Party{
			Logger:   l,
			Address:  lsnr.Addr().String(),
			Identity: s.Cert,
		})

		membership[UniversalID(id)] = PartyID(id)
	}

	var parties []*Scheme

	for id := 1; id <= n; id++ {
		stop, s := createParty(id, signers[id-1], n, certPool, listeners, loggers, commParties, members)
		s.Membership = func() map[UniversalID]PartyID {
			return membership
		}
		parties = append(parties, s)
		stopFuncs = append(stopFuncs, stop)
	}

	defer func() {
		for _, stop := range stopFuncs {
			stop()
		}
	}()

	var wg sync.WaitGroup
	wg.Add(len(parties))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	start := time.Now()
	for _, p := range parties {
		go func(p *Scheme) {
			defer wg.Done()
			data, err := p.KeyGen(ctx, len(parties), len(parties)-1)
			p.StoredData = data
			assert.NoError(t, err)
			assert.NotNil(t, data)
		}(p)
	}

	wg.Wait()
	cancel()

	elapsed := time.Since(start)
	t.Log("DKG elapsed", elapsed)

	t.Log("Running signing")

	k := 10
	concurrentWg := sync.WaitGroup{}
	concurrentWg.Add(k)

	for i := 0; i < k; i++ {
		// Sleep to simulate parties starting at different times
		time.Sleep(time.Millisecond * 50)
		go func(i int) {
			defer concurrentWg.Done()
			thresholdSign(t, i, parties, k)
		}(i)
	}

	concurrentWg.Wait()
}

func thresholdSign(t *testing.T, i int, parties []*Scheme, k int) {
	msg := fmt.Sprintf("msg %d", i)
	topic := fmt.Sprintf("topic %d", i)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second * time.Duration(k) * 2)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(parties))

	start := time.Now()

	for _, p := range parties {
		// Sleep to simulate parties starting at different times
		time.Sleep(time.Millisecond * 50)
		go func(p *Scheme) {
			defer wg.Done()
			signature, err := p.Sign(ctx, []byte(msg), topic)
			assert.NoError(t, err)
			assert.NotEmpty(t, signature)

			pkBytes, err := p.ThresholdPK()
			assert.NoError(t, err)

			pk, err := x509.ParsePKIXPublicKey(pkBytes)
			assert.NoError(t, err)

			assert.True(t, ecdsa.VerifyASN1(pk.(*ecdsa.PublicKey), hash([]byte(msg)), signature))
		}(p)
	}

	wg.Wait()

	elapsed := time.Since(start)
	t.Log("Signing elapsed", elapsed)
}

func TestRBCEncoding(t *testing.T) {
	encoding := newRBCEncoding("digest", 8, 2)
	digest, sender, round, err := encoding.Ack()
	assert.NoError(t, err)
	assert.Equal(t, []byte("digest"), digest)
	assert.Equal(t, uint16(8), sender)
	assert.Equal(t, uint8(2), round)
}

func createParty(id int, signer *tlsgen.CertKeyPair, n int, certPool *x509.CertPool, listeners []net.Listener, loggers []*commLogger, commParties []*comm.Party, members []uint16) (func(), *Scheme) {
	remoteParties := make(comm.SocketRemoteParties)

	auth := func(tlsContext []byte) comm.Handshake {
		h := comm.Handshake{
			TLSBinding: tlsContext,
			Identity:   signer.Cert,
			Timestamp:  time.Now().Unix(),
		}

		sig, err := signer.Sign(rand.Reader, sha256Digest(h.Bytes()), nil)
		if err != nil {
			panic("failed signing")
		}

		h.Signature = sig

		return h
	}

	for i := 0; i < n; i++ {
		if i+1 == id {
			continue
		}

		remoteParties[i+1] = comm.NewSocketRemoteParty(comm.PartyConnectionConfig{
			AuthFunc: auth,
			TlsCAs:   certPool,
			Id:       i + 1,
			Endpoint: listeners[i].Addr().String(),
		}, loggers[id-1])

	}

	commParties[id-1].SendMessage = remoteParties.Send

	p2id := make(map[string]uint16)
	for i, p := range commParties {
		p2id[hex.EncodeToString(sha256Digest(p.Identity))] = uint16(i + 1)
	}

	in, stop := comm.ServiceConnections(listeners[id-1], p2id, loggers[id-1])
	commParties[id-1].InMessages = in

	kgf := func(id uint16) KeyGenerator {
		return mpc.NewParty(id, loggers[id-1])
	}

	sf := func(id uint16) Signer {
		return mpc.NewParty(id, loggers[id-1])
	}

	s := &Scheme{
		Logger:        loggers[id-1],
		KeyGenFactory: kgf,
		SignerFactory: sf,
		Send: func(msgType uint8, topic []byte, msg []byte, to ...UniversalID) {
			destinations := make([]uint16, len(to))
			for i, dst := range to {
				destinations[i] = uint16(dst)
			}
			remoteParties.Send(msgType, topic, msg, destinations...)
		},
		Threshold: len(commParties) - 1,
		SelfID:    UniversalID(id),
		RBF: func(bcast BroadcastFunc, fwd ForwardFunc, n int) ReliableBroadcast {
			r := &rbc.Receiver{
				SelfID: uint16(id),
				Logger: loggers[id-1],
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
				Logger:     loggers[id-1],
				ID:         uint16(id),
				Broadcast:  broadcast,
				Send: send,
			}
		},
	}

	go func(in <-chan comm.InMsg) {
		for msg := range in {
			inMsg :=  &IncMessage{
				MsgType: msg.Type,
				Data:    msg.Data,
				Topic:   msg.Topic,
				Source:  msg.From,
			}

			s.HandleMessage(inMsg)
		}
	}(in)
	return stop, s
}

func logger(id int, testName string) *commLogger {
	logConfig := zap.NewDevelopmentConfig()
	baseLogger, _ := logConfig.Build()
	logger := baseLogger.With(zap.String("t", testName)).With(zap.String("id", fmt.Sprintf("%d", id)))
	return &commLogger{Logger: logger.Sugar(), conf: &logConfig}
}

type receiver struct {
	*rbc.Receiver
}

func (r *receiver) Receive(m RBCMessage, from uint16) {
	r.Receiver.Receive(m, from)
}

type commLogger struct {
	conf *zap.Config
	Logger
}

func (l *commLogger) mute() {
	l.conf.Level.SetLevel(zapcore.WarnLevel)
}

func (*commLogger) DebugEnabled() bool {
	return false
}

func newSigner(ca tlsgen.CA, t *testing.T) *tlsgen.CertKeyPair {
	clientPair, err := ca.NewClientCertKeyPair()
	assert.NoError(t, err, "failed to create client key pair")

	return clientPair
}

func sha256Digest(b ...[]byte) []byte {
	hash := sha256.New()
	for _, bytes := range b {
		hash.Write(bytes)
	}
	return hash.Sum(nil)
}
