/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tps

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/IBM/TSS/mpc/ps"
	comm "github.com/IBM/TSS/net"
	"github.com/IBM/TSS/testutil/tlsgen"
	. "github.com/IBM/TSS/threshold"
	. "github.com/IBM/TSS/types"
	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	msg = [][]byte{
		[]byte(`“Would you tell me, please, which way I ought to go from here?”`),
		[]byte(`“That depends a good deal on where you want to get to,” said the Cat.`),
		[]byte(`“I don’t much care where—” said Alice.`),
		[]byte(`“Then it doesn’t matter which way you go,” said the Cat.`),
		[]byte(`“—so long as I get somewhere,” Alice added as an explanation.`),
		[]byte(`“Oh, you’re sure to do that,” said the Cat, “if you only walk long enough.”`),
	}
)

func TestThresholdPS(t *testing.T) {
	var commParties []*comm.Party
	var signers []*tlsgen.CertKeyPair
	var loggers []*commLogger
	var listeners []net.Listener
	var stopFuncs []func()

	n := 3

	members, certPool, loggers, signers, listeners, commParties, membershipFunc, parties, kgf := setup(t, n, loggers, signers, listeners, commParties)

	for id := 1; id <= n; id++ {
		stop, s := createParty(id, kgf, signers[id-1], n, certPool, listeners, loggers, commParties, membershipFunc)
		parties = append(parties, s)
		stopFuncs = append(stopFuncs, stop)
	}

	defer func() {
		for _, stop := range stopFuncs {
			stop()
		}
	}()

	shares, start := keygen(t, parties, n)

	elapsed := time.Since(start)
	t.Log("DKG elapsed", elapsed)

	// Create the threshold signers.
	thresholdSigners := make([]*ps.TPS, n)
	for id := 1; id <= n; id++ {
		thresholdSigners[id-1] = &ps.TPS{
			Logger:        logger(id, t.Name()),
			Party:         uint16(id),
			Curve:         math.Curves[1],
			MessageLength: len(msg),
		}
	}

	// Initialize them with a nil send function
	for i, signer := range thresholdSigners {
		signer.Init(members, n-1, nil)
		signer.SetShareData(shares[i])
	}

	tpk, err := thresholdSigners[0].ThresholdPK()
	assert.NoError(t, err)

	// Blind the message we sign prior to signing it
	var prover ps.Prover
	prover.Init(math.Curves[1], len(msg), tpk, []uint16{1, 2, 3})
	blindSignature, secret := prover.Blind(msg)

	var signatures [][]byte

	// Sign a message
	for _, signer := range thresholdSigners {
		sig, err := signer.Sign(nil, blindSignature.Bytes())
		assert.NoError(t, err)
		signatures = append(signatures, sig)
	}

	var witnesses []ps.SignatureWitness

	// Unblind the signature
	for id := uint16(1); id <= uint16(n); id++ {
		w, err := prover.UnBlind(id, signatures[int(id)-1], &secret)
		assert.NoError(t, err)
		witnesses = append(witnesses, w)
	}

	for _, parties := range [][]uint16{
		{1, 2}, {2, 3}, {1, 3},
	} {
		first := parties[0]
		second := parties[1]
		sigPoK := prover.ProveKnowledgeOfSignature(&secret, []uint16{first, second}, []ps.SignatureWitness{witnesses[first-1], witnesses[second-1]})

		var verifier ps.Verifier
		err = verifier.Init(math.Curves[1], len(msg), tpk)
		assert.NoError(t, err)

		err = verifier.Verify(sigPoK.Bytes())
		assert.NoError(t, err)
	}
}

func keygen(t *testing.T, parties []MpcParty, n int) ([][]byte, time.Time) {
	var wg sync.WaitGroup
	wg.Add(len(parties))

	shares := make([][]byte, n)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	start := time.Now()
	for i, p := range parties {
		go func(i int, p MpcParty) {
			defer wg.Done()
			secretShareData, err := p.KeyGen(ctx, len(parties), n-1)
			shares[i] = secretShareData
			assert.NoError(t, err)
			assert.NotNil(t, secretShareData)
		}(i, p)
	}

	wg.Wait()
	cancel()
	return shares, start
}

type loggerWithDebug struct {
	*zap.SugaredLogger
}

func (lwd *loggerWithDebug) DebugEnabled() bool {
	return false
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

func setup(t *testing.T, n int, loggers []*commLogger, signers []*tlsgen.CertKeyPair, listeners []net.Listener, commParties []*comm.Party) ([]uint16, *x509.CertPool, []*commLogger, []*tlsgen.CertKeyPair, []net.Listener, []*comm.Party, func() map[UniversalID]PartyID, []MpcParty, func(id uint16) KeyGenerator) {
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

	membership := make(map[UniversalID]PartyID)

	for id := 1; id <= n; id++ {
		l := logger(id, t.Name())
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

	membershipFunc := func() map[UniversalID]PartyID {
		return membership
	}

	var parties []MpcParty

	kgf := func(id uint16) KeyGenerator {
		return &ps.TPS{
			Curve:         math.Curves[1],
			MessageLength: len(msg),
			Logger:        logger(int(id), fmt.Sprintf(t.Name())),
			Party:         id,
		}
	}
	return members, certPool, loggers, signers, listeners, commParties, membershipFunc, parties, kgf
}

func createParty(id int, kgf func(id uint16) KeyGenerator, signer *tlsgen.CertKeyPair, n int, certPool *x509.CertPool, listeners []net.Listener, loggers []*commLogger, commParties []*comm.Party, membershipFunc func() map[UniversalID]PartyID) (func(), MpcParty) {
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

	s := LoudScheme(uint16(id), loggers[id-1], kgf, nil, len(commParties)-1, remoteParties.Send, membershipFunc)

	go func(in <-chan comm.InMsg) {
		for msg := range in {
			inMsg := &IncMessage{
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

func logger(id int, testName string) *commLogger {
	logConfig := zap.NewDevelopmentConfig()
	baseLogger, _ := logConfig.Build()
	logger := baseLogger.With(zap.String("t", testName)).With(zap.String("id", fmt.Sprintf("%d", id)))
	return &commLogger{Logger: &loggerWithDebug{SugaredLogger: logger.Sugar()}, conf: &logConfig}
}
