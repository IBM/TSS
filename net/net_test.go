/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package net

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/IBM/TSS/testutil/tlsgen"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func allocatePorts(t *testing.T, count int) []int {
	var ports []int
	var listeners []net.Listener
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		assert.NoError(t, err)
		listeners = append(listeners, listener)
		_, portString, err := net.SplitHostPort(listener.Addr().String())
		assert.NoError(t, err)

		port, err := strconv.ParseInt(portString, 10, 32)
		assert.NoError(t, err)

		ports = append(ports, int(port))
	}

	for _, listener := range listeners {
		listener.Close()
	}

	return ports
}

func TestSocketRemoteParties(t *testing.T) {
	l := logger("test", t.Name())
	ca, err := tlsgen.NewCA()
	assert.NoError(t, err)

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca.CertBytes())

	ports := allocatePorts(t, 4)

	tlsCert, err := ca.NewServerCertKeyPair("127.0.0.1")
	assert.NoError(t, err)

	var signingIdentities []*tlsgen.CertKeyPair
	for i := 0; i < len(ports); i++ {
		s := newSigner(ca, t)
		signingIdentities = append(signingIdentities, s)
	}

	parties, allRemoteParties := partiesFromPorts(t, ports, certPool, signingIdentities, l)
	p2id := parties.participant2ID()

	var stops []func()

	for i := range parties {
		socketRemoteParties := remotePartiesForPeer(i, allRemoteParties, signingIdentities[i])
		parties[i].SendMessage = socketRemoteParties.Send
		lsnr := Listen(parties[i].Address, tlsCert.Cert, tlsCert.Key)
		in, stop := ServiceConnections(lsnr, p2id, parties[i].Logger)
		stops = append(stops, stop)
		parties[i].InMessages = in
	}

	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()

	ctx := sha256Digest([]byte("context"))

	t1 := time.Now()

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			parties[0].SendMessage(uint8(MsgTypeMPC), ctx, []byte{byte(i)}, 1, 2, 3)
		}
	}()

	for _, msgChan := range []<-chan InMsg{parties[1].InMessages, parties[2].InMessages, parties[3].InMessages} {
		go func(msgChan <-chan InMsg) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				n := <-msgChan
				assert.True(t, bytes.Equal(ctx, n.Topic))
				assert.True(t, bytes.Equal([]byte{byte(i)}, n.Data))
			}
		}(msgChan)
	}

	wg.Wait()
	fmt.Println(time.Since(t1))
}

func newSigner(ca tlsgen.CA, t *testing.T) *tlsgen.CertKeyPair {
	clientPair, err := ca.NewClientCertKeyPair()
	assert.NoError(t, err, "failed to create client key pair")

	return clientPair
}

func partiesFromPorts(t *testing.T, ports []int, certPool *x509.CertPool, signingIdentities []*tlsgen.CertKeyPair, l Logger) (Parties, SocketRemoteParties) {
	p0 := Party{
		Identity: signingIdentities[0].Cert,
		Logger:   logger("p0", t.Name()),
		Address:  fmt.Sprintf("127.0.0.1:%d", ports[0]),
	}

	p1 := Party{
		Identity: signingIdentities[1].Cert,
		Logger:   logger("p1", t.Name()),
		Address:  fmt.Sprintf("127.0.0.1:%d", ports[1]),
	}

	p2 := Party{
		Identity: signingIdentities[2].Cert,
		Logger:   logger("p2", t.Name()),
		Address:  fmt.Sprintf("127.0.0.1:%d", ports[2]),
	}

	p3 := Party{
		Identity: signingIdentities[3].Cert,
		Logger:   logger("p3", t.Name()),
		Address:  fmt.Sprintf("127.0.0.1:%d", ports[3]),
	}

	rp0 := NewSocketRemoteParty(PartyConnectionConfig{
		Endpoint: p0.Address,
		TlsCAs:   certPool,
		Id:       0,
	}, l)

	rp1 := NewSocketRemoteParty(PartyConnectionConfig{
		Endpoint: p1.Address,
		TlsCAs:   certPool,
		Id:       1,
	}, l)

	rp2 := NewSocketRemoteParty(PartyConnectionConfig{
		Endpoint: p2.Address,
		TlsCAs:   certPool,
		Id:       2,
	}, l)

	rp3 := NewSocketRemoteParty(PartyConnectionConfig{
		Endpoint: p3.Address,
		TlsCAs:   certPool,
		Id:       3,
	}, l)

	return []Party{p0, p1, p2, p3}, SocketRemoteParties{
		0: rp0,
		1: rp1,
		2: rp2,
		3: rp3,
	}
}

func remotePartiesForPeer(id int, remoteParties SocketRemoteParties, sID *tlsgen.CertKeyPair) SocketRemoteParties {
	auth := func(tlsContext []byte) Handshake {
		h := Handshake{
			TLSBinding: tlsContext,
			Identity:   sID.Cert,
			Timestamp:  time.Now().Unix(),
		}

		sig, err := sID.Sign(rand.Reader, sha256Digest(h.Bytes()), nil)
		if err != nil {
			panic("failed signing")
		}

		h.Signature = sig

		return h
	}
	parties := remoteParties.Clone()
	delete(parties, id)
	for _, party := range parties {
		party.authenticate = auth
	}
	return parties
}

func logger(id string, testName string) Logger {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	logger = logger.With(zap.String("t", testName)).With(zap.String("id", id))
	return &testLogger{
		SugaredLogger: logger.Sugar(),
		debugEnabled:  logConfig.Level.Enabled(zapcore.DebugLevel),
	}
}

type testLogger struct {
	debugEnabled bool
	*zap.SugaredLogger
}

func (tl *testLogger) DebugEnabled() bool {
	return false
}

type Parties []Party

func (parties Parties) participant2ID() participant2ID {
	m := make(participant2ID)
	for i, p := range parties {
		m[hex.EncodeToString(sha256Digest(p.Identity))] = uint16(i)
	}
	return m
}
