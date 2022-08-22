/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package net

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	baseTLSConfig = &tls.Config{
		SessionTicketsDisabled: true,
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256},
		Renegotiation:          tls.RenegotiateNever,
		MinVersion:             tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	shouldHaveTopic = map[MsgType]bool{
		MsgTypeMPC:       true,
		MsgTypeDiscovery: true,
	}
)

type MsgType uint8

const (
	MsgTypeNone MsgType = iota
	MsgTypeDiscovery
	MsgTypeMPC

	maxBuffLen = 1024 * 1024 * 20 // 20MB
)

type Logger interface {
	DebugEnabled() bool
	Debugf(format string, a ...interface{})
	Warnf(format string, a ...interface{})
}

type PartyConnectionConfig struct {
	AuthFunc func(tlsContext []byte) Handshake
	Domain   string
	Id       int
	Endpoint string
	TlsCAs   *x509.CertPool
}

type errReporter func(string, ...interface{})

type outChan chan *outMsg

func (o outChan) enqueue(msg *outMsg, onFailure func(), timeout time.Duration) {
	t1 := time.NewTimer(timeout)
	defer t1.Stop()

	select {
	case o <- msg:
	case <-t1.C:
		onFailure()
	}
}

type remoteParty struct {
	onStart      sync.Once
	authenticate func(tlsTopic []byte) Handshake
	// config
	domain    string
	id        int
	reportErr errReporter
	endpoint  string
	// state
	tlsConf *tls.Config
	conn    *tls.Conn
	msgs    outChan
}

type outMsg struct {
	msgType MsgType
	data    []byte
	topic   []byte
}

type InMsg struct {
	Domain string
	From   uint16
	Data   []byte
	Topic  []byte
	Type   uint8
}

type Out struct {
	Broadcast bool
	Data      []byte
	Topic     string
}

type Party struct {
	InMessages  <-chan InMsg
	SendMessage SendMessage
	Address     string
	Logger      Logger
	Identity    []byte
}

type SendMessage func(msgType uint8, topic []byte, msg []byte, to ...uint16)

type SocketRemoteParties map[int]*remoteParty

func (parties SocketRemoteParties) Clone() SocketRemoteParties {
	res := make(SocketRemoteParties)
	for k, v := range parties {
		res[k] = &remoteParty{
			msgs:      make(outChan, 10),
			reportErr: v.reportErr,
			endpoint:  v.endpoint,
			tlsConf:   v.tlsConf,
			id:        v.id,
		}
	}

	return res
}

func (parties SocketRemoteParties) Send(msgType uint8, topic []byte, msg []byte, to ...uint16) {
	for _, dst := range to {
		p, exists := parties[int(dst)]
		if !exists {
			panic(fmt.Sprintf("party %d doesn't exist", dst))
		}

		p.startOnce()

		msgToSend := outMsg{
			msgType: MsgType(msgType),
			topic:   topic,
			data:    msg,
		}

		onTimeout := func() {
			p.reportErr(fmt.Sprintf("timeout sending to %d", dst))
			panic("bla")
		}

		p.msgs.enqueue(&msgToSend, onTimeout, time.Second*10)
	}
}

func NewSocketRemoteParty(config PartyConnectionConfig, l Logger) *remoteParty {
	tlsConfig := baseTLSConfig.Clone()
	tlsConfig.RootCAs = config.TlsCAs
	p := &remoteParty{
		authenticate: config.AuthFunc,
		msgs:         make(chan *outMsg, 1000),
		reportErr:    l.Warnf,
		endpoint:     config.Endpoint,
		tlsConf:      tlsConfig,
		id:           config.Id,
		domain:       config.Domain,
	}

	return p
}

func (rp *remoteParty) startOnce() {
	rp.onStart.Do(func() {
		go rp.sendMessages()
	})
}

func ServiceConnections(listener net.Listener, p2id participant2ID, l Logger) (<-chan InMsg, func()) {
	var stopFlag uint32
	stop := func() {
		atomic.StoreUint32(&stopFlag, 1)
		listener.Close()
	}

	inMsgs := make(chan InMsg)

	go func() {
		for atomic.LoadUint32(&stopFlag) == 0 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go handleConn(p2id, conn, inMsgs, &stopFlag, l)
		}
	}()

	return inMsgs, stop
}

func Listen(addr string, rawCert []byte, privateKey []byte) net.Listener {
	tlsConfig := baseTLSConfig.Clone()

	cert, err := tls.X509KeyPair(rawCert, privateKey)
	if err != nil {
		panic(fmt.Errorf("failed parsing TLS certificate and private key: %v", err))
	}

	tlsConfig.Certificates = []tls.Certificate{cert}

	lsnr, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		panic(fmt.Errorf("failed listening on %s: %v", addr, err))
	}
	return lsnr
}

type participant2ID map[string]uint16

func handleConn(p2id participant2ID, conn net.Conn, inMsgs chan InMsg, stopFlag *uint32, l Logger) {
	l.Debugf("Connection from %s", conn.RemoteAddr())
	domain, from, authenticationSucceeded := authenticateConnection(p2id, conn, l)
	if !authenticationSucceeded {
		l.Warnf("Connection from %s failed authenticating", conn.RemoteAddr())
		return
	}

	l.Debugf("Connection from %s authenticated as %d", conn.RemoteAddr(), from)

	for atomic.LoadUint32(stopFlag) == 0 {
		msgType, topic, data, err := readMsg(conn)
		if err != nil {
			fmt.Printf("Failed reading message from %s: %v\n", conn.RemoteAddr().String(), err)
			return
		}
		if l.DebugEnabled() {
			l.Debugf("Read message for %s of %d bytes from %d", hex.EncodeToString(topic), len(data), from)
		}
		inMsgs <- InMsg{
			Domain: domain,
			Type:   uint8(msgType),
			Topic:  topic,
			Data:   data,
			From:   from,
		}

	}
}

func authenticateConnection(p2id participant2ID, conn net.Conn, logger Logger) (string, uint16, bool) {
	var h Handshake
	if err := h.Read(conn); err != nil {
		logger.Warnf("failed authenticating %s: %v", conn.RemoteAddr().String(), err)
		return "", 0, false
	}

	now := time.Now()
	createTime := time.Unix(h.Timestamp, 0)
	if createTime.Add(time.Second * 30).Before(now) {
		logger.Warnf("Authentication message was created on %v and is too late in the past (now it's %v)", createTime, now)
	}

	binding := extractTLSBinding(conn)
	if !bytes.Equal(binding, h.TLSBinding) {
		logger.Warnf("TLS binding mismatch\n")
		return "", 0, false
	}

	bl, _ := pem.Decode(h.Identity)
	if bl == nil {
		logger.Warnf("Identity received is not a PEM (%s)", string(h.Identity))
		return "", 0, false
	}

	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		logger.Warnf("Identity received (%s) is not a valid x509 certificate: %v", string(h.Identity), err)
		return "", 0, false
	}

	pk := cert.PublicKey.(*ecdsa.PublicKey)

	sig := h.Signature
	h.Signature = nil

	if !ecdsa.VerifyASN1(pk, sha256Digest(h.Bytes()), sig) {
		logger.Warnf("Signature mismatch")
		return "", 0, false
	}

	lookupKey := hex.EncodeToString(sha256Digest([]byte(h.Domain), h.Identity))

	from, exists := p2id[lookupKey]
	if !exists {
		logger.Warnf("Node %s doesn't exist", lookupKey)
		return "", 0, false
	}

	logger.Debugf("Node %d authenticated", from)
	return h.Domain, uint16(from), true
}

func readMsg(conn net.Conn) (MsgType, []byte, []byte, error) {
	// Read message type and length to figure out whether message should have a topic or not

	typeAndLengthBuff := make([]byte, 5)
	if _, err := io.ReadFull(conn, typeAndLengthBuff); err != nil {
		return 0, nil, nil, fmt.Errorf("failed reading length from %s: %v", conn.RemoteAddr().String(), err)
	}
	msgType := MsgType(typeAndLengthBuff[0])
	bufferLength := binary.LittleEndian.Uint32(typeAndLengthBuff[1:])

	if int(bufferLength) > maxBuffLen {
		return 0, nil, nil, fmt.Errorf("buffer length too big (%d), allowed up to %d", bufferLength, maxBuffLen)
	}

	var topic []byte
	if shouldHaveTopic[msgType] {
		topic = make([]byte, 32)
		if _, err := io.ReadFull(conn, topic); err != nil {
			return 0, nil, nil, fmt.Errorf("failed reading topic from %s: %v", conn.RemoteAddr().String(), err)
		}
	}

	buff := make([]byte, bufferLength)
	if _, err := io.ReadFull(conn, buff); err != nil {
		return 0, nil, nil, fmt.Errorf("failed reading data from %s: %v", conn.RemoteAddr().String(), err)
	}

	return msgType, topic, buff, nil
}

func sha256Digest(b ...[]byte) []byte {
	hash := sha256.New()
	for _, bytes := range b {
		hash.Write(bytes)
	}
	return hash.Sum(nil)
}

func extractTLSBinding(conn net.Conn) []byte {
	cs := conn.(*tls.Conn).ConnectionState()
	tlsBinding, err := cs.ExportKeyingMaterial("MPC", []byte("MPC"), 32)
	if err != nil {
		panic("failed extracting TLS topic")
	}
	return tlsBinding
}

type Handshake struct {
	Domain     string
	TLSBinding []byte
	Identity   []byte
	Timestamp  int64
	Signature  []byte
}

func (h *Handshake) Read(reader io.Reader) error {
	lengthBuff := make([]byte, 2)
	if _, err := io.ReadFull(reader, lengthBuff); err != nil {
		return fmt.Errorf("failed reading size buffer: %v", err)
	}

	bufferLength := binary.LittleEndian.Uint16(lengthBuff)

	if int(bufferLength) > maxBuffLen {
		return fmt.Errorf("buffer length too big (%d), allowed up to %d", bufferLength, maxBuffLen)
	}

	buff := make([]byte, bufferLength)
	if _, err := io.ReadFull(reader, buff); err != nil {
		return fmt.Errorf("failed reading the buffer: %v", err)
	}
	if _, err := asn1.Unmarshal(buff, h); err != nil {
		return fmt.Errorf("failed unmarshaling error: %v", err)
	}
	return nil
}

func (h *Handshake) Write(writer io.Writer) error {
	data := h.Bytes()
	lengthBuff := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBuff, uint16(len(data)))

	_, err := writer.Write(lengthBuff)
	if err != nil {
		return fmt.Errorf("failed sending handshake message length: %w", err)
	}

	_, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed sending handshake data: %w", err)
	}

	return nil
}

func (h Handshake) Bytes() []byte {
	b, err := asn1.Marshal(h)
	if err != nil {
		panic(err)
	}

	return b
}

func (rp *remoteParty) sendMessages() {
	for {
		if !rp.maybeConnect() {
			time.Sleep(time.Second)
			continue
		}
		msg := <-rp.msgs
		rp.send(msg)
	}
}

func (rp *remoteParty) send(msg *outMsg) {
	// Ensure topic is either 32 bytes or 0 bytes
	ctxSize := len(msg.topic)
	if ctxSize != 0 && ctxSize != 32 {
		panic("topic should be either empty or 32 bytes")
	}

	// Prepare the buffer to send the data
	buffSize := 1 + 4 + len(msg.topic)
	header := make([]byte, buffSize)

	dataLen := len(msg.data)
	if dataLen > math.MaxUint32 {
		panic(fmt.Sprintf("data too large (doesn't fit in 16 bits): %d", dataLen))
	}

	header[0] = uint8(msg.msgType)
	binary.LittleEndian.PutUint32(header[1:], uint32(dataLen))
	if ctxSize > 0 {
		copy(header[5:], msg.topic)
	}

	// Write the header to stream
	_, err := rp.conn.Write(header)
	if err != nil {
		rp.reportErr("failed sending header of %d bytes to %s: %v", len(header), rp.endpoint, err)
		rp.conn.Close()
		rp.conn = nil
		return
	}

	// Write the data to stream
	_, err = rp.conn.Write(msg.data)
	if err != nil {
		rp.reportErr("failed sending data of %d bytes to %s: %v", len(msg.data), rp.endpoint, err)
		rp.conn.Close()
		rp.conn = nil
		return
	}
}

func (rp *remoteParty) maybeConnect() bool {
	if rp.conn != nil {
		return true
	}

	conn, err := tls.Dial("tcp", rp.endpoint, rp.tlsConf)
	if err != nil {
		rp.reportErr("failed connecting to %s: %v", rp.endpoint, err)
		return false
	}
	rp.conn = conn

	handshake := rp.authenticate(extractTLSBinding(rp.conn))
	handshake.Domain = rp.domain
	if err := handshake.Write(rp.conn); err != nil {
		rp.reportErr("failed sending handshake to %s: %v", rp.endpoint, err)
		rp.conn.Close()
		rp.conn = nil
		return false
	}

	return true
}
