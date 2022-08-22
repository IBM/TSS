/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rbc

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/assert"
)

func TestBroadcast(t *testing.T) {
	receivers := receivers{newReceiver(0, t), newReceiver(1, t), newReceiver(2, t)}
	callSet := receivers.setup()

	// 0 broadcasts "baz"
	receivers[1].Receive(&mockMsg{content: "baz"}, 0)
	receivers[2].Receive(&mockMsg{content: "baz"}, 0)

	assert.Equal(t, map[call]struct{}{
		{who: 1, msg: "baz", from: 0}: {},
		{who: 2, msg: "baz", from: 0}: {},
	}, callSet)
}

func TestByzantineBroadcast(t *testing.T) {
	receivers := receivers{newReceiver(0, t), newReceiver(1, t), newReceiver(2, t)}
	callSet := receivers.setup()

	// 0 sends a broadcast of "baz" but sends to 2 "b$z" instead of "baz"
	receivers[1].Receive(&mockMsg{content: "baz"}, 0)
	receivers[2].Receive(&mockMsg{content: "b$z"}, 0)

	assert.Empty(t, callSet)
}

func TestByzantineBroadcastII(t *testing.T) {
	receivers := receivers{newReceiver(0, t), newReceiver(1, t), newReceiver(2, t)}
	callSet := receivers.setup()

	// 0 sends a broadcast of "baz" but sends to 2 "b$z" instead of "baz",
	// and later on it sends a broadcast of "baz" to 2 and a broadcast of "b$z" to 1.
	receivers[1].Receive(&mockMsg{content: "baz"}, 0)
	receivers[2].Receive(&mockMsg{content: "b$z"}, 0)
	receivers[2].Receive(&mockMsg{content: "baz"}, 0)
	receivers[1].Receive(&mockMsg{content: "b$z"}, 0)

	assert.Empty(t, callSet)
}

func TestPointToPointMessage(t *testing.T) {
	receivers := receivers{newReceiver(0, t), newReceiver(1, t), newReceiver(2, t)}
	callSet := receivers.setup()

	// 0 sends 1 the string "foo"
	receivers[1].Receive(directMsg("foo"), 0)
	// 2 sends 1 the string "bar"
	receivers[1].Receive(directMsg("bar"), 2)

	assert.Equal(t, map[call]struct{}{
		{who: 1, msg: "foo", from: 0}: {},
		{who: 1, msg: "bar", from: 2}: {},
	}, callSet)
}

type directMsg string

func (d directMsg) String() string {
	return string(d)
}

func (d directMsg) Round() uint8 {
	panic("implement me")
}

func (d directMsg) Digest() []byte {
	panic("implement me")
}

func (d directMsg) WasBroadcast() bool {
	return false
}

func (d directMsg) Ack() ([]byte, uint16, uint8) {
	return nil, 0, 0
}

type mockMsg struct {
	content string
	ack     *msgReception
}

func (m *mockMsg) String() string {
	return m.content
}

func (m *mockMsg) Round() uint8 {
	return 0
}

func (m *mockMsg) Digest() []byte {
	h := sha256.New()
	h.Write([]byte(m.content))
	return h.Sum(nil)
}

func (m *mockMsg) WasBroadcast() bool {
	return m.ack == nil
}

func (m *mockMsg) Ack() ([]byte, uint16, uint8) {
	if m.ack == nil {
		return nil, 0, 0
	}
	return []byte(m.ack.digest), m.ack.sender, m.ack.msgRound
}

type call struct {
	who  uint16
	msg  string
	from uint16
}

type receivers []*Receiver

func (rs receivers) setup() map[call]struct{} {
	calls := make(map[call]struct{})

	for _, r := range rs {
		r.N = len(rs)
		r := r
		r.ForwardToBackend = func(msg interface{}, from uint16) {
			if ack, isMock := msg.(*mockMsg); isMock && ack.ack != nil {
				return
			}
			calls[call{
				from: from,
				msg:  msg.(fmt.Stringer).String(),
				who:  r.SelfID,
			}] = struct{}{}
		}

		r.BroadcastAck = func(digest string, sender uint16, msgRound uint8) {
			for _, receiver := range rs {
				if receiver.SelfID == r.SelfID {
					continue
				}
				receiver.Receive(&mockMsg{
					ack: &msgReception{sender: sender, msgRound: msgRound, digest: digest},
				}, r.SelfID)
			}
		}
	}

	return calls
}

func newReceiver(id uint16, t *testing.T) *Receiver {
	return &Receiver{SelfID: id, Logger: logger(fmt.Sprintf("%d", id), t.Name())}
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
