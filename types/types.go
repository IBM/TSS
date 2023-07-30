/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tss

import (
	"context"
	"time"
)

type MsgType uint8

const (
	MsgTypeNone MsgType = iota
	MsgTypeSync
	MsgTypeMPC

	DkgTopicName = "DKG"
)

// Logger logs messages in a synchronized fashion to the same destination (usually to a file)
type Logger interface {
	DebugEnabled() bool
	Debugf(format string, a ...interface{})
	Infof(format string, a ...interface{})
	Warnf(format string, a ...interface{})
	Errorf(format string, a ...interface{})
}

// UniversalID is a unique identifier across all parties in the universe.
// It is only used to send messages to other parties, or to select a subset
// of parties to run either DKG or signing.
type UniversalID uint16

// PartyID denotes the identifier of a party within an MPC protocol execution.
// Multiple UniversalIDs can map into the same PartyID.
type PartyID uint16

// Membership provides information about the identifiers of the parties.
// Each party has a global identifier and a local identifier.
type Membership func() map[UniversalID]PartyID

type SendFunc func(msgType uint8, topic []byte, msg []byte, to ...UniversalID)

type SignerFactory func(id uint16) Signer

type KeyGenFactory func(id uint16) KeyGenerator

type KeyGenerator interface {
	ClassifyMsg(msgBytes []byte) (uint8, bool, error)

	Init(parties []uint16, threshold int, sendMsg func(msg []byte, isBroadcast bool, to uint16))

	OnMsg(msgBytes []byte, from uint16, broadcast bool)

	KeyGen(ctx context.Context) ([]byte, error)
}

type Signer interface {
	ClassifyMsg(msgBytes []byte) (uint8, bool, error)

	Init(parties []uint16, threshold int, sendMsg func(msg []byte, isBroadcast bool, to uint16))

	OnMsg(msgBytes []byte, from uint16, broadcast bool)

	SetShareData(shareData []byte) error

	Sign(ctx context.Context, msg []byte) ([]byte, error)

	ThresholdPK() ([]byte, error)
}

type SynchronizerFactory func(members []uint16, broadcast func(msg []byte), send func(msg []byte, to uint16)) Synchronizer

type Synchronizer interface {
	Synchronize(ctx context.Context, f func([]uint16), topicToSynchronizeOn []byte, expectedMemberCount int, interval time.Duration) error

	HandleMessage(from uint16, msg []byte)
}

type RBCMessage interface {
	Round() uint8
	Digest() []byte
	WasBroadcast() bool
	// If message isn't an ack, all values are zeroes
	Ack() (digest []byte, sender uint16, msgRound uint8)
}

type BroadcastFunc func(digest string, sender uint16, msgRound uint8)

type ForwardFunc func(msg interface{}, from uint16)

type ReliableBroadcastFactory func(BroadcastFunc, ForwardFunc, int) ReliableBroadcast

type ReliableBroadcast interface {
	Receive(m RBCMessage, from uint16)
}

type IncMessage struct {
	Data    []byte
	Source  uint16
	MsgType uint8
	Topic   []byte
}

type MpcParty interface {
	Sign(c context.Context, msgHash []byte, topic string) ([]byte, error)

	KeyGen(ctx context.Context, totalParties, threshold int) ([]byte, error)

	HandleMessage(msg *IncMessage)

	SetStoredData(data []byte)

	ThresholdPK() ([]byte, error)
}

type ThresholdVerifier interface {
	Init([]byte) error
	Verify(digest []byte, parties []uint16, signatures [][]byte) error
}
