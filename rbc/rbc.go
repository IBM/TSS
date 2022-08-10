/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rbc

import (
	"encoding/hex"
	"fmt"
)

type Message interface {
	Round() uint8
	Digest() []byte
	WasBroadcast() bool
	// If message isn't an ack, all values are zeroes
	Ack() (digest []byte, sender uint16, msgRound uint8)
}

type Logger interface {
	DebugEnabled() bool
	Debugf(format string, a ...interface{})
	Warnf(format string, a ...interface{})
}

type idSet map[uint16]struct{}

func (ids idSet) keys() []uint16 {
	var res []uint16
	for k := range ids {
		res = append(res, k)
	}
	return res
}

type msgAndIdSet struct {
	m     Message
	idSet idSet
}

type Backend func(msg interface{}, from uint16)

type Broadcast func(digest string, sender uint16, msgRound uint8)

type msgReception struct {
	digest   string
	sender   uint16
	msgRound uint8
}

type senderAndRound struct {
	s uint16
	r uint8
}

type Receiver struct {
	// Config
	SelfID           uint16
	N                int
	ForwardToBackend Backend
	BroadcastAck     Broadcast
	Logger           Logger
	// State
	reception               map[msgReception]*msgAndIdSet
	receivedRoundFromSender map[senderAndRound]string
	equivocationDetected    bool
}

func (r *Receiver) Receive(m Message, from uint16) {
	r.initIfNeeded()

	if r.equivocationDetected {
		r.Logger.Warnf("Equivocation detected, dropping message")
		return
	}

	digest, sender, msgRound := m.Ack()
	// It's an ack
	if len(digest) > 0 {
		if from == r.SelfID {
			panic(fmt.Sprintf("received ack from myself"))
		}
		// Ignore acknowledgements about things I sent
		if sender == r.SelfID {
			return
		}
		r.Logger.Debugf("Got ack {sender: %d, digest: %s, round: %d} from %d",
			sender, hex.EncodeToString(digest[:8]), msgRound, from)
		r.registerMsg(msgReception{
			digest:   string(digest),
			msgRound: msgRound,
			sender:   sender,
		}, from, nil)
		return
	}

	if !m.WasBroadcast() {
		r.Logger.Debugf("Got point to point message from %d", from)
		r.ForwardToBackend(m, from)
		return
	}

	reception := msgReception{
		digest:   string(m.Digest()),
		msgRound: m.Round(),
		sender:   from,
	}

	r.registerMsg(reception, r.SelfID, m)
	r.BroadcastAck(reception.digest, reception.sender, reception.msgRound)

	r.Logger.Debugf("Got broadcast of round %d with digest %s from %d, broadcasting its digest",
		reception.msgRound, hex.EncodeToString([]byte(reception.digest[:8])), from)
}

func (r *Receiver) initIfNeeded() {
	if r.reception != nil {
		return
	}
	r.reception = make(map[msgReception]*msgAndIdSet)
	r.receivedRoundFromSender = make(map[senderAndRound]string)
}

func (r *Receiver) registerMsg(ack msgReception, from uint16, msg Message) {
	msgOrAck := "ack"
	receivedFrom := fmt.Sprintf("received from %d", from)
	if msg != nil {
		msgOrAck = "message"
		receivedFrom = ""
	}

	st := senderAndRound{s: ack.sender, r: ack.msgRound}
	if savedDigest, exists := r.receivedRoundFromSender[st]; !exists {
		r.Logger.Debugf("Registering  %s {sender: %d, digest: %s, round: %d} %s",
			msgOrAck, ack.sender, hex.EncodeToString([]byte(ack.digest[:8])), ack.msgRound, receivedFrom)
		r.receivedRoundFromSender[st] = ack.digest
	} else if savedDigest != ack.digest {
		r.Logger.Debugf("Detected conflicting digests for {sender: %d, round: %d}: %s vs %s",
			st.s, st.r, savedDigest, ack.digest)
		r.equivocationDetected = true
		return
	}

	if _, exists := r.reception[ack]; !exists {
		r.reception[ack] = &msgAndIdSet{
			idSet: make(idSet),
		}
	}

	r.reception[ack].idSet[from] = struct{}{}

	if msg != nil {
		r.reception[ack].m = msg
	}

	if len(r.reception[ack].idSet) == r.N-1 {
		r.Logger.Debugf("Collected enough acknowledgements (from %v) on {sender: %d, digest: %s, round: %d}",
			r.reception[ack].idSet, ack.sender, hex.EncodeToString([]byte(ack.digest[:8])), ack.msgRound)
		r.ForwardToBackend(r.reception[ack].m, ack.sender)
	} else {
		r.Logger.Debugf("%d more acknowledgements on  {sender: %d, digest: %s, round: %d} are expected",
			r.N-1-len(r.reception[ack].idSet), ack.sender, hex.EncodeToString([]byte(ack.digest[:8])), ack.msgRound)
	}
}
