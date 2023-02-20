/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package threshold

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	discovery "github.com/IBM/TSS/disc"
	"github.com/IBM/TSS/msg"
	"github.com/IBM/TSS/rbc"
	. "github.com/IBM/TSS/types"
)

var (
	SyncInterval = time.Millisecond * 200
)

type Scheme struct {
	// State
	dkgRunning         bool
	setupOnce          sync.Once
	lock               sync.RWMutex
	syncsInProgress    map[string]func(uint16, []byte)
	rbcInProgress      map[string]func(m RBCMessage, from uint16)
	messageClassifiers map[string]func([]byte) (uint8, bool, error)
	// Config
	Threshold     int
	SelfID        UniversalID
	Membership    Membership
	Send          SendFunc
	StoredData    []byte
	RBF           ReliableBroadcastFactory
	SyncFactory   SynchronizerFactory
	SignerFactory SignerFactory
	KeyGenFactory KeyGenFactory
	Logger        Logger
}

func (s *Scheme) SetStoredData(d []byte) {
	s.StoredData = d
}

func (s *Scheme) HandleMessage(msg *IncMessage) {
	switch msg.MsgType {
	case uint8(MsgTypeSync):
		s.handleSync(msg)
		return
	case uint8(MsgTypeMPC):
		s.handleMPC(msg)
		return
	default:
		s.Logger.Warnf("received message of unknown type: %d", msg.MsgType)
	}
}

func (s *Scheme) handleSync(msg *IncMessage) {
	s.lock.RLock()
	h, exists := s.syncsInProgress[string(msg.Topic)]
	s.lock.RUnlock()

	if !exists {
		s.Logger.Debugf("Received SYNC message for topic %s from %d but no instance expects it", hex.EncodeToString(msg.Topic)[:8], msg.Source)
		return
	}

	h(msg.Source, msg.Data)
}

func (s *Scheme) handleMPC(msg *IncMessage) {
	s.Logger.Debugf("msg on topic %s from %d", hex.EncodeToString(msg.Topic[:8]), msg.Source)
	s.lock.RLock()
	handleRBC, rbcExists := s.rbcInProgress[string(msg.Topic)]
	classifier, classifierExists := s.messageClassifiers[string(msg.Topic)]
	s.lock.RUnlock()

	if !rbcExists {
		s.Logger.Warnf("Received MPC message for topic %s but no RBC instance expects it", hex.EncodeToString(msg.Topic)[:8])
		s.Logger.Warnf("RBCMessage: %s", base64.StdEncoding.EncodeToString(msg.Data))
		return
	}

	if !classifierExists {
		s.Logger.Warnf("Received MPC message for topic %s but no classifier for it", hex.EncodeToString(msg.Topic)[:8])
		return
	}

	rbcEncoding := rbcEncoding(msg.Data)
	digest, sender, round, err := rbcEncoding.Ack()
	if err != nil {
		s.Logger.Warnf("Received MPC message (%s) from %d but it is malformed: %v", base64.StdEncoding.EncodeToString(msg.Data), msg.Source, err)
		return
	}

	if len(digest) > 0 {
		s.handleAck(msg, round, sender, digest, handleRBC)
	} else {
		s.handleRBC(msg, rbcEncoding, classifier, handleRBC)
	}
}

func (s *Scheme) handleRBC(msg *IncMessage, rbcEncoding rbcEncoding, classifier func([]byte) (uint8, bool, error), handleRBC func(m RBCMessage, from uint16)) {
	var rbcMsg rbcMsg
	rawMsgBytes := rbcEncoding.Payload()
	msgRound, broadcast, err := classifier(rawMsgBytes)
	if err != nil {
		s.Logger.Warnf("Received malformed MPC message from %d: %v", msg.Source, err)
		return
	}

	var broadcastString string
	if broadcast {
		broadcastString = "broadcast "
	}

	rbcMsg.payload = rawMsgBytes
	rbcMsg.round = msgRound
	rbcMsg.sender = msg.Source
	rbcMsg.broadcast = broadcast
	rbcMsg.digest = hash(rawMsgBytes)

	s.Logger.Debugf("Received MPC %smessage from %d on topic %s for round %d",
		broadcastString, msg.Source, hex.EncodeToString(msg.Topic[:8]), msgRound)

	handleRBC(&rbcMsg, msg.Source)
}

func (s *Scheme) handleAck(msg *IncMessage, round uint8, sender uint16, digest []byte, handleRBC func(m RBCMessage, from uint16)) {
	var rbcMsg rbcMsg

	s.Logger.Debugf("Received RBC ack for topic %s with digest %s on round %d about %d from %d",
		hex.EncodeToString(msg.Topic[:8]), hex.EncodeToString(digest[:8]), round, sender, msg.Source)
	rbcMsg.digest = digest
	rbcMsg.sender = sender
	rbcMsg.round = round

	handleRBC(&rbcMsg, msg.Source)
}

// KeyGen collaborates with parties and generates a threshold signature public key.
// The private key generated is unknown to any threshold or less parties.
// On success, returns data to be securely saved for later signing, namely the secret share of the party.
// In case the given context expires, or any other problem occurs, returns an error.
// It is up to the caller to ensure that exactly the given amount of total parties invoke KeyGen concurrently.
func (s *Scheme) KeyGen(ctx context.Context, totalParties, threshold int) ([]byte, error) {
	s.setupOnce.Do(s.setup)

	membership := computeMembership(s.Membership())

	s.Logger.Infof("Membership:\n%s", membership)

	if err := s.ensureDKGNotRunning(); err != nil {
		return nil, err
	}

	defer func() {
		s.lock.Lock()
		s.dkgRunning = false
		s.lock.Unlock()
	}()

	dkgTopicHash := hash([]byte(DkgTopicName))

	broadcastParties := excludeUniversal(membership.universalIdentifiers, s.SelfID)

	// We use a synchronizer to wait for all parties to be ready to initialize the DKG
	sync := s.SyncFactory(universalIDsToUInts(membership.universalIdentifiers), func(msg []byte) {
		s.Send(uint8(MsgTypeSync), dkgTopicHash, msg, broadcastParties...)
	}, func(msg []byte, to uint16) {
		s.Send(uint8(MsgTypeSync), dkgTopicHash, msg, UniversalID(to))
	})

	dkgProtocolInstance := s.KeyGenFactory(uint16(s.SelfID))

	cleanup := s.initializeHandlers(dkgTopicHash, sync.HandleMessage, dkgProtocolInstance.ClassifyMsg)
	defer cleanup()

	data, parties, err := s.runDKG(ctx, membership, dkgProtocolInstance, sync, dkgTopicHash, totalParties, threshold)
	s.Logger.Infof("DKG completed with parties %v", parties)
	return data, err
}

type membership struct {
	universalIdentifiers []UniversalID
	uID2PID              map[UniversalID]PartyID
	pID2UID              map[PartyID]UniversalID
}

func (m *membership) String() string {
	sb := strings.Builder{}
	for _, uID := range m.universalIdentifiers {
		sb.WriteString(fmt.Sprintf("%d --> %d\n", uID, m.uID2PID[uID]))
	}
	s := sb.String()
	return s[:len(s)-1]
}

func (m *membership) partyIDByUniversalID(id UniversalID) PartyID {
	return m.uID2PID[id]
}

func (m *membership) partyIDsByUniversalIDs(ids []UniversalID) ([]PartyID, error) {
	used := make(map[PartyID]struct{})

	var res []PartyID

	for _, id := range ids {
		pid := m.partyIDByUniversalID(id)
		if _, exists := used[pid]; exists {
			return nil, fmt.Errorf("party %d tried to participate twice or more in the DKG", pid)
		}
		used[pid] = struct{}{}
		res = append(res, pid)
	}

	sortPartyIdentifiers(res)

	return res, nil
}

func (m *membership) universalIDByPartyID(id PartyID) UniversalID {
	return m.pID2UID[id]
}

func computeMembership(mapping map[UniversalID]PartyID) *membership {
	protocol2universal := make(map[PartyID]UniversalID)
	universal2Protocol := make(map[UniversalID]PartyID)

	var uIDs []UniversalID
	for uID, pID := range mapping {
		protocol2universal[pID] = uID
		universal2Protocol[uID] = pID
		uIDs = append(uIDs, uID)
	}

	sortUniversalIdentifiers(uIDs)

	return &membership{
		universalIdentifiers: uIDs,
		pID2UID:              protocol2universal,
		uID2PID:              universal2Protocol,
	}
}

type mpcResult struct {
	data    []byte
	parties []PartyID
	err     error
}

func (s *Scheme) runDKG(ctx context.Context, membership *membership, dkgProtocolInstance KeyGenerator, sync Synchronizer, dkgTopicHash []byte, n, t int) ([]byte, []PartyID, error) {
	resultChan := make(chan mpcResult, 1)

	membershipConsensus := make(chan struct{})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	callback := func(members []uint16) {
		universalIds := UIntsToUniversalIDs(members)
		parties, err := membership.partyIDsByUniversalIDs(universalIds)
		if err != nil {
			resultChan <- struct {
				data    []byte
				parties []PartyID
				err     error
			}{err: err}
			return
		}

		broadcastParties := excludeUniversal(membership.universalIdentifiers, s.SelfID)

		rbc := s.RBF(func(digest string, sender uint16, msgRound uint8) {
			s.Logger.Debugf("Broadcasting ack with digest %s for round %d about %d", hex.EncodeToString([]byte(digest)[:8]), msgRound, sender)
			payload := newRBCEncoding(digest, sender, msgRound)
			s.Send(uint8(MsgTypeMPC), dkgTopicHash, payload, broadcastParties...)
		}, func(m interface{}, from uint16) {
			msg := m.(*rbcMsg)
			s.Logger.Debugf("Got round %d message from %d", msg.round, from)
			sourceParty := uint16(membership.partyIDByUniversalID(UniversalID(from)))
			dkgProtocolInstance.OnMsg(msg.payload, sourceParty, msg.broadcast)
		}, n)

		rbc = &rbcFilter{
			h:           rbc.Receive,
			warn:        s.Logger.Warnf,
			allowedList: universalIDsToUintMap(universalIds),
		}

		s.lock.Lock()
		_, rbcExisted := s.rbcInProgress[string(dkgTopicHash)]
		s.rbcInProgress[string(dkgTopicHash)] = rbc.Receive
		s.lock.Unlock()

		if rbcExisted {
			panic("Programming error: we shouldn't have gotten to a situation with two concurrent signing with the same topic")
		}

		s.Logger.Debugf("Running keygen with parties %v", members)

		if err := s.initializeDKG(dkgProtocolInstance, t, UIntsToUniversalIDs(members), membership); err != nil {
			s.Logger.Errorf("Failed initializing DKG: %v", err)
			resultChan <- mpcResult{err: err}
			return
		}

		// We use a synchronizer to synchronize on the hash of the parties, to ensure that all parties that participate
		// in DKG are in agreement on the membership of the DKG.

		membersSyncTopicHash := membershipSyncTopicName(members)

		sync := s.SyncFactory(members, func(msg []byte) {
			s.Send(uint8(MsgTypeSync), membersSyncTopicHash, msg, broadcastParties...)
		}, func(msg []byte, to uint16) {
			s.Send(uint8(MsgTypeSync), membersSyncTopicHash, msg, UniversalID(to))
		})

		s.lock.Lock()
		s.syncsInProgress[string(membersSyncTopicHash)] = sync.HandleMessage
		s.lock.Unlock()

		defer func() {
			s.lock.Lock()
			delete(s.syncsInProgress, string(membersSyncTopicHash))
			s.lock.Unlock()
		}()

		go sync.Synchronize(ctx, func([]uint16) {
			close(membershipConsensus)
		}, membersSyncTopicHash, n, SyncInterval)

		select {
		case <-membershipConsensus:
		case <-ctx.Done():
			resultChan <- mpcResult{err: fmt.Errorf("could not reach consensus on membership")}
			return
		}

		result, err := dkgProtocolInstance.KeyGen(ctx)

		resultChan <- mpcResult{data: result, err: err, parties: parties}
	}

	go func() {
		if err := sync.Synchronize(ctx, callback, dkgTopicHash, n, SyncInterval); err != nil {
			resultChan <- mpcResult{data: nil, err: err}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case res := <-resultChan:
		return res.data, res.parties, res.err
	}
}

func membershipSyncTopicName(members []uint16) []byte {
	h := sha256.New()
	for _, member := range members {
		h.Write([]byte{uint8(member), uint8(member >> 8)})
	}
	membersSyncTopicHash := h.Sum(nil)
	return membersSyncTopicHash
}

func (s *Scheme) initializeHandlers(
	dkgTopicHash []byte,
	syncHandler func(uint16, []byte),
	classifierInstance func([]byte) (uint8, bool, error)) func() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.syncsInProgress[string(dkgTopicHash)] = syncHandler

	_, classifierExisted := s.messageClassifiers[string(dkgTopicHash)]
	s.messageClassifiers[string(dkgTopicHash)] = classifierInstance

	defer func() {
		if classifierExisted {
			panic("Programming error: we shouldn't have gotten to a situation with two concurrent distributed key generation takes place")
		}
	}()

	return func() {
		s.lock.Lock()
		delete(s.syncsInProgress, string(dkgTopicHash))
		delete(s.messageClassifiers, string(dkgTopicHash))
		delete(s.rbcInProgress, string(dkgTopicHash))
		s.lock.Unlock()
	}
}

func (s *Scheme) ensureDKGNotRunning() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.dkgRunning {
		return fmt.Errorf("key generation already running")
	}
	s.dkgRunning = true

	return nil
}

func (s *Scheme) ThresholdPK() ([]byte, error) {
	signer := s.SignerFactory(uint16(s.SelfID))
	if err := signer.SetShareData(s.StoredData); err != nil {
		s.Logger.Errorf("Failed setting share data: %v", err)
		return nil, err
	}

	return signer.ThresholdPK()
}

// Sign produces a threshold signature on `msgHash`, collaborating with all parties concurrently invoke Sign with the same topic.
// In case the deadline of the given context expires, or any other problem occurs, returns an error.
func (s *Scheme) Sign(c context.Context, msgHash []byte, topic string) ([]byte, error) {
	s.setupOnce.Do(s.setup)

	membership := computeMembership(s.Membership())

	topicHash := hash([]byte(topic))
	topicHashText := hex.EncodeToString(topicHash)
	msgHashHex := hex.EncodeToString(msgHash)

	start := time.Now()

	s.Logger.Infof("Topic <%s> hash is %s", topic, topicHashText[:8])

	resultChan := make(chan struct {
		sig []byte
		err error
	}, 1)

	ctx, cancel := context.WithCancel(c)
	defer cancel()

	cleanup := func() {
		s.lock.Lock()
		delete(s.syncsInProgress, string(topicHash))
		delete(s.messageClassifiers, string(topicHash))
		delete(s.rbcInProgress, string(topicHash))
		s.lock.Unlock()
	}

	var signedSuccessfully uint32

	initializeSigningInstance := func(signers []uint16) {
		partyIDs, err := membership.partyIDsByUniversalIDs(UIntsToUniversalIDs(signers))
		if err != nil {
			resultChan <- struct {
				sig []byte
				err error
			}{err: err}
			return
		}

		s.Logger.Infof("Parties %v out of %v (mapped to %v) were selected to sign message hash %s with a topic of %s",
			signers, membership.universalIdentifiers, partyIDs, msgHashHex[:8], topicHashText[:8])

		s.Logger.Debugf("Synchronization on topic %s took %v", topicHashText[:8], time.Since(start))

		start2 := time.Now()

		signingProtocol, err := s.prepareSigning(membership, partyIDs, topicHash, UIntsToUniversalIDs(signers))
		if err != nil {
			s.Logger.Errorf("Failed initializing signing instance: %v", err)
			return
		}

		// We will synchronize again to ensure all parties have initialized the signing instance before
		// we actually start signing.
		syncTopic := hash(topicHash)
		signersWithoutMe := excludeUniversal(UIntsToUniversalIDs(signers), s.SelfID)

		sync := s.SyncFactory(signers, func(msg []byte) {
			s.Send(uint8(MsgTypeSync), syncTopic, msg, signersWithoutMe...)
		}, func(msg []byte, to uint16) {
			s.Send(uint8(MsgTypeSync), syncTopic, msg, UniversalID(to))
		})

		s.lock.Lock()
		s.syncsInProgress[string(syncTopic)] = sync.HandleMessage
		s.lock.Unlock()

		cleanupSyncTopic := func() {
			s.lock.Lock()
			delete(s.syncsInProgress, string(syncTopic))
			s.lock.Unlock()
		}

		s.Logger.Infof("Synchronizing on pre-signing topic %s with %v", hex.EncodeToString(syncTopic)[:8], signers)

		err = sync.Synchronize(ctx, func([]uint16) {
			defer cleanupSyncTopic()
			defer cleanup()

			s.Logger.Debugf("Time elapsed to ensure all signers for topic %s are ready: %v", topicHashText[:8], time.Since(start2))

			signature, err := s.runSigningProtocol(ctx, signingProtocol, msgHash)
			if err == nil {
				atomic.StoreUint32(&signedSuccessfully, 1)
			}
			resultChan <- struct {
				sig []byte
				err error
			}{sig: signature, err: err}
		}, syncTopic, len(signers), SyncInterval)
		if err != nil {
			// suppress error in case we signed successfully
			if atomic.LoadUint32(&signedSuccessfully) == 0 {
				s.Logger.Warnf("Failed synchronizing on pre-signing topic: %v", err)
			}
			cleanupSyncTopic()
		}
	}

	sync, err := s.initializeSyncForSigning(topic, topicHash, membership.universalIdentifiers)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := sync.Synchronize(ctx, initializeSigningInstance, topicHash, s.Threshold+1, SyncInterval); err != nil {
			// suppress error in case we signed successfully
			if atomic.LoadUint32(&signedSuccessfully) == 0 {
				s.Logger.Errorf("Failed synchronizing on signing topic %s", hex.EncodeToString(topicHash))
			}
			resultChan <- struct {
				sig []byte
				err error
			}{sig: nil, err: err}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		s.Logger.Infof("Successfully signed message hash %s", msgHashHex[:8])
		return res.sig, res.err
	}
}

func (s *Scheme) runSigningProtocol(ctx context.Context, signingProtocol Signer, msgHash []byte) ([]byte, error) {
	signature, err := signingProtocol.Sign(ctx, msgHash)
	if err != nil {
		s.Logger.Errorf("Failed signing: %v", err)
		return nil, err
	}
	return signature, nil
}

func (s *Scheme) initializeSyncForSigning(topic string, topicHash []byte, members []UniversalID) (Synchronizer, error) {
	membersWithoutMe := excludeUniversal(members, s.SelfID)
	// We will synchronize on the topic (hash) to find out the parties that will participate in the signing
	sync := s.SyncFactory(universalIDsToUInts(members), func(msg []byte) {
		s.Send(uint8(MsgTypeSync), topicHash, msg, membersWithoutMe...)
	}, func(msg []byte, to uint16) {
		s.Send(uint8(MsgTypeSync), topicHash, msg, UniversalID(to))
	})

	s.lock.Lock()
	_, exists := s.syncsInProgress[string(topicHash)]
	if exists {
		s.Logger.Debugf("Already in the process of signing topic %s", topic)
		s.lock.Unlock()
		return nil, fmt.Errorf("already signing topic %s", topic)
	}

	s.syncsInProgress[string(topicHash)] = sync.HandleMessage
	s.lock.Unlock()

	return sync, nil
}

func (s *Scheme) prepareSigning(membership *membership, parties []PartyID, topicHash []byte, signers []UniversalID) (Signer, error) {
	signingProtocol, err := s.initializeThresholdSigning(membership, parties, topicHash, signers)
	if err != nil {
		return nil, err
	}

	broadcastParties := excludeUniversal(signers, s.SelfID)
	rbc := s.RBF(func(digest string, sender uint16, msgRound uint8) {
		payload := newRBCEncoding(digest, sender, msgRound)
		s.Send(uint8(MsgTypeMPC), topicHash, payload, broadcastParties...)
	}, func(m interface{}, from uint16) {
		msg := m.(*rbcMsg)
		s.Logger.Debugf("Got round %d message from %d", msg.round, from)
		signingProtocol.OnMsg(msg.payload, from, msg.broadcast)
	}, len(signers))

	rbc = &rbcFilter{
		allowedList: universalIDsToUintMap(signers),
		h:           rbc.Receive,
		warn:        s.Logger.Warnf,
	}

	s.lock.Lock()

	_, rbcExisted := s.rbcInProgress[string(topicHash)]
	s.rbcInProgress[string(topicHash)] = rbc.Receive

	_, classifierExisted := s.messageClassifiers[string(topicHash)]
	s.messageClassifiers[string(topicHash)] = signingProtocol.ClassifyMsg

	s.lock.Unlock()

	if rbcExisted || classifierExisted {
		panic("Programming error: we shouldn't have gotten to a situation with two concurrent signing with the same topic")
	}

	return signingProtocol, signingProtocol.SetShareData(s.StoredData)
}

func (s *Scheme) initializeDKG(dkg KeyGenerator, threshold int, members []UniversalID, membership *membership) error {
	membersWithoutMe := excludeUniversal(members, s.SelfID)

	dkgTopicHash := hash([]byte(DkgTopicName))

	dkg.Init(universalIDsToUInts(members), threshold, func(msg []byte, isBroadcast bool, to uint16) {
		var payload []byte
		payload = append(payload, 255)
		payload = append(payload, msg...)
		if isBroadcast {
			s.Send(uint8(MsgTypeMPC), dkgTopicHash, payload, membersWithoutMe...)
			return
		}
		s.Send(uint8(MsgTypeMPC), dkgTopicHash, payload, membership.universalIDByPartyID(PartyID(to)))
	})

	return nil
}

func (s *Scheme) initializeThresholdSigning(membership *membership, parties []PartyID, topicHash []byte, signers []UniversalID) (Signer, error) {
	signer := s.SignerFactory(uint16(s.SelfID))
	if err := signer.SetShareData(s.StoredData); err != nil {
		s.Logger.Errorf("Failed setting share data: %v", err)
		return nil, err
	}

	membersWithoutMe := excludeUniversal(signers, s.SelfID)

	signer.Init(partyIDsToUInts(parties), s.Threshold, func(msg []byte, isBroadcast bool, to uint16) {
		var payload []byte
		payload = append(payload, 255)
		payload = append(payload, msg...)
		if isBroadcast {
			s.Send(uint8(MsgTypeMPC), topicHash, payload, membersWithoutMe...)
			return
		}
		s.Send(uint8(MsgTypeMPC), topicHash, payload, membership.universalIDByPartyID(PartyID(to)))
	})

	return signer, nil
}

func (s *Scheme) setup() {
	s.syncsInProgress = make(map[string]func(uint16, []byte))
	s.rbcInProgress = make(map[string]func(m RBCMessage, from uint16))
	s.messageClassifiers = make(map[string]func([]byte) (uint8, bool, error))

	// Initialize thread safety wrappers for sync and RBC.
	// They're needed to ensure that each instance processes a message at a time.
	oldRBF := s.RBF
	s.RBF = func(broadcast BroadcastFunc, fwd ForwardFunc, n int) ReliableBroadcast {
		rbc := oldRBF(broadcast, fwd, n)
		return &threadSafeRBC{
			h: rbc.Receive,
		}
	}

	oldSyncFactory := s.SyncFactory
	s.SyncFactory = func(members []uint16, broadcast func(msg []byte), send func(msg []byte, to uint16)) Synchronizer {
		sync := oldSyncFactory(members, broadcast, send)
		return &threadSafeSync{
			Synchronizer: sync,
		}
	}
}

func LoudScheme(id uint16, l Logger, kgf KeyGenFactory, sf SignerFactory, threshold int, send func(msgType uint8, topic []byte, msg []byte, to ...uint16), membership func() map[UniversalID]PartyID) MpcParty {
	return &Scheme{
		Membership:    membership,
		Logger:        l,
		KeyGenFactory: kgf,
		SignerFactory: sf,
		Send: func(msgType uint8, topic []byte, msg []byte, to ...UniversalID) {
			destinations := make([]uint16, len(to))
			for i, dst := range to {
				destinations[i] = uint16(dst)
			}
			send(msgType, topic, msg, destinations...)
		},
		Threshold: threshold,
		SelfID:    UniversalID(id),
		RBF: func(bcast BroadcastFunc, fwd ForwardFunc, n int) ReliableBroadcast {
			r := &rbc.Receiver{
				SelfID: id,
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
				ID:         id,
				Broadcast:  broadcast,
				Send:       send,
			}
		},
	}
}

func SilentScheme(id uint16, l Logger, kgf KeyGenFactory, sf SignerFactory, threshold int, send func(msgType uint8, topic []byte, msg []byte, to ...uint16), membership func() map[UniversalID]PartyID, pickMembers func(topic []byte, expectedMemberCount int) []uint16) MpcParty {
	s := &Scheme{
		Membership:    membership,
		Logger:        l,
		KeyGenFactory: kgf,
		SignerFactory: sf,
		Send: func(msgType uint8, topic []byte, msg []byte, to ...UniversalID) {
			destinations := make([]uint16, len(to))
			for i, dst := range to {
				destinations[i] = uint16(dst)
			}
			send(msgType, topic, msg, destinations...)
		},
		Threshold: threshold,
		SelfID:    UniversalID(id),
		RBF: func(bcast BroadcastFunc, fwd ForwardFunc, n int) ReliableBroadcast {
			r := &rbc.Receiver{
				SelfID: id,
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
		SyncFactory: func(members []uint16, _ func(msg []byte), _ func(msg []byte, to uint16)) Synchronizer {
			return discovery.NewSilentSynchronizer(pickMembers, nil, nil, nil)
		},
	}

	originalSend := s.Send

	box := &msg.Box{
		Logger:                    s.Logger,
		MaxInFlightTopicsBySender: 10000,
		GCSweep:                   time.Second * 20,
		NewTicker: func(t time.Duration) *time.Ticker {
			return time.NewTicker(t)
		},
		ForwardSend:    originalSend,
		MessageHandler: s,
		GCExpire:       time.Minute * 2,
	}

	embedded := &embeddedBoxWithScheme{Scheme: s, Box: box}
	s.Send = embedded.Box.Send

	return embedded
}

type embeddedBoxWithScheme struct {
	*msg.Box
	*Scheme
}

func (ebs *embeddedBoxWithScheme) HandleMessage(msg *IncMessage) {
	ebs.Box.HandleMessage(msg)
}

type receiver struct {
	*rbc.Receiver
}

func (r *receiver) Receive(m RBCMessage, from uint16) {
	r.Receiver.Receive(m, from)
}

type threadSafeSync struct {
	lock sync.Mutex
	Synchronizer
}

func (s *threadSafeSync) HandleMessage(from uint16, msg []byte) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.Synchronizer.HandleMessage(from, msg)
}

type rbcFilter struct {
	h           func(m RBCMessage, from uint16)
	allowedList map[uint16]struct{}
	warn        func(format string, a ...interface{})
}

func (f *rbcFilter) Receive(m RBCMessage, from uint16) {
	_, exists := f.allowedList[from]
	if !exists {
		f.warn("Received a message from %d but we expect only to receive messages from: %v", from, f.allowedList)
		return
	}
	f.h(m, from)
}

type threadSafeRBC struct {
	lock sync.Mutex
	h    func(m RBCMessage, from uint16)
}

func (r *threadSafeRBC) Receive(m RBCMessage, from uint16) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.h(m, from)
}

func hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

type rbcMsg struct {
	round     uint8
	digest    []byte
	broadcast bool
	sender    uint16
	payload   []byte
}

func (r *rbcMsg) Round() uint8 {
	return r.round
}

func (r *rbcMsg) Digest() []byte {
	return r.digest
}

func (r *rbcMsg) WasBroadcast() bool {
	return r.broadcast
}

func (r *rbcMsg) Ack() (digest []byte, sender uint16, msgRound uint8) {
	if len(r.payload) > 0 {
		return nil, 0, 0
	}
	return r.digest, r.sender, r.round
}

type rbcEncoding []byte

func newRBCEncoding(digest string, sender uint16, msgRound uint8) rbcEncoding {
	if msgRound>>7 != 0 {
		panic("round must be in [0, 127]")
	}

	m := rbcEncoding{msgRound, byte(sender >> 8), byte(sender)}
	m = append(m, []byte(digest)...)
	return m
}

func (r rbcEncoding) Payload() []byte {
	return r[1:]
}

func (r rbcEncoding) Ack() (digest []byte, sender uint16, msgRound uint8, err error) {
	// In ack messages, the MSB of the first byte is 0
	if r[0]>>7 != 0 {
		return nil, 0, 0, nil
	}

	// If it's an ack, message needs to be at least 4 bytes of size
	if len(r) < 4 {
		return nil, 0, 0, fmt.Errorf("message %s is shorter than 4 bytes", hex.EncodeToString(r))
	}

	// RBCMessage round is the first byte, a uint7
	msgRound = r[0]
	// The next two bytes are the sender
	sender = uint16(r[1]<<8) + uint16(r[2])
	// The remaining bytes are the digest
	digest = r[3:]
	return
}

func universalIDsToUInts(in []UniversalID) []uint16 {
	res := make([]uint16, len(in))
	for i, n := range in {
		res[i] = uint16(n)
	}
	return res
}

func universalIDsToUintMap(in []UniversalID) map[uint16]struct{} {
	res := make(map[uint16]struct{})
	for _, n := range in {
		res[uint16(n)] = struct{}{}
	}
	return res
}

func partyIDsToUInts(in []PartyID) []uint16 {
	res := make([]uint16, len(in))
	for i, n := range in {
		res[i] = uint16(n)
	}
	return res
}

func UIntsToUniversalIDs(in []uint16) []UniversalID {
	res := make([]UniversalID, len(in))
	for i, n := range in {
		res[i] = UniversalID(n)
	}
	return res
}

func excludeUniversal(in []UniversalID, x UniversalID) []UniversalID {
	var res []UniversalID

	for _, n := range in {
		if x == n {
			continue
		}
		res = append(res, n)
	}

	return res
}

func sortPartyIdentifiers(in partyIdentifiers) {
	sort.Sort(in)
}

type partyIdentifiers []PartyID

func (x partyIdentifiers) Len() int           { return len(x) }
func (x partyIdentifiers) Less(i, j int) bool { return x[i] < x[j] }
func (x partyIdentifiers) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

func sortUniversalIdentifiers(in universalIdentifiers) {
	sort.Sort(in)
}

type universalIdentifiers []UniversalID

func (x universalIdentifiers) Len() int           { return len(x) }
func (x universalIdentifiers) Less(i, j int) bool { return x[i] < x[j] }
func (x universalIdentifiers) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
