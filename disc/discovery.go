/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package discovery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Broadcast func(msg []byte)

type Send func(msg []byte, to uint16)

type Logger interface {
	Debugf(format string, a ...interface{})
	Warnf(format string, a ...interface{})
}

type uint16PRF func(uint16) []byte

type msgType uint8

const (
	msgTypeNone msgType = iota
	msgTypeMembership
	msgTypeQuery
	msgTypeResponse
)

func makePRF(key []byte) uint16PRF {
	h := hmac.New(sha256.New, key)

	return func(x uint16) []byte {
		defer h.Reset()
		h.Write([]byte{byte(x), byte(x >> 8)})
		return h.Sum(nil)
	}
}

type topicPeerView struct {
	receivedMsg       chan struct{}
	memberToView      *sync.Map // (id uint16) --> (ids []uint16)
	responsesReceived *sync.Map // uint16 --> struct{}
	responses         chan []uint16
}

type Membership []uint16

type topicAndID struct {
	topic topic
	id    uint16
}

type (
	topic string
	tag   string
)

type Member struct {
	// State
	tagsToIDsAndTopics  sync.Map // tag --> topicAndID
	topicsToMemberViews sync.Map // topic --> *topicPeerView
	// Config
	Membership Membership
	Broadcast  Broadcast
	Send       Send
	Logger     Logger
	ID         uint16
}

// Synchronize agrees on a common ordered set of identifiers, passing them to f().
// The identifiers agreed upon correspond to all members that invoked Synchronize() with the given topic name.
// In order for this method to run securely, the topic name must be sampled from a high entropy distribution.
// The given probeInterval specifies how frequent we send out a synchronization message.
// The lower the probeInterval the lower the latency, but a higher amount of messages sent.
// Returns error if the deadline of the context expires, or if too many members were agreed upon.
func (m *Member) Synchronize(ctx context.Context, f func([]uint16), topicToSynchronizeOn []byte, expectedMemberCount int, probeInterval time.Duration) error {
	topic := topic(topicToSynchronizeOn)
	topicHex := hex.EncodeToString(topicToSynchronizeOn)

	m.Logger.Debugf("Synchronizing on topic %s, expecting %d members including ourselves", topicHex[:8], expectedMemberCount)

	tpv, err := m.registerInterestInTopic(topic)
	if err != nil {
		return err
	}

	m.precomputeTagsForTopic(topic, topicHex)

	myTag := m.computeMyTag(topic)
	myTagHex := hex.EncodeToString([]byte(myTag))
	m.Logger.Debugf("Our tag for topic %s is: %s", topicHex[:8], myTagHex[:8])

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	var members []uint16

	for {
		members = m.intersectedView(topic, topicHex[:8], tpv)
		if len(members) >= expectedMemberCount {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("only %d out of %d parties synchronized", len(members), expectedMemberCount)
		case <-ticker.C:
			myView := m.myMemberViewSorted(topic)
			m.Logger.Debugf("Broadcasting my tag (%s) for %s and current view: %v", myTagHex[:8], topicHex[:8], myView)
			msgToBroadcast := encodeTagAndMembershipList(msgTypeMembership, myTag, myView)
			m.Broadcast(msgToBroadcast)
		case <-tpv.receivedMsg:
		}
	}

	if len(members) > expectedMemberCount {
		return fmt.Errorf("too many members (%d) for topic %s, expected only %d", len(members), topicHex, expectedMemberCount)
	}

	sortIntSlice(members)

	m.Logger.Debugf("Learned about %v for topic %s", members, topicHex[:8])

	msgToBroadcast := encodeTagAndMembershipList(msgTypeQuery, myTag, members)
	m.Broadcast(msgToBroadcast)

	myView := fmt.Sprintf("%v", members)

	acknowledgementsLeft := expectedMemberCount - 1

	for acknowledgementsLeft > 0 {
		select {
		case peers := <-tpv.responses:
			if myView != fmt.Sprintf("%v", peers) {
				continue
			}
			acknowledgementsLeft--
		case <-ctx.Done():
			return fmt.Errorf("haven't received %d out of %d acknowledgements", acknowledgementsLeft, expectedMemberCount-1)
		}
	}

	m.Logger.Debugf("Synchronized on topic %s with members %v", topicHex[:8], members)

	f(members)

	return nil
}

type view struct {
	size    int
	content string
}

type views map[view]struct{}

func (vs views) String() string {
	s := make([]string, 0, len(vs))
	for v := range vs {
		s = append(s, v.content)
	}
	return fmt.Sprintf("%s", s)
}

func (m *Member) intersectedView(topic topic, topicHex string, tpv *topicPeerView) []uint16 {
	var members []uint16

	views := make(views)

	memberToView := tpv.memberToView
	memberToView.Range(func(_, v interface{}) bool {
		members = v.([]uint16)
		views[view{
			content: fmt.Sprintf("%v", members),
			size:    len(members),
		}] = struct{}{}
		return true
	})

	myView := m.myMemberViewSorted(topic)
	views[view{
		size:    len(myView),
		content: fmt.Sprintf("%v", myView),
	}] = struct{}{}

	if len(views) != 1 {
		m.Logger.Debugf("Disjoint views for topic %s: %v", topicHex[:8], views)
		return nil
	}

	return members
}

func (m *Member) myMemberViewSorted(topic topic) intSlice {
	v, exists := m.topicsToMemberViews.Load(topic)
	if !exists {
		return nil
	}

	res := intSlice{m.ID}

	v.(*topicPeerView).memberToView.Range(func(key, _ interface{}) bool {
		res = append(res, key.(uint16))
		return true
	})

	sortIntSlice(res)

	return res
}

func (m *Member) registerInterestInTopic(topic topic) (*topicPeerView, error) {
	tpv := &topicPeerView{
		receivedMsg:       make(chan struct{}, 1),
		memberToView:      &sync.Map{},
		responses:         make(chan []uint16, len(m.Membership)-1),
		responsesReceived: &sync.Map{},
	}
	_, loaded := m.topicsToMemberViews.LoadOrStore(topic, tpv)

	if loaded {
		topicHex := hex.EncodeToString([]byte(topic))
		return nil, fmt.Errorf("already synchronizing on topic %s", topicHex)
	}

	return tpv, nil
}

func (m *Member) precomputeTagsForTopic(topic topic, topicHex string) {
	PRF := makePRF([]byte(topic))
	for _, id := range m.Membership {
		if id == m.ID {
			continue
		}

		tag := tag(PRF(id))

		m.Logger.Debugf("%s[%d] ==> %s", topicHex[:8], id, hex.EncodeToString([]byte(tag[:8])))

		m.tagsToIDsAndTopics.Store(tag, topicAndID{
			topic: topic,
			id:    id,
		})
	}
}

func (m *Member) computeMyTag(topic topic) tag {
	return tag(makePRF([]byte(topic))(m.ID))
}

func (m *Member) HandleMessage(from uint16, msg []byte) {
	msgType, tag, peers, err := decodeTagAndMembershipList(msg)
	if err != nil {
		m.Logger.Warnf("Failed decoding message (%s) from %d: %v", hex.EncodeToString(msg), from)
	}

	v, exists := m.tagsToIDsAndTopics.Load(tag)
	if !exists {
		return
	}

	topicAndID := v.(topicAndID)
	if topicAndID.id != from {
		m.Logger.Debugf("Got topic associated to %d from %d", topicAndID.id, from)
		return
	}

	tpv, exists := m.topicsToMemberViews.Load(topicAndID.topic)
	if !exists {
		return
	}

	switch msgType {
	case msgTypeMembership:
		m.handleMembershipMessage(from, tpv, peers)
	case msgTypeQuery:
		m.handleMembershipMessage(from, tpv, peers)
		m.respondToQuery(from, topicAndID)
	case msgTypeResponse:
		m.handleResponse(from, peers, tpv)
	default:
		panic(fmt.Sprintf("programming error: msgType %d is not supported but passed decoding", msgType))
	}
}

func (m *Member) handleResponse(from uint16, peers []uint16, tpv interface{}) {
	topicPeerView := tpv.(*topicPeerView)
	_, existed := topicPeerView.responsesReceived.LoadOrStore(from, struct{}{})
	if !existed {
		topicPeerView.responses <- peers
	}
}

func (m *Member) handleMembershipMessage(from uint16, tpv interface{}, peers []uint16) {
	topicPeerView := tpv.(*topicPeerView)
	topicPeerView.memberToView.Store(from, peers)

	select {
	case topicPeerView.receivedMsg <- struct{}{}:
	default:
	}
}

func (m *Member) respondToQuery(from uint16, topicAndID topicAndID) {
	myTag := m.computeMyTag(topicAndID.topic)
	myView := m.myMemberViewSorted(topicAndID.topic)
	reply := encodeTagAndMembershipList(msgTypeResponse, myTag, myView)
	m.Send(reply, from)
}

func encodeTagAndMembershipList(msgType msgType, tag tag, peers []uint16) []byte {
	if len(tag) != 32 {
		panic("tag should be 32 bytes")
	}

	if msgType < msgTypeMembership || msgType > msgTypeResponse {
		panic(fmt.Sprintf("invalid msgType: %d", msgType))
	}

	size := 32 + len(peers)*2 + 1
	buff := make([]byte, size)
	buff[0] = uint8(msgType)
	copy(buff[1:], tag)
	offset := 33
	for _, p := range peers {
		buff[offset] = byte(p)
		buff[offset+1] = byte(p >> 8)
		offset += 2
	}

	return buff
}

func decodeTagAndMembershipList(msg []byte) (msgType, tag, []uint16, error) {
	if len(msg) < 32 {
		return 0, "", nil, fmt.Errorf("message too small (%d bytes), should be 32 bytes", len(msg))
	}

	msgType := msgType(msg[0])
	if msgType < msgTypeMembership || msgType > msgTypeResponse {
		return 0, "", nil, fmt.Errorf("invalid message type: %d", msgType)
	}

	var peers []uint16

	offset := 33
	for offset < len(msg) {
		p := uint16(msg[offset+1]<<8) + uint16(msg[offset])
		peers = append(peers, p)
		offset += 2
	}

	return msgType, tag(msg[1:33]), peers, nil
}

func sortIntSlice(in intSlice) {
	sort.Sort(in)
}

type intSlice []uint16

func (x intSlice) Len() int           { return len(x) }
func (x intSlice) Less(i, j int) bool { return x[i] < x[j] }
func (x intSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
