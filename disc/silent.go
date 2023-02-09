package discovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

func NewSilentSynchronizer(pickmembers func(topic []byte, expectedMemberCount int) []uint16, _ []uint16, _ func(msg []byte), _ func(msg []byte, to uint16)) *SilentSynchronizer {
	return &SilentSynchronizer{PickMembers: pickmembers}
}

type SilentSynchronizer struct {
	PickMembers             func(topic []byte, expectedMemberCount int) []uint16
	startedSynchronizations sync.Map
}

func (s *SilentSynchronizer) Synchronize(_ context.Context, f func([]uint16), topicToSynchronizeOn []byte, expectedMemberCount int, _ time.Duration) error {
	var found bool
	var members []uint16
	s.startedSynchronizations.Range(func(key, value interface{}) bool {
		if bytes.Equal(hash([]byte(key.(string))), topicToSynchronizeOn) {
			s.startedSynchronizations.Delete(key)
			found = true
			members = value.([]uint16)
			return false
		}
		return true
	})

	if found {
		f(members)
		return nil
	}

	pickedMembers := s.PickMembers(topicToSynchronizeOn, expectedMemberCount)
	s.startedSynchronizations.Store(string(topicToSynchronizeOn), pickedMembers)
	f(pickedMembers)
	return nil
}

func (s *SilentSynchronizer) HandleMessage(_ uint16, _ []byte) {
}

func hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

type RandFromHash struct {
	i    uint64
	Hash []byte
}

func (r RandFromHash) Int63() int64 {
	i := atomic.AddUint64(&r.i, 1)
	buff := make([]byte, 8)
	binary.BigEndian.PutUint64(buff, i)

	prf := hmac.New(sha256.New, r.Hash)
	prf.Write(buff)
	digest := prf.Sum(nil)

	n := int64(binary.BigEndian.Uint64(digest[:8]))

	if n < 0 {
		n *= -1
	}

	return n
}

func (r RandFromHash) Seed(seed int64) {
	panic("should not be ever called")
}
