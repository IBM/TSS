package discovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"sync"
	"time"
)

func NewSynchronizer(members []uint16, _ func(msg []byte), _ func(msg []byte, to uint16)) *SilentSynchronizer {
	return &SilentSynchronizer{members: members}
}

type SilentSynchronizer struct {
	members                 []uint16
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

	pickedMembers := randMembers(s.members, topicToSynchronizeOn, expectedMemberCount)
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

type randFromHash struct {
	i    int
	hash []byte
}

func (r randFromHash) Int63() int64 {
	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, uint16(r.i))

	prf := hmac.New(sha256.New, r.hash)
	prf.Write(buff)
	digest := prf.Sum(nil)

	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func (r randFromHash) Seed(seed int64) {
	panic("should not be ever called")
}

func randMembers(members []uint16, topic []byte, requiredSize int) []uint16 {
	r := rand.New(&randFromHash{
		hash: topic,
	})

	res := make([]uint16, requiredSize)
	for i, index := range r.Perm(len(members)) {
		res[i] = members[index]
	}

	return res
}
