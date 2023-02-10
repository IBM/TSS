/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package discovery

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	tag := tag(make([]byte, 32))
	membership := []uint16{1, 3, 5, 7, 11, 13}
	msgType, tag2, membership2, err := decodeTagAndMembershipList(encodeTagAndMembershipList(msgTypeMembership, tag, membership))
	assert.NoError(t, err)
	assert.Equal(t, tag, tag2)
	assert.Equal(t, membership, membership2)
	assert.Equal(t, msgTypeMembership, msgType)

	msgType, tag2, membership2, err = decodeTagAndMembershipList(encodeTagAndMembershipList(msgTypeQuery, tag, []uint16{1, 2, 3}))
	assert.NoError(t, err)
	assert.Equal(t, []uint16{1, 2, 3}, membership2)
	assert.Equal(t, tag, tag2)
	assert.Equal(t, msgTypeQuery, msgType)

	assert.Panics(t, func() {
		decodeTagAndMembershipList(encodeTagAndMembershipList(msgTypeMembership, tag[:30], nil))
	})

	_, _, _, err = decodeTagAndMembershipList([]byte{1, 2, 3})
	assert.EqualError(t, err, "message too small (3 bytes), should be 32 bytes")
}

func TestSort(t *testing.T) {
	s := intSlice{11, 3, 13, 1, 7, 5}
	sortIntSlice(s)
	assert.Equal(t, intSlice{1, 3, 5, 7, 11, 13}, s)
}

func TestSynchronize(t *testing.T) {
	t.Parallel()

	var members members
	var membership []uint16
	n := 13

	for i := 0; i < n; i++ {
		members = append(members, makeMember(uint16(i), t))
		membership = append(membership, uint16(i))
	}

	for i := 0; i < n; i++ {
		members[i].Membership = membership
		from := uint16(i)
		members[i].Broadcast = func(msg []byte) {
			for j := 0; j < n; j++ {
				if i == j {
					continue
				}
				members[j].HandleMessage(from, msg)
			}
		}

		members[i].Send = func(msg []byte, to uint16) {
			members[to].HandleMessage(from, msg)
		}
	}

	t.Run("first five", func(t *testing.T) {
		t.Parallel()

		f := func(result []uint16) {
			assert.Equal(t, []uint16{0, 1, 2, 3, 4}, result)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		err := members[:5].synchronize(f, []byte("first five"), 5, ctx)
		assert.NoError(t, err)
	})

	t.Run("last five", func(t *testing.T) {
		t.Parallel()

		f := func(result []uint16) {
			assert.Equal(t, []uint16{5, 6, 7, 8, 9, 10, 11, 12}, result)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		err := members[5:].synchronize(f, []byte("all but first five"), n-5, ctx)
		assert.NoError(t, err)
	})

	t.Run("everyone", func(t *testing.T) {
		t.Parallel()

		f := func(result []uint16) {
			assert.Equal(t, []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, result)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		err := members.synchronize(f, []byte("everyone"), n, ctx)
		assert.NoError(t, err)
	})

	t.Run("too much parties than expected", func(t *testing.T) {
		t.Skipf("flaky test :(")
		t.Parallel()

		f := func(result []uint16) {
			assert.Fail(t, "should not have been invoked")
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		err := members.synchronize(f, []byte("too much"), n/2, ctx)
		assert.EqualError(t, err, "too many members (13) for topic 746f6f206d756368, expected only 6")
	})

	t.Run("too few parties than expected", func(t *testing.T) {
		t.Parallel()

		f := func(result []uint16) {
			assert.Fail(t, "should not have been invoked")
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		err := members[2:].synchronize(f, []byte("too few"), n, ctx)
		assert.EqualError(t, err, "only 11 out of 13 parties synchronized")
	})
}

type members []*Member

func (ms members) synchronize(f func([]uint16), topicToSynchronizeOn []byte, expectedPeerCount int, ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(len(ms))

	atomicErr := &atomic.Value{}

	for _, m := range ms {
		go func(m *Member) {
			defer wg.Done()
			err := m.Synchronize(ctx, f, topicToSynchronizeOn, expectedPeerCount, time.Millisecond*100)
			if err != nil {
				atomicErr.Store(err)
			}
		}(m)
	}

	wg.Wait()

	if atomicErr.Load() == nil {
		return nil
	}

	return atomicErr.Load().(error)
}

func makeMember(id uint16, t *testing.T) *Member {
	return &Member{
		Logger: logger(id, t.Name()),
		ID:     id,
	}
}

func logger(id uint16, testName string) Logger {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	logger = logger.With(zap.String("t", testName)).With(zap.String("id", fmt.Sprintf("%d", id)))
	return logger.Sugar()
}
