package msg

import (
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/IBM/TSS/types"
)

const (
	limitPerSender = 100
)

type storedMessages struct {
	logger                Logger
	lock                  sync.RWMutex
	lastUsed              time.Time
	messages              []*IncMessage
	messageCountPerSender map[uint16]int
}

type MessageHandler interface {
	HandleMessage(msg *IncMessage)
}

func (sm *storedMessages) add(msg *IncMessage) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if sm.messageCountPerSender[msg.Source] > limitPerSender {
		sm.logger.Warnf("Received too many messages from %d (limit is %d) for topic %s",
			msg.Source, limitPerSender, hex.EncodeToString(msg.Topic[:8]))
		return
	}

	sm.messageCountPerSender[msg.Source]++

	sm.messages = append(sm.messages, msg)
	now := time.Now()

	if now.After(sm.lastUsed) {
		sm.lastUsed = now
	}
}

func (sm *storedMessages) senders() []uint16 {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	var res []uint16
	for sender := range sm.messageCountPerSender {
		res = append(res, sender)
	}
	return res
}

type Box struct {
	// State
	stopClock                   func()
	currentGCEpochNum           uint64
	lastGC                      uint64
	init                        sync.Once
	lock                        sync.RWMutex
	pendingMessages             map[string]*storedMessages
	startedSending              map[string]uint64
	totalInFlightTopicsBySender map[uint16]map[string]struct{}
	//Config
	MessageHandler
	NewTicker                 func(time.Duration) *time.Ticker
	GCExpire                  time.Duration
	GCSweep                   time.Duration
	Logger                    Logger
	ForwardSend               SendFunc
	MaxInFlightTopicsBySender int
}

func (b *Box) startClock() {
	if b.GCExpire/b.GCSweep < 2 {
		panic(fmt.Sprintf("GC GCExpire (%v) must be at least twice than GC GCSweep (%v)", b.GCExpire, b.GCSweep))
	}

	stopChan := make(chan struct{})

	ticker := b.NewTicker(b.GCSweep)
	b.stopClock = func() {
		ticker.Stop()
		close(stopChan)
	}

	go func() {
		for {
			select {
			case <-ticker.C:
				atomic.AddUint64(&b.currentGCEpochNum, 1)
			case <-stopChan:
				return
			}
		}
	}()

}

func (b *Box) Stop() {
	b.stopClock()
}

func (b *Box) HandleMessage(msg *IncMessage) {
	switch msg.MsgType {
	case uint8(MsgTypeMPC):
		b.storeOrForward(msg)
		return
	default:
		b.Logger.Warnf("received message of unknown type: %d", msg.MsgType)
	}
}

func (b *Box) getOrCreateMessagesByTopic(topic []byte) *storedMessages {
	b.initialize()

	b.lock.RLock()
	messages, exists := b.pendingMessages[string(topic)]
	b.lock.RUnlock()

	if exists {
		return messages
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	messages, exists = b.pendingMessages[string(topic)]
	if !exists {
		messages = &storedMessages{messageCountPerSender: make(map[uint16]int)}
	}

	b.pendingMessages[string(topic)] = messages
	return messages
}

func (b *Box) storeOrForward(msg *IncMessage) {
	b.initialize()

	if b.hasStartedSending(msg.Topic) {
		b.MessageHandler.HandleMessage(msg)
		return
	}

	var tooManyTopicsFromSender bool

	b.lock.RLock()
	if activeTopicsFromSource, exists := b.totalInFlightTopicsBySender[msg.Source]; exists {
		tooManyTopicsFromSender = len(activeTopicsFromSource) > b.MaxInFlightTopicsBySender
	}
	b.lock.RUnlock()

	if tooManyTopicsFromSender {
		b.Logger.Warnf("Received too many topics from %d (limit is %d)", msg.Source, b.MaxInFlightTopicsBySender)
		return
	}

	b.markTopicForSender(msg)

	messages := b.getOrCreateMessagesByTopic(msg.Topic)
	messages.add(msg)
}

func (b *Box) markTopicForSender(msg *IncMessage) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if _, exists := b.totalInFlightTopicsBySender[msg.Source]; !exists {
		b.totalInFlightTopicsBySender[msg.Source] = make(map[string]struct{})
	}
	b.totalInFlightTopicsBySender[msg.Source][string(msg.Topic)] = struct{}{}
}

func (b *Box) initialize() {
	b.init.Do(func() {
		b.pendingMessages = make(map[string]*storedMessages)
		b.startedSending = make(map[string]uint64)
		b.totalInFlightTopicsBySender = make(map[uint16]map[string]struct{})
		b.startClock()
	})
}

func (b *Box) hasStartedSending(topic []byte) bool {
	b.initialize()

	b.lock.RLock()
	defer b.lock.RUnlock()

	_, exists := b.startedSending[string(topic)]

	return exists
}

func (b *Box) maybeGC() {
	b.initialize()

	lastGC := atomic.LoadUint64(&b.lastGC)
	now := atomic.LoadUint64(&b.currentGCEpochNum)

	epochsAfterWhichWeGC := b.GCExpire / b.GCSweep

	if time.Duration(now-lastGC) > epochsAfterWhichWeGC {
		return
	}

	if !atomic.CompareAndSwapUint64(&b.lastGC, lastGC, now) {
		return
	}

	defer atomic.StoreUint64(&b.lastGC, now)

	topics2Delete := b.mark(now, epochsAfterWhichWeGC)
	b.sweep(topics2Delete)
}

func (b *Box) sweep(topics2Delete []string) {
	b.lock.Lock()
	defer b.lock.Unlock()

	for _, topic := range topics2Delete {
		messages, exists := b.pendingMessages[topic]
		if exists {
			for _, sender := range messages.senders() {
				delete(b.totalInFlightTopicsBySender[sender], topic)
			}
		}
		delete(b.pendingMessages, topic)
		delete(b.startedSending, topic)

	}
}

func (b *Box) mark(now uint64, epochsAfterWhichWeGC time.Duration) []string {
	var topics2Delete []string

	b.lock.RLock()
	defer b.lock.RUnlock()

	for topic, messages := range b.pendingMessages {
		if float64(messages.lastUsed.Unix())+b.GCExpire.Seconds() < float64(now) {
			topics2Delete = append(topics2Delete, topic)
		}
	}

	for topic, lastSent := range b.startedSending {
		if time.Duration(now-lastSent) > epochsAfterWhichWeGC {
			topics2Delete = append(topics2Delete, topic)
		}
	}

	return topics2Delete
}

func (b *Box) Send(msgType uint8, topic []byte, msg []byte, to ...UniversalID) {
	b.initialize()

	defer b.maybeGC()

	b.lock.Lock()
	b.startedSending[string(topic)] = atomic.LoadUint64(&b.currentGCEpochNum)
	msgs := b.pendingMessages[string(topic)]
	var messages []*IncMessage
	if msgs != nil {
		msgs.lock.RLock()
		messages = msgs.messages
		msgs.lock.RUnlock()
	}

	defer func() {
		for _, msg := range messages {
			b.HandleMessage(msg)
		}
	}()

	delete(b.pendingMessages, string(topic))

	b.lock.Unlock()

	b.ForwardSend(msgType, topic, msg, to...)
}
