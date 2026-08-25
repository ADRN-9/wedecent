package relay

import (
	"errors"
	"net"
	"sync"
	"time"
)

var ErrNoAgent = errors.New("no agent relay slot is available")
var ErrTooManySlots = errors.New("device has too many parked relay slots")

type slot struct {
	conn       net.Conn
	createdAt  time.Time
	done       chan struct{}
	finishOnce sync.Once
}

func (s *slot) finish() {
	s.finishOnce.Do(func() { close(s.done) })
}

type Broker struct {
	mu                sync.Mutex
	slots             map[string][]*slot
	maxSlotsPerDevice int
	slotTTL           time.Duration
}

func NewBroker(maxSlotsPerDevice int, slotTTL time.Duration) *Broker {
	if maxSlotsPerDevice < 1 {
		maxSlotsPerDevice = 8
	}
	if slotTTL <= 0 {
		slotTTL = 5 * time.Minute
	}
	return &Broker{slots: make(map[string][]*slot), maxSlotsPerDevice: maxSlotsPerDevice, slotTTL: slotTTL}
}

func (b *Broker) Park(deviceID string, conn net.Conn) (*slot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(deviceID)
	if len(b.slots[deviceID]) >= b.maxSlotsPerDevice {
		return nil, ErrTooManySlots
	}
	s := &slot{conn: conn, createdAt: time.Now(), done: make(chan struct{})}
	b.slots[deviceID] = append(b.slots[deviceID], s)
	return s, nil
}

func (b *Broker) Take(deviceID string) (*slot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(deviceID)
	q := b.slots[deviceID]
	if len(q) == 0 {
		return nil, ErrNoAgent
	}
	s := q[0]
	if len(q) == 1 {
		delete(b.slots, deviceID)
	} else {
		b.slots[deviceID] = q[1:]
	}
	return s, nil
}

func (b *Broker) Remove(deviceID string, target *slot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.slots[deviceID]
	for i, s := range q {
		if s == target {
			q = append(q[:i], q[i+1:]...)
			if len(q) == 0 {
				delete(b.slots, deviceID)
			} else {
				b.slots[deviceID] = q
			}
			return
		}
	}
}

func (b *Broker) pruneLocked(deviceID string) {
	q := b.slots[deviceID]
	if len(q) == 0 {
		return
	}
	cutoff := time.Now().Add(-b.slotTTL)
	keep := q[:0]
	for _, s := range q {
		if s.createdAt.Before(cutoff) {
			_ = s.conn.Close()
			s.finish()
			continue
		}
		keep = append(keep, s)
	}
	if len(keep) == 0 {
		delete(b.slots, deviceID)
	} else {
		b.slots[deviceID] = keep
	}
}
