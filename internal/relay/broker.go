package relay

import (
	"errors"
	"net"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/relayproto"
)

var ErrNoAgent = errors.New("no agent relay slot is available")
var ErrTooManySlots = errors.New("device has too many parked relay slots")
var ErrSlotNotReserved = errors.New("relay slot is not reserved")

type slotState uint8

const (
	slotReserved slotState = iota
	slotActive
	slotClaimed
	slotClosed
)

type slot struct {
	conn           net.Conn
	createdAt      time.Time
	done           chan struct{}
	finishOnce     sync.Once
	writeMu        sync.Mutex
	state          slotState
	watchStop      chan struct{}
	watchDone      chan struct{}
	watchOnce      sync.Once
	disconnected   chan struct{}
	disconnectOnce sync.Once
}

func (s *slot) finish() {
	s.finishOnce.Do(func() { close(s.done) })
}

func (s *slot) write(msg relayproto.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return relayproto.Write(s.conn, msg)
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

// Reserve accounts for capacity without making the connection claimable.
func (b *Broker) Reserve(deviceID string, conn net.Conn) (*slot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(deviceID)
	if len(b.slots[deviceID]) >= b.maxSlotsPerDevice {
		return nil, ErrTooManySlots
	}
	s := &slot{conn: conn, createdAt: time.Now(), done: make(chan struct{}), state: slotReserved, disconnected: make(chan struct{})}
	b.slots[deviceID] = append(b.slots[deviceID], s)
	return s, nil
}

// Activate publishes a reservation only after the registration acknowledgement succeeds.
func (b *Broker) Activate(deviceID string, target *slot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.slots[deviceID] {
		if s != target {
			continue
		}
		if s.state != slotReserved {
			return ErrSlotNotReserved
		}
		select {
		case <-s.disconnected:
			b.removeLocked(deviceID, s)
			return ErrNoAgent
		default:
		}
		if s.createdAt.Before(time.Now().Add(-b.slotTTL)) {
			b.removeLocked(deviceID, s)
			return ErrNoAgent
		}
		s.state = slotActive
		return nil
	}
	return ErrNoAgent
}

// Park retains the active-only semantics for callers that already completed registration.
func (b *Broker) Park(deviceID string, conn net.Conn) (*slot, error) {
	s, err := b.Reserve(deviceID, conn)
	if err != nil {
		return nil, err
	}
	if err := b.Activate(deviceID, s); err != nil {
		b.Remove(deviceID, s)
		return nil, err
	}
	return s, nil
}

func (b *Broker) Take(deviceID string) (*slot, error) {
	b.mu.Lock()
	b.pruneLocked(deviceID)
	for _, candidate := range append([]*slot(nil), b.slots[deviceID]...) {
		select {
		case <-candidate.disconnected:
			b.removeLocked(deviceID, candidate)
		default:
		}
	}
	q := b.slots[deviceID]
	for i, s := range q {
		if s.state != slotActive {
			continue
		}
		s.state = slotClaimed
		q = append(q[:i], q[i+1:]...)
		if len(q) == 0 {
			delete(b.slots, deviceID)
		} else {
			b.slots[deviceID] = q
		}
		b.mu.Unlock()
		s.stopDisconnectWatch()
		return s, nil
	}
	b.mu.Unlock()
	return nil, ErrNoAgent
}

func (b *Broker) WatchDisconnect(deviceID string, target *slot) {
	target.watchStop = make(chan struct{})
	target.watchDone = make(chan struct{})
	go func() {
		defer close(target.watchDone)
		var one [1]byte
		_, _ = target.conn.Read(one[:])
		select {
		case <-target.watchStop:
			return
		default:
			target.disconnectOnce.Do(func() { close(target.disconnected) })
			b.Remove(deviceID, target)
		}
	}()
}

func (s *slot) stopDisconnectWatch() {
	if s.watchStop == nil {
		return
	}
	s.watchOnce.Do(func() {
		close(s.watchStop)
		_ = s.conn.SetReadDeadline(time.Now())
		<-s.watchDone
		_ = s.conn.SetReadDeadline(time.Time{})
	})
}

func (b *Broker) Remove(deviceID string, target *slot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.slots[deviceID] {
		if s == target {
			b.removeLocked(deviceID, s)
			return
		}
	}
}

func (b *Broker) removeLocked(deviceID string, target *slot) {
	q := b.slots[deviceID]
	for i, s := range q {
		if s != target {
			continue
		}
		s.state = slotClosed
		q = append(q[:i], q[i+1:]...)
		if len(q) == 0 {
			delete(b.slots, deviceID)
		} else {
			b.slots[deviceID] = q
		}
		s.finish()
		_ = s.conn.Close()
		return
	}
}

func (b *Broker) pruneLocked(deviceID string) {
	q := b.slots[deviceID]
	if len(q) == 0 {
		return
	}
	cutoff := time.Now().Add(-b.slotTTL)
	for _, s := range append([]*slot(nil), q...) {
		if s.createdAt.Before(cutoff) {
			b.removeLocked(deviceID, s)
		}
	}
}
