package relay

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/relayproto"
)

func TestBrokerReservationIsNotClaimableUntilActivated(t *testing.T) {
	broker := NewBroker(2, time.Minute)
	server, client := net.Pipe()
	defer client.Close()
	reserved, err := broker.Reserve("device", server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Take("device"); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("Take before activation = %v, want ErrNoAgent", err)
	}
	if err := broker.Activate("device", reserved); err != nil {
		t.Fatal(err)
	}
	claimed, err := broker.Take("device")
	if err != nil || claimed != reserved {
		t.Fatalf("Take after activation = (%p, %v), want (%p, nil)", claimed, err, reserved)
	}
	if _, err := broker.Take("device"); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("duplicate Take = %v, want ErrNoAgent", err)
	}
	claimed.finish()
	_ = claimed.conn.Close()
}

func TestBrokerConcurrentTakeClaimsSlotExactlyOnce(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	server, client := net.Pipe()
	defer client.Close()
	slot, err := broker.Reserve("device", server)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Activate("device", slot); err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	claims := 0
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			if claimed, err := broker.Take("device"); err == nil {
				claimed.finish()
				_ = claimed.conn.Close()
				mu.Lock()
				claims++
				mu.Unlock()
			} else if !errors.Is(err, ErrNoAgent) {
				t.Errorf("unexpected Take error: %v", err)
			}
		}()
	}
	wg.Wait()
	if claims != 1 {
		t.Fatalf("successful claims = %d, want 1", claims)
	}
	slot.finish()
}

func TestBrokerExpirationRemovesReservationAndClosesConnection(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	server, client := net.Pipe()
	defer client.Close()
	slot, err := broker.Reserve("device", server)
	if err != nil {
		t.Fatal(err)
	}
	broker.mu.Lock()
	slot.createdAt = time.Now().Add(-2 * time.Minute)
	broker.mu.Unlock()
	if _, err := broker.Take("device"); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("Take expired reservation = %v, want ErrNoAgent", err)
	}
	if _, err := client.Write([]byte("probe")); err == nil {
		t.Fatal("expired reservation left the peer connection open")
	}
	select {
	case <-slot.done:
	default:
		t.Fatal("expired reservation did not signal completion")
	}
}

func TestBrokerRemoveReservedSlotSignalsAndCloses(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	server, client := net.Pipe()
	defer client.Close()
	slot, err := broker.Reserve("device", server)
	if err != nil {
		t.Fatal(err)
	}
	broker.Remove("device", slot)
	if _, err := broker.Take("device"); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("Take removed reservation = %v, want ErrNoAgent", err)
	}
	select {
	case <-slot.done:
	default:
		t.Fatal("removed reservation did not signal completion")
	}
	if _, err := client.Write([]byte("probe")); err == nil {
		t.Fatal("removed reservation left peer connection open")
	}
}

func TestBrokerConcurrentParkAndTake(t *testing.T) {
	broker := NewBroker(32, time.Minute)
	const workers = 32
	peers := make([]net.Conn, workers)
	var parkWG sync.WaitGroup
	startPark := make(chan struct{})
	parkWG.Add(workers)
	for i := range workers {
		go func(i int) {
			defer parkWG.Done()
			<-startPark
			server, client := net.Pipe()
			peers[i] = client
			slot, err := broker.Reserve("device", server)
			if err != nil {
				t.Errorf("Reserve: %v", err)
				_ = client.Close()
				return
			}
			if err := broker.Activate("device", slot); err != nil {
				t.Errorf("Activate: %v", err)
				_ = client.Close()
			}
		}(i)
	}
	close(startPark)
	parkWG.Wait()

	var takeWG sync.WaitGroup
	var mu sync.Mutex
	claims := 0
	startTake := make(chan struct{})
	takeWG.Add(workers)
	for range workers {
		go func() {
			defer takeWG.Done()
			<-startTake
			if claimed, err := broker.Take("device"); err == nil {
				claimed.finish()
				_ = claimed.conn.Close()
				mu.Lock()
				claims++
				mu.Unlock()
			} else {
				t.Errorf("Take after concurrent Park = %v", err)
			}
		}()
	}
	close(startTake)
	takeWG.Wait()
	if claims != workers {
		t.Fatalf("successful claims = %d, want %d", claims, workers)
	}
	for _, peer := range peers {
		if peer != nil {
			_ = peer.Close()
		}
	}
}

func TestBrokerDisconnectBeforeActivationCannotPublishReservation(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	server, client := net.Pipe()
	slot, err := broker.Reserve("device", server)
	if err != nil {
		t.Fatal(err)
	}
	broker.WatchDisconnect("device", slot)
	_ = client.Close()
	select {
	case <-slot.disconnected:
	case <-time.After(time.Second):
		t.Fatal("disconnect watcher did not publish disconnect state")
	}
	if err := broker.Activate("device", slot); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("Activate disconnected reservation = %v, want ErrNoAgent", err)
	}
	if _, err := broker.Take("device"); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("Take disconnected reservation = %v, want ErrNoAgent", err)
	}
	select {
	case <-slot.done:
	default:
		t.Fatal("disconnected reservation was not finished")
	}
}

type concurrentWriteConn struct {
	net.Conn
	active  atomic.Int32
	maximum atomic.Int32
}

func (c *concurrentWriteConn) Write(p []byte) (int, error) {
	active := c.active.Add(1)
	for {
		maximum := c.maximum.Load()
		if active <= maximum || c.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	n, err := c.Conn.Write(p)
	c.active.Add(-1)
	return n, err
}

func TestSlotSerializesCompleteProtocolWrites(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	conn := &concurrentWriteConn{Conn: server}
	slot := &slot{conn: conn, done: make(chan struct{})}
	const writers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	errors := make(chan error, writers)
	wg.Add(writers)
	for i := range writers {
		go func(i int) {
			defer wg.Done()
			<-start
			errors <- slot.write(relayproto.Message{Type: "test", Code: strconv.Itoa(i)})
		}(i)
	}
	received := make(chan error, 1)
	go func() {
		seen := make(map[string]bool, writers)
		for range writers {
			msg, err := relayproto.Read(client)
			if err != nil {
				received <- err
				return
			}
			if seen[msg.Code] {
				received <- fmt.Errorf("duplicate protocol message %q", msg.Code)
				return
			}
			seen[msg.Code] = true
		}
		received <- nil
	}()
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("serialized write failed: %v", err)
		}
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	if maximum := conn.maximum.Load(); maximum != 1 {
		t.Fatalf("maximum concurrent connection writes = %d, want 1", maximum)
	}
}


type gatedReadConn struct {
	net.Conn
	entered       chan struct{}
	release       chan struct{}
	deadlineSet   chan struct{}
	deadlineOnce  sync.Once
	readOnce      sync.Once
}

func (c *gatedReadConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.entered) })
	<-c.release
	p[0] = 'x'
	return 1, nil
}

func (c *gatedReadConn) SetReadDeadline(time.Time) error {
	c.deadlineOnce.Do(func() { close(c.deadlineSet) })
	return nil
}

func TestDisconnectWatcherRejectsBytesRacingWithHandoff(t *testing.T) {
	server, peer := net.Pipe()
	defer peer.Close()
	conn := &gatedReadConn{
		Conn: server, entered: make(chan struct{}), release: make(chan struct{}),
		deadlineSet: make(chan struct{}),
	}
	broker := NewBroker(1, time.Minute)
	slot, err := broker.Reserve("device", conn)
	if err != nil {
		t.Fatal(err)
	}
	broker.WatchDisconnect("device", slot)
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("disconnect watcher did not enter Read")
	}
	stopped := make(chan bool, 1)
	go func() { stopped <- slot.stopDisconnectWatch() }()
	select {
	case <-conn.deadlineSet:
	case <-time.After(time.Second):
		t.Fatal("handoff did not interrupt watcher read")
	}
	close(conn.release)
	select {
	case violation := <-stopped:
		if !violation {
			t.Fatal("handoff accepted a byte consumed by the disconnect watcher")
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect watcher did not terminate")
	}
}

func TestDisconnectImmediatelyBeforeActivationIsRejected(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	server, peer := net.Pipe()
	slot, err := broker.Reserve("device", server)
	if err != nil {
		t.Fatal(err)
	}
	broker.WatchDisconnect("device", slot)
	_ = peer.Close()
	select {
	case <-slot.done:
	case <-time.After(time.Second):
		t.Fatal("disconnect before activation did not remove reservation")
	}
	if err := broker.Activate("device", slot); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("activation after disconnect = %v, want ErrNoAgent", err)
	}
	if _, err := broker.Take("device"); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("claim after disconnect = %v, want ErrNoAgent", err)
	}
}

func TestDisconnectImmediatelyAfterActivationIsRejected(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	server, peer := net.Pipe()
	slot, err := broker.Reserve("device", server)
	if err != nil {
		t.Fatal(err)
	}
	broker.WatchDisconnect("device", slot)
	select {
	case <-slot.watchDone:
		t.Fatal("watcher exited before disconnect")
	default:
	}
	if err := broker.Activate("device", slot); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	select {
	case <-slot.done:
	case <-time.After(time.Second):
		t.Fatal("disconnect after activation did not remove slot")
	}
	if _, err := broker.Take("device"); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("claim after activated disconnect = %v, want ErrNoAgent", err)
	}
}


func TestBrokerConcurrentRegistrationConnectionAndReconnection(t *testing.T) {
	const workers = 16
	const rounds = 12
	broker := NewBroker(workers, time.Minute)
	for round := 0; round < rounds; round++ {
		start := make(chan struct{})
		var registered sync.WaitGroup
		registered.Add(workers)
		for range workers {
			go func() {
				defer registered.Done()
				<-start
				server, peer := net.Pipe()
				slot, err := broker.Reserve("shared-device", server)
				if err != nil {
					t.Errorf("reserve round %d: %v", round, err)
					_ = peer.Close()
					return
				}
				broker.WatchDisconnect("shared-device", slot)
				if err := broker.Activate("shared-device", slot); err != nil {
					t.Errorf("activate round %d: %v", round, err)
					broker.Remove("shared-device", slot)
					_ = peer.Close()
					return
				}
				// The peer remains open until a concurrent Take stops its watcher.
				peersMu.Lock()
				peers[server] = peer
				peersMu.Unlock()
			}()
		}
		close(start)
		registered.Wait()

		startClaims := make(chan struct{})
		var claimed sync.WaitGroup
		claimed.Add(workers)
		for range workers {
			go func() {
				defer claimed.Done()
				<-startClaims
				slot, err := broker.Take("shared-device")
				if err != nil {
					t.Errorf("take round %d: %v", round, err)
					return
				}
				peer := peersForSlot(slot)
				if peer == nil {
					t.Errorf("round %d: claimed slot has no peer", round)
					broker.Remove("shared-device", slot)
					_ = slot.conn.Close()
					return
				}
				readDone := make(chan error, 1)
				go func() {
					msg, err := relayproto.Read(peer)
					if err == nil && msg.Type != relayproto.TypeReady {
						err = fmt.Errorf("unexpected ready message %q", msg.Type)
					}
					readDone <- err
				}()
				if err := slot.write(relayproto.Message{Type: relayproto.TypeReady}); err != nil {
					t.Errorf("ready round %d: %v", round, err)
				}
				if err := <-readDone; err != nil {
					t.Errorf("read ready round %d: %v", round, err)
				}
				slot.finish()
				_ = slot.conn.Close()
				_ = peer.Close()
				peersMu.Lock()
				delete(peers, slot.conn)
				peersMu.Unlock()
			}()
		}
		close(startClaims)
		claimed.Wait()
	}
}

var (
	peersMu sync.Mutex
	peers = make(map[net.Conn]net.Conn)
)

func peersForSlot(slot *slot) net.Conn {
	peersMu.Lock()
	defer peersMu.Unlock()
	return peers[slot.conn]
}
