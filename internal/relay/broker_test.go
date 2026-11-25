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
	active atomic.Int32
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
