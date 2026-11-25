package relay

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
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
