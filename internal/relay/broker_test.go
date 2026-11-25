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
			if _, err := broker.Take("device"); err == nil {
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
