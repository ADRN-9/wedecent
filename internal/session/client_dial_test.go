package session

import (
	"context"
	"sync"
	"testing"
)

func TestClientDialDefaultIsConcurrentReadOnly(t *testing.T) {
	client := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	const callers = 32
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := client.dial(ctx, "127.0.0.1:1")
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil {
			t.Fatal("client.dial() error = nil with canceled context")
		}
	}
	if client.Dialer != nil {
		t.Fatalf("client.dial() mutated default Dialer to %T", client.Dialer)
	}
}
