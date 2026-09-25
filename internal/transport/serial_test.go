package transport

import (
	"context"
	"errors"
	"testing"
)

func TestSerialDialerRejectsUnsupportedBaudBeforePlatformAccess(t *testing.T) {
	_, err := (SerialDialer{Baud: 9600}).Dial(context.Background(), "ignored")
	if err == nil || err.Error() != "transport: serial currently requires 115200 baud" {
		t.Fatalf("Dial error = %v", err)
	}
}

func TestSerialDialerHonorsCanceledContextBeforePlatformAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (SerialDialer{}).Dial(ctx, "ignored")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial error = %v, want context.Canceled", err)
	}
}

func TestSerialDialerRejectsNilContext(t *testing.T) {
	if _, err := (SerialDialer{}).Dial(nil, "ignored"); err == nil {
		t.Fatal("Dial(nil, ...) unexpectedly succeeded")
	}
}
