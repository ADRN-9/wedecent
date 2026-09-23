package coreapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestConnectIdempotencyRejectsInvalidOperationIDs(t *testing.T) {
	inner := &idempotencyConnectionService{}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}

	for _, operationID := range []string{
		"contains space",
		"contains/slash",
		strings.Repeat("a", v1.MaxConnectOperationIDBytes+1),
	} {
		_, err := service.Connect(context.Background(), v1.ConnectRequest{
			DeviceID:    "wd_dest0000000000",
			OperationID: operationID,
		})
		if !errors.Is(err, ErrInvalidConnectionRequest) {
			t.Fatalf("operation ID %q error = %v, want ErrInvalidConnectionRequest", operationID, err)
		}
	}
	if inner.connectCount() != 0 {
		t.Fatalf("inner Connect calls = %d, want 0", inner.connectCount())
	}
}

func TestConnectIdempotencyCacheExhaustionFailsClosed(t *testing.T) {
	inner := &idempotencyConnectionService{}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	service.maxEntries = 1

	if _, err := service.Connect(context.Background(), v1.ConnectRequest{
		DeviceID:    "wd_dest0000000000",
		OperationID: "op_first",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = service.Connect(context.Background(), v1.ConnectRequest{
		DeviceID:    "wd_other000000000",
		OperationID: "op_second",
	})
	if !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("cache exhaustion error = %v, want ErrConnectionLimit", err)
	}
	if inner.connectCount() != 1 {
		t.Fatalf("inner Connect calls = %d, want 1", inner.connectCount())
	}
}
