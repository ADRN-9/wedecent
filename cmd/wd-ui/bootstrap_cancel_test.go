package main

import (
	"context"
	"errors"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
)

func TestEnsureLocalCoreHonorsCanceledParentBeforeLaunch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	core := &bootstrapCore{steps: []error{coreclient.ErrUnavailable}}
	launched := false
	err := ensureLocalCore(ctx, core, func() (<-chan error, error) {
		launched = true
		return nil, nil
	}, testBootstrapConfig)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if launched {
		t.Fatal("canceled bootstrap unexpectedly launched Local Core")
	}
}
