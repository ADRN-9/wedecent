//go:build windows

package scmbroker

import (
	"context"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRunContextStopsBeforeOpeningPipeWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunContext(ctx); err != nil {
		t.Fatalf("RunContext with cancelled context: %v", err)
	}
}

func TestConnectPipeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := connectPipe(ctx, windows.InvalidHandle); err == nil {
		t.Fatal("connectPipe unexpectedly accepted a cancelled context")
	}
}
