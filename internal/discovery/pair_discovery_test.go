package discovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCollectPairCandidateWaitsForAmbiguity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := collectPairCandidate(ctx, testPairDeviceID, testPairFP, func(context.Context) (<-chan Result, <-chan error) {
		results := make(chan Result, 2)
		errs := make(chan error)
		results <- Result{DeviceID: testPairDeviceID, Endpoint: "192.0.2.10:7443", Fingerprint: testPairFP}
		results <- Result{DeviceID: testPairDeviceID, Endpoint: "192.0.2.11:7443", Fingerprint: testPairFP}
		close(results)
		close(errs)
		return results, errs
	})
	if !errors.Is(err, ErrAmbiguousPairCandidate) {
		t.Fatalf("error = %v, want ErrAmbiguousPairCandidate", err)
	}
}

func TestCollectPairCandidateReturnsSingleCandidate(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := collectPairCandidate(ctx, testPairDeviceID, testPairFP, func(context.Context) (<-chan Result, <-chan error) {
		results := make(chan Result, 1)
		errs := make(chan error)
		results <- Result{DeviceID: testPairDeviceID, Endpoint: "192.0.2.10:7443", Fingerprint: testPairFP}
		close(results)
		close(errs)
		return results, errs
	})
	if err != nil {
		t.Fatalf("collectPairCandidate() error: %v", err)
	}
	if got.Endpoint != "192.0.2.10:7443" {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
}

func TestCollectPairCandidatePropagatesDiscoveryError(t *testing.T) {
	t.Parallel()

	want := errors.New("listener failure")
	_, err := collectPairCandidate(context.Background(), testPairDeviceID, testPairFP, func(context.Context) (<-chan Result, <-chan error) {
		results := make(chan Result)
		errs := make(chan error, 1)
		close(results)
		errs <- want
		close(errs)
		return results, errs
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestCollectPairCandidateSelectsAtDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	got, err := collectPairCandidate(ctx, testPairDeviceID, testPairFP, func(context.Context) (<-chan Result, <-chan error) {
		results := make(chan Result, 1)
		errs := make(chan error)
		results <- Result{DeviceID: testPairDeviceID, Endpoint: "192.0.2.10:7443", Fingerprint: testPairFP}
		return results, errs
	})
	if err != nil {
		t.Fatalf("collectPairCandidate() error: %v", err)
	}
	if got.Endpoint != "192.0.2.10:7443" {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
}
