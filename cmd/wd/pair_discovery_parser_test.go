package main

import (
	"strings"
	"testing"
)

const pairParserTestFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestRunPairRejectsInvalidFingerprintBeforeDiscovery(t *testing.T) {
	t.Parallel()

	err := runPair([]string{
		"--discover-lan",
		"--device-id", "wd_aaaaaaaaaaaaaaaa",
		"--fingerprint", "not-a-fingerprint",
	})
	if err == nil {
		t.Fatal("invalid fingerprint unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("error = %v, want fingerprint validation error", err)
	}
}

func TestRunPairRejectsDiscoveryTimeoutWithoutDiscovery(t *testing.T) {
	t.Parallel()

	err := runPair([]string{
		"--endpoint", "192.0.2.10:7443",
		"--discover-timeout", "1s",
		"--fingerprint", pairParserTestFingerprint,
	})
	if err == nil {
		t.Fatal("--discover-timeout without --discover-lan unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "--discover-timeout requires --discover-lan") {
		t.Fatalf("error = %v, want discovery-timeout guard", err)
	}
}
