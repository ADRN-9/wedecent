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

func TestRunPairRejectsDiscoveryWithExplicitTransportBeforeSecretPrompt(t *testing.T) {
	t.Parallel()

	err := runPair([]string{
		"--discover-lan",
		"--device-id", "wd_aaaaaaaaaaaaaaaa",
		"--endpoint", "192.0.2.10:7443",
		"--fingerprint", pairParserTestFingerprint,
	})
	if err == nil {
		t.Fatal("mixed discovery/explicit transport unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("error = %v, want mutual-exclusion guard", err)
	}
}

func TestRunPairFingerprintGuidanceRequiresIndependentChannel(t *testing.T) {
	t.Parallel()

	err := runPair([]string{"--endpoint", "192.0.2.10:7443"})
	if err == nil {
		t.Fatal("missing fingerprint unexpectedly accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "independent trusted channel") {
		t.Fatalf("error = %v, want independent-channel guidance", err)
	}
	if strings.Contains(msg, "obtain it from wd discover") {
		t.Fatalf("error = %v, discovery must not be presented as a trust source", err)
	}
}

func TestRunPairRejectsExplicitEmptyTransportFlagsWithDiscoveryBeforeSecretPrompt(t *testing.T) {
	for _, name := range []string{"endpoint", "rfcomm", "serial", "relay", "web-relay"} {
		_, err := runPair([]string{
			"--discover-lan",
			"--device-id", "wd_aaaaaaaaaaaaaaaa",
			"--fingerprint", pairParserTestFingerprint,
			"--" + name + "=",
		})
		if err == nil || !strings.Contains(err.Error(), "--"+name+" must not be empty") {
			t.Errorf("--%s=: error = %v; want explicit-empty rejection before discovery/secret prompt", name, err)
		}
	}
}

func TestRunPairRejectsExplicitEmptyTransportFlagsWithoutDiscovery(t *testing.T) {
	for _, name := range []string{"endpoint", "rfcomm", "serial", "relay", "web-relay"} {
		_, err := runPair([]string{
			"--fingerprint", pairParserTestFingerprint,
			"--" + name + "=",
		})
		if err == nil || !strings.Contains(err.Error(), "--"+name+" must not be empty") {
			t.Errorf("--%s=: error = %v; want explicit-empty rejection", name, err)
		}
	}
}

func TestRunPairRejectsWhitespaceOnlyTransportFlags(t *testing.T) {
	for _, name := range []string{"endpoint", "rfcomm", "serial", "relay", "web-relay"} {
		_, err := runPair([]string{
			"--fingerprint", pairParserTestFingerprint,
			"--" + name + "= ",
		})
		if err == nil || !strings.Contains(err.Error(), "surrounding whitespace") {
			t.Errorf("--%s whitespace-only: error = %v; want whitespace rejection", name, err)
		}
	}
}

func TestRunPairRejectsConflictingTransportFlags(t *testing.T) {
	_, err := runPair([]string{
		"--fingerprint", pairParserTestFingerprint,
		"--endpoint=192.0.2.10:7443",
		"--rfcomm=01:23:45:67:89:AB/7",
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("conflicting transport flags error = %v", err)
	}
}
