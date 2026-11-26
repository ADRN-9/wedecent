package main

import (
	"path/filepath"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/trust"
)

func TestRunConnectRejectsRoutedWithDestinationOverride(t *testing.T) {
	_, err := runConnect([]string{
		"--state", t.TempDir(),
		"--route-router", "wd_bbbbbbbbbbbbbbbb",
		"--route-first-transport", "lan",
		"--route-second-transport", "lan",
		"--endpoint", "127.0.0.1:7443",
		"wd_cccccccccccccccc",
	})
	if err == nil || !strings.Contains(err.Error(), "routed connections cannot be combined") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunConnectRejectsPartialRoutedConfiguration(t *testing.T) {
	_, err := runConnect([]string{
		"--state", t.TempDir(),
		"--route-router", "wd_bbbbbbbbbbbbbbbb",
		"wd_cccccccccccccccc",
	})
	if err == nil || !strings.Contains(err.Error(), "both hop transports") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunConnectUsageMentionsRouting(t *testing.T) {
	_, err := runConnect(nil)
	if err == nil || !strings.Contains(err.Error(), "--route-router") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunConnectRejectsExplicitEmptyTransportFlagsWithoutStoredLocatorFallback(t *testing.T) {
	transportFlags := []string{"endpoint", "rfcomm", "serial", "relay", "web-relay"}
	for _, name := range transportFlags {
		name := name
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			deviceID := "wd_cccccccccccccccc"
			store, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
			if err != nil {
				t.Fatal(err)
			}
			storedLocator := "tcp://192.0.2.44:7443"
			if err := store.Put(trust.Peer{ID: deviceID, Endpoint: storedLocator, Fingerprint: "test-fingerprint"}); err != nil {
				t.Fatal(err)
			}

			args := []string{"--state", stateDir, "--lan-timeout", "0", "--" + name + "=", deviceID}
			_, err = runConnect(args)
			if err == nil || !strings.Contains(err.Error(), "--"+name+" must not be empty") {
				t.Fatalf("runConnect error = %v; want explicit-empty rejection", err)
			}
			peer, ok := store.Get(deviceID)
			if !ok || peer.Endpoint != storedLocator {
				t.Fatalf("stored peer changed after rejected override: %#v, exists=%v", peer, ok)
			}
		})
	}
}

func TestRunConnectRejectsExplicitEmptyTransportFlagsWithRoutedOptions(t *testing.T) {
	for _, name := range []string{"endpoint", "rfcomm", "serial", "relay", "web-relay"} {
		_, err := runConnect([]string{
			"--state", t.TempDir(),
			"--route-router", "wd_bbbbbbbbbbbbbbbb",
			"--route-first-transport", "lan",
			"--route-second-transport", "lan",
			"--" + name + "=",
			"wd_cccccccccccccccc",
		})
		if err == nil || !strings.Contains(err.Error(), "--"+name+" must not be empty") {
			t.Errorf("--%s=: error = %v; want explicit-empty rejection before route handling", name, err)
		}
	}
}

func TestRunConnectRejectsWhitespaceOnlyTransportFlags(t *testing.T) {
	for _, name := range []string{"endpoint", "rfcomm", "serial", "relay", "web-relay"} {
		_, err := runConnect([]string{"--state", t.TempDir(), "--" + name + "= ", "wd_cccccccccccccccc"})
		if err == nil || !strings.Contains(err.Error(), "surrounding whitespace") {
			t.Errorf("--%s whitespace-only: error = %v; want whitespace rejection", name, err)
		}
	}
}

func TestRunConnectRejectsConflictingTransportFlags(t *testing.T) {
	_, err := runConnect([]string{
		"--state", t.TempDir(),
		"--endpoint=192.0.2.10:7443",
		"--rfcomm=01:23:45:67:89:AB/7",
		"wd_cccccccccccccccc",
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("conflicting transport flags error = %v", err)
	}
}
