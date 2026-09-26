package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/discovery"
)

const testPairDiscoveryFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const testPairDiscoveryDeviceID = "wd_aaaaaaaaaaaaaaaa"

func TestResolvePairLocatorDiscoverLANSuccess(t *testing.T) {
	t.Parallel()

	called := false
	got, err := resolvePairLocatorWithFinder(context.Background(), true, time.Second, "", "", "", "", testPairDiscoveryDeviceID, testPairDiscoveryFingerprint, "", func(ctx context.Context, deviceID, fingerprint string) (discovery.Result, error) {
		called = true
		if deviceID != testPairDiscoveryDeviceID || fingerprint != testPairDiscoveryFingerprint {
			t.Fatalf("finder selectors = %q %q", deviceID, fingerprint)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("finder context has no deadline")
		}
		return discovery.Result{DeviceID: deviceID, Endpoint: "192.0.2.10:7443", Fingerprint: fingerprint}, nil
	})
	if err != nil {
		t.Fatalf("resolvePairLocatorWithFinder() error: %v", err)
	}
	if !called {
		t.Fatal("finder was not called")
	}
	if got != "tcp://192.0.2.10:7443" {
		t.Fatalf("locator = %q", got)
	}
}

func TestResolvePairLocatorDiscoverLANRejectsExplicitTransport(t *testing.T) {
	t.Parallel()

	for name, values := range map[string][5]string{
		"endpoint": {"192.0.2.10:7443", "", "", "", ""},
		"rfcomm":  {"", "AA:BB:CC:DD:EE:FF/3", "", "", ""},
		"relay":   {"", "", "relay.example:443", "", ""},
		"webrelay": {"", "", "", "https://relay.example", ""},
		"serial":  {"", "", "", "", "/dev/ttyACM0"},
	} {
		name, values := name, values
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			called := false
			_, err := resolvePairLocatorWithFinder(context.Background(), true, time.Second, values[0], values[1], values[2], values[3], testPairDiscoveryDeviceID, testPairDiscoveryFingerprint, values[4], func(context.Context, string, string) (discovery.Result, error) {
				called = true
				return discovery.Result{}, nil
			})
			if err == nil {
				t.Fatal("explicit transport unexpectedly accepted with --discover-lan")
			}
			if called {
				t.Fatal("finder called after invalid transport combination")
			}
		})
	}
}

func TestResolvePairLocatorDiscoverLANValidatesBeforeNetwork(t *testing.T) {
	t.Parallel()

	for name, deviceID, fingerprint, timeout := range []struct {
		name        string
		deviceID    string
		fingerprint string
		timeout     time.Duration
	}{
		{"bad-device", "not-a-device", testPairDiscoveryFingerprint, time.Second},
		{"spaced-device", " " + testPairDiscoveryDeviceID, testPairDiscoveryFingerprint, time.Second},
		{"bad-fingerprint", testPairDiscoveryDeviceID, "not-a-fingerprint", time.Second},
		{"zero-timeout", testPairDiscoveryDeviceID, testPairDiscoveryFingerprint, 0},
		{"long-timeout", testPairDiscoveryDeviceID, testPairDiscoveryFingerprint, 11 * time.Second},
	} {
		name, deviceID, fingerprint, timeout := name, deviceID, fingerprint, timeout
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			called := false
			_, err := resolvePairLocatorWithFinder(context.Background(), true, timeout, "", "", "", "", deviceID, fingerprint, "", func(context.Context, string, string) (discovery.Result, error) {
				called = true
				return discovery.Result{}, nil
			})
			if err == nil {
				t.Fatal("invalid discovery configuration unexpectedly accepted")
			}
			if called {
				t.Fatal("finder called before validation completed")
			}
		})
	}
}

func TestResolvePairLocatorDiscoverLANDoesNotFallback(t *testing.T) {
	t.Parallel()

	want := errors.New("discovery failed")
	_, err := resolvePairLocatorWithFinder(context.Background(), true, time.Second, "", "", "", "", testPairDiscoveryDeviceID, testPairDiscoveryFingerprint, "", func(context.Context, string, string) (discovery.Result, error) {
		return discovery.Result{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestResolvePairLocatorExplicitTransportSkipsDiscovery(t *testing.T) {
	t.Parallel()

	called := false
	got, err := resolvePairLocatorWithFinder(context.Background(), false, time.Second, "192.0.2.10:7443", "", "", "", "", testPairDiscoveryFingerprint, "", func(context.Context, string, string) (discovery.Result, error) {
		called = true
		return discovery.Result{}, nil
	})
	if err != nil {
		t.Fatalf("resolvePairLocatorWithFinder() error: %v", err)
	}
	if called {
		t.Fatal("finder called for explicit transport")
	}
	if got != "tcp://192.0.2.10:7443" {
		t.Fatalf("locator = %q", got)
	}
}
