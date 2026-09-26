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
	got, err := resolvePairLocator(context.Background(), pairLocatorOptions{
		DeviceID:        testPairDiscoveryDeviceID,
		Fingerprint:     testPairDiscoveryFingerprint,
		DiscoverLAN:     true,
		DiscoverTimeout: time.Second,
	}, func(ctx context.Context, deviceID, fingerprint string) (discovery.Result, error) {
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
		t.Fatalf("resolvePairLocator() error: %v", err)
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

	for name, mutate := range map[string]func(*pairLocatorOptions){
		"endpoint": func(o *pairLocatorOptions) { o.Endpoint = "192.0.2.10:7443" },
		"rfcomm":   func(o *pairLocatorOptions) { o.RFCOMM = "AA:BB:CC:DD:EE:FF/3" },
		"relay":    func(o *pairLocatorOptions) { o.Relay = "relay.example:443" },
		"webrelay": func(o *pairLocatorOptions) { o.WebRelay = "https://relay.example" },
		"serial":   func(o *pairLocatorOptions) { o.SerialDevice = "/dev/ttyACM0" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := pairLocatorOptions{DeviceID: testPairDiscoveryDeviceID, Fingerprint: testPairDiscoveryFingerprint, DiscoverLAN: true, DiscoverTimeout: time.Second}
			mutate(&opts)
			called := false
			_, err := resolvePairLocator(context.Background(), opts, func(context.Context, string, string) (discovery.Result, error) {
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

	cases := []struct {
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
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			called := false
			_, err := resolvePairLocator(context.Background(), pairLocatorOptions{
				DeviceID:        tc.deviceID,
				Fingerprint:     tc.fingerprint,
				DiscoverLAN:     true,
				DiscoverTimeout: tc.timeout,
			}, func(context.Context, string, string) (discovery.Result, error) {
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
	_, err := resolvePairLocator(context.Background(), pairLocatorOptions{
		DeviceID:        testPairDiscoveryDeviceID,
		Fingerprint:     testPairDiscoveryFingerprint,
		DiscoverLAN:     true,
		DiscoverTimeout: time.Second,
	}, func(context.Context, string, string) (discovery.Result, error) {
		return discovery.Result{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestResolvePairLocatorExplicitTransportSkipsDiscovery(t *testing.T) {
	t.Parallel()

	called := false
	got, err := resolvePairLocator(context.Background(), pairLocatorOptions{
		Endpoint:    "192.0.2.10:7443",
		Fingerprint: "not-validated-on-explicit-path",
	}, func(context.Context, string, string) (discovery.Result, error) {
		called = true
		return discovery.Result{}, nil
	})
	if err != nil {
		t.Fatalf("resolvePairLocator() error: %v", err)
	}
	if called {
		t.Fatal("finder called for explicit transport")
	}
	if got != "tcp://192.0.2.10:7443" {
		t.Fatalf("locator = %q", got)
	}
}
