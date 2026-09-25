package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/discovery"
)

func TestResolvePairLocatorExplicitTransport(t *testing.T) {
	t.Parallel()

	got, err := resolvePairLocator(context.Background(), pairLocatorOptions{Endpoint: "192.0.2.10:7443"}, nil)
	if err != nil {
		t.Fatalf("resolvePairLocator() error: %v", err)
	}
	if got != "tcp://192.0.2.10:7443" {
		t.Fatalf("locator = %q", got)
	}
}

func TestResolvePairLocatorDiscovery(t *testing.T) {
	t.Parallel()

	called := false
	got, err := resolvePairLocator(context.Background(), pairLocatorOptions{
		DiscoverLAN:     true,
		DiscoverTimeout: time.Second,
		DeviceID:        "wd_aaaaaaaaaaaaaaaa",
		Fingerprint:     "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}, func(ctx context.Context, deviceID, fingerprint string) (discovery.Result, error) {
		called = true
		if deviceID != "wd_aaaaaaaaaaaaaaaa" {
			t.Fatalf("deviceID = %q", deviceID)
		}
		if fingerprint == "" {
			t.Fatal("fingerprint is empty")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("discovery context has no deadline")
		}
		return discovery.Result{Endpoint: "192.0.2.20:7443"}, nil
	})
	if err != nil {
		t.Fatalf("resolvePairLocator() error: %v", err)
	}
	if !called {
		t.Fatal("finder was not called")
	}
	if got != "tcp://192.0.2.20:7443" {
		t.Fatalf("locator = %q", got)
	}
}

func TestResolvePairLocatorDiscoveryRejectsExplicitTransport(t *testing.T) {
	t.Parallel()

	for name, opts := range map[string]pairLocatorOptions{
		"endpoint": {Endpoint: "192.0.2.10:7443"},
		"rfcomm":   {RFCOMM: "01:23:45:67:89:AB/7"},
		"serial":   {SerialDevice: "/dev/ttyACM0"},
		"relay":    {Relay: "relay.example:443"},
		"webRelay": {WebRelay: "https://relay.example"},
	} {
		name, opts := name, opts
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts.DiscoverLAN = true
			opts.DiscoverTimeout = time.Second
			opts.DeviceID = "wd_aaaaaaaaaaaaaaaa"
			_, err := resolvePairLocator(context.Background(), opts, func(context.Context, string, string) (discovery.Result, error) {
				t.Fatal("finder called for invalid mixed transport selection")
				return discovery.Result{}, nil
			})
			if err == nil {
				t.Fatal("mixed discovery/explicit transport unexpectedly accepted")
			}
		})
	}
}

func TestResolvePairLocatorDiscoveryRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	finder := func(context.Context, string, string) (discovery.Result, error) {
		t.Fatal("finder called for invalid discovery input")
		return discovery.Result{}, nil
	}
	for name, opts := range map[string]pairLocatorOptions{
		"missing device": {DiscoverLAN: true, DiscoverTimeout: time.Second},
		"spaced device":  {DiscoverLAN: true, DiscoverTimeout: time.Second, DeviceID: " wd_aaaaaaaaaaaaaaaa"},
		"zero timeout":   {DiscoverLAN: true, DeviceID: "wd_aaaaaaaaaaaaaaaa"},
		"long timeout":   {DiscoverLAN: true, DiscoverTimeout: time.Minute + time.Nanosecond, DeviceID: "wd_aaaaaaaaaaaaaaaa"},
	} {
		name, opts := name, opts
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := resolvePairLocator(context.Background(), opts, finder); err == nil {
				t.Fatal("invalid discovery input unexpectedly accepted")
			}
		})
	}
}

func TestResolvePairLocatorDiscoveryPropagatesFinderError(t *testing.T) {
	t.Parallel()

	want := errors.New("ambiguous candidate")
	_, err := resolvePairLocator(context.Background(), pairLocatorOptions{
		DiscoverLAN:     true,
		DiscoverTimeout: time.Second,
		DeviceID:        "wd_aaaaaaaaaaaaaaaa",
	}, func(context.Context, string, string) (discovery.Result, error) {
		return discovery.Result{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
