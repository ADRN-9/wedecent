package transport

import (
	"context"
	"errors"
	"testing"
)

func TestParseRFCOMMLocator(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:ab/7")
	if err != nil {
		t.Fatalf("parse RFCOMM locator: %v", err)
	}
	if locator.canonical != "01:23:45:67:89:AB/7" {
		t.Fatalf("canonical locator = %q", locator.canonical)
	}
	wantAddr := [6]uint8{0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	if locator.addr != wantAddr {
		t.Fatalf("little-endian address = %#v, want %#v", locator.addr, wantAddr)
	}
	if locator.channel != 7 {
		t.Fatalf("channel = %d, want 7", locator.channel)
	}
}

func TestNormalizeRFCOMMLocator(t *testing.T) {
	got, err := NormalizeRFCOMMLocator("01:23:45:67:89:ab/7")
	if err != nil {
		t.Fatal(err)
	}
	if got != "01:23:45:67:89:AB/7" {
		t.Fatalf("NormalizeRFCOMMLocator = %q", got)
	}
}

func TestParseRFCOMMLocatorRejectsAmbiguousInput(t *testing.T) {
	for _, endpoint := range []string{
		"01:23:45:67:89:AB",
		"01-23-45-67-89-AB/1",
		"01:23:45:67:89:AZ/1",
		"01:23:45:67:89:AB/0",
		"01:23:45:67:89:AB/31",
		"01:23:45:67:89:AB/01",
		"01:23:45:67:89:AB/+1",
		"01:23:45:67:89:AB/1/2",
		" 01:23:45:67:89:AB/1",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := parseRFCOMMLocator(endpoint); err == nil {
				t.Fatalf("parseRFCOMMLocator(%q) unexpectedly succeeded", endpoint)
			}
		})
	}
}

func TestRFCOMMDialerHonorsCanceledContextBeforePlatformAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (RFCOMMDialer{}).Dial(ctx, "01:23:45:67:89:AB/1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial error = %v, want context.Canceled", err)
	}
}

func TestRFCOMMDialerRejectsNilContext(t *testing.T) {
	_, err := (RFCOMMDialer{}).Dial(nil, "01:23:45:67:89:AB/1")
	if err == nil {
		t.Fatal("Dial(nil, ...) unexpectedly succeeded")
	}
}
