package main

import (
	"strings"
	"testing"
)

func TestRFCOMMLocatorCanonicalizesExplicitEndpoint(t *testing.T) {
	got, err := rfcommLocator("01:23:45:67:89:ab/7")
	if err != nil {
		t.Fatalf("rfcommLocator: %v", err)
	}
	if got != "rfcomm://01:23:45:67:89:AB/7" {
		t.Fatalf("locator = %q", got)
	}

	got, err = rfcommLocator("rfcomm://01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("rfcommLocator with scheme: %v", err)
	}
	if got != "rfcomm://01:23:45:67:89:AB/7" {
		t.Fatalf("locator with scheme = %q", got)
	}
}

func TestRFCOMMLocatorRejectsMalformedEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"01:23:45:67:89:AB",
		"01:23:45:67:89:AB/0",
		"01:23:45:67:89:AB/01",
		"rfcomm://01:23:45:67:89:AB/31",
	} {
		if _, err := rfcommLocator(endpoint); err == nil {
			t.Fatalf("rfcommLocator(%q) unexpectedly succeeded", endpoint)
		}
	}
}

func TestSerialLocatorCanonicalizesExplicitDevice(t *testing.T) {
	for _, endpoint := range []string{"/dev/ttyACM0", "serial:///dev/ttyACM0"} {
		got, err := serialLocator(endpoint)
		if err != nil {
			t.Fatalf("serialLocator(%q): %v", endpoint, err)
		}
		if got != "serial:///dev/ttyACM0" {
			t.Fatalf("serialLocator(%q) = %q", endpoint, got)
		}
	}
}

func TestSerialLocatorRejectsUnsafeDevice(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"ttyACM0",
		"/tmp/ttyACM0",
		"/dev",
		"/dev/../tmp/ttyACM0",
		" /dev/ttyACM0 ",
		"/dev/ttyACM0?baud=9600",
		"serial://host/dev/ttyACM0",
	} {
		if _, err := serialLocator(endpoint); err == nil {
			t.Fatalf("serialLocator(%q) unexpectedly succeeded", endpoint)
		}
	}
}

func TestPairTransportLocatorRequiresExactlyOneTransport(t *testing.T) {
	if _, err := pairTransportLocator("", "", "", "", ""); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("empty selection error = %v", err)
	}
	if _, err := pairTransportLocator("127.0.0.1:7443", "01:23:45:67:89:AB/7", "", "", ""); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("multiple selection error = %v", err)
	}
}

func TestPairTransportLocatorRFCOMMDoesNotRequireRelayDeviceID(t *testing.T) {
	got, err := pairTransportLocator("", "01:23:45:67:89:ab/7", "", "", "")
	if err != nil {
		t.Fatalf("pair RFCOMM locator: %v", err)
	}
	if got != "rfcomm://01:23:45:67:89:AB/7" {
		t.Fatalf("locator = %q", got)
	}
}

func TestPairTransportLocatorSerialDoesNotRequireRelayDeviceID(t *testing.T) {
	got, err := pairTransportLocator("", "", "", "", "", "/dev/ttyACM0")
	if err != nil {
		t.Fatalf("pair serial locator: %v", err)
	}
	if got != "serial:///dev/ttyACM0" {
		t.Fatalf("locator = %q", got)
	}
}

func TestPairTransportLocatorRejectsSerialWithOtherTransport(t *testing.T) {
	if _, err := pairTransportLocator("127.0.0.1:7443", "", "", "", "", "/dev/ttyACM0"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("multiple selection error = %v", err)
	}
}

func TestPairTransportLocatorRelayStillRequiresDeviceID(t *testing.T) {
	if _, err := pairTransportLocator("", "", "relay.example:443", "", ""); err == nil || !strings.Contains(err.Error(), "--device-id") {
		t.Fatalf("relay without device ID error = %v", err)
	}
}

func TestConnectTransportOverrideRFCOMM(t *testing.T) {
	got, selected, err := connectTransportOverride("", "01:23:45:67:89:ab/7", "", "", "wd_aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("connect RFCOMM override: %v", err)
	}
	if !selected {
		t.Fatal("RFCOMM override was not selected")
	}
	if got != "rfcomm://01:23:45:67:89:AB/7" {
		t.Fatalf("locator = %q", got)
	}
}

func TestConnectTransportOverrideSerial(t *testing.T) {
	got, selected, err := connectTransportOverride("", "", "", "", "wd_aaaaaaaaaaaaaaaa", "/dev/ttyACM0")
	if err != nil {
		t.Fatalf("connect serial override: %v", err)
	}
	if !selected {
		t.Fatal("serial override was not selected")
	}
	if got != "serial:///dev/ttyACM0" {
		t.Fatalf("locator = %q", got)
	}
}

func TestConnectTransportOverrideMutualExclusion(t *testing.T) {
	if _, _, err := connectTransportOverride("127.0.0.1:7443", "", "", "", "wd_aaaaaaaaaaaaaaaa", "/dev/ttyACM0"); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("multiple overrides error = %v", err)
	}
}

func TestConnectTransportOverrideNone(t *testing.T) {
	got, selected, err := connectTransportOverride("", "", "", "", "wd_aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("no override: %v", err)
	}
	if selected || got != "" {
		t.Fatalf("selected=%v locator=%q", selected, got)
	}
}
