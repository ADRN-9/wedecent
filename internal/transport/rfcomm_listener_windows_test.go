//go:build windows

package transport

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestWindowsRFCOMMAddressFromSockaddr(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("parseRFCOMMLocator: %v", err)
	}
	raw := windowsRFCOMMSockaddr(locator)
	got, err := windowsRFCOMMAddressFromSockaddr(raw)
	if err != nil {
		t.Fatalf("windowsRFCOMMAddressFromSockaddr: %v", err)
	}
	if got != locator.canonical {
		t.Fatalf("address = %q, want %q", got, locator.canonical)
	}
}

func TestWindowsRFCOMMAddressFromSockaddrRejectsFamily(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("parseRFCOMMLocator: %v", err)
	}
	raw := windowsRFCOMMSockaddr(locator)
	binary.LittleEndian.PutUint16(raw[0:2], 2)
	if _, err := windowsRFCOMMAddressFromSockaddr(raw); err == nil || !strings.Contains(err.Error(), "address family") {
		t.Fatalf("family error = %v", err)
	}
}

func TestWindowsRFCOMMAddressFromSockaddrRejectsChannel(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("parseRFCOMMLocator: %v", err)
	}
	for _, channel := range []uint32{0, 31} {
		raw := windowsRFCOMMSockaddr(locator)
		binary.LittleEndian.PutUint32(raw[32:36], channel)
		if _, err := windowsRFCOMMAddressFromSockaddr(raw); err == nil || !strings.Contains(err.Error(), "invalid channel") {
			t.Fatalf("channel %d error = %v", channel, err)
		}
	}
}

func TestWindowsRFCOMMListenerAddress(t *testing.T) {
	listener := &windowsRFCOMMListener{channel: 9}
	if got := listener.Addr().String(); got != "*/9" {
		t.Fatalf("listener address = %q", got)
	}
}
