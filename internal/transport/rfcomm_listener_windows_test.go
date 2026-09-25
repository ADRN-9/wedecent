//go:build windows

package transport

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestWindowsRFCOMMAddressFromSockaddrUsesListenerChannel(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("parseRFCOMMLocator: %v", err)
	}
	raw := windowsRFCOMMSockaddr(locator)
	binary.LittleEndian.PutUint32(raw[32:36], 0)
	got, err := windowsRFCOMMAddressFromSockaddr(raw, 9)
	if err != nil {
		t.Fatalf("windowsRFCOMMAddressFromSockaddr: %v", err)
	}
	if got != "01:23:45:67:89:AB/9" {
		t.Fatalf("address = %q", got)
	}
}

func TestWindowsRFCOMMAddressFromSockaddrRejectsFamily(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("parseRFCOMMLocator: %v", err)
	}
	raw := windowsRFCOMMSockaddr(locator)
	binary.LittleEndian.PutUint16(raw[0:2], 2)
	if _, err := windowsRFCOMMAddressFromSockaddr(raw, 7); err == nil || !strings.Contains(err.Error(), "address family") {
		t.Fatalf("family error = %v", err)
	}
}

func TestWindowsRFCOMMAddressFromSockaddrRejectsListenerChannel(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("parseRFCOMMLocator: %v", err)
	}
	raw := windowsRFCOMMSockaddr(locator)
	for _, channel := range []uint8{0, 31} {
		if _, err := windowsRFCOMMAddressFromSockaddr(raw, channel); err == nil || !strings.Contains(err.Error(), "listener channel") {
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
