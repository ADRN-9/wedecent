//go:build windows

package transport

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestWindowsRFCOMMSockaddrLayout(t *testing.T) {
	locator, err := parseRFCOMMLocator("01:23:45:67:89:AB/7")
	if err != nil {
		t.Fatalf("parseRFCOMMLocator: %v", err)
	}
	raw := windowsRFCOMMSockaddr(locator)
	if got := binary.LittleEndian.Uint16(raw[0:2]); got != windowsAFBTH {
		t.Fatalf("address family = %d", got)
	}
	wantAddr := [6]byte{0xAB, 0x89, 0x67, 0x45, 0x23, 0x01}
	for i, want := range wantAddr {
		if raw[8+i] != want {
			t.Fatalf("btAddr byte %d = %#x, want %#x", i, raw[8+i], want)
		}
	}
	for i := 14; i < 32; i++ {
		if raw[i] != 0 {
			t.Fatalf("service/padding byte %d = %#x, want zero", i, raw[i])
		}
	}
	if got := binary.LittleEndian.Uint32(raw[32:36]); got != 7 {
		t.Fatalf("port = %d", got)
	}
	for i := 36; i < len(raw); i++ {
		if raw[i] != 0 {
			t.Fatalf("trailing padding byte %d = %#x, want zero", i, raw[i])
		}
	}
}

func TestWindowsFDSetMatchesWinsockABI(t *testing.T) {
	var set windowsFDSet
	want := uintptr(4 + 64*4)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		want = 8 + 64*8
	}
	if got := unsafe.Sizeof(set); got != want {
		t.Fatalf("fd_set size = %d, want %d", got, want)
	}
	set = newWindowsFDSet(123)
	if set.Count != 1 || set.Socket != 123 {
		t.Fatalf("fd_set = count %d socket %d", set.Count, set.Socket)
	}
}

func TestWindowsSelectTimeoutRoundsUp(t *testing.T) {
	tv := windowsSelectTimeout(1501)
	if tv.Sec != 0 || tv.Usec != 2 {
		t.Fatalf("timeval = %d.%06d", tv.Sec, tv.Usec)
	}
}
