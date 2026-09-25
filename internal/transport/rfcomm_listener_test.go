package transport

import "testing"

func TestListenRFCOMMRejectsInvalidChannelBeforePlatformAccess(t *testing.T) {
	for _, channel := range []int{-1, 0, 31, 255} {
		if listener, err := ListenRFCOMM(channel); err == nil || listener != nil {
			t.Fatalf("ListenRFCOMM(%d) = (%v, %v), want nil,error", channel, listener, err)
		}
	}
}

func TestCanonicalRFCOMMAddress(t *testing.T) {
	addr := [6]uint8{0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	if got, want := canonicalRFCOMMAddress(addr, 7), "01:23:45:67:89:AB/7"; got != want {
		t.Fatalf("canonicalRFCOMMAddress() = %q, want %q", got, want)
	}
}

func TestFormatRFCOMMMAC(t *testing.T) {
	addr := [6]uint8{0x00, 0x0f, 0x10, 0xa0, 0xbe, 0xff}
	if got, want := formatRFCOMMMAC(addr), "00:0F:10:A0:BE:FF"; got != want {
		t.Fatalf("formatRFCOMMMAC() = %q, want %q", got, want)
	}
}
