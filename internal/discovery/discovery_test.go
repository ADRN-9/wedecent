package discovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"wedecent.com/wedecent/internal/identity"
)

func TestMatchTrustedResult(t *testing.T) {
	t.Parallel()

	fp := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	result := Result{
		DeviceID:    "wd_aaaaaaaaaaaaaaaa",
		Fingerprint: fp,
	}

	match, err := matchTrustedResult(result, result.DeviceID, fp)
	if err != nil {
		t.Fatalf("matchTrustedResult() error: %v", err)
	}
	if !match {
		t.Fatal("trusted result did not match")
	}
}

func TestMatchTrustedResultIgnoresOtherDevice(t *testing.T) {
	t.Parallel()

	fp := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	match, err := matchTrustedResult(Result{
		DeviceID:    "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: fp,
	}, "wd_aaaaaaaaaaaaaaaa", fp)
	if err != nil {
		t.Fatalf("matchTrustedResult() error: %v", err)
	}
	if match {
		t.Fatal("different device unexpectedly matched")
	}
}

func TestMatchTrustedResultRejectsFingerprintMismatch(t *testing.T) {
	t.Parallel()

	_, err := matchTrustedResult(Result{
		DeviceID:    "wd_aaaaaaaaaaaaaaaa",
		Fingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}, "wd_aaaaaaaaaaaaaaaa", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !errors.Is(err, ErrTrustedIdentityMismatch) {
		t.Fatalf("error = %v, want ErrTrustedIdentityMismatch", err)
	}
}

func TestMatchTrustedResultRejectsInvalidDiscoveredFingerprint(t *testing.T) {
	t.Parallel()

	_, err := matchTrustedResult(Result{
		DeviceID:    "wd_aaaaaaaaaaaaaaaa",
		Fingerprint: "not-a-fingerprint",
	}, "wd_aaaaaaaaaaaaaaaa", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !errors.Is(err, ErrTrustedIdentityMismatch) {
		t.Fatalf("error = %v, want ErrTrustedIdentityMismatch", err)
	}
}

func TestUsableMulticastInterface(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		flags net.Flags
		want  bool
	}{
		{name: "up multicast", flags: net.FlagUp | net.FlagMulticast, want: true},
		{name: "down", flags: net.FlagMulticast, want: false},
		{name: "loopback", flags: net.FlagUp | net.FlagLoopback | net.FlagMulticast, want: false},
		{name: "no multicast", flags: net.FlagUp, want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := usableMulticastInterface(net.Interface{Flags: tc.flags}); got != tc.want {
				t.Fatalf("usableMulticastInterface() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAnnouncementBytesRoundTrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	id := &identity.Identity{
		ID:         identity.DeviceID(pub),
		Name:       "test-device",
		PublicKey:  pub,
		PrivateKey: priv,
	}
	data, err := announcementBytes(id, 7443)
	if err != nil {
		t.Fatalf("announcementBytes() error: %v", err)
	}
	res, err := verifyAnnouncement(data, net.ParseIP("192.0.2.10"))
	if err != nil {
		t.Fatalf("verifyAnnouncement() error: %v", err)
	}
	if res.DeviceID != id.ID || res.Name != id.Name || res.Endpoint != "192.0.2.10:7443" {
		t.Fatalf("verifyAnnouncement() = %+v", res)
	}
}
