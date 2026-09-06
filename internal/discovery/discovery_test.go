package discovery

import (
	"errors"
	"testing"
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
