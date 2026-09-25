package discovery

import (
	"errors"
	"testing"
)

const (
	testPairDeviceID = "wd_aaaaaaaaaaaaaaaa"
	testPairFP       = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestSelectPairCandidateSingleMatch(t *testing.T) {
	t.Parallel()

	got, err := SelectPairCandidate([]Result{{
		DeviceID:    testPairDeviceID,
		Name:        "agent",
		Endpoint:    "192.0.2.10:7443",
		Fingerprint: testPairFP,
	}}, testPairDeviceID, testPairFP)
	if err != nil {
		t.Fatalf("SelectPairCandidate() error: %v", err)
	}
	if got.Endpoint != "192.0.2.10:7443" || got.DeviceID != testPairDeviceID {
		t.Fatalf("SelectPairCandidate() = %+v", got)
	}
}

func TestSelectPairCandidateIgnoresOtherDevices(t *testing.T) {
	t.Parallel()

	_, err := SelectPairCandidate([]Result{{
		DeviceID:    "wd_bbbbbbbbbbbbbbbb",
		Endpoint:    "192.0.2.11:7443",
		Fingerprint: testPairFP,
	}}, testPairDeviceID, testPairFP)
	if !errors.Is(err, ErrNoPairCandidate) {
		t.Fatalf("error = %v, want ErrNoPairCandidate", err)
	}
}

func TestSelectPairCandidateRejectsIdentityConflict(t *testing.T) {
	t.Parallel()

	_, err := SelectPairCandidate([]Result{{
		DeviceID:    testPairDeviceID,
		Endpoint:    "192.0.2.10:7443",
		Fingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}}, testPairDeviceID, testPairFP)
	if !errors.Is(err, ErrTrustedIdentityMismatch) {
		t.Fatalf("error = %v, want ErrTrustedIdentityMismatch", err)
	}
}

func TestSelectPairCandidateRejectsAmbiguousEndpoints(t *testing.T) {
	t.Parallel()

	_, err := SelectPairCandidate([]Result{
		{DeviceID: testPairDeviceID, Endpoint: "192.0.2.10:7443", Fingerprint: testPairFP},
		{DeviceID: testPairDeviceID, Endpoint: "192.0.2.11:7443", Fingerprint: testPairFP},
	}, testPairDeviceID, testPairFP)
	if !errors.Is(err, ErrAmbiguousPairCandidate) {
		t.Fatalf("error = %v, want ErrAmbiguousPairCandidate", err)
	}
}

func TestSelectPairCandidateDeduplicatesExactEndpoint(t *testing.T) {
	t.Parallel()

	got, err := SelectPairCandidate([]Result{
		{DeviceID: testPairDeviceID, Endpoint: "192.0.2.10:7443", Fingerprint: testPairFP},
		{DeviceID: testPairDeviceID, Endpoint: "192.0.2.10:7443", Fingerprint: testPairFP},
	}, testPairDeviceID, testPairFP)
	if err != nil {
		t.Fatalf("SelectPairCandidate() error: %v", err)
	}
	if got.Endpoint != "192.0.2.10:7443" {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
}

func TestSelectPairCandidateRejectsMalformedEndpoint(t *testing.T) {
	t.Parallel()

	_, err := SelectPairCandidate([]Result{{
		DeviceID:    testPairDeviceID,
		Endpoint:    "not-an-endpoint",
		Fingerprint: testPairFP,
	}}, testPairDeviceID, testPairFP)
	if err == nil || errors.Is(err, ErrNoPairCandidate) {
		t.Fatalf("error = %v, want malformed endpoint error", err)
	}
}

func TestSelectPairCandidateRejectsInvalidExpectedIdentity(t *testing.T) {
	t.Parallel()

	_, err := SelectPairCandidate(nil, testPairDeviceID, "not-a-fingerprint")
	if !errors.Is(err, ErrTrustedIdentityMismatch) {
		t.Fatalf("error = %v, want ErrTrustedIdentityMismatch", err)
	}

	_, err = SelectPairCandidate(nil, "not-a-device", testPairFP)
	if err == nil {
		t.Fatal("invalid device ID unexpectedly accepted")
	}
}
