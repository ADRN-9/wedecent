package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeStatusSource func(context.Context) (v1.Status, error)

func (f fakeStatusSource) GetStatus(ctx context.Context) (v1.Status, error) {
	return f(ctx)
}

func TestRunStatusEmitsSanitizedJSON(t *testing.T) {
	source := fakeStatusSource(func(context.Context) (v1.Status, error) {
		return v1.Status{
			APIVersion: "v1",
			SignedIn:   true,
			UserID:     "user-123",
			Email:      "person@example.com",
			DeviceID:   "wd_0123456789abcdef",
			DeviceName: "laptop",
		}, nil
	})
	var out bytes.Buffer
	if err := run([]string{"status"}, &out, source); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{`"api_version":"v1"`, `"signed_in":true`, `"device_id":"wd_0123456789abcdef"`, `"device_name":"laptop"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("status output %q does not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"user-123", "person@example.com", "fingerprint", "endpoint"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("status output %q contains forbidden renderer data %q", got, forbidden)
		}
	}
}

func TestRunStatusDoesNotEmitPartialJSONOnCoreError(t *testing.T) {
	want := errors.New("boom")
	source := fakeStatusSource(func(context.Context) (v1.Status, error) {
		return v1.Status{}, want
	})
	var out bytes.Buffer
	err := run([]string{"status"}, &out, source)
	if !errors.Is(err, want) {
		t.Fatalf("run() error = %v, want %v", err, want)
	}
	if out.Len() != 0 {
		t.Fatalf("status output = %q, want empty", out.String())
	}
}

func TestRunRejectsUnknownCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"status", "extra"}} {
		if err := run(args, &bytes.Buffer{}, fakeStatusSource(func(context.Context) (v1.Status, error) {
			t.Fatal("status source called for invalid command")
			return v1.Status{}, nil
		})); !errors.Is(err, errUsage) {
			t.Fatalf("run(%q) error = %v, want usage", args, err)
		}
	}
}

func TestPublicErrorDoesNotLeakRemoteMessage(t *testing.T) {
	remote := &coreclient.RemoteError{Code: "denied", Message: "sensitive implementation detail"}
	got := publicError(remote)
	if strings.Contains(got, remote.Message) || strings.Contains(got, remote.Code) {
		t.Fatalf("publicError() leaked remote detail: %q", got)
	}
	if got != "Local Core rejected the status request" {
		t.Fatalf("publicError() = %q", got)
	}
}

func TestPublicErrorClassifiesUnavailable(t *testing.T) {
	if got := publicError(coreclient.ErrUnavailable); got != "Local Core is unavailable" {
		t.Fatalf("publicError() = %q", got)
	}
}
