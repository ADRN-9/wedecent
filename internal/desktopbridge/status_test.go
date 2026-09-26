package desktopbridge

import (
	"context"
	"errors"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type statusSourceFunc func(context.Context) (v1.Status, error)

func (f statusSourceFunc) GetStatus(ctx context.Context) (v1.Status, error) {
	return f(ctx)
}

func TestGetStatusExposesOnlyDesktopSafeFields(t *testing.T) {
	source := statusSourceFunc(func(context.Context) (v1.Status, error) {
		return v1.Status{
			APIVersion: "v1",
			SignedIn:   true,
			UserID:     "user-secretish-identifier",
			Email:      "person@example.com",
			DeviceID:   "wd_0123456789abcdef",
			DeviceName: "workstation",
		}, nil
	})

	got, err := GetStatus(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	want := Status{
		APIVersion: "v1",
		SignedIn:   true,
		DeviceID:   "wd_0123456789abcdef",
		DeviceName: "workstation",
	}
	if got != want {
		t.Fatalf("GetStatus() = %#v, want %#v", got, want)
	}
}

func TestGetStatusRequiresSource(t *testing.T) {
	_, err := GetStatus(context.Background(), nil)
	if !errors.Is(err, ErrStatusSourceRequired) {
		t.Fatalf("GetStatus() error = %v, want %v", err, ErrStatusSourceRequired)
	}
}

func TestGetStatusPropagatesCoreError(t *testing.T) {
	want := errors.New("core unavailable")
	source := statusSourceFunc(func(context.Context) (v1.Status, error) {
		return v1.Status{}, want
	})
	_, err := GetStatus(context.Background(), source)
	if !errors.Is(err, want) {
		t.Fatalf("GetStatus() error = %v, want %v", err, want)
	}
}

func TestGetStatusPassesContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := statusSourceFunc(func(got context.Context) (v1.Status, error) {
		if !errors.Is(got.Err(), context.Canceled) {
			t.Fatalf("source context error = %v, want canceled", got.Err())
		}
		return v1.Status{}, got.Err()
	})
	_, err := GetStatus(ctx, source)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GetStatus() error = %v, want canceled", err)
	}
}
