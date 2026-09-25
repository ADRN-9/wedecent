package transport

import (
	"context"
	"errors"
	"testing"
)

func TestNormalizeSerialPath(t *testing.T) {
	got, err := normalizeSerialPath("/dev/ttyACM0")
	if err != nil {
		t.Fatalf("normalize serial path: %v", err)
	}
	if got != "/dev/ttyACM0" {
		t.Fatalf("path = %q", got)
	}
}

func TestNormalizeSerialPathRejectsUnsafeInput(t *testing.T) {
	for _, path := range []string{
		"",
		"ttyACM0",
		"/tmp/ttyACM0",
		"/dev",
		"/dev/../tmp/tty",
		" /dev/ttyACM0 ",
	} {
		t.Run(path, func(t *testing.T) {
			if _, err := normalizeSerialPath(path); err == nil {
				t.Fatalf("normalizeSerialPath(%q) unexpectedly succeeded", path)
			}
		})
	}
}

func TestSerialDialerRejectsUnsupportedBaudBeforePlatformAccess(t *testing.T) {
	_, err := (SerialDialer{Baud: 9600}).Dial(context.Background(), "/dev/ttyACM0")
	if err == nil || err.Error() != "transport: serial currently requires 115200 baud" {
		t.Fatalf("Dial error = %v", err)
	}
}

func TestSerialDialerHonorsCanceledContextBeforePlatformAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (SerialDialer{}).Dial(ctx, "/dev/ttyACM0")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial error = %v, want context.Canceled", err)
	}
}

func TestSerialDialerRejectsNilContext(t *testing.T) {
	if _, err := (SerialDialer{}).Dial(nil, "/dev/ttyACM0"); err == nil {
		t.Fatal("Dial(nil, ...) unexpectedly succeeded")
	}
}
