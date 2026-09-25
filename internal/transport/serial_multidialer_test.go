package transport

import (
	"context"
	"strings"
	"testing"
)

func TestMultiDialerRejectsMalformedSerialLocator(t *testing.T) {
	for _, locator := range []string{
		"serial://",
		"serial://host/dev/ttyACM0",
		"serial:///dev/ttyACM0?baud=115200",
		"serial:///dev/ttyACM0#fragment",
		"serial:///dev%2FttyACM0",
		"serial:opaque",
	} {
		t.Run(locator, func(t *testing.T) {
			_, err := (MultiDialer{}).Dial(context.Background(), locator)
			if err == nil || !strings.Contains(err.Error(), "invalid serial locator") {
				t.Fatalf("Dial(%q) error = %v, want invalid serial locator", locator, err)
			}
		})
	}
}

func TestMultiDialerSerialLocatorReachesPlatformDialer(t *testing.T) {
	_, err := (MultiDialer{}).Dial(context.Background(), "serial:///dev/does-not-exist-wedecent-test")
	if err == nil {
		t.Fatal("Dial(serial locator) unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "invalid serial locator") {
		t.Fatalf("valid serial locator rejected by multiplexer: %v", err)
	}
}
