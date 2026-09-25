package transport

import (
	"context"
	"strings"
	"testing"
)

func TestMultiDialerRoutesRFCOMMLocatorThroughStrictParser(t *testing.T) {
	for _, locator := range []string{
		"rfcomm://",
		"rfcomm://01:23:45:67:89:AB/0",
		"rfcomm://01:23:45:67:89:AB/01",
		"rfcomm://01:23:45:67:89:AZ/7",
		"rfcomm://01:23:45:67:89:AB/7?channel=8",
		"rfcomm://01:23:45:67:89:AB/7#fragment",
	} {
		t.Run(locator, func(t *testing.T) {
			_, err := (MultiDialer{}).Dial(context.Background(), locator)
			if err == nil {
				t.Fatalf("Dial(%q) unexpectedly succeeded", locator)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "rfcomm") {
				t.Fatalf("Dial(%q) error = %v", locator, err)
			}
		})
	}
}
