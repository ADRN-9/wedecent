//go:build windows

package scmbroker

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDecodePublisherPolicyAcceptsCanonicalPin(t *testing.T) {
	const pin = "0123456789ABCDEF0123456789ABCDEF01234567"
	got, err := decodePublisherPolicy([]byte(`{"schema":1,"publisher_thumbprint":"` + pin + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != 1 || got.PublisherThumbprint != pin {
		t.Fatalf("unexpected policy: %#v", got)
	}
}

func TestDecodePublisherPolicyRejectsUnsafeShapes(t *testing.T) {
	cases := []string{
		`{"schema":1,"publisher_thumbprint":"0123456789abcdef0123456789abcdef01234567"}`,
		`{"schema":1,"publisher_thumbprint":"0123456789ABCDEF0123456789ABCDEF01234567","extra":true}`,
		`{"schema":1,"schema":1,"publisher_thumbprint":"0123456789ABCDEF0123456789ABCDEF01234567"}`,
		`{"schema":2,"publisher_thumbprint":"0123456789ABCDEF0123456789ABCDEF01234567"}`,
		`{"schema":1,"publisher_thumbprint":"0123456789ABCDEF0123456789ABCDEF0123456Z"}`,
		`{"schema":1,"publisher_thumbprint":"0123456789ABCDEF0123456789ABCDEF01234567"} {}`,
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if _, err := decodePublisherPolicy([]byte(input)); err == nil {
				t.Fatal("invalid publisher policy was accepted")
			}
		})
	}
}

func TestVerifyAuthenticodePublisherRejectsRelativeAndMissingFiles(t *testing.T) {
	if _, err := verifyAuthenticodePublisher("wd-agent.exe"); err == nil {
		t.Fatal("relative executable path was accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing.exe")
	if _, err := verifyAuthenticodePublisher(missing); err == nil {
		t.Fatal("missing executable was accepted")
	}
}

func TestProcessImagePathRejectsInvalidHandle(t *testing.T) {
	if _, err := processImagePath(windows.Handle(0)); err == nil {
		t.Fatal("invalid process handle produced an image path")
	}
}

func TestPublisherPolicyFailsClosedWhenNotProvisioned(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramData", root)
	if _, err := loadPublisherPolicy(); err == nil {
		t.Fatal("missing publisher policy was accepted")
	}
}

func TestPublisherPolicyRequiresUppercaseSHA1Pin(t *testing.T) {
	pin := strings.Repeat("A", 40)
	if !publisherThumbprintPattern.MatchString(pin) {
		t.Fatal("canonical SHA-1 thumbprint was rejected")
	}
	if publisherThumbprintPattern.MatchString(strings.Repeat("a", 40)) {
		t.Fatal("lowercase thumbprint was accepted")
	}
}


func TestInstallServiceRejectsUnprotectedExecutablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wd-scm-broker.exe")
	if err := InstallService(path); err == nil {
		t.Fatal("broker service accepted an executable outside Program Files")
	}
}
