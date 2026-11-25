package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestParseServeConfigOutboundOnly(t *testing.T) {
	cfg, err := parseServeConfigForTest(t, []string{
		"--listen=",
		"--web-relay=https://relay.wedecent.com",
		"--relay-slots=4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "" {
		t.Fatalf("ListenAddr = %q, want empty", cfg.ListenAddr)
	}
	if cfg.WebRelay != "https://relay.wedecent.com" {
		t.Fatalf("WebRelay = %q", cfg.WebRelay)
	}
	if cfg.RelaySlots != 4 {
		t.Fatalf("RelaySlots = %d", cfg.RelaySlots)
	}
}

func TestParseServeConfigRFCOMMOnly(t *testing.T) {
	cfg, err := parseServeConfigForTest(t, []string{
		"--listen=",
		"--rfcomm-channel=7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "" {
		t.Fatalf("ListenAddr = %q, want empty", cfg.ListenAddr)
	}
	if cfg.RFCOMMChannel != 7 {
		t.Fatalf("RFCOMMChannel = %d", cfg.RFCOMMChannel)
	}
}

func TestParseServeConfigSerialOnly(t *testing.T) {
	cfg, err := parseServeConfigForTest(t, []string{
		"--listen=",
		"--serial=/dev/ttyACM0",
	})
	if runtime.GOOS != "linux" {
		if err == nil || !strings.Contains(err.Error(), "supported only on Linux") {
			t.Fatalf("non-Linux serial error = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "" {
		t.Fatalf("ListenAddr = %q, want empty", cfg.ListenAddr)
	}
	if cfg.SerialDevice != "/dev/ttyACM0" {
		t.Fatalf("SerialDevice = %q", cfg.SerialDevice)
	}
}

func TestParseServeConfigRejectsUnsafeSerialPath(t *testing.T) {
	for _, endpoint := range []string{
		"ttyACM0",
		"/tmp/ttyACM0",
		"/dev/../tmp/ttyACM0",
		" /dev/ttyACM0 ",
		"/dev/ttyACM0?baud=9600",
	} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := parseServeConfigForTest(t, []string{
				"--listen=",
				"--serial=" + endpoint,
			})
			if err == nil || !strings.Contains(err.Error(), "--serial") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseServeConfigRejectsInvalidRFCOMMChannel(t *testing.T) {
	for _, channel := range []string{"-1", "31"} {
		t.Run(channel, func(t *testing.T) {
			_, err := parseServeConfigForTest(t, []string{
				"--listen=",
				"--rfcomm-channel=" + channel,
			})
			if err == nil || !strings.Contains(err.Error(), "rfcomm-channel") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseServeConfigRejectsNoTransport(t *testing.T) {
	_, err := parseServeConfigForTest(t, []string{"--listen="})
	if err == nil {
		t.Fatal("expected error")
	}
}

func parseServeConfigForTest(t *testing.T, args []string) (serveConfig, error) {
	t.Helper()
	t.Setenv("WEDECENT_PAIRING_RECOVERY_AUTHORITY_TOKEN", "test-only-token")
	args = append(args,
		"--pairing-recovery-authority-url=https://recovery.example",
		"--pairing-recovery-authority-spki-sha256="+strings.Repeat("0", 64),
		"--pairing-recovery-trust=/tmp/recovery-trust.json",
	)
	return parseServeConfig(args)
}

func TestParseServeConfigRequiresIndependentRecoveryAuthority(t *testing.T) {
	t.Setenv("WEDECENT_PAIRING_RECOVERY_AUTHORITY_TOKEN", "")
	_, err := parseServeConfig([]string{"--listen=127.0.0.1:7443"})
	if err == nil || !strings.Contains(err.Error(), "pairing recovery requires") {
		t.Fatalf("missing recovery authority was not rejected: %v", err)
	}
}

func TestParseServeConfigRejectsEachMissingRecoveryTrustInput(t *testing.T) {
	valid := []string{
		"--listen=127.0.0.1:7443",
		"--pairing-recovery-authority-url=https://recovery.example",
		"--pairing-recovery-authority-spki-sha256=" + strings.Repeat("0", 64),
		"--pairing-recovery-trust=/tmp/recovery-trust.json",
	}
	for _, tc := range []struct {
		name  string
		args  []string
		token string
	}{
		{name: "authority URL", args: []string{"--listen=127.0.0.1:7443", valid[2], valid[3]}, token: "test-token"},
		{name: "SPKI pin", args: []string{"--listen=127.0.0.1:7443", valid[1], valid[3]}, token: "test-token"},
		{name: "pinned trust file", args: []string{"--listen=127.0.0.1:7443", valid[1], valid[2]}, token: "test-token"},
		{name: "bearer token", args: valid, token: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WEDECENT_PAIRING_RECOVERY_AUTHORITY_TOKEN", tc.token)
			if _, err := parseServeConfig(tc.args); err == nil || !strings.Contains(err.Error(), "pairing recovery requires") {
				t.Fatalf("missing %s was not rejected: %v", tc.name, err)
			}
		})
	}
}
