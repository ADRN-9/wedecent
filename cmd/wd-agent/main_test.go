package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestParseServeConfigOutboundOnly(t *testing.T) {
	cfg, err := parseServeConfig([]string{
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
	cfg, err := parseServeConfig([]string{
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
	cfg, err := parseServeConfig([]string{
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
			_, err := parseServeConfig([]string{
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
			_, err := parseServeConfig([]string{
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
	_, err := parseServeConfig([]string{"--listen="})
	if err == nil {
		t.Fatal("expected error")
	}
}
