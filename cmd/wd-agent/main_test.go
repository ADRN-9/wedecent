package main

import (
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
