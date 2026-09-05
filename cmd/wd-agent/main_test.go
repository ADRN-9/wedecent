package main

import "testing"

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

func TestParseServeConfigRejectsNoTransport(t *testing.T) {
	_, err := parseServeConfig([]string{"--listen="})
	if err == nil {
		t.Fatal("expected error")
	}
}
