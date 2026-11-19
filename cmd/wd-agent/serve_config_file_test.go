package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestServeConfigFilePrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	contents := `{
  "listen": "192.0.2.1:9000",
  "direct_tcp_underlay": "usb_ncm",
  "rfcomm_channel": 6,
  "discover": false,
  "max_connections": 17,
  "session_idle_timeout": "45m",
  "session_max_duration": "10h",
  "relay_slots": 6,
  "route_control_transport": "lan",
  "route_max_connections": 19
}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	expanded, err := expandServeConfigArgs([]string{
		"--config", path,
		"--listen=192.0.2.1:9100",
		"--direct-tcp-underlay=usb_ncm",
		"--rfcomm-channel=7",
		"--discover=true",
		"--max-connections=23",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseServeConfig(expanded)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ListenAddr != "192.0.2.1:9100" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.DirectTCPUnderlyingTransport != "usb_ncm" {
		t.Fatalf("DirectTCPUnderlyingTransport = %q", cfg.DirectTCPUnderlyingTransport)
	}
	if cfg.RFCOMMChannel != 7 {
		t.Fatalf("RFCOMMChannel = %d", cfg.RFCOMMChannel)
	}
	if !cfg.Discover {
		t.Fatal("explicit --discover=true did not override config")
	}
	if cfg.MaxConnections != 23 {
		t.Fatalf("MaxConnections = %d", cfg.MaxConnections)
	}
	if cfg.SessionIdleTimeout != 45*time.Minute {
		t.Fatalf("SessionIdleTimeout = %v", cfg.SessionIdleTimeout)
	}
	if cfg.SessionMaxDuration != 10*time.Hour {
		t.Fatalf("SessionMaxDuration = %v", cfg.SessionMaxDuration)
	}
	if cfg.RelaySlots != 6 {
		t.Fatalf("RelaySlots = %d", cfg.RelaySlots)
	}
	if cfg.RouteControlTransport != "lan" {
		t.Fatalf("RouteControlTransport = %q", cfg.RouteControlTransport)
	}
	if cfg.RouteMaxConnections != 19 {
		t.Fatalf("RouteMaxConnections = %d", cfg.RouteMaxConnections)
	}
}

func TestServeConfigSerialFlagExpansion(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"","serial":"/dev/ttyACM0"}`)
	expanded, err := expandServeConfigArgs([]string{"--config", path})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(expanded, "\x00")
	if !strings.Contains(joined, "--serial=/dev/ttyACM0") {
		t.Fatalf("expanded = %#v", expanded)
	}
}

func TestServeConfigUnknownFieldFailsClosed(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"127.0.0.1:7443","unexpected":true}`)
	_, err := expandServeConfigArgs([]string{"--config=" + path})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeConfigRejectsMultipleJSONValues(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"127.0.0.1:7443"} {"listen":"127.0.0.1:7444"}`)
	_, err := expandServeConfigArgs([]string{"--config", path})
	if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeConfigRejectsDuplicateConfigFlags(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"127.0.0.1:7443"}`)
	_, err := expandServeConfigArgs([]string{"--config", path, "--config=" + path})
	if err == nil || !strings.Contains(err.Error(), "only once") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeConfigRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxServeConfigBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := expandServeConfigArgs([]string{"--config", path})
	if err == nil || !strings.Contains(err.Error(), "between 1 byte") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeConfigRejectsWritableByOtherUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not authoritative on Windows")
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:7443"}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := expandServeConfigArgs([]string{"--config", path})
	if err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeConfigRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks may require elevated privileges on Windows")
	}
	target := writeServeConfigTestFile(t, `{"listen":"127.0.0.1:7443"}`)
	link := filepath.Join(filepath.Dir(target), "agent-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := expandServeConfigArgs([]string{"--config", link})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeConfigPreservesExistingNoConfigBehavior(t *testing.T) {
	args := []string{"--listen=127.0.0.1:7443", "--relay-slots=5"}
	expanded, err := expandServeConfigArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(expanded, "\x00") != strings.Join(args, "\x00") {
		t.Fatalf("expanded = %#v", expanded)
	}
}

func writeServeConfigTestFile(t *testing.T, contents string) string {
	t.Helper()
	contents = strings.ReplaceAll(contents, `\"`, `"`)
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServeConfigListenerOverrideClearsStaleNCMAssertion(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"192.0.2.1:7443","direct_tcp_underlay":"usb_ncm"}`)
	expanded, err := expandServeConfigArgs([]string{"--config", path, "--listen=192.0.2.2:7443"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseServeConfig(expanded)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "192.0.2.2:7443" || cfg.DirectTCPUnderlyingTransport != "" {
		t.Fatalf("listener override retained stale NCM assertion: listen=%q underlay=%q", cfg.ListenAddr, cfg.DirectTCPUnderlyingTransport)
	}

	expanded, err = expandServeConfigArgs([]string{
		"--config", path,
		"--listen=192.0.2.2:7443",
		"--direct-tcp-underlay=usb_ncm",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = parseServeConfig(expanded)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DirectTCPUnderlyingTransport != "usb_ncm" {
		t.Fatalf("explicit NCM reassertion was cleared: %q", cfg.DirectTCPUnderlyingTransport)
	}
}

func TestServeConfigClearsNCMAssertionBeforeArgumentTerminator(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"192.0.2.1:7443","direct_tcp_underlay":"usb_ncm"}`)
	expanded, err := expandServeConfigArgs([]string{"--config", path, "--listen=192.0.2.2:7443", "--", "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	clearIndex, terminatorIndex := -1, -1
	for i, arg := range expanded {
		if arg == "--direct-tcp-underlay=" {
			clearIndex = i
		}
		if arg == "--" {
			terminatorIndex = i
		}
	}
	if clearIndex < 0 || terminatorIndex < 0 || clearIndex >= terminatorIndex {
		t.Fatalf("NCM clear flag was not placed before argument terminator: %q", expanded)
	}
}

func TestServeConfigSingleDashListenerOverrideClearsNCMAssertion(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"192.0.2.1:7443","direct_tcp_underlay":"usb_ncm"}`)
	expanded, err := expandServeConfigArgs([]string{"--config", path, "-listen=192.0.2.2:7443"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseServeConfig(expanded)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DirectTCPUnderlyingTransport != "" {
		t.Fatalf("single-dash listener override retained stale NCM assertion: %q", cfg.DirectTCPUnderlyingTransport)
	}
}

func TestServeConfigSameListenerOverridePreservesNCMAssertion(t *testing.T) {
	path := writeServeConfigTestFile(t, `{"listen":"192.0.2.1:7443","direct_tcp_underlay":"usb_ncm"}`)
	expanded, err := expandServeConfigArgs([]string{"--config", path, "--listen=192.0.2.1:7443"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseServeConfig(expanded)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DirectTCPUnderlyingTransport != "usb_ncm" {
		t.Fatalf("unchanged listener unexpectedly cleared NCM assertion: %q", cfg.DirectTCPUnderlyingTransport)
	}
}

func TestServeConfigDirectTCPUnderlayValidation(t *testing.T) {
	cfg, err := parseServeConfig([]string{"--listen=192.0.2.1:7443", "--direct-tcp-underlay=usb_ncm"})
	if err != nil || cfg.DirectTCPUnderlyingTransport != "usb_ncm" {
		t.Fatalf("valid NCM underlay: cfg=%+v err=%v", cfg, err)
	}
	if _, err := parseServeConfig([]string{"--listen=192.0.2.1:7443", "--direct-tcp-underlay=bluetooth_rfcomm"}); err == nil {
		t.Fatal("invalid direct TCP underlay was accepted")
	}
	for _, listen := range []string{"127.0.0.1:7443", "0.0.0.0:7443", "wedecent.local:7443"} {
		if _, err := parseServeConfig([]string{"--listen=" + listen, "--direct-tcp-underlay=usb_ncm"}); err == nil {
			t.Fatalf("NCM underlay accepted non-specific listener %q", listen)
		}
	}
	if _, err := parseServeConfig([]string{"--listen=", "--direct-tcp-underlay=usb_ncm"}); err == nil {
		t.Fatal("NCM underlay was accepted without a TCP listener")
	}
}

func TestRawRelayRequiresApprovedAuthorizationOrigin(t *testing.T) {
	base := []string{"--listen=", "--relay=127.0.0.1:18443"}
	if _, err := parseServeConfig(base); err == nil || !strings.Contains(err.Error(), "requires an approved") {
		t.Fatalf("raw relay without authorization origin: %v", err)
	}

	unapproved := append(append([]string{}, base...), "--authorization-url=https://relay.example.test")
	if _, err := parseServeConfig(unapproved); err == nil {
		t.Fatal("raw relay accepted an unapproved authorization origin")
	}

	approved := append(append([]string{}, base...), "--authorization-url=https://relay.wedecent.com")
	cfg, err := parseServeConfig(approved)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthorizationURL != "https://relay.wedecent.com" {
		t.Fatalf("AuthorizationURL = %q", cfg.AuthorizationURL)
	}

	fromWebRelay := append(append([]string{}, base...), "--web-relay=https://relay.wedecent.com")
	cfg, err = parseServeConfig(fromWebRelay)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthorizationURL != "https://relay.wedecent.com" {
		t.Fatalf("WebSocket relay authorization origin = %q", cfg.AuthorizationURL)
	}
}
