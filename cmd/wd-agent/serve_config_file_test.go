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
  "listen": "127.0.0.1:9000",
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
		"--listen=127.0.0.1:9100",
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

	if cfg.ListenAddr != "127.0.0.1:9100" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
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
