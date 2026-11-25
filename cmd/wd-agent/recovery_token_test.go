package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadRecoveryAuthorityTokenRequiresPrivateRegularFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := preflightAgentState(dir); err != nil {
		t.Skipf("secure test directory unavailable: %v", err)
	}
	path := filepath.Join(dir, "token")
	token := strings.Repeat("a", 48)
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadRecoveryAuthorityToken(path)
	if err != nil {
		t.Fatalf("load private token: %v", err)
	}
	if got != token {
		t.Fatal("loaded token differs from provisioned value")
	}

	link := filepath.Join(dir, "token-link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := loadRecoveryAuthorityToken(link); err == nil {
			t.Fatal("symlink credential accepted")
		}
	} else if runtime.GOOS != "windows" {
		t.Fatalf("create symlink fixture: %v", err)
	}
}

func TestLoadRecoveryAuthorityTokenRejectsShortAndOversizedValues(t *testing.T) {
	dir := t.TempDir()
	for name, value := range map[string][]byte{
		"short":     []byte("too-short"),
		"oversized": []byte(strings.Repeat("x", maxRecoveryAuthorityTokenBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, value, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRecoveryAuthorityToken(path); err == nil {
				t.Fatal("invalid credential accepted")
			}
		})
	}
}
