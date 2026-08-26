package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConnectionGrantFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grant.jwt")
	if err := os.WriteFile(path, []byte("header.payload.signature\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readConnectionGrantFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "header.payload.signature" {
		t.Fatalf("got %q", got)
	}
}

func TestReadConnectionGrantFileRejectsEmbeddedWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grant.jwt")
	if err := os.WriteFile(path, []byte("header.payload.signature extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConnectionGrantFile(path); err == nil {
		t.Fatal("expected embedded whitespace to fail")
	}
}
