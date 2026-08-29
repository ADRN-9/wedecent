//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestReadServicePassword(t *testing.T) {
	got, err := readServicePassword(strings.NewReader("s3cret!\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret!" {
		t.Fatalf("password = %q", got)
	}
}

func TestReadServicePasswordRejectsOversizedInput(t *testing.T) {
	_, err := readServicePassword(strings.NewReader(strings.Repeat("x", maxServicePasswordBytes+1)))
	if err == nil {
		t.Fatal("expected oversized password to be rejected")
	}
}
