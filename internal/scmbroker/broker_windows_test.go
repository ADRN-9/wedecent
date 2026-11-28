//go:build windows

package scmbroker

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestBrokerServiceSIDIsStableAndFixed(t *testing.T) {
	got, err := brokerServiceSID("WeDecentSCMBroker")
	if err != nil {
		t.Fatal(err)
	}
	const want = "S-1-5-80-967815454-2107788201-2399119272-786999881-3336038536"
	if got != want {
		t.Fatalf("broker service SID = %q, want %q", got, want)
	}
	if _, err := brokerServiceSID("attacker-controlled-service"); err == nil {
		t.Fatal("unexpected service name was accepted")
	}
}

func TestBrokerAuthenticationRejectsInvalidPipeHandle(t *testing.T) {
	authorized, err := authenticateClient(windows.InvalidHandle, 1)
	if err == nil {
		t.Fatal("invalid pipe handle unexpectedly authenticated")
	}
	if authorized {
		t.Fatal("invalid pipe handle was authorized")
	}
}

func TestBrokerPipePathIsLocalNamedPipe(t *testing.T) {
	if pipePath != `\\.\pipe\WeDecent.SCM.v1` {
		t.Fatalf("pipe path = %q", pipePath)
	}
}
