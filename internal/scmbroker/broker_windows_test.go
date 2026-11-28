//go:build windows

package scmbroker

import (
	"testing"
	"unsafe"

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

func TestSameTokenUserSIDRejectsCrossUserIdentity(t *testing.T) {
	userA, err := windows.StringToSid("S-1-5-21-111-222-333-1001")
	if err != nil {
		t.Fatal(err)
	}
	userB, err := windows.StringToSid("S-1-5-21-111-222-333-1002")
	if err != nil {
		t.Fatal(err)
	}
	type sidAndAttributes struct {
		SID        uintptr
		Attributes uint32
	}
	a := sidAndAttributes{SID: uintptr(unsafe.Pointer(userA))}
	b := sidAndAttributes{SID: uintptr(unsafe.Pointer(userB))}
	if sameTokenUserSID((*byte)(unsafe.Pointer(&a)), (*byte)(unsafe.Pointer(&b))) {
		t.Fatal("different user SIDs were treated as equal")
	}
	if !sameTokenUserSID((*byte)(unsafe.Pointer(&a)), (*byte)(unsafe.Pointer(&a))) {
		t.Fatal("identical user SIDs were treated as different")
	}
}


func TestVerifyBrokerServiceSIDRejectsInteractiveProcess(t *testing.T) {
	sid, err := brokerServiceSID("WeDecentSCMBroker")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBrokerServiceSID(sid); err == nil {
		t.Fatal("interactive test process unexpectedly had the broker service SID")
	}
}

func TestProcessImagePathUsesOpenProcessHandle(t *testing.T) {
	path, err := processImagePath(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, string(os.PathSeparator)) {
		t.Fatalf("process image path is not absolute: %q", path)
	}
}
