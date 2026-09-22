package v1

import "testing"

func TestConnectionWireMethodNames(t *testing.T) {
	if MethodConnectionConnect != "connection.connect" {
		t.Fatalf("MethodConnectionConnect = %q", MethodConnectionConnect)
	}
	if MethodConnectionDisconnect != "connection.disconnect" {
		t.Fatalf("MethodConnectionDisconnect = %q", MethodConnectionDisconnect)
	}
}
