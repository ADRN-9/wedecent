package main

import (
	"net"
	"testing"

	"wedecent.com/wedecent/internal/session"
)

func TestOpenAgentListenersRFCOMMUsesSharedSupervisor(t *testing.T) {
	original := listenRFCOMM
	t.Cleanup(func() {
		listenRFCOMM = original
	})

	var gotChannel int
	listenRFCOMM = func(channel int) (net.Listener, error) {
		gotChannel = channel
		return net.Listen("tcp", "127.0.0.1:0")
	}

	set, err := openAgentListeners(
		serveConfig{
			ListenAddr:     "",
			RFCOMMChannel:  7,
			MaxConnections: 3,
		},
		&session.Server{},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer set.close()

	if gotChannel != 7 {
		t.Fatalf("RFCOMM channel = %d", gotChannel)
	}
	if len(set.listeners) != 1 {
		t.Fatalf("listeners = %d, want 1", len(set.listeners))
	}
	listener := set.listeners[0]
	if listener.role != listenerRoleRFCOMM {
		t.Fatalf("role = %q", listener.role)
	}
	if listener.maxConnections != 3 {
		t.Fatalf("maxConnections = %d", listener.maxConnections)
	}
	if listener.handler == nil {
		t.Fatal("RFCOMM listener has no session handler")
	}
	if set.direct != nil {
		t.Fatal("RFCOMM listener must not masquerade as LAN TCP discovery listener")
	}
}

func TestOpenAgentListenersRFCOMMFailureClosesPreviouslyBoundTCP(t *testing.T) {
	original := listenRFCOMM
	t.Cleanup(func() {
		listenRFCOMM = original
	})

	listenRFCOMM = func(int) (net.Listener, error) {
		return nil, errTestRFCOMMListen
	}

	set, err := openAgentListeners(
		serveConfig{
			ListenAddr:     "127.0.0.1:0",
			RFCOMMChannel:  7,
			MaxConnections: 3,
		},
		&session.Server{},
		nil,
	)
	if err == nil {
		if set != nil {
			set.close()
		}
		t.Fatal("expected RFCOMM listener failure")
	}
}

var errTestRFCOMMListen = &rfcommTestError{}

type rfcommTestError struct{}

func (*rfcommTestError) Error() string { return "rfcomm test listen failure" }
