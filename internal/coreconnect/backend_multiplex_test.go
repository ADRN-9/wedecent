package coreconnect

import (
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/session"
)

func TestManagedMultiplexTerminalSatisfiesCoreHandleContracts(t *testing.T) {
	var handle coreapi.ConnectionHandle = (*session.ManagedMultiplexTerminal)(nil)

	if _, ok := handle.(coreapi.TerminalConnectionHandle); !ok {
		t.Fatal("managed multiplex terminal does not satisfy terminal Core handle contract")
	}
	if _, ok := handle.(coreapi.ObservableConnectionHandle); !ok {
		t.Fatal("managed multiplex terminal does not satisfy observable Core handle contract")
	}
	if _, ok := handle.(coreapi.LatencyConnectionHandle); !ok {
		t.Fatal("managed multiplex terminal does not satisfy latency Core handle contract")
	}
}
