package coreconnect

import (
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/session"
)

func TestManagedMultiplexTerminalSatisfiesCoreMultiplexStreamContract(t *testing.T) {
	var handle coreapi.ConnectionHandle = (*session.ManagedMultiplexTerminal)(nil)
	if _, ok := handle.(coreapi.MultiplexTerminalConnectionHandle); !ok {
		t.Fatal("managed multiplex terminal does not satisfy Core multiplex stream contract")
	}
}
