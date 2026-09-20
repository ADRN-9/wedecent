package coreprocess

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/identity"
)

func TestOpenReadOnlyUsesExistingIdentityWithoutCreatingSession(t *testing.T) {
	dir := t.TempDir()
	created, err := identity.Ensure(dir, "core-test")
	if err != nil {
		t.Fatal(err)
	}

	server, err := OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	client, serverConn := net.Pipe()
	defer client.Close()

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ServeOne(context.Background(), serverConn) }()
	if err := ipc.WriteRequest(client, ipc.Request{Version: v1.Version, ID: "1", Method: v1.MethodStatusGet}); err != nil {
		t.Fatal(err)
	}
	response, err := ipc.ReadResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	var status v1.Status
	if err := json.Unmarshal(response.Result, &status); err != nil {
		t.Fatal(err)
	}
	if status.DeviceID != created.ID || status.DeviceName != "core-test" || status.SignedIn {
		t.Fatalf("status = %#v", status)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
}

func TestOpenReadOnlyMissingIdentityFailsWithoutCreatingIt(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenReadOnly(dir); err == nil {
		t.Fatal("OpenReadOnly succeeded without identity")
	}
	if _, err := identity.Load(dir); err == nil {
		t.Fatal("identity unexpectedly exists after OpenReadOnly")
	}
}

func TestRunLocalRejectsNilServerBeforeListening(t *testing.T) {
	err := RunLocal(context.Background(), nil)
	if err == nil || !errors.Is(err, errors.New("core process: IPC server is required")) && err.Error() != "core process: IPC server is required" {
		t.Fatalf("RunLocal(nil) error = %v", err)
	}
}
