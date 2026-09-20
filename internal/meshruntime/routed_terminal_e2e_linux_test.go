//go:build linux

package meshruntime_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/meshruntime"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/trust"
)

const routedE2EKeyID = "route-e2e-key"

type routedE2ENoopHandler struct{}

func (routedE2ENoopHandler) ServeConn(conn net.Conn) {
	_ = conn.Close()
}

type routedE2EDirectAuthorizer struct {
	source      string
	destination string
	grant       string
}

func (a routedE2EDirectAuthorizer) Authorize(
	ctx context.Context,
	source string,
	destination string,
	grant string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if source != a.source || destination != a.destination || grant != a.grant {
		return errors.New("unexpected routed terminal authorization")
	}
	return nil
}

func TestRoutedTerminalE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	aDir := filepath.Join(t.TempDir(), "a")
	bDir := filepath.Join(t.TempDir(), "b")
	cDir := filepath.Join(t.TempDir(), "c")

	aID, err := identity.Ensure(aDir, "route-source-a")
	if err != nil {
		t.Fatal(err)
	}
	bID, err := identity.Ensure(bDir, "route-router-b")
	if err != nil {
		t.Fatal(err)
	}
	cID, err := identity.Ensure(cDir, "route-destination-c")
	if err != nil {
		t.Fatal(err)
	}

	aFP := routedE2EFingerprint(t, aID)
	bFP := routedE2EFingerprint(t, bID)
	cFP := routedE2EFingerprint(t, cID)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, stateDir := range []string{bDir, cDir} {
		if err := routedE2EWriteAuthority(stateDir, publicKey); err != nil {
			t.Fatal(err)
		}
	}

	cListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cListener.Close()

	bListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bListener.Close()

	terminalTrust, err := trust.Open(filepath.Join(cDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := terminalTrust.Put(trust.Peer{
		ID:          aID.ID,
		Name:        aID.Name,
		Fingerprint: aFP,
	}); err != nil {
		t.Fatal(err)
	}

	const connectionGrant = "route-e2e.connection.grant"
	endpointServer := &session.Server{
		Identity: aNilIdentity(cID),
		Trust:    terminalTrust,
		StateDir: cDir,
		Shell:    "/bin/sh",
		DirectAuthorizer: routedE2EDirectAuthorizer{
			source:      aID.ID,
			destination: cID.ID,
			grant:       connectionGrant,
		},
	}

	policy := mesh.RouterPolicy{
		Enabled:            true,
		TrustedDevicesOnly: true,
		MaxSessions:        4,
	}

	bRuntime, err := meshruntime.Open(meshruntime.Config{
		StateDir:             bDir,
		Identity:             bID,
		EndpointHandler:      routedE2ENoopHandler{},
		RouterPolicy:         policy,
		DestinationTransport: mesh.TransportInternet,
	})
	if err != nil {
		t.Fatal(err)
	}
	cRuntime, err := meshruntime.Open(meshruntime.Config{
		StateDir:             cDir,
		Identity:             cID,
		EndpointHandler:      endpointServer,
		RouterPolicy:         policy,
		DestinationTransport: mesh.TransportInternet,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := bRuntime.RouterSources.Put(trust.Peer{
		ID:          aID.ID,
		Name:        aID.Name,
		Fingerprint: aFP,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bRuntime.RouterDestinations.Put(trust.Peer{
		ID:          cID.ID,
		Name:        cID.Name,
		Fingerprint: cFP,
		Endpoint:    "tcp://" + cListener.Addr().String(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := cRuntime.DestinationRouters.Put(trust.Peer{
		ID:          bID.ID,
		Name:        bID.Name,
		Fingerprint: bFP,
	}); err != nil {
		t.Fatal(err)
	}

	aRouterTrust, err := meshnet.OpenRouteSourceRoutersTrust(aDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := aRouterTrust.Put(trust.Peer{
		ID:          bID.ID,
		Name:        bID.Name,
		Fingerprint: bFP,
		Endpoint:    "tcp://" + bListener.Addr().String(),
	}); err != nil {
		t.Fatal(err)
	}

	cErr := make(chan error, 1)
	go func() {
		raw, err := cListener.Accept()
		if err != nil {
			cErr <- err
			return
		}
		cErr <- cRuntime.ServeRouteTunnel(ctx, raw)
	}()

	bErr := make(chan error, 1)
	go func() {
		raw, err := bListener.Accept()
		if err != nil {
			bErr <- err
			return
		}
		_, err = bRuntime.ServeRouteControl(ctx, raw, mesh.TransportInternet)
		bErr <- err
	}()

	now := time.Now().UTC().Truncate(time.Millisecond)
	route := mesh.Route{
		ID:          "00000000-0000-4000-8000-0000000000e2",
		Source:      mesh.DeviceID(aID.ID),
		Destination: mesh.DeviceID(cID.ID),
		Hops: []mesh.RouteHop{
			{
				From:      mesh.DeviceID(aID.ID),
				To:        mesh.DeviceID(bID.ID),
				Transport: mesh.TransportInternet,
				Cost:      10,
			},
			{
				From:      mesh.DeviceID(bID.ID),
				To:        mesh.DeviceID(cID.ID),
				Transport: mesh.TransportInternet,
				Cost:      20,
			},
		},
		ExpiresAt: now.Add(60 * time.Second),
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	authorization, err := mesh.SignRouteAuthorization(
		privateKey,
		routedE2EKeyID,
		mesh.NewRouteAuthorizationClaims(
			route,
			mesh.DeviceID(bID.ID),
			jti,
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	dialer := meshnet.RoutedDialer{
		Identity: aID,
		Resolver: meshnet.TrustedPeerResolver{
			Store: aRouterTrust,
		},
		Route:         route,
		Authorization: authorization,
	}

	clientTerminalTrust, err := trust.Open(filepath.Join(aDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTerminalTrust.Put(trust.Peer{
		ID:          cID.ID,
		Name:        cID.Name,
		Fingerprint: cFP,
	}); err != nil {
		t.Fatal(err)
	}

	input, err := os.CreateTemp(t.TempDir(), "routed-e2e-input-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := input.WriteString("printf 'WEDECENT_ROUTED_E2E_OK\\n'; exit\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	client := &session.Client{
		Identity:        aID,
		Trust:           clientTerminalTrust,
		Dialer:          dialer,
		ConnectionGrant: connectionGrant,
	}

	exitCode, err := client.ConnectTerminal(
		ctx,
		trust.Peer{
			ID:          cID.ID,
			Name:        cID.Name,
			Fingerprint: cFP,
		},
		input,
		&output,
	)
	if err != nil {
		t.Fatalf("ConnectTerminal() error: %v; output=%q", err, output.String())
	}
	if exitCode != 0 {
		t.Fatalf("ConnectTerminal() exit code = %d; output=%q", exitCode, output.String())
	}
	if !strings.Contains(output.String(), "WEDECENT_ROUTED_E2E_OK") {
		t.Fatalf("routed terminal marker missing; output=%q", output.String())
	}

	for name, ch := range map[string]<-chan error{
		"router":      bErr,
		"destination": cErr,
	} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("%s runtime error: %v", name, err)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s runtime: %v", name, ctx.Err())
		}
	}
}

func routedE2EFingerprint(t *testing.T, id *identity.Identity) string {
	t.Helper()
	fp, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func routedE2EWriteAuthority(stateDir string, publicKey ed25519.PublicKey) error {
	data, err := json.Marshal(map[string]any{
		"version":    1,
		"key_id":     routedE2EKeyID,
		"public_key": base64.RawURLEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(
		filepath.Join(stateDir, "route-authorization-authority.json"),
		data,
		0o600,
	)
}

// aNilIdentity makes accidental replacement of the endpoint identity obvious
// in compiler errors while keeping the setup line visually distinct.
func aNilIdentity(id *identity.Identity) *identity.Identity {
	if id == nil {
		panic(fmt.Sprintf("nil routed e2e identity"))
	}
	return id
}
