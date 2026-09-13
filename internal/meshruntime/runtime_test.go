package meshruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/meshstate"
	"wedecent.com/wedecent/internal/trust"
)

type endpointHandlerFunc func(net.Conn)

func (f endpointHandlerFunc) ServeConn(conn net.Conn) {
	f(conn)
}

var _ meshnet.EndpointConnHandler = endpointHandlerFunc(nil)

func testPolicy() mesh.RouterPolicy {
	return mesh.RouterPolicy{
		Enabled:            true,
		TrustedDevicesOnly: true,
		MaxSessions:        4,
	}
}

func testIdentity(
	t *testing.T,
	stateDir string,
	name string,
) *identity.Identity {
	t.Helper()

	id, err := identity.Ensure(stateDir, name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func provisionAuthority(
	t *testing.T,
	stateDir string,
) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	path, err :=
		meshstate.RouteAuthorizationAuthorityPath(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	content := fmt.Sprintf(
		"{\n"+
			"  \"version\": 1,\n"+
			"  \"key_id\": \"runtime-control-key\",\n"+
			"  \"public_key\": %q\n"+
			"}\n",
		base64.RawURLEncoding.EncodeToString(publicKey),
	)

	if err := os.WriteFile(
		path,
		[]byte(content),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	return publicKey, privateKey
}

func peerForIdentity(
	t *testing.T,
	id *identity.Identity,
) trust.Peer {
	t.Helper()

	fp, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return trust.Peer{
		ID:          id.ID,
		Name:        id.Name,
		Fingerprint: fp,
	}
}

func runtimeRoute(
	now time.Time,
	sourceID string,
	routerID string,
	destinationID string,
) mesh.Route {
	return mesh.Route{
		ID:          "runtime-a-b-c",
		Source:      mesh.DeviceID(sourceID),
		Destination: mesh.DeviceID(destinationID),
		ExpiresAt:   now.Add(90 * time.Second),
		Hops: []mesh.RouteHop{
			{
				From:      mesh.DeviceID(sourceID),
				To:        mesh.DeviceID(routerID),
				Transport: mesh.TransportLAN,
				Cost:      10,
			},
			{
				From:      mesh.DeviceID(routerID),
				To:        mesh.DeviceID(destinationID),
				Transport: mesh.TransportInternet,
				Cost:      20,
			},
		},
	}
}

func signedRuntimeAuthorization(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	now time.Time,
	route mesh.Route,
	routerID string,
	last byte,
) mesh.RouteAuthorization {
	t.Helper()

	var rawJTI [16]byte
	rawJTI[15] = last

	auth, err := mesh.SignRouteAuthorization(
		privateKey,
		"runtime-control-key",
		mesh.NewRouteAuthorizationClaims(
			route,
			mesh.DeviceID(routerID),
			base64.RawURLEncoding.EncodeToString(rawJTI[:]),
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	return auth
}

func openTestRuntime(
	t *testing.T,
	stateDir string,
	routerID *identity.Identity,
) *Runtime {
	t.Helper()

	runtime, err := Open(Config{
		StateDir: stateDir,
		Identity: routerID,
		EndpointHandler: endpointHandlerFunc(
			func(net.Conn) {},
		),
		RouterPolicy:         testPolicy(),
		DestinationTransport: mesh.TransportInternet,
		LANDiscoveryTimeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	return runtime
}

func TestOpenFailsClosedWithoutProvisionedAuthority(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()
	id := testIdentity(t, stateDir, "router")

	_, err := Open(Config{
		StateDir: stateDir,
		Identity: id,
		EndpointHandler: endpointHandlerFunc(
			func(net.Conn) {},
		),
		RouterPolicy:         testPolicy(),
		DestinationTransport: mesh.TransportInternet,
	})

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"Open() error = %v, want os.ErrNotExist",
			err,
		)
	}
}

func TestOpenBuildsNonListeningRoleSeparatedRuntime(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()
	id := testIdentity(t, stateDir, "router")
	publicKey, _ := provisionAuthority(t, stateDir)

	runtime := openTestRuntime(t, stateDir, id)

	if runtime.Identity != id {
		t.Fatal("runtime identity was not preserved")
	}
	if runtime.Authority.KeyID != "runtime-control-key" {
		t.Fatalf(
			"authority key ID = %q",
			runtime.Authority.KeyID,
		)
	}
	if !runtime.Authority.PublicKey.Equal(publicKey) {
		t.Fatal("runtime loaded the wrong route authority")
	}
	if runtime.Replay == nil {
		t.Fatal("durable replay store is nil")
	}

	if runtime.SourceRouters == nil ||
		runtime.RouterSources == nil ||
		runtime.RouterDestinations == nil ||
		runtime.DestinationRouters == nil {
		t.Fatal("one or more routing trust domains are nil")
	}

	if runtime.SourceRouters == runtime.RouterSources ||
		runtime.SourceRouters == runtime.RouterDestinations ||
		runtime.SourceRouters == runtime.DestinationRouters ||
		runtime.RouterSources == runtime.RouterDestinations ||
		runtime.RouterSources == runtime.DestinationRouters ||
		runtime.RouterDestinations == runtime.DestinationRouters {
		t.Fatal("routing trust domains unexpectedly share stores")
	}

	if runtime.SourceRouterResolver == nil ||
		runtime.SourceRouterResolver.Store != runtime.SourceRouters {
		t.Fatal("source-router resolver uses wrong trust domain")
	}

	if runtime.RouterDestinationResolver == nil ||
		runtime.RouterDestinationResolver.Store !=
			runtime.RouterDestinations {
		t.Fatal(
			"router-destination resolver uses wrong trust domain",
		)
	}

	if runtime.Router == nil ||
		runtime.Router.Authorizer == nil ||
		runtime.Router.DialNext == nil {
		t.Fatal("router composition is incomplete")
	}

	if runtime.Router.LocalID != mesh.DeviceID(id.ID) {
		t.Fatalf(
			"router local ID = %q, want %q",
			runtime.Router.LocalID,
			id.ID,
		)
	}

	if runtime.Destination.Identity != id ||
		runtime.Destination.TrustedRouters !=
			runtime.DestinationRouters ||
		runtime.Destination.Transport !=
			mesh.TransportInternet ||
		runtime.Destination.Handler == nil {
		t.Fatal("destination ingress composition is incorrect")
	}

	replayPath := filepath.Join(
		stateDir,
		RouteAuthorizationReplayFile,
	)
	if _, err := os.Stat(replayPath); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"opening runtime unexpectedly created replay state: %v",
			err,
		)
	}
}

func TestRouterAuthorizationUsesTrustedSourceAndDurableReplay(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	routerID := testIdentity(t, stateDir, "router")
	sourceID := testIdentity(t, t.TempDir(), "source")
	destinationID := testIdentity(
		t,
		t.TempDir(),
		"destination",
	)

	_, privateKey := provisionAuthority(t, stateDir)

	routerSources, err :=
		meshnet.OpenRouteRouterSourcesTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := routerSources.Put(
		peerForIdentity(t, sourceID),
	); err != nil {
		t.Fatal(err)
	}

	runtime := openTestRuntime(t, stateDir, routerID)

	now := time.Now().UTC().Truncate(time.Millisecond)
	route := runtimeRoute(
		now,
		sourceID.ID,
		routerID.ID,
		destinationID.ID,
	)

	auth := signedRuntimeAuthorization(
		t,
		privateKey,
		now,
		route,
		routerID.ID,
		1,
	)

	request := mesh.ForwardRequest{
		Router:        mesh.DeviceID(routerID.ID),
		Route:         route,
		Authorization: auth,
		Policy:        runtime.Router.Policy,
	}

	if err := runtime.Router.Authorizer.AuthorizeForward(
		context.Background(),
		request,
	); err != nil {
		t.Fatalf(
			"first authorization failed: %v",
			err,
		)
	}

	err = runtime.Router.Authorizer.AuthorizeForward(
		context.Background(),
		request,
	)
	if !errors.Is(
		err,
		mesh.ErrRouteAuthorizationReplay,
	) {
		t.Fatalf(
			"second authorization error = %v, want replay",
			err,
		)
	}

	// Reopen the production composition to model process restart. The same
	// capability must remain consumed.
	runtime = nil

	reopened := openTestRuntime(t, stateDir, routerID)

	err = reopened.Router.Authorizer.AuthorizeForward(
		context.Background(),
		mesh.ForwardRequest{
			Router:        mesh.DeviceID(routerID.ID),
			Route:         route,
			Authorization: auth,
			Policy:        reopened.Router.Policy,
		},
	)
	if !errors.Is(
		err,
		mesh.ErrRouteAuthorizationReplay,
	) {
		t.Fatalf(
			"reopened authorization error = %v, want replay",
			err,
		)
	}
}

func TestUntrustedSourceDenialDoesNotConsumeCapability(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	routerID := testIdentity(t, stateDir, "router")
	sourceID := testIdentity(t, t.TempDir(), "source")
	destinationID := testIdentity(
		t,
		t.TempDir(),
		"destination",
	)

	_, privateKey := provisionAuthority(t, stateDir)

	runtime := openTestRuntime(t, stateDir, routerID)

	now := time.Now().UTC().Truncate(time.Millisecond)
	route := runtimeRoute(
		now,
		sourceID.ID,
		routerID.ID,
		destinationID.ID,
	)

	auth := signedRuntimeAuthorization(
		t,
		privateKey,
		now,
		route,
		routerID.ID,
		2,
	)

	request := mesh.ForwardRequest{
		Router:        mesh.DeviceID(routerID.ID),
		Route:         route,
		Authorization: auth,
		Policy:        runtime.Router.Policy,
	}

	err := runtime.Router.Authorizer.AuthorizeForward(
		context.Background(),
		request,
	)
	if !errors.Is(err, mesh.ErrForwardDenied) {
		t.Fatalf(
			"untrusted source error = %v, want forward denied",
			err,
		)
	}

	replayPath := filepath.Join(
		stateDir,
		RouteAuthorizationReplayFile,
	)
	if _, err := os.Stat(replayPath); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"local denial consumed/persisted JTI: %v",
			err,
		)
	}

	if err := runtime.RouterSources.Put(
		peerForIdentity(t, sourceID),
	); err != nil {
		t.Fatal(err)
	}

	// The exact same capability must remain usable because local denial ran
	// before signed-capability consumption.
	if err := runtime.Router.Authorizer.AuthorizeForward(
		context.Background(),
		request,
	); err != nil {
		t.Fatalf(
			"authorization after adding source trust failed: %v",
			err,
		)
	}

	if _, err := os.Stat(replayPath); err != nil {
		t.Fatalf(
			"successful authorization did not persist replay state: %v",
			err,
		)
	}
}

func TestOpenRejectsUnsupportedStage3Policy(
	t *testing.T,
) {
	t.Parallel()

	id := testIdentity(t, t.TempDir(), "router")

	tests := []mesh.RouterPolicy{
		{
			Enabled:            true,
			TrustedDevicesOnly: false,
		},
		{
			Enabled:            true,
			TrustedDevicesOnly: true,
			PublicRouting:      true,
		},
	}

	for i, policy := range tests {
		policy := policy

		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			t.Parallel()

			_, err := Open(Config{
				StateDir: t.TempDir(),
				Identity: id,
				EndpointHandler: endpointHandlerFunc(
					func(net.Conn) {},
				),
				RouterPolicy:         policy,
				DestinationTransport: mesh.TransportInternet,
			})

			if !errors.Is(err, ErrUnsupportedPolicy) {
				t.Fatalf(
					"Open() error = %v, want unsupported policy",
					err,
				)
			}
		})
	}
}

func TestOpenRejectsUnsupportedDestinationTransport(
	t *testing.T,
) {
	t.Parallel()

	id := testIdentity(t, t.TempDir(), "router")

	_, err := Open(Config{
		StateDir: t.TempDir(),
		Identity: id,
		EndpointHandler: endpointHandlerFunc(
			func(net.Conn) {},
		),
		RouterPolicy:         testPolicy(),
		DestinationTransport: mesh.TransportBluetooth,
	})

	if !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatalf(
			"Open() error = %v, want unsupported transport",
			err,
		)
	}
}
