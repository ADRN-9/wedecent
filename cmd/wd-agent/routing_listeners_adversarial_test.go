package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/meshstate"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/trust"
)

const adversarialRouteKeyID = "listener-adversarial-key"

type adversarialAuthority struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func newAdversarialAuthority(t *testing.T) adversarialAuthority {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return adversarialAuthority{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

func installAdversarialAuthority(
	t *testing.T,
	stateDir string,
	authority adversarialAuthority,
) {
	t.Helper()

	path, err := meshstate.RouteAuthorizationAuthorityPath(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	content := fmt.Sprintf(
		"{\n"+
			"  \"version\": 1,\n"+
			"  \"key_id\": %q,\n"+
			"  \"public_key\": %q\n"+
			"}\n",
		adversarialRouteKeyID,
		base64.RawURLEncoding.EncodeToString(authority.publicKey),
	)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func adversarialIdentity(
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

func adversarialPeer(
	t *testing.T,
	id *identity.Identity,
	endpoint string,
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
		Endpoint:    endpoint,
	}
}

func adversarialPutPeer(
	t *testing.T,
	store *trust.Store,
	peer trust.Peer,
) {
	t.Helper()

	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
}

func adversarialRoute(
	a *identity.Identity,
	b *identity.Identity,
	c *identity.Identity,
	id string,
) mesh.Route {
	expiresAt := time.UnixMilli(
		time.Now().UTC().Add(30 * time.Second).UnixMilli(),
	).UTC()

	return mesh.Route{
		ID:          id,
		Source:      mesh.DeviceID(a.ID),
		Destination: mesh.DeviceID(c.ID),
		Hops: []mesh.RouteHop{
			{
				From:      mesh.DeviceID(a.ID),
				To:        mesh.DeviceID(b.ID),
				Transport: mesh.TransportInternet,
				Cost:      10,
			},
			{
				From:      mesh.DeviceID(b.ID),
				To:        mesh.DeviceID(c.ID),
				Transport: mesh.TransportInternet,
				Cost:      20,
			},
		},
		ExpiresAt: expiresAt,
	}
}

func adversarialAuthorization(
	t *testing.T,
	authority adversarialAuthority,
	route mesh.Route,
	router *identity.Identity,
) mesh.RouteAuthorization {
	t.Helper()

	jti, err := mesh.NewRouteAuthorizationJTI()
	if err != nil {
		t.Fatal(err)
	}

	claims := mesh.NewRouteAuthorizationClaims(
		route,
		mesh.DeviceID(router.ID),
		jti,
		time.Now().UTC().Add(-time.Second),
	)

	authorization, err := mesh.SignRouteAuthorization(
		authority.privateKey,
		adversarialRouteKeyID,
		claims,
	)
	if err != nil {
		t.Fatal(err)
	}

	return authorization
}

type adversarialEndpointResult struct {
	data []byte
	err  error
}

type adversarialEndpointHandler struct {
	results chan adversarialEndpointResult
}

func newAdversarialEndpointHandler() *adversarialEndpointHandler {
	return &adversarialEndpointHandler{
		results: make(chan adversarialEndpointResult, 8),
	}
}

func (h *adversarialEndpointHandler) ServeConn(conn net.Conn) {
	data, err := io.ReadAll(conn)

	h.results <- adversarialEndpointResult{
		data: data,
		err:  err,
	}
}

func adversarialListenerAddress(
	t *testing.T,
	set *agentListenerSet,
	role string,
) string {
	t.Helper()

	for _, listener := range set.listeners {
		if listener.role == role {
			return listener.listener.Addr().String()
		}
	}

	t.Fatalf("listener role %q not found", role)
	return ""
}

func adversarialStartListenerSet(
	t *testing.T,
	set *agentListenerSet,
) (context.CancelFunc, <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- set.serve(ctx)
	}()

	return cancel, done
}

func adversarialStopListenerSet(
	t *testing.T,
	cancel context.CancelFunc,
	set *agentListenerSet,
	done <-chan error,
) {
	t.Helper()

	cancel()
	set.close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listener set stop: %v", err)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("listener set did not stop")
	}
}

func adversarialStartRouter(
	t *testing.T,
	stateDir string,
	id *identity.Identity,
	maxConnections int,
) (
	*agentListenerSet,
	context.CancelFunc,
	<-chan error,
) {
	t.Helper()

	cfg := serveConfig{
		StateDir:               stateDir,
		ListenAddr:             "",
		MaxConnections:         1,
		RouteControlListenAddr: "127.0.0.1:0",
		RouteControlTransport:  string(mesh.TransportInternet),
		RouteMaxConnections:    maxConnections,
	}

	server := &session.Server{}

	routing, err := openAgentRoutingRuntime(
		cfg,
		id,
		server,
	)
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := openAgentListeners(
		cfg,
		server,
		routing,
	)
	if err != nil {
		t.Fatal(err)
	}

	cancel, done := adversarialStartListenerSet(t, listeners)

	return listeners, cancel, done
}

func adversarialStartDestination(
	t *testing.T,
	stateDir string,
	id *identity.Identity,
	handler meshnet.EndpointConnHandler,
) (
	*agentListenerSet,
	context.CancelFunc,
	<-chan error,
) {
	t.Helper()

	cfg := serveConfig{
		StateDir:              stateDir,
		ListenAddr:            "",
		MaxConnections:        1,
		RouteTunnelListenAddr: "127.0.0.1:0",
		RouteTunnelTransport:  string(mesh.TransportInternet),
		RouteMaxConnections:   4,
	}

	routing, err := openAgentRoutingRuntime(
		cfg,
		id,
		handler,
	)
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := openAgentListeners(
		cfg,
		&session.Server{},
		routing,
	)
	if err != nil {
		t.Fatal(err)
	}

	cancel, done := adversarialStartListenerSet(t, listeners)

	return listeners, cancel, done
}

func adversarialSourceResolver(
	t *testing.T,
	stateDir string,
	router *identity.Identity,
	routerAddress string,
) (*meshnet.TrustedPeerResolver, *trust.Store) {
	t.Helper()

	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		store,
		adversarialPeer(
			t,
			router,
			"tcp://"+routerAddress,
		),
	)

	return &meshnet.TrustedPeerResolver{
		Store: store,
	}, store
}

func adversarialDial(
	ctx context.Context,
	source *identity.Identity,
	resolver meshnet.PeerResolver,
	route mesh.Route,
	authorization mesh.RouteAuthorization,
) (net.Conn, error) {
	dialer := meshnet.RoutedDialer{
		Identity:      source,
		Resolver:      resolver,
		Route:         route,
		Authorization: authorization,
	}

	return dialer.Dial(ctx, "ignored-by-routed-dialer")
}

func requireAdversarialRouteCode(
	t *testing.T,
	err error,
	code mesh.RouteOpenCode,
) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected route rejection %q", code)
	}

	var rejected *meshnet.RouteRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf(
			"error = %v, want RouteRejectedError(%q)",
			err,
			code,
		)
	}

	if rejected.Code != code {
		t.Fatalf(
			"route code = %q, want %q",
			rejected.Code,
			code,
		)
	}
}

func adversarialClosedTCPAddress(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	address := ln.Addr().String()

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	return address
}

func TestRoutingListenerAdversarialReplaySurvivesRestartBeforeDestinationDial(
	t *testing.T,
) {
	aDir := t.TempDir()
	bDir := t.TempDir()
	cDir := t.TempDir()

	a := adversarialIdentity(t, aDir, "source-a")
	b := adversarialIdentity(t, bDir, "router-b")
	c := adversarialIdentity(t, cDir, "destination-c")

	authority := newAdversarialAuthority(t)

	installAdversarialAuthority(t, bDir, authority)
	installAdversarialAuthority(t, cDir, authority)

	cTrustedRouters, err :=
		meshnet.OpenRouteDestinationRoutersTrust(cDir)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		cTrustedRouters,
		adversarialPeer(t, b, ""),
	)

	endpoint := newAdversarialEndpointHandler()

	cListeners, cCancel, cDone :=
		adversarialStartDestination(
			t,
			cDir,
			c,
			endpoint,
		)

	cAddress := adversarialListenerAddress(
		t,
		cListeners,
		listenerRoleRouteTunnel,
	)

	bTrustedSources, err :=
		meshnet.OpenRouteRouterSourcesTrust(bDir)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		bTrustedSources,
		adversarialPeer(t, a, ""),
	)

	bTrustedDestinations, err :=
		meshnet.OpenRouteRouterDestinationsTrust(bDir)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		bTrustedDestinations,
		adversarialPeer(
			t,
			c,
			"tcp://"+cAddress,
		),
	)

	bListeners, bCancel, bDone :=
		adversarialStartRouter(t, bDir, b, 4)

	bAddress := adversarialListenerAddress(
		t,
		bListeners,
		listenerRoleRouteControl,
	)

	resolver, sourceRouters := adversarialSourceResolver(
		t,
		aDir,
		b,
		bAddress,
	)

	route := adversarialRoute(
		a,
		b,
		c,
		"listener-replay-a-b-c",
	)
	authorization := adversarialAuthorization(
		t,
		authority,
		route,
		b,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	conn, err := adversarialDial(
		ctx,
		a,
		resolver,
		route,
		authorization,
	)
	if err != nil {
		t.Fatalf("first routed dial: %v", err)
	}

	payload := []byte{
		0x16, 0x03, 0x03, 0x00,
		0x04, 0xde, 0xad, 0xbe, 0xef,
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write opaque payload: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close first tunnel: %v", err)
	}

	select {
	case result := <-endpoint.results:
		if string(result.data) != string(payload) {
			t.Fatalf(
				"destination payload = %x, want %x",
				result.data,
				payload,
			)
		}

	case <-ctx.Done():
		t.Fatal("destination did not receive first tunnel")
	}

	// Remove C completely. A replay rejection must still be route_denied;
	// route_unavailable would prove B tried to dial the now-offline C.
	adversarialStopListenerSet(
		t,
		cCancel,
		cListeners,
		cDone,
	)

	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		route,
		authorization,
	)

	requireAdversarialRouteCode(
		t,
		err,
		mesh.RouteOpenCodeDenied,
	)

	// Restart the actual B listener/runtime from the same state directory.
	// Durable replay must survive this boundary.
	adversarialStopListenerSet(
		t,
		bCancel,
		bListeners,
		bDone,
	)

	bListeners2, bCancel2, bDone2 :=
		adversarialStartRouter(t, bDir, b, 4)
	defer adversarialStopListenerSet(
		t,
		bCancel2,
		bListeners2,
		bDone2,
	)

	bAddress2 := adversarialListenerAddress(
		t,
		bListeners2,
		listenerRoleRouteControl,
	)

	adversarialPutPeer(
		t,
		sourceRouters,
		adversarialPeer(
			t,
			b,
			"tcp://"+bAddress2,
		),
	)

	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		route,
		authorization,
	)

	requireAdversarialRouteCode(
		t,
		err,
		mesh.RouteOpenCodeDenied,
	)
}

func TestRoutingListenerAdversarialAuthorizationFailuresHaveNoDialSideEffects(
	t *testing.T,
) {
	aDir := t.TempDir()
	bDir := t.TempDir()
	cDir := t.TempDir()

	a := adversarialIdentity(t, aDir, "source-a")
	b := adversarialIdentity(t, bDir, "router-b")
	c := adversarialIdentity(t, cDir, "destination-c")

	authority := newAdversarialAuthority(t)
	installAdversarialAuthority(t, bDir, authority)

	routerSources, err :=
		meshnet.OpenRouteRouterSourcesTrust(bDir)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		routerSources,
		adversarialPeer(t, a, ""),
	)

	// Destination is intentionally offline. A valid authorization therefore
	// reaches DialNext and produces route_unavailable.
	closedDestination := adversarialClosedTCPAddress(t)

	routerDestinations, err :=
		meshnet.OpenRouteRouterDestinationsTrust(bDir)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		routerDestinations,
		adversarialPeer(
			t,
			c,
			"tcp://"+closedDestination,
		),
	)

	bListeners, bCancel, bDone :=
		adversarialStartRouter(t, bDir, b, 8)
	defer adversarialStopListenerSet(
		t,
		bCancel,
		bListeners,
		bDone,
	)

	bAddress := adversarialListenerAddress(
		t,
		bListeners,
		listenerRoleRouteControl,
	)

	resolver, _ := adversarialSourceResolver(
		t,
		aDir,
		b,
		bAddress,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	// Invalid signature must be denied without consuming the JTI.
	routeSignature := adversarialRoute(
		a,
		b,
		c,
		"listener-invalid-signature",
	)
	validSignatureAuth := adversarialAuthorization(
		t,
		authority,
		routeSignature,
		b,
	)

	invalidSignatureAuth := validSignatureAuth

	if invalidSignatureAuth.Signature[0] == 'A' {
		invalidSignatureAuth.Signature =
			"B" + invalidSignatureAuth.Signature[1:]
	} else {
		invalidSignatureAuth.Signature =
			"A" + invalidSignatureAuth.Signature[1:]
	}

	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		routeSignature,
		invalidSignatureAuth,
	)

	requireAdversarialRouteCode(
		t,
		err,
		mesh.RouteOpenCodeDenied,
	)

	// The exact valid capability with the same JTI must still reach DialNext.
	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		routeSignature,
		validSignatureAuth,
	)

	requireAdversarialRouteCode(
		t,
		err,
		mesh.RouteOpenCodeUnavailable,
	)

	// Route mismatch must also avoid consuming the valid capability.
	routeMismatch := adversarialRoute(
		a,
		b,
		c,
		"listener-route-mismatch",
	)
	mismatchAuth := adversarialAuthorization(
		t,
		authority,
		routeMismatch,
		b,
	)

	alteredRoute := routeMismatch
	alteredRoute.Hops = append(
		[]mesh.RouteHop(nil),
		routeMismatch.Hops...,
	)
	alteredRoute.Hops[1].Cost++

	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		alteredRoute,
		mismatchAuth,
	)

	requireAdversarialRouteCode(
		t,
		err,
		mesh.RouteOpenCodeDenied,
	)

	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		routeMismatch,
		mismatchAuth,
	)

	requireAdversarialRouteCode(
		t,
		err,
		mesh.RouteOpenCodeUnavailable,
	)

	// Missing authorization is stable and nonsensitive.
	routeMissing := adversarialRoute(
		a,
		b,
		c,
		"listener-missing-authorization",
	)

	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		routeMissing,
		mesh.RouteAuthorization{},
	)

	requireAdversarialRouteCode(
		t,
		err,
		mesh.RouteOpenCodeDenied,
	)
}

func TestRoutingListenerAdversarialTerminalTrustDoesNotGrantRoutingTrust(
	t *testing.T,
) {
	aDir := t.TempDir()
	bDir := t.TempDir()
	cDir := t.TempDir()

	a := adversarialIdentity(t, aDir, "source-a")
	b := adversarialIdentity(t, bDir, "router-b")
	c := adversarialIdentity(t, cDir, "destination-c")

	authority := newAdversarialAuthority(t)
	installAdversarialAuthority(t, bDir, authority)

	// Deliberately trust A only in ordinary terminal trust.
	ordinaryTrust, err := trust.Open(
		filepath.Join(bDir, "trusted-clients.json"),
	)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		ordinaryTrust,
		adversarialPeer(t, a, ""),
	)

	routerSources, err :=
		meshnet.OpenRouteRouterSourcesTrust(bDir)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := routerSources.Get(a.ID); ok {
		t.Fatal("source unexpectedly present in routing trust domain")
	}

	bListeners, bCancel, bDone :=
		adversarialStartRouter(t, bDir, b, 4)
	defer adversarialStopListenerSet(
		t,
		bCancel,
		bListeners,
		bDone,
	)

	bAddress := adversarialListenerAddress(
		t,
		bListeners,
		listenerRoleRouteControl,
	)

	resolver, _ := adversarialSourceResolver(
		t,
		aDir,
		b,
		bAddress,
	)

	route := adversarialRoute(
		a,
		b,
		c,
		"listener-trust-domain-confusion",
	)
	authorization := adversarialAuthorization(
		t,
		authority,
		route,
		b,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	_, err = adversarialDial(
		ctx,
		a,
		resolver,
		route,
		authorization,
	)

	if err == nil {
		t.Fatal(
			"ordinary trusted client unexpectedly opened route-control",
		)
	}

	var rejected *meshnet.RouteRejectedError
	if errors.As(err, &rejected) {
		t.Fatalf(
			"ordinary client reached WDRT authorization; code=%q",
			rejected.Code,
		)
	}
}

func TestRoutingListenerAdversarialOversizedWDRTGetsStableInvalidRequest(
	t *testing.T,
) {
	aDir := t.TempDir()
	bDir := t.TempDir()

	a := adversarialIdentity(t, aDir, "source-a")
	b := adversarialIdentity(t, bDir, "router-b")

	authority := newAdversarialAuthority(t)
	installAdversarialAuthority(t, bDir, authority)

	routerSources, err :=
		meshnet.OpenRouteRouterSourcesTrust(bDir)
	if err != nil {
		t.Fatal(err)
	}

	adversarialPutPeer(
		t,
		routerSources,
		adversarialPeer(t, a, ""),
	)

	bListeners, bCancel, bDone :=
		adversarialStartRouter(t, bDir, b, 4)
	defer adversarialStopListenerSet(
		t,
		bCancel,
		bListeners,
		bDone,
	)

	bAddress := adversarialListenerAddress(
		t,
		bListeners,
		listenerRoleRouteControl,
	)

	raw, err := net.DialTimeout(
		"tcp",
		bAddress,
		5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}

	bFingerprint, err :=
		identity.FingerprintPublicKey(b.PublicKey)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	link, err := meshnet.DialRouteControlLink(
		ctx,
		raw,
		a,
		meshnet.ResolvedPeer{
			ID:          mesh.DeviceID(b.ID),
			Fingerprint: bFingerprint,
			Transport:   mesh.TransportInternet,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()

	if err := link.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	// WDRT v2 header: magic, version, route-open type, reserved, length.
	// Type 1 is the route-open message defined by the protocol.
	header := make([]byte, 12)
	copy(header[0:4], []byte("WDRT"))
	header[4] = byte(mesh.RouteControlVersion)
	header[5] = 1
	binary.BigEndian.PutUint32(
		header[8:12],
		uint32(mesh.MaxRouteControlPayload+1),
	)

	if _, err := link.Write(header); err != nil {
		t.Fatalf("write oversized WDRT header: %v", err)
	}

	response, err := mesh.ReadRouteOpenResponse(link)
	if err != nil {
		t.Fatalf("read stable rejection: %v", err)
	}

	if response.Accepted ||
		response.Code != mesh.RouteOpenCodeInvalidRequest {
		t.Fatalf(
			"response = %+v, want invalid_request",
			response,
		)
	}
}

func TestServeAgentListenerAdversarialCapacityReleasesAfterHandlerReturns(
	t *testing.T,
) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{})

	spec := agentListener{
		role:           listenerRoleRouteControl,
		listener:       ln,
		maxConnections: 1,
		handler: func(ctx context.Context, conn net.Conn) error {
			switch calls.Add(1) {
			case 1:
				close(firstEntered)

				select {
				case <-releaseFirst:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}

			case 2:
				close(secondEntered)
				return nil

			default:
				return errors.New("unexpected extra handler call")
			}
		},
	}

	done := make(chan error, 1)

	go func() {
		done <- serveAgentListener(ctx, spec)
	}()

	first, err := net.DialTimeout(
		"tcp",
		ln.Addr().String(),
		5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	select {
	case <-firstEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("first handler was not entered")
	}

	// While the only slot is occupied, the next accepted connection must not
	// enter the handler.
	second, err := net.DialTimeout(
		"tcp",
		ln.Addr().String(),
		5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)

	if got := calls.Load(); got != 1 {
		_ = second.Close()
		t.Fatalf(
			"handler calls while saturated = %d, want 1",
			got,
		)
	}
	_ = second.Close()

	close(releaseFirst)
	_ = first.Close()

	deadline := time.Now().Add(5 * time.Second)

	for calls.Load() < 2 && time.Now().Before(deadline) {
		probe, err := net.DialTimeout(
			"tcp",
			ln.Addr().String(),
			250*time.Millisecond,
		)
		if err == nil {
			_ = probe.Close()
		}

		select {
		case <-secondEntered:
		case <-time.After(25 * time.Millisecond):
		}
	}

	if got := calls.Load(); got != 2 {
		t.Fatalf(
			"handler calls after release = %d, want 2",
			got,
		)
	}

	cancel()
	_ = ln.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listener stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not stop after cancellation")
	}
}
