package meshnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/trust"
)

type endpointConnHandlerFunc func(net.Conn)

func (f endpointConnHandlerFunc) ServeConn(conn net.Conn) {
	f(conn)
}

var _ EndpointConnHandler = endpointConnHandlerFunc(nil)

func TestDestinationIngressAuthenticatesRouterBeforeHandoff(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	destinationTrust := testNeighborStore(t, routerID)

	routerRaw, destinationRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	const request = "inner-a-to-c-endpoint-tls"
	const response = "inner-c-to-a-endpoint-tls"

	handlerDone := make(chan error, 1)

	ingress := DestinationIngress{
		Identity:       destinationID,
		TrustedRouters: destinationTrust,
		Transport:      mesh.TransportInternet,
		Handler: endpointConnHandlerFunc(func(conn net.Conn) {
			buf := make([]byte, len(request))
			if _, err := io.ReadFull(conn, buf); err != nil {
				handlerDone <- fmt.Errorf("handler read: %w", err)
				return
			}
			if string(buf) != request {
				handlerDone <- fmt.Errorf(
					"handler request = %q, want %q",
					buf,
					request,
				)
				return
			}

			if _, err := conn.Write([]byte(response)); err != nil {
				handlerDone <- fmt.Errorf("handler write: %w", err)
				return
			}

			handlerDone <- nil
		}),
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ingress.Serve(ctx, destinationRaw)
	}()

	routerLink, err := DialRouteTunnelLink(
		ctx,
		routerRaw,
		routerID,
		ResolvedPeer{
			ID:          mesh.DeviceID(destinationID.ID),
			Fingerprint: fingerprintForIdentity(t, destinationID),
			Transport:   mesh.TransportInternet,
		},
	)
	if err != nil {
		t.Fatalf("DialRouteTunnelLink() error: %v", err)
	}
	defer routerLink.Close()

	if _, err := routerLink.Write([]byte(request)); err != nil {
		t.Fatalf("router Write() error: %v", err)
	}

	buf := make([]byte, len(response))
	if _, err := io.ReadFull(routerLink, buf); err != nil {
		t.Fatalf("router read: %v", err)
	}
	if string(buf) != response {
		t.Fatalf("response = %q, want %q", buf, response)
	}

	if err := <-handlerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("DestinationIngress.Serve() error: %v", err)
	}
}

func TestDestinationIngressRejectsUntrustedRouterBeforeHandoff(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")

	emptyTrust, err := trust.Open(
		filepath.Join(t.TempDir(), "trusted-routers.json"),
	)
	if err != nil {
		t.Fatalf("trust.Open() error: %v", err)
	}

	routerRaw, destinationRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var handled atomic.Bool
	ingress := DestinationIngress{
		Identity:       destinationID,
		TrustedRouters: emptyTrust,
		Transport:      mesh.TransportInternet,
		Handler: endpointConnHandlerFunc(func(net.Conn) {
			handled.Store(true)
		}),
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ingress.Serve(ctx, destinationRaw)
	}()

	routerLink, dialErr := DialRouteTunnelLink(
		ctx,
		routerRaw,
		routerID,
		ResolvedPeer{
			ID:          mesh.DeviceID(destinationID.ID),
			Fingerprint: fingerprintForIdentity(t, destinationID),
			Transport:   mesh.TransportInternet,
		},
	)
	if routerLink != nil {
		_ = routerLink.Close()
	}

	// TLS 1.3 can allow the dialing side to transiently complete before the
	// server's client-certificate trust rejection is observed. Therefore the
	// authoritative assertion is the destination's local authentication result.
	_ = dialErr

	select {
	case err := <-serveDone:
		if !errors.Is(err, ErrNeighborUntrusted) {
			t.Fatalf(
				"DestinationIngress.Serve() error = %v, want ErrNeighborUntrusted",
				err,
			)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("destination ingress did not finish trust rejection")
	}

	if handled.Load() {
		t.Fatal("untrusted router reached endpoint handler")
	}
}

func TestDestinationIngressRejectsRouteControlRoleBeforeHandoff(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	destinationTrust := testNeighborStore(t, routerID)

	routerRaw, destinationRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var handled atomic.Bool
	ingress := DestinationIngress{
		Identity:       destinationID,
		TrustedRouters: destinationTrust,
		Transport:      mesh.TransportLAN,
		Handler: endpointConnHandlerFunc(func(net.Conn) {
			handled.Store(true)
		}),
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ingress.Serve(ctx, destinationRaw)
	}()

	// Deliberately offer the A -> B route-control TLS role to a destination
	// ingress that accepts only B -> C route-tunnel TLS.
	routerLink, _ := DialRouteControlLink(
		ctx,
		routerRaw,
		routerID,
		ResolvedPeer{
			ID:          mesh.DeviceID(destinationID.ID),
			Fingerprint: fingerprintForIdentity(t, destinationID),
			Transport:   mesh.TransportLAN,
		},
	)
	if routerLink != nil {
		_ = routerLink.Close()
	}

	select {
	case err := <-serveDone:
		if err == nil {
			t.Fatal("destination ingress accepted route-control TLS role")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("destination ingress did not reject route-control role")
	}

	if handled.Load() {
		t.Fatal("route-control connection reached endpoint handler")
	}
}

func TestDestinationIngressRejectsInvalidConfigBeforeHandoff(t *testing.T) {
	t.Parallel()

	local, peer := net.Pipe()
	defer peer.Close()

	var handled atomic.Bool
	ingress := DestinationIngress{
		Handler: endpointConnHandlerFunc(func(net.Conn) {
			handled.Store(true)
		}),
	}

	err := ingress.Serve(context.Background(), local)
	if !errors.Is(err, ErrDestinationIngressConfig) {
		t.Fatalf(
			"DestinationIngress.Serve() error = %v, want ErrDestinationIngressConfig",
			err,
		)
	}
	if handled.Load() {
		t.Fatal("invalid ingress configuration reached endpoint handler")
	}

	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := peer.Read(one[:]); err == nil {
		t.Fatal("invalid ingress configuration left raw connection open")
	}
}

func TestDestinationIngressHonorsCanceledContextBeforeTLS(t *testing.T) {
	t.Parallel()

	destinationID := testIdentity(t, "destination")
	routerID := testIdentity(t, "router")
	destinationTrust := testNeighborStore(t, routerID)

	local, peer := net.Pipe()
	defer peer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var handled atomic.Bool
	ingress := DestinationIngress{
		Identity:       destinationID,
		TrustedRouters: destinationTrust,
		Transport:      mesh.TransportInternet,
		Handler: endpointConnHandlerFunc(func(net.Conn) {
			handled.Store(true)
		}),
	}

	err := ingress.Serve(ctx, local)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"DestinationIngress.Serve() error = %v, want context.Canceled",
			err,
		)
	}
	if handled.Load() {
		t.Fatal("canceled destination ingress reached endpoint handler")
	}
}
