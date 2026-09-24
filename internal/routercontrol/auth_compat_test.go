package routercontrol

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

func TestProtocolVersionCompatibilityRouterAdminTLS(t *testing.T) {
	if RouterAdminALPN != "wedecent-router-admin/1" {
		t.Fatalf("RouterAdminALPN = %q, want wedecent-router-admin/1", RouterAdminALPN)
	}

	for _, tc := range []struct {
		name       string
		nextProtos []string
	}{
		{name: "missing", nextProtos: nil},
		{name: "older", nextProtos: []string{"wedecent-router-admin/0"}},
		{name: "newer", nextProtos: []string{"wedecent-router-admin/2"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			agent := routerControlTestIdentity(t, "agent")
			controller := routerControlTestIdentity(t, "controller")
			controllers := routerControllerStore(t)
			if err := controllers.Put(routerControlPeer(t, controller)); err != nil {
				t.Fatal(err)
			}

			clientRaw, serverRaw := routerControlTestPipe(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			serverDone := make(chan error, 1)
			go func() {
				conn, err := AcceptAuthenticated(ctx, serverRaw, agent, controllers)
				if conn != nil {
					_ = conn.Close()
				}
				serverDone <- err
			}()

			client := tls.Client(clientRaw, &tls.Config{
				MinVersion:         tls.VersionTLS13,
				Certificates:       []tls.Certificate{controller.Certificate},
				InsecureSkipVerify: true, // Test deliberately isolates server-side ALPN rejection.
				NextProtos:         tc.nextProtos,
			})
			// A TLS client with no ALPN can observe its handshake as complete before
			// the server's VerifyConnection callback rejects the negotiated state.
			// The security boundary is the authoritative router-admin server: it
			// must never return an authenticated connection for an incompatible ALPN.
			_ = client.HandshakeContext(ctx)
			_ = client.Close()

			select {
			case err := <-serverDone:
				if err == nil {
					t.Fatalf("AcceptAuthenticated(%s ALPN) unexpectedly succeeded", tc.name)
				}
			case <-ctx.Done():
				t.Fatal("router-admin server did not finish rejecting incompatible ALPN")
			}
		})
	}
}
