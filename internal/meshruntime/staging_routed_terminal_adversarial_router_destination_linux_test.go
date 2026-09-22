//go:build linux

package meshruntime_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/meshruntime"
	"wedecent.com/wedecent/internal/trust"
)

// TestStagingRoutedTerminalAdversarialRouterDestinationTrust verifies that a
// valid staging-issued route capability does not let B forward to an untrusted
// destination. B->C routing trust is independent from both B->A source trust
// and C->B destination trust. Because B verifies and consumes a single-use
// capability before destination dialing, the trusted retry intentionally uses
// a freshly issued capability after explicit B->C trust is installed.
func TestStagingRoutedTerminalAdversarialRouterDestinationTrust(t *testing.T) {
	if strings.TrimSpace(os.Getenv("WEDECENT_STAGING_ROUTED_TERMINAL_E2E")) != "1" {
		t.Skip("live staging routed terminal adversarial test is opt-in")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	supabaseURL := strings.TrimSpace(os.Getenv("WEDECENT_STAGING_SUPABASE_URL"))
	if supabaseURL == productionSupabaseURL {
		t.Fatal("refusing production Supabase project")
	}
	if supabaseURL != stagingRoutedE2ESupabaseURL {
		t.Fatalf("refusing unknown Supabase project %q", supabaseURL)
	}

	publishableKey := strings.TrimSpace(os.Getenv("WEDECENT_STAGING_PUBLISHABLE_KEY"))
	email := strings.TrimSpace(os.Getenv("WEDECENT_STAGING_ACCOUNT_EMAIL"))
	password := os.Getenv("WEDECENT_STAGING_ACCOUNT_PASSWORD")
	if publishableKey == "" || email == "" || password == "" {
		t.Fatal("staging account environment is incomplete")
	}

	baseDir := strings.TrimSpace(os.Getenv("WEDECENT_STAGING_E2E_STATE_DIR"))
	if baseDir == "" || !filepath.IsAbs(baseDir) {
		t.Fatal("WEDECENT_STAGING_E2E_STATE_DIR must be an absolute persistent path")
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}

	aDir := filepath.Join(baseDir, "source-a")
	bDir := filepath.Join(baseDir, "router-b")
	cDir := filepath.Join(baseDir, "destination-c")

	aID, err := identity.Ensure(aDir, "staging-e2e-source-a")
	if err != nil {
		t.Fatal(err)
	}
	bID, err := identity.Ensure(bDir, "staging-e2e-router-b")
	if err != nil {
		t.Fatal(err)
	}
	cID, err := identity.Ensure(cDir, "staging-e2e-destination-c")
	if err != nil {
		t.Fatal(err)
	}

	accountClient := account.Client{}
	accountSession, err := accountClient.Login(ctx, supabaseURL, publishableKey, email, password)
	password = ""
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		logoutCtx, logoutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer logoutCancel()
		_ = accountClient.Logout(logoutCtx, accountSession)
	}()

	stagingEnsureEnrolled(t, ctx, accountClient, accountSession, aID, "client", aDir)
	stagingEnsureEnrolled(t, ctx, accountClient, accountSession, bID, "agent", bDir)
	stagingEnsureEnrolled(t, ctx, accountClient, accountSession, cID, "agent", cDir)

	aFP := stagingRoutedFingerprint(t, aID)
	bFP := stagingRoutedFingerprint(t, bID)
	cFP := stagingRoutedFingerprint(t, cID)

	issueRoute := func() (mesh.Route, mesh.RouteAuthorization) {
		t.Helper()

		route, authorization, err := accountClient.IssueRouteAuthorization(
			ctx,
			accountSession,
			account.RouteAuthorizationRequest{
				SourceDeviceID:      aID.ID,
				RouterDeviceID:      bID.ID,
				DestinationDeviceID: cID.ID,
				FirstTransport:      mesh.TransportInternet,
				SecondTransport:     mesh.TransportInternet,
				FirstCost:           10,
				SecondCost:          20,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if authorization.KeyID != stagingRouteAuthorityKeyID {
			t.Fatalf("route authorization key id = %q", authorization.KeyID)
		}
		return route, authorization
	}

	bState := t.TempDir()
	cState := t.TempDir()
	stagingInstallRouteAuthority(t, bState)
	stagingInstallRouteAuthority(t, cState)

	policy := mesh.RouterPolicy{
		Enabled:            true,
		TrustedDevicesOnly: true,
		MaxSessions:        4,
	}
	bRuntime, err := meshruntime.Open(meshruntime.Config{
		StateDir:             bState,
		Identity:             bID,
		EndpointHandler:      stagingRoutedNoopHandler{},
		RouterPolicy:         policy,
		DestinationTransport: mesh.TransportInternet,
	})
	if err != nil {
		t.Fatal(err)
	}
	cRuntime, err := meshruntime.Open(meshruntime.Config{
		StateDir:             cState,
		Identity:             cID,
		EndpointHandler:      stagingRoutedDrainHandler{},
		RouterPolicy:         policy,
		DestinationTransport: mesh.TransportInternet,
	})
	if err != nil {
		t.Fatal(err)
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

	if err := bRuntime.RouterSources.Put(trust.Peer{
		ID:          aID.ID,
		Name:        aID.Name,
		Fingerprint: aFP,
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

	aRouterTrust, err := meshnet.OpenRouteSourceRoutersTrust(t.TempDir())
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

	route, authorization := issueRoute()
	dialer := meshnet.RoutedDialer{
		Identity:      aID,
		Resolver:      meshnet.TrustedPeerResolver{Store: aRouterTrust},
		Route:         route,
		Authorization: authorization,
	}

	firstRouterErr := serveOneRouteControl(ctx, bListener, bRuntime)
	conn, err := dialer.Dial(ctx, "")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("routed dial unexpectedly succeeded without router->destination trust")
	}
	if err := waitStagingRuntime(ctx, firstRouterErr); err == nil {
		t.Fatal("router unexpectedly forwarded to untrusted destination")
	}

	if _, ok := bRuntime.RouterDestinations.Get(cID.ID); ok {
		t.Fatal("router destination trust was inferred instead of explicitly configured")
	}

	if err := bRuntime.RouterDestinations.Put(trust.Peer{
		ID:          cID.ID,
		Name:        cID.Name,
		Fingerprint: cFP,
		Endpoint:    "tcp://" + cListener.Addr().String(),
	}); err != nil {
		t.Fatal(err)
	}

	route, authorization = issueRoute()
	dialer.Route = route
	dialer.Authorization = authorization

	destinationErr := serveOneRouteTunnel(ctx, cListener, cRuntime)
	secondRouterErr := serveOneRouteControl(ctx, bListener, bRuntime)
	conn, err = dialer.Dial(ctx, "")
	if err != nil {
		t.Fatalf("fresh route capability failed after explicit router->destination trust: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitStagingRuntime(ctx, secondRouterErr); err != nil {
		t.Fatalf("router runtime after trusted destination retry: %v", err)
	}
	if err := waitStagingRuntime(ctx, destinationErr); err != nil {
		t.Fatalf("destination runtime after router trusted destination: %v", err)
	}

	t.Log("WEDECENT_STAGING_ROUTED_TERMINAL_ADVERSARIAL_ROUTER_DESTINATION_TRUST_OK")
}
