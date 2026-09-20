//go:build linux

package meshruntime_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/enrollment"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/meshruntime"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/trust"
)

const (
	stagingRoutedE2ESupabaseURL = "https://kefwiuqipnkbcqpxwqha.supabase.co"
	productionSupabaseURL       = "https://hopraknkfzxpdijhcjzv.supabase.co"
	stagingRouteAuthorityKeyID  = "TWxSlC-My5Z9h-lD9mrTmeKx7amqhfVEvRsMK6kpUdc"
)

type stagingEnrollmentMarker struct {
	Version     int    `json:"version"`
	SupabaseURL string `json:"supabase_url"`
	UserID      string `json:"user_id"`
	DeviceID    string `json:"device_id"`
	Kind        string `json:"kind"`
}

type stagingRouteAuthorityDocument struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type stagingRoutedNoopHandler struct{}

func (stagingRoutedNoopHandler) ServeConn(conn net.Conn) {
	_ = conn.Close()
}

type stagingRoutedGrantAuthorizer struct {
	source      string
	destination string
	grant       string
}

func (a stagingRoutedGrantAuthorizer) Authorize(
	ctx context.Context,
	source string,
	destination string,
	grant string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if source != a.source || destination != a.destination || grant != a.grant {
		return errors.New("unexpected live staging terminal authorization")
	}
	return nil
}

// TestStagingRoutedTerminalE2E is deliberately opt-in. It uses the hosted
// WeDecent Staging control plane for login, persistent device enrollment,
// connection-grant issuance, and route-capability issuance while exercising
// the real A -> B -> C routed terminal data path over authenticated TCP links.
//
// The three identities live under a persistent self-hosted-runner directory so
// staging is enrolled only once instead of accumulating throw-away devices on
// every run. Normal unit/CI runs compile this test and skip it.
func TestStagingRoutedTerminalE2E(t *testing.T) {
	if strings.TrimSpace(os.Getenv("WEDECENT_STAGING_ROUTED_TERMINAL_E2E")) != "1" {
		t.Skip("live staging routed terminal e2e is opt-in")
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
	accountSession, err := accountClient.Login(
		ctx,
		supabaseURL,
		publishableKey,
		email,
		password,
	)
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

	stagingInstallRouteAuthority(t, bDir)
	stagingInstallRouteAuthority(t, cDir)

	aFP := stagingRoutedFingerprint(t, aID)
	bFP := stagingRoutedFingerprint(t, bID)
	cFP := stagingRoutedFingerprint(t, cID)

	connectionGrant, err := accountClient.IssueConnectionGrant(
		ctx,
		accountSession,
		aID.ID,
		cID.ID,
	)
	if err != nil {
		t.Fatal(err)
	}

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

	cTerminalTrust, err := trust.Open(filepath.Join(cDir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cTerminalTrust.Put(trust.Peer{
		ID:          aID.ID,
		Name:        aID.Name,
		Fingerprint: aFP,
	}); err != nil {
		t.Fatal(err)
	}

	endpointServer := &session.Server{
		Identity: cID,
		Trust:    cTerminalTrust,
		StateDir: cDir,
		Shell:    "/bin/sh",
		DirectAuthorizer: stagingRoutedGrantAuthorizer{
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
		EndpointHandler:      stagingRoutedNoopHandler{},
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

	aTerminalTrust, err := trust.Open(filepath.Join(aDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := aTerminalTrust.Put(trust.Peer{
		ID:          cID.ID,
		Name:        cID.Name,
		Fingerprint: cFP,
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

	dialer := meshnet.RoutedDialer{
		Identity: aID,
		Resolver: meshnet.TrustedPeerResolver{
			Store: aRouterTrust,
		},
		Route:         route,
		Authorization: authorization,
	}

	input, err := os.CreateTemp(t.TempDir(), "staging-routed-e2e-input-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := input.WriteString("printf 'WEDECENT_STAGING_ROUTED_TERMINAL_E2E_OK\\n'; exit\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	client := &session.Client{
		Identity:        aID,
		Trust:           aTerminalTrust,
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
	if !strings.Contains(output.String(), "WEDECENT_STAGING_ROUTED_TERMINAL_E2E_OK") {
		t.Fatalf("staging routed terminal marker missing; output=%q", output.String())
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

	t.Log("WEDECENT_STAGING_ROUTED_TERMINAL_E2E_OK")
}

func stagingEnsureEnrolled(
	t *testing.T,
	ctx context.Context,
	client account.Client,
	accountSession *account.Session,
	id *identity.Identity,
	kind string,
	stateDir string,
) {
	t.Helper()

	markerPath := filepath.Join(stateDir, ".staging-enrollment.json")
	if data, err := os.ReadFile(markerPath); err == nil {
		var marker stagingEnrollmentMarker
		if err := json.Unmarshal(data, &marker); err != nil {
			t.Fatalf("parse %s: %v", markerPath, err)
		}
		if marker.Version != 1 ||
			marker.SupabaseURL != accountSession.SupabaseURL ||
			marker.UserID != accountSession.UserID ||
			marker.DeviceID != id.ID ||
			marker.Kind != kind {
			t.Fatalf("persistent staging enrollment marker does not match %s", id.ID)
		}
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	publicKey := base64.RawURLEncoding.EncodeToString(id.PublicKey)
	challenge, err := client.RequestDeviceEnrollmentChallenge(
		ctx,
		accountSession,
		account.DeviceEnrollmentRequest{
			Action:    "challenge",
			DeviceID:  id.ID,
			PublicKey: publicKey,
			Kind:      kind,
			Name:      id.Name,
		},
	)
	if err != nil {
		t.Fatalf("request enrollment challenge for %s: %v", id.ID, err)
	}

	message, err := enrollment.Message(enrollment.ProofFields{
		ChallengeID:    challenge.ChallengeID,
		Challenge:      challenge.Challenge,
		UserID:         challenge.UserID,
		DeviceID:       id.ID,
		PublicKey:      publicKey,
		Kind:           kind,
		OrganizationID: challenge.OrganizationID,
		ExpiresUnixMS:  challenge.ExpiresUnixMS,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.CompleteDeviceEnrollment(
		ctx,
		accountSession,
		account.DeviceEnrollmentProof{
			ChallengeID:    challenge.ChallengeID,
			Challenge:      challenge.Challenge,
			DeviceID:       id.ID,
			PublicKey:      publicKey,
			Kind:           kind,
			Name:           id.Name,
			OrganizationID: challenge.OrganizationID,
			ExpiresUnixMS:  challenge.ExpiresUnixMS,
			Signature: base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(id.PrivateKey, message),
			),
		},
	)
	if err != nil {
		t.Fatalf("complete enrollment for %s: %v", id.ID, err)
	}

	markerData, err := json.Marshal(stagingEnrollmentMarker{
		Version:     1,
		SupabaseURL: accountSession.SupabaseURL,
		UserID:      accountSession.UserID,
		DeviceID:    id.ID,
		Kind:        kind,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, markerData, 0o600); err != nil {
		t.Fatalf("write persistent staging enrollment marker: %v", err)
	}
}

func stagingInstallRouteAuthority(t *testing.T, stateDir string) {
	t.Helper()

	raw := strings.TrimSpace(os.Getenv("WEDECENT_STAGING_ROUTE_AUTHORITY_JSON"))
	if raw == "" {
		t.Fatal("WEDECENT_STAGING_ROUTE_AUTHORITY_JSON is required")
	}

	var document stagingRouteAuthorityDocument
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		t.Fatal("WEDECENT_STAGING_ROUTE_AUTHORITY_JSON is invalid JSON")
	}
	if document.Version != 1 || document.KeyID != stagingRouteAuthorityKeyID {
		t.Fatal("staging route authority metadata does not match the expected staging signer")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(document.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("staging route authority public key is invalid")
	}

	if err := os.WriteFile(
		filepath.Join(stateDir, "route-authorization-authority.json"),
		[]byte(raw),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func stagingRoutedFingerprint(t *testing.T, id *identity.Identity) string {
	t.Helper()
	fingerprint, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func stagingRoutedMarkerSummary(marker stagingEnrollmentMarker) string {
	return fmt.Sprintf("%s/%s/%s", marker.UserID, marker.DeviceID, marker.Kind)
}
