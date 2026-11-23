package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/buildinfo"
	"wedecent.com/wedecent/internal/coreapi/coreprocess"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/routercontrol"
	"wedecent.com/wedecent/internal/trust"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "release-trust" {
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "wd-core: release-trust takes no arguments")
			os.Exit(2)
		}
		if err := buildinfo.WriteReleaseTrust(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "wd-core:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if err := buildinfo.Write(os.Stdout, "wd-core"); err != nil {
			fmt.Fprintln(os.Stderr, "wd-core:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "wd-core:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("wd-core", flag.ContinueOnError)
	clientStateDir := fs.String("state", state, "existing client state directory")
	supabaseURL := fs.String("supabase-url", strings.TrimSpace(os.Getenv("WEDECENT_SUPABASE_URL")), "Supabase project URL (or WEDECENT_SUPABASE_URL)")
	publishableKey := fs.String("publishable-key", strings.TrimSpace(os.Getenv("WEDECENT_SUPABASE_PUBLISHABLE_KEY")), "Supabase publishable key (or WEDECENT_SUPABASE_PUBLISHABLE_KEY)")
	routerAgentID := fs.String("router-agent-id", strings.TrimSpace(os.Getenv("WEDECENT_ROUTER_AGENT_ID")), "local router agent device ID (or WEDECENT_ROUTER_AGENT_ID)")
	routerAgentFingerprint := fs.String("router-agent-fingerprint", strings.TrimSpace(os.Getenv("WEDECENT_ROUTER_AGENT_FINGERPRINT")), "local router agent public-key fingerprint (or WEDECENT_ROUTER_AGENT_FINGERPRINT)")
	forwardingPublicKeyPath := fs.String("port-forward-authorization-public-key", "", "path to the trusted Ed25519 public key used to verify port-forwarding capabilities")
	forwardingReplayURL := fs.String("port-forward-replay-url", strings.TrimSpace(os.Getenv("WEDECENT_PORT_FORWARD_REPLAY_URL")), "independent replay authority URL (or WEDECENT_PORT_FORWARD_REPLAY_URL)")
	replayAPIKeyDefault := strings.TrimSpace(os.Getenv("WEDECENT_PORT_FORWARD_REPLAY_API_KEY"))
	if replayAPIKeyDefault == "" {
		replayAPIKeyDefault = strings.TrimSpace(os.Getenv("WEDECENT_SUPABASE_ANON_KEY"))
	}
	forwardingReplayAPIKey := fs.String("port-forward-replay-api-key", replayAPIKeyDefault, "public Supabase Data API key (never a service-role key)")
	forwardingLegacyMigration := fs.Bool("port-forward-allow-legacy-replay-migration", false, "deprecated; local replay migration is not supported by production Local Core")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-core [--state directory] [--supabase-url URL] [--publishable-key key] [--router-agent-id id --router-agent-fingerprint SHA256:hex] [--port-forward-authorization-public-key path --port-forward-replay-url https://HOST/functions/v1/port-forward-replay --port-forward-replay-api-key PUBLIC_KEY]")
	}

	agentID := strings.TrimSpace(*routerAgentID)
	agentFingerprint := strings.TrimSpace(*routerAgentFingerprint)
	if (agentID == "") != (agentFingerprint == "") {
		return errors.New("router agent ID and fingerprint must be configured together")
	}

	config := coreprocess.Config{
		ClientStateDir: *clientStateDir,
		SupabaseURL:    *supabaseURL,
		PublishableKey: *publishableKey,
	}
	if keyPath := strings.TrimSpace(*forwardingPublicKeyPath); keyPath != "" {
		publicKey, err := loadForwardingAuthorizationPublicKey(keyPath)
		if err != nil {
			return fmt.Errorf("load forwarding authorization trust anchor: %w", err)
		}
		if strings.TrimSpace(*forwardingReplayURL) == "" || strings.TrimSpace(*forwardingReplayAPIKey) == "" {
			return errors.New("Local Core port forwarding requires --port-forward-replay-url and a public --port-forward-replay-api-key; the endpoint hostname and SPKI pins must also be embedded in the release build")
		}
		if *forwardingLegacyMigration {
			return errors.New("--port-forward-allow-legacy-replay-migration is unsupported; preserve legacy replay artifacts and follow the documented identity recovery procedure")
		}
		config.Forwarding = &portforward.ManagerConfig{
			AuthorizationPublicKey: publicKey,
			Limits:                 portforward.DefaultManagerLimits(),
		}
		config.ForwardingReplayEndpoint = strings.TrimSpace(*forwardingReplayURL)
		config.ForwardingReplayAPIKey = strings.TrimSpace(*forwardingReplayAPIKey)
	} else if *forwardingLegacyMigration || strings.TrimSpace(*forwardingReplayURL) != "" || strings.TrimSpace(*forwardingReplayAPIKey) != "" {
		return errors.New("port-forward replay configuration requires --port-forward-authorization-public-key")
	}
	if agentID != "" {
		controller, err := identity.Load(*clientStateDir)
		if err != nil {
			return fmt.Errorf("load router controller identity: %w", err)
		}
		routerClient, err := routercontrol.NewAuthenticatedClient(
			routercontrol.DialLocal,
			controller,
			trust.Peer{
				ID:          agentID,
				Fingerprint: agentFingerprint,
			},
		)
		if err != nil {
			return fmt.Errorf("configure local router service: %w", err)
		}
		config.RouterService = routerClient
	}

	runtime, err := coreprocess.OpenRuntime(config)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return coreprocess.RunLocalRuntime(ctx, runtime)
}

func loadForwardingAuthorizationPublicKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < ed25519.PublicKeySize || info.Size() > 256 {
		return nil, errors.New("authorization trust anchor must be a bounded regular file, not a symlink")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), data...), nil
	}
	encoded := strings.TrimSpace(string(data))
	key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		key, err = base64.StdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("authorization trust anchor must contain exactly 32 Ed25519 public-key bytes")
	}
	return ed25519.PublicKey(key), nil
}
