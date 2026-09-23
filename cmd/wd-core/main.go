package main

import (
	"context"
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
	"wedecent.com/wedecent/internal/routercontrol"
	"wedecent.com/wedecent/internal/trust"
)

func main() {
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-core [--state directory] [--supabase-url URL] [--publishable-key key] [--router-agent-id id --router-agent-fingerprint SHA256:hex]")
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
