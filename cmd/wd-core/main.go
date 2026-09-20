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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-core [--state directory] [--supabase-url URL] [--publishable-key key]")
	}

	server, err := coreprocess.Open(coreprocess.Config{
		ClientStateDir: *clientStateDir,
		SupabaseURL:    *supabaseURL,
		PublishableKey: *publishableKey,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return coreprocess.RunLocal(ctx, server)
}
