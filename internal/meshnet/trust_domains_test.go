package meshnet

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"wedecent.com/wedecent/internal/trust"
)

func TestRoutingTrustPathsAreRoleSeparated(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	paths, err := RoutingTrustPathsForStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	want := RoutingTrustPaths{
		SourceRouters: filepath.Join(
			stateDir,
			"trusted-route-routers.json",
		),
		RouterSources: filepath.Join(
			stateDir,
			"trusted-route-sources.json",
		),
		RouterDestinations: filepath.Join(
			stateDir,
			"trusted-route-destinations.json",
		),
		DestinationRouters: filepath.Join(
			stateDir,
			"trusted-route-tunnel-routers.json",
		),
	}

	if paths != want {
		t.Fatalf(
			"RoutingTrustPathsForStateDir() = %+v, want %+v",
			paths,
			want,
		)
	}

	seen := map[string]bool{}
	for _, path := range []string{
		paths.SourceRouters,
		paths.RouterSources,
		paths.RouterDestinations,
		paths.DestinationRouters,
	} {
		if seen[path] {
			t.Fatalf("routing trust path reused: %q", path)
		}
		seen[path] = true

		if filepath.Base(path) == "trusted-clients.json" {
			t.Fatal(
				"routing trust reused ordinary terminal-client trust",
			)
		}
	}
}

func TestRoutingTrustStoresPersistIndependently(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	sourceRouters, err := OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	routerSources, err := OpenRouteRouterSourcesTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	routerDestinations, err :=
		OpenRouteRouterDestinationsTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	destinationRouters, err :=
		OpenRouteDestinationRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	const sameID = "wd_aaaaaaaaaaaaaaaa"

	peers := []struct {
		store       *trust.Store
		fingerprint string
	}{
		{
			sourceRouters,
			"SHA256:SOURCE-ROUTER",
		},
		{
			routerSources,
			"SHA256:ROUTER-SOURCE",
		},
		{
			routerDestinations,
			"SHA256:ROUTER-DESTINATION",
		},
		{
			destinationRouters,
			"SHA256:DESTINATION-ROUTER",
		},
	}

	for _, item := range peers {
		if err := item.store.Put(trust.Peer{
			ID:          sameID,
			Name:        "same-device-different-role",
			Fingerprint: item.fingerprint,
		}); err != nil {
			t.Fatal(err)
		}
	}

	reopenedSourceRouters, err :=
		OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	reopenedRouterSources, err :=
		OpenRouteRouterSourcesTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	reopenedRouterDestinations, err :=
		OpenRouteRouterDestinationsTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	reopenedDestinationRouters, err :=
		OpenRouteDestinationRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		store       *trust.Store
		fingerprint string
	}{
		{
			reopenedSourceRouters,
			"SHA256:SOURCE-ROUTER",
		},
		{
			reopenedRouterSources,
			"SHA256:ROUTER-SOURCE",
		},
		{
			reopenedRouterDestinations,
			"SHA256:ROUTER-DESTINATION",
		},
		{
			reopenedDestinationRouters,
			"SHA256:DESTINATION-ROUTER",
		},
	}

	for _, check := range checks {
		peer, ok := check.store.Get(sameID)
		if !ok {
			t.Fatalf(
				"peer missing from isolated trust domain %q",
				check.fingerprint,
			)
		}
		if peer.Fingerprint != check.fingerprint {
			t.Fatalf(
				"fingerprint = %q, want %q",
				peer.Fingerprint,
				check.fingerprint,
			)
		}
	}

	paths, err := RoutingTrustPathsForStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		paths.SourceRouters,
		paths.RouterSources,
		paths.RouterDestinations,
		paths.DestinationRouters,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %q: %v", path, err)
		}

		if runtime.GOOS != "windows" &&
			info.Mode().Perm() != 0o600 {
			t.Fatalf(
				"%q permissions = %o, want 600",
				path,
				info.Mode().Perm(),
			)
		}
	}
}

func TestRoutingTrustDoesNotReuseTerminalClientStore(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()
	const peerID = "wd_bbbbbbbbbbbbbbbb"

	terminalClients, err := trust.Open(
		filepath.Join(stateDir, "trusted-clients.json"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := terminalClients.Put(trust.Peer{
		ID:          peerID,
		Name:        "ordinary-terminal-client",
		Fingerprint: "SHA256:TERMINAL",
	}); err != nil {
		t.Fatal(err)
	}

	stores := []func(string) (*trust.Store, error){
		OpenRouteSourceRoutersTrust,
		OpenRouteRouterSourcesTrust,
		OpenRouteRouterDestinationsTrust,
		OpenRouteDestinationRoutersTrust,
	}

	for _, openStore := range stores {
		store, err := openStore(stateDir)
		if err != nil {
			t.Fatal(err)
		}

		if _, ok := store.Get(peerID); ok {
			t.Fatal(
				"terminal-client trust leaked into routing trust",
			)
		}
	}
}

func TestRoutingTrustRejectsEmptyStateDirectory(
	t *testing.T,
) {
	t.Parallel()

	if _, err := RoutingTrustPathsForStateDir("   "); !errors.Is(
		err,
		ErrRoutingTrustStateDir,
	) {
		t.Fatalf(
			"RoutingTrustPathsForStateDir() error = %v",
			err,
		)
	}

	if _, err := OpenRouteRouterDestinationsTrust(""); !errors.Is(
		err,
		ErrRoutingTrustStateDir,
	) {
		t.Fatalf(
			"OpenRouteRouterDestinationsTrust() error = %v",
			err,
		)
	}
}
