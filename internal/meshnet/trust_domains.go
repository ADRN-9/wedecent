package meshnet

import (
	"errors"
	"path/filepath"
	"strings"

	"wedecent.com/wedecent/internal/trust"
)

const (
	// RouteSourceRoutersTrustFile is source-owned trust for routers that a
	// source endpoint may contact over the route-control TLS role.
	RouteSourceRoutersTrustFile = "trusted-route-routers.json"

	// RouteRouterSourcesTrustFile is router-owned trust for source endpoints
	// permitted to authenticate as inbound route-control neighbors.
	RouteRouterSourcesTrustFile = "trusted-route-sources.json"

	// RouteRouterDestinationsTrustFile is router-owned trust for destinations
	// that the router may dial using the route-tunnel TLS role.
	RouteRouterDestinationsTrustFile = "trusted-route-destinations.json"

	// RouteDestinationRoutersTrustFile is destination-owned trust for routers
	// permitted to authenticate as inbound route-tunnel neighbors.
	RouteDestinationRoutersTrustFile = "trusted-route-tunnel-routers.json"
)

var ErrRoutingTrustStateDir = errors.New(
	"meshnet: routing trust state directory is unavailable",
)

// RoutingTrustPaths gives every routing trust role its own persistent file.
//
// These paths are deliberately separate from trusted-clients.json. Ordinary
// terminal pairing must never implicitly grant a mesh routing role.
type RoutingTrustPaths struct {
	SourceRouters      string
	RouterSources      string
	RouterDestinations string
	DestinationRouters string
}

func RoutingTrustPathsForStateDir(
	stateDir string,
) (RoutingTrustPaths, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return RoutingTrustPaths{}, ErrRoutingTrustStateDir
	}

	return RoutingTrustPaths{
		SourceRouters: filepath.Join(
			stateDir,
			RouteSourceRoutersTrustFile,
		),
		RouterSources: filepath.Join(
			stateDir,
			RouteRouterSourcesTrustFile,
		),
		RouterDestinations: filepath.Join(
			stateDir,
			RouteRouterDestinationsTrustFile,
		),
		DestinationRouters: filepath.Join(
			stateDir,
			RouteDestinationRoutersTrustFile,
		),
	}, nil
}

func OpenRouteSourceRoutersTrust(
	stateDir string,
) (*trust.Store, error) {
	paths, err := RoutingTrustPathsForStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	return trust.Open(paths.SourceRouters)
}

func OpenRouteRouterSourcesTrust(
	stateDir string,
) (*trust.Store, error) {
	paths, err := RoutingTrustPathsForStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	return trust.Open(paths.RouterSources)
}

func OpenRouteRouterDestinationsTrust(
	stateDir string,
) (*trust.Store, error) {
	paths, err := RoutingTrustPathsForStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	return trust.Open(paths.RouterDestinations)
}

func OpenRouteDestinationRoutersTrust(
	stateDir string,
) (*trust.Store, error) {
	paths, err := RoutingTrustPathsForStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	return trust.Open(paths.DestinationRouters)
}
