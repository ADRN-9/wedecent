package main

import (
	"errors"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
)

func buildRoutedDialer(
	stateDir string,
	id *identity.Identity,
	route mesh.Route,
	authorization mesh.RouteAuthorization,
	lanDiscoveryTimeout time.Duration,
) (meshnet.RoutedDialer, error) {
	if id == nil {
		return meshnet.RoutedDialer{}, errors.New("routed connection identity is required")
	}
	if len(route.Hops) != 2 {
		return meshnet.RoutedDialer{}, errors.New("routed connection requires exactly two route hops")
	}

	localID := mesh.DeviceID(id.ID)
	if route.Source != localID || route.Hops[0].From != localID {
		return meshnet.RoutedDialer{}, errors.New("routed connection source does not match local identity")
	}

	routerID := route.Hops[0].To
	if authorization.Claims.Router != routerID {
		return meshnet.RoutedDialer{}, errors.New("route authorization router does not match route")
	}

	if err := validateRoutedDialerPreflight(route, authorization, time.Now()); err != nil {
		return meshnet.RoutedDialer{}, err
	}

	store, err := openRoutedSourceRouterTrust(stateDir, string(routerID))
	if err != nil {
		return meshnet.RoutedDialer{}, err
	}

	return meshnet.RoutedDialer{
		Identity: id,
		Resolver: meshnet.TrustedPeerResolver{
			Store:               store,
			LANDiscoveryTimeout: lanDiscoveryTimeout,
		},
		Route:         route,
		Authorization: authorization,
	}, nil
}
