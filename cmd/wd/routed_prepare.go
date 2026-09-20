package main

import (
	"context"
	"errors"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/meshnet"
)

func prepareRoutedDialer(
	ctx context.Context,
	stateDir string,
	id *identity.Identity,
	destinationDeviceID string,
	config routedConnectConfig,
	lanDiscoveryTimeout time.Duration,
	accountClient account.Client,
) (meshnet.RoutedDialer, bool, error) {
	if id == nil {
		return meshnet.RoutedDialer{}, false, errors.New("routed connection identity is required")
	}

	request, enabled, err := buildRoutedConnectRequest(
		id.ID,
		destinationDeviceID,
		config,
	)
	if err != nil {
		return meshnet.RoutedDialer{}, false, err
	}
	if !enabled {
		return meshnet.RoutedDialer{}, false, nil
	}

	if _, err := openRoutedSourceRouterTrust(
		stateDir,
		request.RouterDeviceID,
	); err != nil {
		return meshnet.RoutedDialer{}, false, err
	}

	route, authorization, err := automaticRouteAuthorization(
		ctx,
		stateDir,
		request,
		accountClient,
	)
	if err != nil {
		return meshnet.RoutedDialer{}, false, err
	}

	dialer, err := buildRoutedDialer(
		stateDir,
		id,
		route,
		authorization,
		lanDiscoveryTimeout,
	)
	if err != nil {
		return meshnet.RoutedDialer{}, false, err
	}

	return dialer, true, nil
}
