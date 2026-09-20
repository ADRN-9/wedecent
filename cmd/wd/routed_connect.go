package main

import (
	"errors"
	"strings"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/mesh"
)

type routedConnectConfig struct {
	RouterDeviceID  string
	FirstTransport  string
	SecondTransport string
	FirstCost       uint64
	SecondCost      uint64
}

func buildRoutedConnectRequest(
	sourceDeviceID string,
	destinationDeviceID string,
	config routedConnectConfig,
) (account.RouteAuthorizationRequest, bool, error) {
	routerDeviceID := strings.TrimSpace(config.RouterDeviceID)
	firstTransport := strings.ToLower(strings.TrimSpace(config.FirstTransport))
	secondTransport := strings.ToLower(strings.TrimSpace(config.SecondTransport))

	enabled := routerDeviceID != "" ||
		firstTransport != "" ||
		secondTransport != "" ||
		config.FirstCost != 0 ||
		config.SecondCost != 0

	if !enabled {
		return account.RouteAuthorizationRequest{}, false, nil
	}

	if routerDeviceID == "" || firstTransport == "" || secondTransport == "" {
		return account.RouteAuthorizationRequest{}, false, errors.New("routed connections require router device ID and both hop transports")
	}

	return account.RouteAuthorizationRequest{
		SourceDeviceID:      strings.TrimSpace(sourceDeviceID),
		RouterDeviceID:      routerDeviceID,
		DestinationDeviceID: strings.TrimSpace(destinationDeviceID),
		FirstTransport:      mesh.TransportName(firstTransport),
		SecondTransport:     mesh.TransportName(secondTransport),
		FirstCost:           config.FirstCost,
		SecondCost:          config.SecondCost,
	}, true, nil
}
