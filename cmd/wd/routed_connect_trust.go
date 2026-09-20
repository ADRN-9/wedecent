package main

import (
	"errors"
	"fmt"
	"strings"

	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

func openRoutedSourceRouterTrust(
	stateDir string,
	routerDeviceID string,
) (*trust.Store, error) {
	routerDeviceID = strings.TrimSpace(routerDeviceID)
	if routerDeviceID == "" {
		return nil, errors.New("routing router device ID is required")
	}

	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		return nil, fmt.Errorf("open source routing trust: %w", err)
	}

	if _, ok := store.Get(routerDeviceID); !ok {
		return nil, fmt.Errorf("router %s is not trusted for routing", routerDeviceID)
	}

	return store, nil
}
