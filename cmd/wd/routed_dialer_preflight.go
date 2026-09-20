package main

import (
	"errors"
	"fmt"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

func validateRoutedDialerPreflight(
	route mesh.Route,
	authorization mesh.RouteAuthorization,
	now time.Time,
) error {
	if err := route.Validate(now); err != nil {
		return fmt.Errorf("invalid routed connection route: %w", err)
	}

	claims := authorization.Claims

	if claims.ExpiresUnixMS <= now.UTC().UnixMilli() {
		return errors.New("route authorization is expired")
	}

	if route.ExpiresAt.UTC().UnixMilli() != claims.ExpiresUnixMS {
		return errors.New("route authorization expiry does not match route")
	}

	claimed := claims.Route
	if claimed.ID != route.ID ||
		claimed.Source != route.Source ||
		claimed.Destination != route.Destination ||
		claimed.ExpiresAt.UTC().UnixMilli() != route.ExpiresAt.UTC().UnixMilli() ||
		len(claimed.Hops) != len(route.Hops) {
		return errors.New("route authorization does not match route")
	}

	for i := range route.Hops {
		got := route.Hops[i]
		want := claimed.Hops[i]
		if got.From != want.From ||
			got.To != want.To ||
			got.Transport != want.Transport ||
			got.Cost != want.Cost {
			return errors.New("route authorization does not match route")
		}
	}

	return nil
}
