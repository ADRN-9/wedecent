package main

import (
	"context"
	"errors"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/mesh"
)

func automaticRouteAuthorization(
	ctx context.Context,
	stateDir string,
	request account.RouteAuthorizationRequest,
	accountClient account.Client,
) (mesh.Route, mesh.RouteAuthorization, error) {
	path := account.SessionPath(stateDir)
	accountSession, err := account.Load(path)
	if errors.Is(err, account.ErrNoSession) {
		return mesh.Route{}, mesh.RouteAuthorization{}, errors.New("WeDecent account sign-in is required for routed connections; run 'wd account login'")
	}
	if err != nil {
		return mesh.Route{}, mesh.RouteAuthorization{}, err
	}

	fresh, refreshed, err := accountClient.EnsureFresh(ctx, accountSession, 2*time.Minute)
	if err != nil {
		return mesh.Route{}, mesh.RouteAuthorization{}, err
	}
	if refreshed {
		if err := account.Save(path, fresh); err != nil {
			return mesh.Route{}, mesh.RouteAuthorization{}, err
		}
	}

	return accountClient.IssueRouteAuthorization(ctx, fresh, request)
}
