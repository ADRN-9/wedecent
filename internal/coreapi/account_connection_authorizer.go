package coreapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/mesh"
)

// ConnectionAuthorizer is the credential-free boundary used by Local Core
// networking. Implementations keep Supabase bearer tokens inside the account
// service instead of handing sessions to transport code.
type ConnectionAuthorizer interface {
	IssueConnectionGrant(context.Context, string, string) (string, error)
	IssueRouteAuthorization(context.Context, account.RouteAuthorizationRequest) (mesh.Route, mesh.RouteAuthorization, error)
}

type connectionGrantClient interface {
	IssueConnectionGrant(context.Context, *account.Session, string, string) (string, error)
}

type routeAuthorizationClient interface {
	IssueRouteAuthorization(context.Context, *account.Session, account.RouteAuthorizationRequest) (mesh.Route, mesh.RouteAuthorization, error)
}

var _ ConnectionAuthorizer = (*AccountService)(nil)

func (s *AccountService) IssueConnectionGrant(ctx context.Context, clientDeviceID, targetDeviceID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	client, ok := s.client.(connectionGrantClient)
	if !ok {
		return "", ErrAccountNotConfigured
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	fresh, err := s.freshSessionLocked(ctx)
	if err != nil {
		return "", err
	}
	grant, err := client.IssueConnectionGrant(ctx, fresh, clientDeviceID, targetDeviceID)
	if err != nil {
		return "", fmt.Errorf("%w: issue connection grant", ErrAccountOperation)
	}
	return grant, nil
}

func (s *AccountService) IssueRouteAuthorization(ctx context.Context, request account.RouteAuthorizationRequest) (mesh.Route, mesh.RouteAuthorization, error) {
	if err := ctx.Err(); err != nil {
		return mesh.Route{}, mesh.RouteAuthorization{}, err
	}
	client, ok := s.client.(routeAuthorizationClient)
	if !ok {
		return mesh.Route{}, mesh.RouteAuthorization{}, ErrAccountNotConfigured
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	fresh, err := s.freshSessionLocked(ctx)
	if err != nil {
		return mesh.Route{}, mesh.RouteAuthorization{}, err
	}
	route, authorization, err := client.IssueRouteAuthorization(ctx, fresh, request)
	if err != nil {
		return mesh.Route{}, mesh.RouteAuthorization{}, fmt.Errorf("%w: issue route authorization", ErrAccountOperation)
	}
	return route, authorization, nil
}

func (s *AccountService) freshSessionLocked(ctx context.Context) (*account.Session, error) {
	if s.session == nil {
		return nil, ErrAccountNotConfigured
	}
	fresh, refreshed, err := s.client.EnsureFresh(ctx, s.session, 2*time.Minute)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: refresh account session", ErrAccountOperation)
	}
	if fresh == nil {
		return nil, fmt.Errorf("%w: invalid account session", ErrAccountOperation)
	}
	if refreshed {
		if err := account.Save(s.sessionPath, fresh); err != nil {
			return nil, fmt.Errorf("%w: persist refreshed session", ErrAccountOperation)
		}
		if err := s.status.SetAccountSession(fresh); err != nil {
			return nil, fmt.Errorf("%w: publish refreshed account status", ErrAccountOperation)
		}
	}
	s.session = fresh
	return fresh, nil
}
