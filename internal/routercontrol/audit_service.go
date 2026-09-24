package routercontrol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type routerAuditActorKey struct{}

func withRouterAuditActor(ctx context.Context, actorID string) context.Context {
	if actorID == "" {
		return ctx
	}
	return context.WithValue(ctx, routerAuditActorKey{}, actorID)
}

func routerAuditActor(ctx context.Context) string {
	actor, _ := ctx.Value(routerAuditActorKey{}).(string)
	return actor
}

type auditedRouterService struct {
	service v1.RouterService
	log     *audit.Log
	agentID string
}

var _ v1.RouterService = (*auditedRouterService)(nil)

func newAuditedRouterService(service v1.RouterService, log *audit.Log, agentID string) v1.RouterService {
	if service == nil || log == nil {
		return service
	}
	return &auditedRouterService{service: service, log: log, agentID: agentID}
}

func (s *auditedRouterService) GetRouterPolicy(ctx context.Context) (v1.RouterPolicy, error) {
	return s.service.GetRouterPolicy(ctx)
}

func (s *auditedRouterService) GetRouterStats(ctx context.Context) (v1.RouterStats, error) {
	return s.service.GetRouterStats(ctx)
}

func (s *auditedRouterService) SetRouterPolicy(ctx context.Context, req v1.SetRouterPolicyRequest) (v1.RouterPolicy, error) {
	event := audit.Event{
		Type:    "router.policy_set",
		Outcome: "attempt",
		ActorID: routerAuditActor(ctx),
		PeerID:  s.agentID,
	}
	if err := s.log.Append(event); err != nil {
		return v1.RouterPolicy{}, fmt.Errorf("%w: persist router policy audit attempt", coreapi.ErrRouterOperation)
	}

	policy, err := s.service.SetRouterPolicy(ctx, req)
	if err != nil {
		event.Outcome = "failed"
		event.Reason = routerAuditFailureReason(err)
		if auditErr := s.log.Append(event); auditErr != nil {
			slog.Warn("persistent router audit event failed", "event_type", event.Type, "error", auditErr)
		}
		return v1.RouterPolicy{}, err
	}

	event.Outcome = "success"
	if auditErr := s.log.Append(event); auditErr != nil {
		slog.Warn("persistent router audit event failed", "event_type", event.Type, "error", auditErr)
	}
	return policy, nil
}

func routerAuditFailureReason(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "request_canceled"
	case errors.Is(err, coreapi.ErrInvalidRouterPolicy):
		return "invalid_policy"
	case errors.Is(err, coreapi.ErrRouterUnavailable):
		return "router_unavailable"
	default:
		return "router_operation_failed"
	}
}
