package mesh

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPeerValidate(t *testing.T) {
	t.Parallel()

	valid := Peer{
		ID: "wd_example",
		Capabilities: Capabilities{
			Client: true,
		},
		Transports: []TransportName{TransportLAN, TransportInternet},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid peer rejected: %v", err)
	}

	duplicate := valid
	duplicate.Transports = []TransportName{TransportLAN, TransportLAN}
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate transport accepted")
	}
}

func TestRouteValidateDirect(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	route := Route{
		ID:          "route-direct",
		Source:      "wd_a",
		Destination: "wd_b",
		ExpiresAt:   now.Add(time.Minute),
		Hops: []RouteHop{{
			From:      "wd_a",
			To:        "wd_b",
			Transport: TransportLAN,
			Cost:      10,
		}},
	}

	if err := route.Validate(now); err != nil {
		t.Fatalf("valid direct route rejected: %v", err)
	}
	if got := route.Cost(); got != 10 {
		t.Fatalf("Cost() = %d, want 10", got)
	}
}

func TestRouteRejectsLoop(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	route := Route{
		ID:          "route-loop",
		Source:      "wd_a",
		Destination: "wd_d",
		ExpiresAt:   now.Add(time.Minute),
		Hops: []RouteHop{
			{From: "wd_a", To: "wd_b", Transport: TransportLAN},
			{From: "wd_b", To: "wd_c", Transport: TransportInternet},
			{From: "wd_c", To: "wd_b", Transport: TransportBluetooth},
			{From: "wd_b", To: "wd_d", Transport: TransportInternet},
		},
	}

	if err := route.Validate(now); err == nil {
		t.Fatal("looping route accepted")
	}
}

func TestRouteRejectsDiscontinuity(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	route := Route{
		ID:          "route-broken",
		Source:      "wd_a",
		Destination: "wd_d",
		ExpiresAt:   now.Add(time.Minute),
		Hops: []RouteHop{
			{From: "wd_a", To: "wd_b", Transport: TransportLAN},
			{From: "wd_c", To: "wd_d", Transport: TransportInternet},
		},
	}

	if err := route.Validate(now); err == nil {
		t.Fatal("discontinuous route accepted")
	}
}

func TestRouteRejectsExpired(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	route := Route{
		ID:          "route-expired",
		Source:      "wd_a",
		Destination: "wd_b",
		ExpiresAt:   now,
		Hops: []RouteHop{{
			From:      "wd_a",
			To:        "wd_b",
			Transport: TransportLAN,
		}},
	}

	if err := route.Validate(now); err == nil {
		t.Fatal("expired route accepted")
	}
}

func TestRouteCostSaturates(t *testing.T) {
	t.Parallel()

	route := Route{
		Hops: []RouteHop{
			{Cost: ^uint64(0)},
			{Cost: 1},
		},
	}
	if got := route.Cost(); got != ^uint64(0) {
		t.Fatalf("Cost() = %d, want saturation", got)
	}
}

func TestLowestCostPlanner(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	direct := Route{
		ID:          "direct",
		Source:      "wd_a",
		Destination: "wd_c",
		ExpiresAt:   now.Add(time.Minute),
		Hops: []RouteHop{{
			From: "wd_a", To: "wd_c", Transport: TransportInternet, Cost: 30,
		}},
	}
	oneHop := Route{
		ID:          "one-hop",
		Source:      "wd_a",
		Destination: "wd_c",
		ExpiresAt:   now.Add(time.Minute),
		Hops: []RouteHop{
			{From: "wd_a", To: "wd_b", Transport: TransportLAN, Cost: 5},
			{From: "wd_b", To: "wd_c", Transport: TransportInternet, Cost: 10},
		},
	}

	got, err := (LowestCostPlanner{}).Plan(context.Background(), PlanRequest{
		Source:      "wd_a",
		Destination: "wd_c",
		Candidates:  []Route{direct, oneHop},
		Now:         now,
	})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}
	if got.ID != "one-hop" {
		t.Fatalf("Plan() selected %q, want one-hop", got.ID)
	}
}

func TestLowestCostPlannerTiePrefersFewerHops(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	twoHop := Route{
		ID:          "two-hop",
		Source:      "wd_a",
		Destination: "wd_c",
		ExpiresAt:   now.Add(time.Minute),
		Hops: []RouteHop{
			{From: "wd_a", To: "wd_b", Transport: TransportLAN, Cost: 5},
			{From: "wd_b", To: "wd_c", Transport: TransportInternet, Cost: 5},
		},
	}
	direct := Route{
		ID:          "direct",
		Source:      "wd_a",
		Destination: "wd_c",
		ExpiresAt:   now.Add(time.Minute),
		Hops: []RouteHop{{
			From: "wd_a", To: "wd_c", Transport: TransportInternet, Cost: 10,
		}},
	}

	got, err := (LowestCostPlanner{}).Plan(context.Background(), PlanRequest{
		Source:      "wd_a",
		Destination: "wd_c",
		Candidates:  []Route{twoHop, direct},
		Now:         now,
	})
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}
	if got.ID != "direct" {
		t.Fatalf("Plan() selected %q, want direct", got.ID)
	}
}

func TestLowestCostPlannerSkipsInvalidAndExpiredCandidates(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	expired := Route{
		ID:          "expired",
		Source:      "wd_a",
		Destination: "wd_b",
		ExpiresAt:   now,
		Hops: []RouteHop{{
			From: "wd_a", To: "wd_b", Transport: TransportLAN, Cost: 1,
		}},
	}

	_, err := (LowestCostPlanner{}).Plan(context.Background(), PlanRequest{
		Source:      "wd_a",
		Destination: "wd_b",
		Candidates:  []Route{expired},
		Now:         now,
	})
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("Plan() error = %v, want ErrNoRoute", err)
	}
}

func TestLowestCostPlannerHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := (LowestCostPlanner{}).Plan(ctx, PlanRequest{
		Source:      "wd_a",
		Destination: "wd_b",
		Now:         time.Unix(1_700_000_000, 0),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Plan() error = %v, want context.Canceled", err)
	}
}

func TestDisabledRouterPolicy(t *testing.T) {
	t.Parallel()

	policy := DisabledRouterPolicy()
	if policy.Enabled {
		t.Fatal("default router policy unexpectedly enables routing")
	}
	if policy.PublicRouting {
		t.Fatal("default router policy unexpectedly enables public routing")
	}
	if !policy.TrustedDevicesOnly {
		t.Fatal("default router policy should restrict to trusted devices")
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("default router policy invalid: %v", err)
	}
}

func TestRouterPolicyRejectsPublicRoutingWhileDisabled(t *testing.T) {
	t.Parallel()

	policy := DisabledRouterPolicy()
	policy.PublicRouting = true

	if err := policy.Validate(); err == nil {
		t.Fatal("public routing accepted while router is disabled")
	}
}

// Compile-time assertion that the initial planner satisfies the interface.
var _ RoutePlanner = LowestCostPlanner{}
