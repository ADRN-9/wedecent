// Package mesh defines transport-independent primitives for WeDecent mesh routing.
//
// This package is intentionally not wired into the v0.3 production connection path yet.
// It provides the boundaries needed for later LAN, routed, and Bluetooth transports.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// MaxRouteHops is a defensive upper bound for route validation.
// Multi-hop routing is not enabled by this package; the bound only prevents
// unbounded route objects from entering future routing code.
const MaxRouteHops = 8

// DeviceID is a WeDecent cryptographic device identifier.
//
// Mesh deliberately does not duplicate the canonical identity-format validation;
// callers should supply IDs that have already been validated by the identity layer.
type DeviceID string

// TransportName identifies a transport without binding mesh routing to
// transport-specific addresses or APIs.
type TransportName string

const (
	TransportLAN       TransportName = "lan"
	TransportInternet  TransportName = "internet"
	TransportBluetooth TransportName = "bluetooth"
)

// Capabilities describes independent roles a WeDecent node may advertise.
type Capabilities struct {
	Client   bool
	Endpoint bool
	Router   bool
}

// Peer is a discovered or known WeDecent node.
//
// Transport-specific addresses intentionally do not live here. A transport
// implementation owns its locator/address details and resolves them when dialing.
type Peer struct {
	ID           DeviceID
	Capabilities Capabilities
	Transports   []TransportName
}

// Validate performs transport-independent structural validation.
func (p Peer) Validate() error {
	if strings.TrimSpace(string(p.ID)) == "" {
		return errors.New("mesh: peer device ID is required")
	}

	seen := make(map[TransportName]struct{}, len(p.Transports))
	for _, transport := range p.Transports {
		if strings.TrimSpace(string(transport)) == "" {
			return errors.New("mesh: peer transport name is required")
		}
		if _, ok := seen[transport]; ok {
			return fmt.Errorf("mesh: duplicate peer transport %q", transport)
		}
		seen[transport] = struct{}{}
	}

	return nil
}

// Link is an authenticated neighbor-to-neighbor byte stream.
//
// Session confidentiality remains an endpoint concern. Routers may forward a
// Link's protected session bytes without learning endpoint plaintext.
type Link interface {
	io.ReadWriteCloser
	Local() DeviceID
	Remote() DeviceID
	Transport() TransportName
}

// Listener accepts authenticated neighboring links for a Transport.
type Listener interface {
	Accept(context.Context) (Link, error)
	Close() error
}

// Transport represents one method of discovering and communicating with
// neighboring WeDecent nodes.
type Transport interface {
	Name() TransportName
	Discover(context.Context) (<-chan Peer, <-chan error)
	Dial(context.Context, Peer) (Link, error)
	Listen(context.Context) (Listener, error)
}

// RouteHop is one neighbor-to-neighbor forwarding step.
type RouteHop struct {
	From      DeviceID
	To        DeviceID
	Transport TransportName

	// Cost is an abstract non-negative route-selection cost. The component that
	// constructs candidate routes decides how latency, bandwidth, metering,
	// battery use, and other policy inputs map into this value.
	Cost uint64
}

// Route is an ordered path from Source to Destination.
type Route struct {
	ID          string
	Source      DeviceID
	Destination DeviceID
	Hops        []RouteHop
	ExpiresAt   time.Time
}

// Validate checks route structure, continuity, expiry, and loops.
//
// It does not authorize the route. Authorization belongs to the control/trust
// layer and must be checked independently before forwarding.
func (r Route) Validate(now time.Time) error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("mesh: route ID is required")
	}
	if strings.TrimSpace(string(r.Source)) == "" {
		return errors.New("mesh: route source is required")
	}
	if strings.TrimSpace(string(r.Destination)) == "" {
		return errors.New("mesh: route destination is required")
	}
	if r.Source == r.Destination {
		return errors.New("mesh: route source and destination must differ")
	}
	if len(r.Hops) == 0 {
		return errors.New("mesh: route must contain at least one hop")
	}
	if len(r.Hops) > MaxRouteHops {
		return fmt.Errorf("mesh: route exceeds maximum hop count of %d", MaxRouteHops)
	}
	if r.ExpiresAt.IsZero() {
		return errors.New("mesh: route expiry is required")
	}
	if !now.Before(r.ExpiresAt) {
		return errors.New("mesh: route is expired")
	}

	expectedFrom := r.Source
	visited := map[DeviceID]struct{}{r.Source: {}}

	for i, hop := range r.Hops {
		if strings.TrimSpace(string(hop.From)) == "" || strings.TrimSpace(string(hop.To)) == "" {
			return fmt.Errorf("mesh: route hop %d has an empty device ID", i)
		}
		if strings.TrimSpace(string(hop.Transport)) == "" {
			return fmt.Errorf("mesh: route hop %d has an empty transport", i)
		}
		if hop.From != expectedFrom {
			return fmt.Errorf("mesh: route hop %d is discontinuous", i)
		}
		if hop.From == hop.To {
			return fmt.Errorf("mesh: route hop %d is a self-loop", i)
		}
		if _, ok := visited[hop.To]; ok {
			return fmt.Errorf("mesh: route hop %d introduces a loop", i)
		}

		visited[hop.To] = struct{}{}
		expectedFrom = hop.To
	}

	if expectedFrom != r.Destination {
		return errors.New("mesh: route does not terminate at destination")
	}

	return nil
}

// Cost returns the aggregate abstract cost of the route.
//
// Saturation prevents integer wraparound from making an extremely expensive
// route appear cheap.
func (r Route) Cost() uint64 {
	var total uint64
	for _, hop := range r.Hops {
		next := total + hop.Cost
		if next < total {
			return ^uint64(0)
		}
		total = next
	}
	return total
}

// RouterPolicy controls whether and under what local resource constraints a
// node may forward WeDecent sessions.
//
// Authorization of a particular peer/session remains a separate decision.
type RouterPolicy struct {
	Enabled bool

	TrustedDevicesOnly bool
	OrganizationOnly   bool
	PublicRouting      bool

	MaxSessions             int
	MaxBandwidthBytesPerSec int64

	AllowOnBattery bool
	AllowMetered   bool
	LANOnly        bool
}

// DisabledRouterPolicy returns the safe default: routing is off and public
// routing is not permitted.
func DisabledRouterPolicy() RouterPolicy {
	return RouterPolicy{
		Enabled:            false,
		TrustedDevicesOnly: true,
	}
}

// Validate checks policy structure without making an authorization decision.
func (p RouterPolicy) Validate() error {
	if p.MaxSessions < 0 {
		return errors.New("mesh: router max sessions cannot be negative")
	}
	if p.MaxBandwidthBytesPerSec < 0 {
		return errors.New("mesh: router max bandwidth cannot be negative")
	}
	if p.PublicRouting && !p.Enabled {
		return errors.New("mesh: public routing requires routing to be enabled")
	}
	return nil
}

// PlanRequest contains candidate routes already discovered or constructed by
// transport/control-plane components.
type PlanRequest struct {
	Source      DeviceID
	Destination DeviceID
	Candidates  []Route
	Now         time.Time
}

// RoutePlanner chooses an authorized candidate route.
//
// Implementations must not treat successful structural validation as
// authorization. Authorization must be established independently.
type RoutePlanner interface {
	Plan(context.Context, PlanRequest) (Route, error)
}

// ErrNoRoute indicates that no valid candidate route is currently available.
var ErrNoRoute = errors.New("mesh: no valid route")

// LowestCostPlanner is the deliberately small initial planner.
//
// It selects the structurally valid, non-expired candidate with the lowest
// aggregate Cost. Ties prefer fewer hops, then preserve candidate order.
// Transport-specific preference is expressed by the costs assigned when
// candidate routes are constructed.
type LowestCostPlanner struct{}

// Plan implements RoutePlanner.
func (LowestCostPlanner) Plan(ctx context.Context, request PlanRequest) (Route, error) {
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	if strings.TrimSpace(string(request.Source)) == "" {
		return Route{}, errors.New("mesh: plan source is required")
	}
	if strings.TrimSpace(string(request.Destination)) == "" {
		return Route{}, errors.New("mesh: plan destination is required")
	}
	if request.Now.IsZero() {
		return Route{}, errors.New("mesh: plan time is required")
	}

	var best Route
	var bestCost uint64
	found := false

	for _, candidate := range request.Candidates {
		if err := ctx.Err(); err != nil {
			return Route{}, err
		}
		if candidate.Source != request.Source || candidate.Destination != request.Destination {
			continue
		}
		if err := candidate.Validate(request.Now); err != nil {
			continue
		}

		cost := candidate.Cost()
		if !found ||
			cost < bestCost ||
			(cost == bestCost && len(candidate.Hops) < len(best.Hops)) {
			best = candidate
			bestCost = cost
			found = true
		}
	}

	if !found {
		return Route{}, ErrNoRoute
	}

	return best, nil
}
