package coreapi

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/mesh"
)

var (
	ErrInvalidRouteRequest = errors.New("invalid route status request")
	ErrRouteNotFound       = errors.New("route status not found")
)

const maxNetworkDetailBytes = 256

// ConnectionPathSnapshot is internal Local Core state for one active
// connection. Routed snapshots retain the already-authorized mesh.Route so the
// UI-facing status is derived from the same route structure used by the mesh
// layer rather than a parallel route model.
type ConnectionPathSnapshot struct {
	ConnectionID  string
	DestinationID string
	Path          v1.ConnectionPath
	Route         *mesh.Route
}

// NetworkReadService exposes non-secret transport capability and connection
// path state to local UI clients. It performs no discovery, dialing, probing,
// authorization, or route selection itself.
type NetworkReadService struct {
	localDeviceID string

	mu         sync.RWMutex
	transports []v1.TransportStatus
	routes     map[string]v1.RouteStatus
	now        func() time.Time
}

var (
	_ v1.TransportService = (*NetworkReadService)(nil)
	_ v1.RouteService     = (*NetworkReadService)(nil)
)

// DefaultTransportStatuses describes transport classes implemented by the
// current core build. Available means supported by the core, not that a
// particular peer is reachable right now.
func DefaultTransportStatuses() []v1.TransportStatus {
	return []v1.TransportStatus{
		{Name: v1.TransportLAN, Available: true, Detail: "supported by this core build"},
		{Name: v1.TransportInternet, Available: true, Detail: "supported by this core build"},
		{Name: v1.TransportBluetooth, Available: false, Detail: "not implemented in this core build"},
	}
}

func NewNetworkReadService(localDeviceID string, transports []v1.TransportStatus) (*NetworkReadService, error) {
	localDeviceID = strings.TrimSpace(localDeviceID)
	if localDeviceID == "" {
		return nil, errors.New("network status local device ID is required")
	}

	copyTransports := append([]v1.TransportStatus(nil), transports...)
	seen := make(map[v1.TransportName]struct{}, len(copyTransports))
	for i := range copyTransports {
		status := &copyTransports[i]
		if !validTransportName(status.Name) {
			return nil, fmt.Errorf("network status has unsupported transport %q", status.Name)
		}
		if _, ok := seen[status.Name]; ok {
			return nil, fmt.Errorf("network status has duplicate transport %q", status.Name)
		}
		seen[status.Name] = struct{}{}
		status.Detail = strings.TrimSpace(status.Detail)
		if len(status.Detail) > maxNetworkDetailBytes || containsControl(status.Detail) {
			return nil, fmt.Errorf("network status detail for %q is invalid", status.Name)
		}
	}
	sort.Slice(copyTransports, func(i, j int) bool {
		return transportOrder(copyTransports[i].Name) < transportOrder(copyTransports[j].Name)
	})

	return &NetworkReadService{
		localDeviceID: localDeviceID,
		transports:    copyTransports,
		routes:        make(map[string]v1.RouteStatus),
		now:           time.Now,
	}, nil
}

func (s *NetworkReadService) GetTransportStatus(ctx context.Context) ([]v1.TransportStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	statuses := append([]v1.TransportStatus(nil), s.transports...)
	s.mu.RUnlock()
	return statuses, nil
}

func (s *NetworkReadService) GetRouteStatus(ctx context.Context, req v1.GetRouteStatusRequest) (v1.RouteStatus, error) {
	if err := ctx.Err(); err != nil {
		return v1.RouteStatus{}, err
	}
	connectionID := req.ConnectionID
	if !validConnectionID(connectionID) {
		return v1.RouteStatus{}, ErrInvalidRouteRequest
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.routes[connectionID]
	if !ok {
		return v1.RouteStatus{}, ErrRouteNotFound
	}
	if status.ExpiresAt != nil && !s.now().UTC().Before(status.ExpiresAt.UTC()) {
		delete(s.routes, connectionID)
		return v1.RouteStatus{}, ErrRouteNotFound
	}
	return cloneRouteStatus(status), nil
}

// SetConnectionPath records non-secret path metadata owned by the Local Core.
// It is intentionally not an IPC mutation. The connection-lifecycle service
// will call this after it has selected and authenticated a path.
func (s *NetworkReadService) SetConnectionPath(snapshot ConnectionPathSnapshot) error {
	if !validConnectionID(snapshot.ConnectionID) {
		return errors.New("network status connection ID is invalid")
	}
	if !validPublicID(snapshot.DestinationID) {
		return errors.New("network status destination ID is invalid")
	}
	if !validConnectionPath(snapshot.Path) {
		return errors.New("network status connection path is invalid")
	}

	status := v1.RouteStatus{
		ConnectionID:  snapshot.ConnectionID,
		DestinationID: snapshot.DestinationID,
		Path:          snapshot.Path,
	}

	if snapshot.Path == v1.ConnectionPathRouted {
		if snapshot.Route == nil {
			return errors.New("network status routed path requires a route")
		}
		route := cloneMeshRoute(*snapshot.Route)
		now := s.now().UTC()
		if err := route.Validate(now); err != nil {
			return fmt.Errorf("network status routed path is invalid: %w", err)
		}
		if route.Source != mesh.DeviceID(s.localDeviceID) ||
			route.Destination != mesh.DeviceID(snapshot.DestinationID) {
			return errors.New("network status route does not match local source and destination")
		}
		if len(route.Hops) < 2 {
			return errors.New("network status routed path must include an intermediate router")
		}
		status.Hops = make([]v1.RouteHop, 0, len(route.Hops))
		for _, hop := range route.Hops {
			transport, ok := publicTransportName(hop.Transport)
			if !ok {
				return fmt.Errorf("network status route has unsupported transport %q", hop.Transport)
			}
			status.Hops = append(status.Hops, v1.RouteHop{
				From:      string(hop.From),
				To:        string(hop.To),
				Transport: transport,
				Cost:      hop.Cost,
			})
		}
		if len(route.Hops) == 2 {
			status.RouterID = string(route.Hops[0].To)
		}
		expires := route.ExpiresAt.UTC()
		status.ExpiresAt = &expires
	} else if snapshot.Route != nil {
		return errors.New("network status non-routed path must not include a mesh route")
	}

	s.mu.Lock()
	s.routes[snapshot.ConnectionID] = cloneRouteStatus(status)
	s.mu.Unlock()
	return nil
}

// RemoveConnectionPath removes status when a connection closes. Unknown IDs are
// harmless so shutdown/cleanup paths can be idempotent.
func (s *NetworkReadService) RemoveConnectionPath(connectionID string) {
	if !validConnectionID(connectionID) {
		return
	}
	s.mu.Lock()
	delete(s.routes, connectionID)
	s.mu.Unlock()
}

func cloneRouteStatus(status v1.RouteStatus) v1.RouteStatus {
	copyStatus := status
	copyStatus.Hops = append([]v1.RouteHop(nil), status.Hops...)
	if status.ExpiresAt != nil {
		expires := *status.ExpiresAt
		copyStatus.ExpiresAt = &expires
	}
	return copyStatus
}

func cloneMeshRoute(route mesh.Route) mesh.Route {
	copyRoute := route
	copyRoute.Hops = append([]mesh.RouteHop(nil), route.Hops...)
	return copyRoute
}

func validConnectionID(value string) bool {
	return validBoundedVisible(value, 128)
}

func validPublicID(value string) bool {
	return validBoundedVisible(value, 128)
}

func validBoundedVisible(value string, maxBytes int) bool {
	return value != "" &&
		value == strings.TrimSpace(value) &&
		len(value) <= maxBytes &&
		!containsControl(value)
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func validConnectionPath(path v1.ConnectionPath) bool {
	switch path {
	case v1.ConnectionPathDirect, v1.ConnectionPathLAN, v1.ConnectionPathRouted, v1.ConnectionPathRelay:
		return true
	default:
		return false
	}
}

func validTransportName(name v1.TransportName) bool {
	switch name {
	case v1.TransportLAN, v1.TransportInternet, v1.TransportBluetooth:
		return true
	default:
		return false
	}
}

func publicTransportName(name mesh.TransportName) (v1.TransportName, bool) {
	switch name {
	case mesh.TransportLAN:
		return v1.TransportLAN, true
	case mesh.TransportInternet:
		return v1.TransportInternet, true
	case mesh.TransportBluetooth:
		return v1.TransportBluetooth, true
	default:
		return "", false
	}
}

func transportOrder(name v1.TransportName) int {
	switch name {
	case v1.TransportLAN:
		return 0
	case v1.TransportInternet:
		return 1
	case v1.TransportBluetooth:
		return 2
	default:
		return 3
	}
}
