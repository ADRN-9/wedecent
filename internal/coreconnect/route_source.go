package coreconnect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
)

const (
	// RouteSelectionPolicyFile is local source-side route selection policy.
	// It is deliberately distinct from every routing trust store and never
	// grants a router, source, or destination any trust role.
	RouteSelectionPolicyFile = "route-selection.json"

	routeSelectionPolicyVersion = 1
	maxRouteSelectionPolicySize = 1 << 20
	maxRouteSelectionCandidates = 256
	maxRouteSelectionCost        = uint64(1_000_000_000)
)

var routeSelectionDeviceIDPattern = regexp.MustCompile(`^wd_[a-z2-7]{16}$`)

type RouteSelectionCandidate struct {
	DestinationDeviceID string             `json:"destination_device_id"`
	RouterDeviceID      string             `json:"router_device_id"`
	FirstTransport      mesh.TransportName `json:"first_transport"`
	SecondTransport     mesh.TransportName `json:"second_transport"`
	FirstCost           uint64             `json:"first_cost"`
	SecondCost          uint64             `json:"second_cost"`
}

type routeSelectionPolicy struct {
	Version        int                       `json:"version"`
	Enabled        bool                      `json:"enabled"`
	SourceDeviceID string                    `json:"source_device_id"`
	Candidates     []RouteSelectionCandidate `json:"candidates"`
}

// PolicyRouteSource turns a local, explicit route-selection policy into one
// exact route-authorization request. The policy is only a candidate source:
// the selected router must independently exist in source-owned routing trust,
// and the router/destination still enforce their own directional trust stores.
//
// The file is re-read for each request so an operator can change route policy
// without restarting wd-core. No file is created by this type.
type PolicyRouteSource struct {
	stateDir string
}

var _ RouteRequestSource = (*PolicyRouteSource)(nil)

func NewPolicyRouteSource(stateDir string) (*PolicyRouteSource, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil, errors.New("core route selection: state directory is required")
	}
	return &PolicyRouteSource{stateDir: stateDir}, nil
}

func (s *PolicyRouteSource) RouteRequest(
	ctx context.Context,
	sourceDeviceID string,
	destinationDeviceID string,
) (account.RouteAuthorizationRequest, bool, error) {
	if err := ctx.Err(); err != nil {
		return account.RouteAuthorizationRequest{}, false, err
	}

	sourceDeviceID = strings.TrimSpace(sourceDeviceID)
	destinationDeviceID = strings.TrimSpace(destinationDeviceID)
	if !routeSelectionDeviceIDPattern.MatchString(sourceDeviceID) {
		return account.RouteAuthorizationRequest{}, false, errors.New("core route selection: invalid source device ID")
	}
	if !routeSelectionDeviceIDPattern.MatchString(destinationDeviceID) {
		return account.RouteAuthorizationRequest{}, false, errors.New("core route selection: invalid destination device ID")
	}
	if sourceDeviceID == destinationDeviceID {
		return account.RouteAuthorizationRequest{}, false, errors.New("core route selection: source and destination must differ")
	}

	policy, exists, err := loadRouteSelectionPolicy(s.stateDir)
	if err != nil {
		return account.RouteAuthorizationRequest{}, false, err
	}
	if !exists || !policy.Enabled {
		return account.RouteAuthorizationRequest{}, false, nil
	}
	if policy.SourceDeviceID != sourceDeviceID {
		return account.RouteAuthorizationRequest{}, false, errors.New("core route selection: policy source does not match local identity")
	}

	routerTrust, err := meshnet.OpenRouteSourceRoutersTrust(s.stateDir)
	if err != nil {
		return account.RouteAuthorizationRequest{}, false, fmt.Errorf("core route selection: open source router trust: %w", err)
	}

	var selected RouteSelectionCandidate
	var selectedCost uint64
	found := false
	for _, candidate := range policy.Candidates {
		if err := ctx.Err(); err != nil {
			return account.RouteAuthorizationRequest{}, false, err
		}
		if candidate.DestinationDeviceID != destinationDeviceID {
			continue
		}
		if _, ok := routerTrust.Get(candidate.RouterDeviceID); !ok {
			continue
		}
		cost := candidate.FirstCost + candidate.SecondCost
		if !found || cost < selectedCost {
			selected = candidate
			selectedCost = cost
			found = true
		}
	}
	if !found {
		return account.RouteAuthorizationRequest{}, false, nil
	}

	return account.RouteAuthorizationRequest{
		SourceDeviceID:      sourceDeviceID,
		RouterDeviceID:      selected.RouterDeviceID,
		DestinationDeviceID: destinationDeviceID,
		FirstTransport:      selected.FirstTransport,
		SecondTransport:     selected.SecondTransport,
		FirstCost:           selected.FirstCost,
		SecondCost:          selected.SecondCost,
	}, true, nil
}

func loadRouteSelectionPolicy(stateDir string) (routeSelectionPolicy, bool, error) {
	path := filepath.Join(stateDir, RouteSelectionPolicyFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return routeSelectionPolicy{}, false, nil
	}
	if err != nil {
		return routeSelectionPolicy{}, false, fmt.Errorf("core route selection: inspect policy: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return routeSelectionPolicy{}, false, errors.New("core route selection: policy must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxRouteSelectionPolicySize {
		return routeSelectionPolicy{}, false, errors.New("core route selection: policy has an invalid size")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return routeSelectionPolicy{}, false, fmt.Errorf("core route selection: secure policy permissions: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return routeSelectionPolicy{}, false, fmt.Errorf("core route selection: read policy: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy routeSelectionPolicy
	if err := decoder.Decode(&policy); err != nil {
		return routeSelectionPolicy{}, false, fmt.Errorf("core route selection: parse policy: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return routeSelectionPolicy{}, false, errors.New("core route selection: policy contains multiple JSON values")
		}
		return routeSelectionPolicy{}, false, fmt.Errorf("core route selection: parse trailing policy data: %w", err)
	}
	if err := validateRouteSelectionPolicy(&policy); err != nil {
		return routeSelectionPolicy{}, false, err
	}
	return policy, true, nil
}

func validateRouteSelectionPolicy(policy *routeSelectionPolicy) error {
	if policy.Version != routeSelectionPolicyVersion {
		return errors.New("core route selection: unsupported policy version")
	}
	policy.SourceDeviceID = strings.TrimSpace(policy.SourceDeviceID)
	if !routeSelectionDeviceIDPattern.MatchString(policy.SourceDeviceID) {
		return errors.New("core route selection: invalid policy source device ID")
	}
	if len(policy.Candidates) > maxRouteSelectionCandidates {
		return errors.New("core route selection: policy has too many candidates")
	}

	for index := range policy.Candidates {
		candidate := policy.Candidates[index]
		candidate.DestinationDeviceID = strings.TrimSpace(candidate.DestinationDeviceID)
		candidate.RouterDeviceID = strings.TrimSpace(candidate.RouterDeviceID)
		candidate.FirstTransport = mesh.TransportName(strings.ToLower(strings.TrimSpace(string(candidate.FirstTransport))))
		candidate.SecondTransport = mesh.TransportName(strings.ToLower(strings.TrimSpace(string(candidate.SecondTransport))))
		policy.Candidates[index] = candidate

		if !routeSelectionDeviceIDPattern.MatchString(candidate.DestinationDeviceID) {
			return fmt.Errorf("core route selection: candidate %d has invalid destination device ID", index)
		}
		if !routeSelectionDeviceIDPattern.MatchString(candidate.RouterDeviceID) {
			return fmt.Errorf("core route selection: candidate %d has invalid router device ID", index)
		}
		if candidate.DestinationDeviceID == policy.SourceDeviceID ||
			candidate.RouterDeviceID == policy.SourceDeviceID ||
			candidate.RouterDeviceID == candidate.DestinationDeviceID {
			return fmt.Errorf("core route selection: candidate %d devices must differ", index)
		}
		if !validRouteSelectionTransport(candidate.FirstTransport) ||
			!validRouteSelectionTransport(candidate.SecondTransport) {
			return fmt.Errorf("core route selection: candidate %d transport must be lan or internet", index)
		}
		if candidate.FirstCost > maxRouteSelectionCost || candidate.SecondCost > maxRouteSelectionCost {
			return fmt.Errorf("core route selection: candidate %d cost exceeds control-plane limit", index)
		}
	}
	return nil
}

func validRouteSelectionTransport(name mesh.TransportName) bool {
	return name == mesh.TransportLAN || name == mesh.TransportInternet
}
