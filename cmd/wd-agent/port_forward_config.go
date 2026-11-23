package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/trust"
)

func (cfg serveConfig) portForwardConfigured() bool {
	return strings.TrimSpace(cfg.PortForwardAuthorizationPublicKey) != "" ||
		strings.TrimSpace(cfg.PortForwardAllowedPorts) != "" ||
		strings.TrimSpace(cfg.PortForwardAllowedPrivateCIDRs) != "" ||
		cfg.PortForwardAllowPublic || cfg.PortForwardMaxConnections != 0 || cfg.PortForwardAllowLegacyReplayMigration || cfg.PortForwardAllowLegacyReplayMigration
}

func (cfg serveConfig) validatePortForward() error {
	if !cfg.portForwardConfigured() {
		return nil
	}
	if strings.TrimSpace(cfg.PortForwardAuthorizationPublicKey) == "" {
		return errors.New("--port-forward-authorization-public-key is required when port forwarding is configured")
	}
	if _, err := parsePortForwardPorts(cfg.PortForwardAllowedPorts); err != nil {
		return fmt.Errorf("--port-forward-allowed-ports: %w", err)
	}
	if _, err := parsePortForwardCIDRs(cfg.PortForwardAllowedPrivateCIDRs); err != nil {
		return fmt.Errorf("--port-forward-allowed-private-cidrs: %w", err)
	}
	if cfg.PortForwardMaxConnections < 1 || cfg.PortForwardMaxConnections > 64 {
		return errors.New("--port-forward-max-connections must be between 1 and 64")
	}
	return nil
}

func parsePortForwardPorts(raw string) ([]portforward.PortRange, error) {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	if len(parts) == 0 || len(parts) > 128 || strings.TrimSpace(raw) == "" {
		return nil, errors.New("at least one and at most 128 port ranges are required")
	}
	ranges := make([]portforward.PortRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		bounds := strings.Split(part, "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		first, err := strconv.ParseUint(strings.TrimSpace(bounds[0]), 10, 16)
		if err != nil || first == 0 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.ParseUint(strings.TrimSpace(bounds[1]), 10, 16)
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		ranges = append(ranges, portforward.PortRange{First: uint16(first), Last: uint16(last)})
	}
	for i := range ranges {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i].First <= ranges[j].Last && ranges[j].First <= ranges[i].Last {
				return nil, fmt.Errorf("overlapping port ranges %q and %q", parts[i], parts[j])
			}
		}
	}
	return ranges, nil
}

func parsePortForwardCIDRs(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 128 {
		return nil, errors.New("at most 128 private CIDRs are allowed")
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix != prefix.Masked() || !prefix.Addr().IsPrivate() {
			return nil, fmt.Errorf("CIDR %q must be a canonical private network prefix", part)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func loadPortForwardAuthorizationPublicKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < ed25519.PublicKeySize || info.Size() > 256 {
		return nil, errors.New("authorization trust anchor must be a bounded regular file, not a symlink")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if len(data) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), data...), nil
	}
	encoded := strings.TrimSpace(string(data))
	key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		key, err = base64.StdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("authorization trust anchor must contain exactly 32 Ed25519 public-key bytes")
	}
	return ed25519.PublicKey(key), nil
}

func openAgentPortForwardRuntime(cfg serveConfig, id *identity.Identity, peers *trust.Store) (*session.PortForwardRuntime, error) {
	if !cfg.portForwardConfigured() {
		return nil, nil
	}
	if err := cfg.validatePortForward(); err != nil {
		return nil, err
	}
	publicKey, err := loadPortForwardAuthorizationPublicKey(strings.TrimSpace(cfg.PortForwardAuthorizationPublicKey))
	if err != nil {
		return nil, fmt.Errorf("load port-forwarding public trust anchor: %w", err)
	}
	verifier, err := portforward.NewPersistentAuthorizationVerifierWithLegacyMigration(
		filepath.Join(cfg.StateDir, "portforward-replay.json"),
		mesh.DeviceID(id.ID),
		publicKey,
		cfg.PortForwardAllowLegacyReplayMigration,
	)
	if err != nil {
		return nil, fmt.Errorf("open destination replay verifier: %w", err)
	}
	routerTrust, err := meshnet.OpenRouteDestinationRoutersTrust(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("open destination route-tunnel router trust: %w", err)
	}
	auditLog, err := audit.Open(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("open destination forwarding audit: %w", err)
	}
	ports, err := parsePortForwardPorts(cfg.PortForwardAllowedPorts)
	if err != nil {
		return nil, err
	}
	privateCIDRs, err := parsePortForwardCIDRs(cfg.PortForwardAllowedPrivateCIDRs)
	if err != nil {
		return nil, err
	}
	runtime := &session.PortForwardRuntime{
		Verifier: verifier,
		TrustChecker: peers,
		RouterTrustChecker: routerTrust,
		PermissionAuthorizer: portforward.CapabilityPermissionAuthorizer{},
		Resolver: net.DefaultResolver,
		Dialer: &net.Dialer{Timeout: 10 * time.Second},
		Policy: portforward.DestinationPolicy{
			AllowedPorts: ports, AllowedPrivate: privateCIDRs, AllowPublic: cfg.PortForwardAllowPublic,
		},
		Audit: auditLog,
		TrustPollInterval: 250 * time.Millisecond,
		MaxConnections: cfg.PortForwardMaxConnections,
		DialTimeout: 10 * time.Second,
	}
	if !runtime.Ready() {
		return nil, errors.New("destination forwarding runtime failed closed: required trust, policy, or audit configuration is invalid")
	}
	return runtime, nil
}
