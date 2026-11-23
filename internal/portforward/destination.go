package portforward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

var (
	ErrDestinationDenied     = errors.New("portforward: destination is not allowed by policy")
	ErrDestinationResolution = errors.New("portforward: destination resolution failed")
)

type PortRange struct {
	First uint16
	Last  uint16
}

type DestinationPolicy struct {
	AllowPublic    bool
	AllowedPrivate []netip.Prefix
	AllowedPorts   []PortRange
}

type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type ApprovedDestination struct {
	Host string
	Port uint16
	IPs  []netip.Addr
}

type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ResolveApprovedDestination validates every DNS answer and returns only pinned IPs.
func ResolveApprovedDestination(ctx context.Context, resolver IPResolver, policy DestinationPolicy, host string, port uint16) (ApprovedDestination, error) {
	if err := ctx.Err(); err != nil {
		return ApprovedDestination{}, err
	}
	host = canonicalDestinationHost(host)
	if host == "" || port == 0 || !policy.allowsPort(port) {
		return ApprovedDestination{}, ErrDestinationDenied
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip.Unmap()}
	} else {
		if resolver == nil {
			return ApprovedDestination{}, ErrDestinationResolution
		}
		resolved, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return ApprovedDestination{}, fmt.Errorf("%w: %v", ErrDestinationResolution, err)
		}
		addresses = resolved
	}
	if len(addresses) == 0 || len(addresses) > 32 {
		return ApprovedDestination{}, ErrDestinationResolution
	}
	unique := make(map[netip.Addr]struct{}, len(addresses))
	approved := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			return ApprovedDestination{}, ErrDestinationDenied
		}
		address = address.Unmap()
		if !policy.allowsAddress(address) {
			return ApprovedDestination{}, ErrDestinationDenied
		}
		if _, exists := unique[address]; exists {
			continue
		}
		unique[address] = struct{}{}
		approved = append(approved, address)
	}
	if len(approved) == 0 {
		return ApprovedDestination{}, ErrDestinationDenied
	}
	sort.Slice(approved, func(i, j int) bool { return approved[i].Less(approved[j]) })
	return ApprovedDestination{Host: host, Port: port, IPs: approved}, nil
}

// DialApprovedTCP dials only approved IP literals; it never resolves Host again.
func DialApprovedTCP(ctx context.Context, dialer ContextDialer, policy DestinationPolicy, destination ApprovedDestination) (net.Conn, error) {
	if dialer == nil || destination.Port == 0 || !policy.allowsPort(destination.Port) || len(destination.IPs) == 0 || len(destination.IPs) > 32 {
		return nil, ErrDestinationDenied
	}
	var lastErr error
	for _, ip := range destination.IPs {
		if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() || !policy.allowsAddress(ip) {
			return nil, ErrDestinationDenied
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprint(destination.Port)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if lastErr == nil {
		lastErr = ErrDestinationDenied
	}
	return nil, lastErr
}

func (p DestinationPolicy) Validate() error {
	if len(p.AllowedPorts) == 0 || len(p.AllowedPorts) > 128 || len(p.AllowedPrivate) > 128 {
		return ErrDestinationDenied
	}
	for _, ports := range p.AllowedPorts {
		if ports.First == 0 || ports.Last < ports.First {
			return ErrDestinationDenied
		}
	}
	for _, prefix := range p.AllowedPrivate {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return ErrDestinationDenied
		}
	}
	return nil
}

func (p DestinationPolicy) allowsPort(port uint16) bool {
	if p.Validate() != nil {
		return false
	}
	for _, allowed := range p.AllowedPorts {
		if port >= allowed.First && port <= allowed.Last {
			return true
		}
	}
	return false
}

func (p DestinationPolicy) allowsAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || isCloudMetadataIP(ip) || isReservedAddress(ip) {
		return false
	}
	if ip.IsPrivate() {
		for _, prefix := range p.AllowedPrivate {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	return p.AllowPublic && ip.IsGlobalUnicast()
}

func isCloudMetadataIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, raw := range []string{
		"169.254.169.254/32", "169.254.170.2/32", "169.254.169.253/32",
		"100.100.100.200/32", "168.63.129.16/32", "fd00:ec2::254/128",
	} {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func isReservedAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, raw := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "2001::/23", "2001:db8::/32", "2001:10::/28", "2002::/16",
	} {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
