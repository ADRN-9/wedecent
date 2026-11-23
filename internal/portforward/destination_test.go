package portforward

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type testResolver struct {
	addresses []netip.Addr
	err       error
	host      string
}

func (r *testResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.host = host
	if network != "ip" {
		return nil, errors.New("unexpected network")
	}
	return r.addresses, r.err
}

type captureDialer struct {
	address string
	conn    net.Conn
}

func (d *captureDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.address = network + ":" + address
	left, right := net.Pipe()
	d.conn = right
	return left, nil
}

func publicPolicy() DestinationPolicy {
	return DestinationPolicy{AllowPublic: true, AllowedPorts: []PortRange{{First: 443, Last: 443}}}
}

func TestDestinationPolicyRejectsSpecialAndMappedAddresses(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "64:ff9b::a00:1",
		"169.254.169.254", "100.100.100.200", "168.63.129.16", "::ffff:127.0.0.1",
		"192.0.2.1", "198.18.0.1", "2001:db8::1", "224.0.0.1", "0.0.0.0",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ResolveApprovedDestination(context.Background(), nil, publicPolicy(), raw, 443); err == nil {
				t.Fatalf("unsafe address %s approved", raw)
			}
		})
	}
}

func TestDestinationPolicyRequiresExplicitPrivateNetworkAllowlist(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("10.20.30.40")}}
	if _, err := ResolveApprovedDestination(context.Background(), resolver, publicPolicy(), "db.example.com", 443); err == nil {
		t.Fatal("private DNS answer accepted without allowlist")
	}
	policy := publicPolicy()
	policy.AllowedPrivate = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	approved, err := ResolveApprovedDestination(context.Background(), resolver, policy, "db.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if len(approved.IPs) != 1 || approved.IPs[0].String() != "10.20.30.40" {
		t.Fatalf("approved IPs = %v", approved.IPs)
	}
}

func TestDestinationPolicyRejectsMixedDNSAnswersToPreventRebinding(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("169.254.169.254")}}
	if _, err := ResolveApprovedDestination(context.Background(), resolver, publicPolicy(), "example.com", 443); err == nil {
		t.Fatal("mixed public/metadata DNS answer accepted")
	}
}

func TestDestinationPolicyRequiresAuthorizedPort(t *testing.T) {
	if _, err := ResolveApprovedDestination(context.Background(), nil, publicPolicy(), "93.184.216.34", 22); err == nil {
		t.Fatal("unauthorized port accepted")
	}
	policy := publicPolicy()
	policy.AllowedPorts = nil
	if _, err := ResolveApprovedDestination(context.Background(), nil, policy, "93.184.216.34", 443); err == nil {
		t.Fatal("empty port allowlist accepted")
	}
}

func TestDialApprovedTCPUsesPinnedResolvedIP(t *testing.T) {
	policy := publicPolicy()
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	approved, err := ResolveApprovedDestination(context.Background(), resolver, policy, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &captureDialer{}
	conn, err := DialApprovedTCP(context.Background(), dialer, policy, approved)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer dialer.conn.Close()
	if dialer.address != "tcp:93.184.216.34:443" {
		t.Fatalf("dial target = %q", dialer.address)
	}
}

func TestDialApprovedTCPRejectsTamperedApprovedAddress(t *testing.T) {
	dialer := &captureDialer{}
	_, err := DialApprovedTCP(context.Background(), dialer, publicPolicy(), ApprovedDestination{
		Host: "example.com", Port: 443, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	})
	if err == nil || dialer.address != "" {
		t.Fatalf("unsafe address was dialed: %v %q", err, dialer.address)
	}
}

func TestDestinationPolicyRequiresCanonicalHostname(t *testing.T) {
	for _, host := range []string{"Example.com", "example.com.", "localhost", "service.local", "metadata.google.internal", "a..example.com", "-bad.example.com", "example.com/path"} {
		if _, err := ResolveApprovedDestination(context.Background(), nil, publicPolicy(), host, 443); err == nil {
			t.Fatalf("non-canonical host %q accepted", host)
		}
	}
}
