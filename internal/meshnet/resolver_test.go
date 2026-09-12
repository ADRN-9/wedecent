package meshnet

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/trust"
)

const testFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func trustedResolverStore(t *testing.T, peer trust.Peer) *trust.Store {
	t.Helper()

	store, err := trust.Open(filepath.Join(t.TempDir(), "router-peers.json"))
	if err != nil {
		t.Fatalf("trust.Open() error: %v", err)
	}
	if err := store.Put(peer); err != nil {
		t.Fatalf("Store.Put() error: %v", err)
	}
	return store
}

func TestTrustedPeerResolverRejectsUnknownPeer(t *testing.T) {
	t.Parallel()

	store, err := trust.Open(filepath.Join(t.TempDir(), "router-peers.json"))
	if err != nil {
		t.Fatalf("trust.Open() error: %v", err)
	}

	resolver := TrustedPeerResolver{Store: store}

	_, err = resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, ErrPeerNotTrusted) {
		t.Fatalf("Resolve() error = %v, want ErrPeerNotTrusted", err)
	}
}

func TestTrustedPeerResolverRejectsInvalidPinnedFingerprint(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: "not-a-fingerprint",
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{Store: store}

	_, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, ErrPeerIdentityInvalid) {
		t.Fatalf("Resolve() error = %v, want ErrPeerIdentityInvalid", err)
	}
}

func TestTrustedPeerResolverUsesOnlyTrustedTCPLocator(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{Store: store}

	got, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportInternet,
	)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	if got.ID != "wd_bbbbbbbbbbbbbbbb" ||
		got.Fingerprint != testFingerprint ||
		got.Locator != "tcp://192.0.2.10:7443" ||
		got.Transport != mesh.TransportInternet {
		t.Fatalf("Resolve() = %+v", got)
	}
}

func TestTrustedPeerResolverRejectsProxyLikeLocator(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"http://192.0.2.10:7443",
		"https://192.0.2.10:7443",
		"relay://relay.example/wd_bbbbbbbbbbbbbbbb",
		"wsrelay://relay.example/wd_bbbbbbbbbbbbbbbb",
		"tcp://user@192.0.2.10:7443",
		"tcp://192.0.2.10:7443/path",
		"tcp://192.0.2.10:7443?target=example.com",
	} {
		endpoint := endpoint
		t.Run(endpoint, func(t *testing.T) {
			store := trustedResolverStore(t, trust.Peer{
				ID:          "wd_bbbbbbbbbbbbbbbb",
				Fingerprint: testFingerprint,
				Endpoint:    endpoint,
			})

			resolver := TrustedPeerResolver{Store: store}

			_, err := resolver.Resolve(
				context.Background(),
				"wd_bbbbbbbbbbbbbbbb",
				mesh.TransportInternet,
			)
			if !errors.Is(err, ErrPeerLocatorMissing) {
				t.Fatalf(
					"Resolve(%q) error = %v, want ErrPeerLocatorMissing",
					endpoint,
					err,
				)
			}
		})
	}
}

func TestTrustedPeerResolverRefreshesLANFromPinnedDiscovery(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{
		Store:               store,
		LANDiscoveryTimeout: time.Second,
		FindTrusted: func(
			_ context.Context,
			deviceID string,
			fingerprint string,
		) (discovery.Result, bool, error) {
			if deviceID != "wd_bbbbbbbbbbbbbbbb" {
				t.Fatalf("deviceID = %q", deviceID)
			}
			if fingerprint != testFingerprint {
				t.Fatalf("fingerprint = %q", fingerprint)
			}

			return discovery.Result{
				DeviceID:    deviceID,
				Endpoint:    "198.51.100.22:7443",
				Fingerprint: fingerprint,
			}, true, nil
		},
	}

	got, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if got.Locator != "tcp://198.51.100.22:7443" {
		t.Fatalf("Locator = %q", got.Locator)
	}
}

func TestTrustedPeerResolverDiscoveryIdentityMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{
		Store:               store,
		LANDiscoveryTimeout: time.Second,
		FindTrusted: func(
			context.Context,
			string,
			string,
		) (discovery.Result, bool, error) {
			return discovery.Result{}, false, discovery.ErrTrustedIdentityMismatch
		},
	}

	_, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, ErrPeerIdentityMismatch) {
		t.Fatalf("Resolve() error = %v, want ErrPeerIdentityMismatch", err)
	}
}

func TestTrustedPeerResolverDiscoveryMissFailsClosed(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{
		Store:               store,
		LANDiscoveryTimeout: time.Second,
		FindTrusted: func(
			context.Context,
			string,
			string,
		) (discovery.Result, bool, error) {
			return discovery.Result{}, false, nil
		},
	}

	_, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("Resolve() error = %v, want ErrPeerUnavailable", err)
	}
}

func TestTrustedPeerResolverLANRequiresPinnedDiscovery(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{Store: store}

	_, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("Resolve() error = %v, want ErrPeerUnavailable", err)
	}
}

func TestTrustedPeerResolverRejectsDiscoveredFingerprintMismatch(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{
		Store:               store,
		LANDiscoveryTimeout: time.Second,
		FindTrusted: func(
			context.Context,
			string,
			string,
		) (discovery.Result, bool, error) {
			return discovery.Result{
				DeviceID:    "wd_bbbbbbbbbbbbbbbb",
				Endpoint:    "198.51.100.22:7443",
				Fingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			}, true, nil
		},
	}

	_, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, ErrPeerIdentityMismatch) {
		t.Fatalf("Resolve() error = %v, want ErrPeerIdentityMismatch", err)
	}
}

func TestTrustedPeerResolverDiscoveryFailureFailsClosed(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{
		Store:               store,
		LANDiscoveryTimeout: time.Second,
		FindTrusted: func(
			context.Context,
			string,
			string,
		) (discovery.Result, bool, error) {
			return discovery.Result{}, false, errors.New("multicast unavailable")
		},
	}

	_, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("Resolve() error = %v, want ErrPeerUnavailable", err)
	}
}

func TestTrustedPeerResolverRejectsUnsupportedTransport(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	resolver := TrustedPeerResolver{Store: store}

	_, err := resolver.Resolve(
		context.Background(),
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportBluetooth,
	)
	if !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatalf("Resolve() error = %v, want ErrUnsupportedTransport", err)
	}
}

func TestTrustedPeerResolverHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	store := trustedResolverStore(t, trust.Peer{
		ID:          "wd_bbbbbbbbbbbbbbbb",
		Fingerprint: testFingerprint,
		Endpoint:    "tcp://192.0.2.10:7443",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := TrustedPeerResolver{Store: store}

	_, err := resolver.Resolve(
		ctx,
		"wd_bbbbbbbbbbbbbbbb",
		mesh.TransportLAN,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve() error = %v, want context.Canceled", err)
	}
}
