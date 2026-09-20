package mesh

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestRouteAuthorizationCrossLanguageFixture(
	t *testing.T,
) {
	t.Parallel()

	const (
		kid = "test-route-key-1"

		expectedCanonical = "AAAAGHdlZGVjZW50LW1lc2gtZm9yd2FyZC12MQAAAAEAAAAQdGVzdC1yb3V0ZS1rZXktMQAAABZ3ZWRlY2VudC1jb250cm9sLXBsYW5lAAAAFHdlZGVjZW50LW1lc2gtcm91dGVyAAAADG1lc2guZm9yd2FyZAAAABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3AAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAAkMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAxAAAAE3dkX2FhYWFhYWFhYWFhYWFhYWEAAAATd2RfY2NjY2NjY2NjY2NjY2NjYwAAAaMYXFAAAAABoxhdOmAAAAGjGF06YAAAAAIAAAATd2RfYWFhYWFhYWFhYWFhYWFhYQAAABN3ZF9iYmJiYmJiYmJiYmJiYmJiAAAACGludGVybmV0AAAAAAAAAAoAAAATd2RfYmJiYmJiYmJiYmJiYmJiYgAAABN3ZF9jY2NjY2NjY2NjY2NjY2NjAAAAA2xhbgAAAAAAAAAU"

		publicKeyBase64 = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"

		signatureBase64 = "N78uguODnD-5_fs_deqgLrC_9_mY3a4O3dg2hB8mplLvxHI76v-YHBhlzID-QS6vKbOatzTS2K5yNbXcFOo5DQ"
	)

	issuedAt :=
		time.UnixMilli(
			1_800_000_000_000,
		).UTC()

	expiresAt :=
		time.UnixMilli(
			1_800_000_060_000,
		).UTC()

	route := Route{
		ID:          "00000000-0000-4000-8000-000000000001",
		Source:      "wd_aaaaaaaaaaaaaaaa",
		Destination: "wd_cccccccccccccccc",
		Hops: []RouteHop{
			{
				From:      "wd_aaaaaaaaaaaaaaaa",
				To:        "wd_bbbbbbbbbbbbbbbb",
				Transport: TransportInternet,
				Cost:      10,
			},
			{
				From:      "wd_bbbbbbbbbbbbbbbb",
				To:        "wd_cccccccccccccccc",
				Transport: TransportLAN,
				Cost:      20,
			},
		},
		ExpiresAt: expiresAt,
	}

	authorization := RouteAuthorization{
		KeyID: kid,
		Claims: RouteAuthorizationClaims{
			Version:        RouteAuthorizationVersion,
			Issuer:         RouteAuthorizationIssuer,
			Audience:       RouteAuthorizationAudience,
			Permission:     RouteAuthorizationPermission,
			JTI:            "AAECAwQFBgcICQoLDA0ODw",
			Router:         "wd_bbbbbbbbbbbbbbbb",
			Route:          route,
			IssuedAtUnixMS: issuedAt.UnixMilli(),
			ExpiresUnixMS:  expiresAt.UnixMilli(),
		},
		Signature: signatureBase64,
	}

	message, err :=
		routeAuthorizationMessage(
			authorization,
		)

	if err != nil {
		t.Fatal(err)
	}

	if got :=
		base64.RawURLEncoding.
			EncodeToString(message); got != expectedCanonical {
		t.Fatalf(
			"canonical message mismatch\n got: %s\nwant: %s",
			got,
			expectedCanonical,
		)
	}

	publicKeyBytes, err :=
		base64.RawURLEncoding.
			DecodeString(publicKeyBase64)

	if err != nil {
		t.Fatal(err)
	}

	if len(publicKeyBytes) !=
		ed25519.PublicKeySize {
		t.Fatal("invalid fixture public key")
	}

	replay :=
		NewMemoryRouteAuthorizationReplay()

	verifyAt :=
		issuedAt.Add(time.Second)

	replay.now =
		func() time.Time {
			return verifyAt
		}

	verifier :=
		RouteAuthorizationVerifier{
			KeyID: kid,
			PublicKey: ed25519.PublicKey(
				publicKeyBytes,
			),
			Replay: replay,
			Now: func() time.Time {
				return verifyAt
			},
		}

	if err := verifier.VerifyAndConsume(
		context.Background(),
		authorization,
		route,
		"wd_bbbbbbbbbbbbbbbb",
	); err != nil {
		t.Fatalf(
			"cross-language signature fixture failed verification: %v",
			err,
		)
	}
}
