package meshstate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

func TestRouteAuthorizationAuthorityPath(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()

	got, err := RouteAuthorizationAuthorityPath(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(
		stateDir,
		"route-authorization-authority.json",
	)
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}

	if _, err := RouteAuthorizationAuthorityPath("   "); !errors.Is(
		err,
		ErrRouteAuthorizationAuthorityInvalid,
	) {
		t.Fatalf(
			"empty-state error = %v, want invalid authority",
			err,
		)
	}
}

func TestOpenRouteAuthorizationAuthorityLoadsVerifierKey(
	t *testing.T,
) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	path, err := RouteAuthorizationAuthorityPath(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(publicKey)

	content := fmt.Sprintf(
		"{\n"+
			"  \"version\": 1,\n"+
			"  \"key_id\": \"control-key-1\",\n"+
			"  \"public_key\": %q\n"+
			"}\n",
		encoded,
	)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	authority, err := OpenRouteAuthorizationAuthority(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	if authority.KeyID != "control-key-1" {
		t.Fatalf(
			"KeyID = %q, want control-key-1",
			authority.KeyID,
		)
	}
	if !authority.PublicKey.Equal(publicKey) {
		t.Fatal("loaded public key does not match provisioned key")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" &&
		info.Mode().Perm() != 0o600 {
		t.Fatalf(
			"authority permissions = %o, want 600",
			info.Mode().Perm(),
		)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)

	route := mesh.Route{
		ID:          "route-authority-loader-a-b-c",
		Source:      "wd_a",
		Destination: "wd_c",
		ExpiresAt:   now.Add(90 * time.Second),
		Hops: []mesh.RouteHop{
			{
				From:      "wd_a",
				To:        "wd_b",
				Transport: mesh.TransportLAN,
				Cost:      10,
			},
			{
				From:      "wd_b",
				To:        "wd_c",
				Transport: mesh.TransportInternet,
				Cost:      20,
			},
		},
	}

	var rawJTI [16]byte
	rawJTI[15] = 1
	jti := base64.RawURLEncoding.EncodeToString(rawJTI[:])

	auth, err := mesh.SignRouteAuthorization(
		privateKey,
		authority.KeyID,
		mesh.NewRouteAuthorizationClaims(
			route,
			"wd_b",
			jti,
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	verifier := mesh.RouteAuthorizationVerifier{
		KeyID:     authority.KeyID,
		PublicKey: authority.PublicKey,
		Replay:    mesh.NewMemoryRouteAuthorizationReplay(),
		Now:       func() time.Time { return now },
	}

	if err := verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	); err != nil {
		t.Fatalf(
			"loaded authority failed route verification: %v",
			err,
		)
	}
}

func TestOpenRouteAuthorizationAuthorityRequiresProvisionedFile(
	t *testing.T,
) {
	t.Parallel()

	_, err := OpenRouteAuthorizationAuthority(t.TempDir())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"missing authority error = %v, want os.ErrNotExist",
			err,
		)
	}
}

func TestOpenRouteAuthorizationAuthorityRejectsSymlink(
	t *testing.T,
) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink availability varies on Windows")
	}

	dir := t.TempDir()

	_, publicKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = publicKey

	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(
		target,
		[]byte(
			`{"version":1,"key_id":"key","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	path, err := RouteAuthorizationAuthorityPath(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := OpenRouteAuthorizationAuthority(dir); !errors.Is(
		err,
		ErrRouteAuthorizationAuthorityInvalid,
	) {
		t.Fatalf(
			"symlink error = %v, want invalid authority",
			err,
		)
	}
}

func TestOpenRouteAuthorizationAuthorityRejectsMalformedState(
	t *testing.T,
) {
	t.Parallel()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validKey := base64.RawURLEncoding.EncodeToString(publicKey)

	cases := []string{
		`{`,
		fmt.Sprintf(
			`{"version":2,"key_id":"key","public_key":%q}`,
			validKey,
		),
		fmt.Sprintf(
			`{"version":1,"key_id":"","public_key":%q}`,
			validKey,
		),
		fmt.Sprintf(
			`{"version":1,"key_id":" key ","public_key":%q}`,
			validKey,
		),
		`{"version":1,"key_id":"key","public_key":"bad"}`,
		fmt.Sprintf(
			`{"version":1,"key_id":"key","public_key":%q,"extra":true}`,
			validKey,
		),
		fmt.Sprintf(
			`{"version":1,"key_id":"key","public_key":%q} {"version":1}`,
			validKey,
		),
	}

	for i, content := range cases {
		i, content := i, content

		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			t.Parallel()

			stateDir := t.TempDir()
			path, err := RouteAuthorizationAuthorityPath(stateDir)
			if err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(
				path,
				[]byte(content),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			if _, err := OpenRouteAuthorizationAuthority(
				stateDir,
			); !errors.Is(
				err,
				ErrRouteAuthorizationAuthorityInvalid,
			) {
				t.Fatalf(
					"error = %v, want invalid authority",
					err,
				)
			}
		})
	}
}
