package meshstate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	RouteAuthorizationAuthorityFile = "route-authorization-authority.json"

	routeAuthorizationAuthorityVersion = 1
	maxRouteAuthorizationAuthoritySize = 16 << 10
	maxRouteAuthorizationKeyIDBytes    = 128
)

var ErrRouteAuthorizationAuthorityInvalid = errors.New(
	"meshstate: invalid route authorization authority",
)

// RouteAuthorizationAuthority is locally trusted control-plane verification
// material for signed mesh.forward capabilities.
//
// It contains public verification material only. The control-plane signing
// private key must never be stored by an agent.
type RouteAuthorizationAuthority struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

type routeAuthorizationAuthorityDisk struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// RouteAuthorizationAuthorityPath returns the fixed agent-state location used
// for control-plane route-authorization verification material.
func RouteAuthorizationAuthorityPath(
	stateDir string,
) (string, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return "", fmt.Errorf(
			"%w: empty state directory",
			ErrRouteAuthorizationAuthorityInvalid,
		)
	}

	return filepath.Join(
		stateDir,
		RouteAuthorizationAuthorityFile,
	), nil
}

// OpenRouteAuthorizationAuthority loads locally provisioned control-plane
// verification material.
//
// public_key is the unpadded base64url encoding of the raw 32-byte Ed25519
// public key. The file is deliberately separate from device identity and from
// every routing/terminal trust store.
func OpenRouteAuthorizationAuthority(
	stateDir string,
) (RouteAuthorizationAuthority, error) {
	path, err := RouteAuthorizationAuthorityPath(stateDir)
	if err != nil {
		return RouteAuthorizationAuthority{}, err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return RouteAuthorizationAuthority{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: authority must not be a symbolic link",
			ErrRouteAuthorizationAuthorityInvalid,
		)
	}
	if !info.Mode().IsRegular() {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: authority is not a regular file",
			ErrRouteAuthorizationAuthorityInvalid,
		)
	}
	if info.Size() <= 0 ||
		info.Size() > maxRouteAuthorizationAuthoritySize {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: invalid authority size",
			ErrRouteAuthorizationAuthorityInvalid,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return RouteAuthorizationAuthority{}, err
	}

	// Public verification material is not secret, but restricting the file
	// helps protect it from accidental modification by other local users.
	if err := os.Chmod(path, 0o600); err != nil {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"meshstate: secure route authority permissions: %w",
			err,
		)
	}

	var disk routeAuthorizationAuthorityDisk

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&disk); err != nil {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: parse authority: %v",
			ErrRouteAuthorizationAuthorityInvalid,
			err,
		)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return RouteAuthorizationAuthority{}, fmt.Errorf(
				"%w: multiple JSON values",
				ErrRouteAuthorizationAuthorityInvalid,
			)
		}
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: trailing authority data: %v",
			ErrRouteAuthorizationAuthorityInvalid,
			err,
		)
	}

	if disk.Version != routeAuthorizationAuthorityVersion {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: unsupported version %d",
			ErrRouteAuthorizationAuthorityInvalid,
			disk.Version,
		)
	}

	keyID := strings.TrimSpace(disk.KeyID)
	if keyID == "" ||
		keyID != disk.KeyID ||
		len(keyID) > maxRouteAuthorizationKeyIDBytes {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: invalid key ID",
			ErrRouteAuthorizationAuthorityInvalid,
		)
	}

	encodedKey := strings.TrimSpace(disk.PublicKey)
	if encodedKey == "" || encodedKey != disk.PublicKey {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: invalid public key encoding",
			ErrRouteAuthorizationAuthorityInvalid,
		)
	}

	rawKey, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(rawKey) != ed25519.PublicKeySize {
		return RouteAuthorizationAuthority{}, fmt.Errorf(
			"%w: invalid Ed25519 public key",
			ErrRouteAuthorizationAuthorityInvalid,
		)
	}

	return RouteAuthorizationAuthority{
		KeyID: keyID,
		PublicKey: ed25519.PublicKey(
			append([]byte(nil), rawKey...),
		),
	}, nil
}
