//go:build !windows

package securestore

import (
	"errors"
	"path/filepath"
)

var ErrUnsupported = errors.New("protected relay-token storage is only available on Windows")

func StoreRelayToken(string, string) error  { return ErrUnsupported }
func LoadRelayToken(string) (string, error) { return "", ErrUnsupported }
func RelayTokenPath(stateDir string) string { return filepath.Join(stateDir, "relay-token.dpapi") }
