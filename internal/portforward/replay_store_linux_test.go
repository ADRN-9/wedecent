//go:build linux

package portforward

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinuxFileReplayRejectsInsecurePreexistingPermissions(t *testing.T) {
	tests := []struct {
		name   string
		target func(string) string
		mode   os.FileMode
	}{
		{
			name:   "replay_state_file",
			target: func(path string) string { return path },
			mode:   0o644,
		},
		{
			name:   "lock_file",
			target: func(path string) string { return path + ".lock" },
			mode:   0o644,
		},
		{
			name:   "replay_directory",
			target: func(path string) string { return filepath.Dir(path) },
			mode:   0o755,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := newReplayTestPath(t)
			replay, err := NewFileReplay(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			first := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
			expiry := time.Now().UTC().Add(time.Minute)
			if err := replay.ConsumePortForwardAuthorization(context.Background(), first, expiry); err != nil {
				t.Fatalf("initialize replay state: %v", err)
			}
			if err := os.Chmod(test.target(path), test.mode); err != nil {
				t.Fatalf("make existing replay metadata insecure: %v", err)
			}

			next := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
			err = replay.ConsumePortForwardAuthorization(context.Background(), next, expiry)
			if !errors.Is(err, ErrReplayUnavailable) {
				t.Fatalf("insecure pre-existing %s error = %v, want fail-closed replay unavailable", test.name, err)
			}
		})
	}
}
