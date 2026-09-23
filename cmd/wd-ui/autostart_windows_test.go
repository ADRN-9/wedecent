//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAutostartExecutableUsesResolvedRegularImage(t *testing.T) {
	root := t.TempDir()
	resolved := filepath.Join(root, "wd-ui.exe")
	if err := os.WriteFile(resolved, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkLike := filepath.Join(root, "link", "wd-ui.exe")

	path, err := resolveAutostartExecutable(
		func() (string, error) { return linkLike, nil },
		func(string) (string, error) { return resolved, nil },
		os.Stat,
	)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Clean(resolved) {
		t.Fatalf("resolved path = %q; want %q", path, filepath.Clean(resolved))
	}
}

func TestResolveAutostartExecutableRejectsNonRegularAndResolutionFailure(t *testing.T) {
	root := t.TempDir()
	for name, tc := range map[string]struct {
		eval evalSymlinksFunc
		stat func(string) (os.FileInfo, error)
	}{
		"resolution failure": {
			eval: func(string) (string, error) { return "", errors.New("resolve failed") },
			stat: os.Stat,
		},
		"directory": {
			eval: func(string) (string, error) { return root, nil },
			stat: os.Stat,
		},
		"missing": {
			eval: func(string) (string, error) { return filepath.Join(root, "missing.exe"), nil },
			stat: os.Stat,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolveAutostartExecutable(
				func() (string, error) { return filepath.Join(root, "wd-ui.exe"), nil },
				tc.eval,
				tc.stat,
			)
			if !errors.Is(err, ErrAutostartExecutable) {
				t.Fatalf("error = %v; want ErrAutostartExecutable", err)
			}
		})
	}
}
