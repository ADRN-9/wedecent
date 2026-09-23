package main

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSiblingExecutablePathUsesResolvedExecutableDirectory(t *testing.T) {
	root := t.TempDir()
	invoked := filepath.Join(root, "launcher", "wd-ui.exe")
	resolved := filepath.Join(root, "installed", "wd-ui.exe")
	path, err := siblingExecutablePath(
		func() (string, error) { return invoked, nil },
		func(got string) (string, error) {
			if got != invoked {
				t.Fatalf("eval path = %q, want %q", got, invoked)
			}
			return resolved, nil
		},
		"wd-core.exe",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(resolved), "wd-core.exe")
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
}

func TestSiblingExecutablePathRejectsLookupAndResolutionFailures(t *testing.T) {
	boom := errors.New("private path detail")
	tests := []struct {
		name       string
		executable executablePathFunc
		eval       evalSymlinksFunc
		sibling    string
	}{
		{
			name:       "executable error",
			executable: func() (string, error) { return "", boom },
			eval:       filepath.EvalSymlinks,
			sibling:    "wd-core.exe",
		},
		{
			name:       "resolution error",
			executable: func() (string, error) { return filepath.Join(t.TempDir(), "wd-ui.exe"), nil },
			eval:       func(string) (string, error) { return "", boom },
			sibling:    "wd-core.exe",
		},
		{
			name:       "path traversal",
			executable: func() (string, error) { return filepath.Join(t.TempDir(), "wd-ui.exe"), nil },
			eval:       func(path string) (string, error) { return path, nil },
			sibling:    filepath.Join("..", "wd-core.exe"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := siblingExecutablePath(tt.executable, tt.eval, tt.sibling)
			if !errors.Is(err, ErrCorePath) {
				t.Fatalf("error = %v, want ErrCorePath", err)
			}
			if err.Error() != ErrCorePath.Error() {
				t.Fatalf("path error leaked detail: %q", err)
			}
		})
	}
}
