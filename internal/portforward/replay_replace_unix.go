//go:build !windows

package portforward

import (
	"os"
	"path/filepath"
)

func createReplayFileExclusive(source, destination string) error {
	if err := os.Link(source, destination); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return syncReplayDirectory(filepath.Dir(destination))
}

func syncReplayDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func replaceReplayFile(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
