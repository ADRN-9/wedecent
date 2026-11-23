//go:build !windows

package portforward

import (
	"os"
)

func replaceReplayFile(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	dir, err := os.Open(filepathDir(destination))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func filepathDir(path string) string {
	return filepath.Dir(path)
}
