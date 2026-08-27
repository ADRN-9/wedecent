//go:build !windows

package trust

import "os"

func replaceStoreFile(source, destination string) error {
	return os.Rename(source, destination)
}
