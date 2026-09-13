//go:build !windows

package meshstate

import "os"

func replaceReplayFile(source, destination string) error {
	return os.Rename(source, destination)
}
