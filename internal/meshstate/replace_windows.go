//go:build windows

package meshstate

import (
	"fmt"
	"os"
)

func replaceReplayFile(source, destination string) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf(
			"stat temporary replay store: %w",
			err,
		)
	}
	if !sourceInfo.Mode().IsRegular() {
		return fmt.Errorf(
			"temporary replay store is not a regular file",
		)
	}

	if err := os.Rename(source, destination); err == nil {
		return nil
	} else {
		firstRenameErr := err

		destinationInfo, statErr := os.Lstat(destination)
		if statErr != nil {
			return fmt.Errorf(
				"replace replay store: %w",
				firstRenameErr,
			)
		}
		if destinationInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf(
				"replay store destination must not be a symbolic link",
			)
		}
		if !destinationInfo.Mode().IsRegular() {
			return fmt.Errorf(
				"replay store destination is not a regular file",
			)
		}
		if removeErr := os.Remove(destination); removeErr != nil {
			return fmt.Errorf(
				"remove old replay store: %w",
				removeErr,
			)
		}
		if renameErr := os.Rename(
			source,
			destination,
		); renameErr != nil {
			return fmt.Errorf(
				"install replacement replay store: %w",
				renameErr,
			)
		}
		return nil
	}
}
