//go:build windows

package trust

import (
	"fmt"
	"os"
)

func replaceStoreFile(source, destination string) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("stat temporary trust store: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() {
		return fmt.Errorf("temporary trust store is not a regular file")
	}

	if err := os.Rename(source, destination); err == nil {
		return nil
	} else {
		firstRenameErr := err

		destinationInfo, statErr := os.Lstat(destination)
		if statErr != nil {
			return fmt.Errorf("replace trust store: %w", firstRenameErr)
		}
		if destinationInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("trust store destination must not be a symbolic link")
		}
		if !destinationInfo.Mode().IsRegular() {
			return fmt.Errorf("trust store destination is not a regular file")
		}
		if removeErr := os.Remove(destination); removeErr != nil {
			return fmt.Errorf("remove old trust store: %w", removeErr)
		}
		if renameErr := os.Rename(source, destination); renameErr != nil {
			return fmt.Errorf("install replacement trust store: %w", renameErr)
		}
		return nil
	}
}
