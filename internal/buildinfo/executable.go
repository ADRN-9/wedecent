package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// ExecutableSHA256 hashes the executable image addressed by the running process.
func ExecutableSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve running executable: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open running executable: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat running executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", errors.New("running executable is not a non-empty regular file")
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash running executable: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
