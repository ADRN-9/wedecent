//go:build !linux && !windows

package terminal

import (
	"errors"
	"os"
)

func ReadPassword(f *os.File) (string, error) {
	return "", errors.New("secure terminal password input is not implemented on this platform")
}
