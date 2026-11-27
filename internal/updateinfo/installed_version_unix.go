//go:build !windows

package updateinfo

import "errors"

func readProtectedInstalledVersion() (string, error) {
	return "", errors.New("protected Windows installer metadata is unavailable on this platform")
}
