//go:build !windows

package identity

import "os"

func replaceCertificateFile(tempPath, path string) error {
	return os.Rename(tempPath, path)
}
