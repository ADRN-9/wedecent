//go:build !windows

package identity

import "os"

func replaceCertificateFile(tempPath, path string) error {
	return os.Rename(tempPath, path)
}

func openCertificateFile(path string) (*os.File, error) {
	return os.Open(path)
}
