package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"wedecent.com/wedecent/internal/trust"
)

const maxRecoveryAuthorityTokenBytes = 4096

func loadRecoveryAuthorityToken(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" {
		return "", errors.New("credential path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("credential must be a regular non-symlink file")
	}
	if info.Size() < 32 || info.Size() > maxRecoveryAuthorityTokenBytes {
		return "", errors.New("credential size is outside the permitted bounds")
	}
	if runtime.GOOS == "windows" {
		if err := trust.VerifyPairingStatePath(path); err != nil {
			return "", fmt.Errorf("unsafe Windows credential ACL: %w", err)
		}
	} else if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("credential file must not be accessible to group or other users")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return "", errors.New("credential changed during secure open")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecoveryAuthorityTokenBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) < 32 || len(data) > maxRecoveryAuthorityTokenBytes {
		return "", errors.New("credential size is outside the permitted bounds")
	}
	token := string(data)
	for i := range data {
		data[i] = 0
	}
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("credential is empty or malformed")
	}
	return token, nil
}
