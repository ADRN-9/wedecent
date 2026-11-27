//go:build windows

package updateinfo

import (
	"context"

	"golang.org/x/sys/windows"
)

func windowsCurrentProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func currentProcessElevated() bool {
	return windowsCurrentProcessElevated()
}

func (e PowerShellInstallerExecutor) verifyExecutableDigest(ctx context.Context, path string) (string, error) {
	if e.verifyExecutable != nil {
		return e.verifyExecutable(ctx, path)
	}
	return verifyWindowsPowerShellExecutable(ctx, path)
}
