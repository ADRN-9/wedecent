//go:build !windows

package updateinfo

import "context"

func currentProcessElevated() bool { return false }

func (e PowerShellInstallerExecutor) verifyExecutableDigest(ctx context.Context, path string) (string, error) {
	if e.verifyExecutable != nil {
		return e.verifyExecutable(ctx, path)
	}
	return hashRegularFile(path)
}
