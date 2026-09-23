//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
)

const createNoWindow = 0x08000000

func prepareLocalCore(ctx context.Context, core *coreclient.Client) error {
	return ensureLocalCore(ctx, core, launchSiblingCore, defaultCoreBootstrapConfig)
}

func launchSiblingCore() (<-chan error, error) {
	path, err := siblingExecutablePath(os.Executable, filepath.EvalSymlinks, "wd-core.exe")
	if err != nil {
		return nil, ErrCoreLaunch
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrCoreLaunch
	}

	cmd := exec.Command(path)
	cmd.Dir = filepath.Dir(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	if err := cmd.Start(); err != nil {
		return nil, ErrCoreLaunch
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		close(done)
	}()
	return done, nil
}
