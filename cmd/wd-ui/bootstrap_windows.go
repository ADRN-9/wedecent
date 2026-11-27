//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/guiapp"
)

const createNoWindow = 0x08000000

var (
	localCoreProcessMu sync.Mutex
	localCoreProcess *exec.Cmd
	localCoreDone chan error
)

func prepareLocalCore(ctx context.Context, core *coreclient.Client) (guiapp.Core, error) {
	if err := ensureLocalCore(ctx, core, launchSiblingCore, defaultCoreBootstrapConfig); err != nil {
		return nil, err
	}
	recover := func(recoveryCtx context.Context) error {
		return ensureLocalCore(recoveryCtx, core, launchSiblingCore, defaultCoreBootstrapConfig)
	}
	return newRecoveringCore(core, recover), nil
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
	localCoreProcessMu.Lock()
	localCoreProcess = cmd
	localCoreDone = done
	localCoreProcessMu.Unlock()
	go func() {
		err := cmd.Wait()
		done <- err
		close(done)
		localCoreProcessMu.Lock()
		if localCoreProcess == cmd {
			localCoreProcess = nil
			localCoreDone = nil
		}
		localCoreProcessMu.Unlock()
	}()
	return done, nil
}

func stopSiblingCore() error {
	localCoreProcessMu.Lock()
	cmd, done := localCoreProcess, localCoreDone
	localCoreProcessMu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if cmd.ProcessState != nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("stop Local Core before update: %w", err)
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return errors.New("Local Core did not stop before update")
		}
	}
	return nil
}
