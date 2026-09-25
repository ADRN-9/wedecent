package updateinfo

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type installerCommandRunner func(context.Context, string, string, []string) error

// PowerShellInstallerExecutor applies a verified Windows installer package by
// invoking only scripts already admitted by WithVerifiedInstallerPackage.
// PowerShellPath must be an absolute regular non-symlink executable path; PATH
// lookup and implicit elevation are deliberately not supported.
//
// The validation script is run before mutation to prove this is an upgrade of
// an existing installation, then again after Install-WeDecent.ps1 reports
// success. Install-WeDecent.ps1 owns binary/service rollback for failures that
// occur inside its transaction.
type PowerShellInstallerExecutor struct {
	PowerShellPath string
	InstallDir     string
	StateDir       string
	ServiceName    string
	WebRelay       string
	run            installerCommandRunner
}

func (e PowerShellInstallerExecutor) Execute(ctx context.Context, pkg VerifiedInstallerPackage) error {
	powershell, err := strictExecutablePath(e.PowerShellPath)
	if err != nil {
		return err
	}
	if pkg.Dir == "" {
		return fmt.Errorf("verified package directory is required")
	}
	pkgDir, err := filepath.Abs(pkg.Dir)
	if err != nil {
		return fmt.Errorf("resolve verified package directory")
	}
	info, err := os.Lstat(pkgDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("verified package directory is unavailable")
	}

	validate := filepath.Join(pkgDir, "Test-WeDecentInstall.ps1")
	install := filepath.Join(pkgDir, "Install-WeDecent.ps1")
	if err := e.runScript(ctx, powershell, validate, e.validationArgs()...); err != nil {
		return fmt.Errorf("installed WeDecent preflight failed")
	}
	installArgs := []string{"-BundlePath", pkgDir}
	installArgs = append(installArgs, e.commonArgs()...)
	if err := e.runScript(ctx, powershell, install, installArgs...); err != nil {
		return fmt.Errorf("WeDecent installer failed")
	}
	if err := e.runScript(ctx, powershell, validate, e.validationArgs()...); err != nil {
		return fmt.Errorf("installed WeDecent postflight failed")
	}
	return nil
}

func (e PowerShellInstallerExecutor) commonArgs() []string {
	var args []string
	if e.InstallDir != "" {
		args = append(args, "-InstallDir", e.InstallDir)
	}
	if e.StateDir != "" {
		args = append(args, "-StateDir", e.StateDir)
	}
	if e.ServiceName != "" {
		args = append(args, "-ServiceName", e.ServiceName)
	}
	if e.WebRelay != "" {
		args = append(args, "-WebRelay", e.WebRelay)
	}
	return args
}

func (e PowerShellInstallerExecutor) validationArgs() []string {
	return e.commonArgs()
}

func (e PowerShellInstallerExecutor) runScript(ctx context.Context, powershell, script string, args ...string) error {
	info, err := os.Lstat(script)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("verified installer script is unavailable")
	}
	if e.run != nil {
		return e.run(ctx, powershell, script, append([]string(nil), args...))
	}
	commandArgs := []string{
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "AllSigned",
		"-File", script,
	}
	commandArgs = append(commandArgs, args...)
	cmd := exec.CommandContext(ctx, powershell, commandArgs...)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("PowerShell installer command failed")
	}
	return nil
}

func strictExecutablePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("PowerShell executable path must be absolute")
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("PowerShell executable is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("PowerShell executable must be a regular non-symlink file")
	}
	return path, nil
}
