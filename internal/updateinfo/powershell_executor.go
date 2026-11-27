package updateinfo

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type installerCommandRunner func(context.Context, string, string, []string) error

type PowerShellInstallerExecutor struct {
	PowerShellPath string
	InstallDir string
	StateDir string
	ServiceName string
	WebRelay string
	TransactionRoot string
	run installerCommandRunner
}

func (e PowerShellInstallerExecutor) Execute(ctx context.Context, transaction InstallTransaction, pkg VerifiedInstallerPackage) error {
	powershell, err := strictExecutablePath(e.PowerShellPath)
	if err != nil { return err }
	if err := pkg.validateFor(transaction); err != nil { return err }
	pkgDir, err := filepath.Abs(pkg.Directory())
	if err != nil { return fmt.Errorf("resolve verified package directory") }

	validate := filepath.Join(pkgDir, "Test-WeDecentInstall.ps1")
	install := filepath.Join(pkgDir, "Install-WeDecent.ps1")
	if err := e.runScript(ctx, powershell, validate, e.validationArgs()...); err != nil {
		return fmt.Errorf("installed WeDecent preflight failed")
	}
	args := []string{
		"-BundlePath", pkgDir,
		"-UpdateTransactionId", transaction.ID,
		"-ExpectedPreviousVersion", transaction.PreviousVersion,
		"-ExpectedTargetVersion", transaction.TargetVersion,
		"-ExpectedPackageSHA256", transaction.PackageDigest,
		"-UpdateTransactionRoot", e.transactionRoot(),
	}
	args = append(args, e.commonArgs()...)
	if err := e.runScript(ctx, powershell, install, args...); err != nil {
		return fmt.Errorf("WeDecent installer failed")
	}
	if err := e.runScript(ctx, powershell, validate, e.validationArgs()...); err != nil {
		return fmt.Errorf("installed WeDecent postflight failed")
	}
	return nil
}

// Commit removes transaction backups only after the protected updater state
// has durably committed the target version and sequence.
func (e PowerShellInstallerExecutor) Commit(ctx context.Context, transaction InstallTransaction) error {
	if err := transaction.validate(); err != nil { return err }
	powershell, err := strictExecutablePath(e.PowerShellPath)
	if err != nil { return err }
	script := filepath.Join(e.transactionRoot(), transaction.ID, "Install-WeDecent.ps1")
	args := []string{
		"-UpdateTransactionAction", "Commit",
		"-UpdateTransactionId", transaction.ID,
		"-ExpectedPreviousVersion", transaction.PreviousVersion,
		"-ExpectedTargetVersion", transaction.TargetVersion,
		"-ExpectedPackageSHA256", transaction.PackageDigest,
		"-UpdateTransactionRoot", e.transactionRoot(),
	}
	args = append(args, e.commonArgs()...)
	if err := e.runScript(ctx, powershell, script, args...); err != nil {
		return fmt.Errorf("installer transaction finalization failed")
	}
	return os.RemoveAll(filepath.Join(e.transactionRoot(), transaction.ID))
}

// Recover reconciles the on-disk installer journal and backup set. The script
// returns "applied" only when all target binaries and metadata are verified;
// otherwise it restores and verifies the previous installation before
// returning "not-applied". Any ambiguous result remains an error.
func (e PowerShellInstallerExecutor) Recover(ctx context.Context, transaction InstallTransaction) (InstallRecoveryResult, error) {
	if err := transaction.validate(); err != nil { return InstallRecoveryUnknown, err }
	powershell, err := strictExecutablePath(e.PowerShellPath)
	if err != nil { return InstallRecoveryUnknown, err }
	script := filepath.Join(e.transactionRoot(), transaction.ID, "Install-WeDecent.ps1")
	args := []string{
		"-UpdateTransactionAction", "Recover",
		"-UpdateTransactionId", transaction.ID,
		"-ExpectedPreviousVersion", transaction.PreviousVersion,
		"-ExpectedTargetVersion", transaction.TargetVersion,
		"-ExpectedPackageSHA256", transaction.PackageDigest,
		"-UpdateTransactionRoot", e.transactionRoot(),
	}
	args = append(args, e.commonArgs()...)
	output, err := e.runScriptOutput(ctx, powershell, script, args...)
	if err != nil { return InstallRecoveryUnknown, fmt.Errorf("installer transaction recovery failed") }
	switch strings.TrimSpace(output) {
	case "applied":
		return InstallRecoveryApplied, nil
	case "not-applied":
		return InstallRecoveryNotApplied, nil
	default:
		return InstallRecoveryUnknown, fmt.Errorf("installer recovery returned an ambiguous result")
	}
}

func (e PowerShellInstallerExecutor) transactionRoot() string {
	if e.TransactionRoot != "" { return filepath.Clean(e.TransactionRoot) }
	return filepath.Join(os.Getenv("ProgramData"), "WeDecent", "update-transactions")
}

func (e PowerShellInstallerExecutor) commonArgs() []string {
	var args []string
	if e.InstallDir != "" { args = append(args, "-InstallDir", e.InstallDir) }
	if e.StateDir != "" { args = append(args, "-StateDir", e.StateDir) }
	if e.ServiceName != "" { args = append(args, "-ServiceName", e.ServiceName) }
	if e.WebRelay != "" { args = append(args, "-WebRelay", e.WebRelay) }
	return args
}

func (e PowerShellInstallerExecutor) validationArgs() []string { return e.commonArgs() }

func (e PowerShellInstallerExecutor) runScript(ctx context.Context, powershell, script string, args ...string) error {
	_, err := e.runScriptOutput(ctx, powershell, script, args...)
	return err
}

func (e PowerShellInstallerExecutor) runScriptOutput(ctx context.Context, powershell, script string, args ...string) (string, error) {
	info, err := os.Lstat(script)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("verified installer script is unavailable")
	}
	if e.run != nil {
		if err := e.run(ctx, powershell, script, append([]string(nil), args...)); err != nil { return "", err }
		return "", nil
	}
	commandArgs := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-File", script}
	commandArgs = append(commandArgs, args...)
	cmd := exec.CommandContext(ctx, powershell, commandArgs...)
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	output, err := cmd.Output()
	if err != nil { return "", fmt.Errorf("PowerShell installer command failed") }
	return string(output), nil
}

func strictExecutablePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) { return "", fmt.Errorf("PowerShell executable path must be absolute") }
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil { return "", fmt.Errorf("PowerShell executable is unavailable") }
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("PowerShell executable must be a regular non-symlink file")
	}
	return path, nil
}
