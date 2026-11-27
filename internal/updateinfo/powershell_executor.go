package updateinfo

import (
	"context"
	"encoding/json"
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
	isElevated     func() bool
	verifyExecutable func(context.Context, string) (string, error)
}

func (e PowerShellInstallerExecutor) Execute(ctx context.Context, transaction InstallTransaction, pkg VerifiedInstallerPackage) error {
	if ctx == nil {
		return fmt.Errorf("installer context is required")
	}
	if err := transaction.validate(); err != nil || transaction.Phase != InstallPhaseExecuting {
		return fmt.Errorf("%w: installer transaction is not authorized for execution", ErrInstallTransaction)
	}
	if err := pkg.validate(); err != nil {
		return err
	}
	if pkg.Version != transaction.TargetVersion || pkg.archiveDigest != transaction.PackageDigest {
		return fmt.Errorf("%w: verified package does not match installer transaction", ErrInstallerPackage)
	}
	if err := e.requireElevatedContext(); err != nil {
		return err
	}
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
	installArgs := []string{"-BundlePath", pkgDir, "-TransactionId", transaction.ID, "-ExpectedPackageSHA256", transaction.PackageDigest, "-ExpectedManifestSHA256", transaction.ManifestDigest, "-PreviousVersion", transaction.PreviousVersion, "-TransactionSequence", fmt.Sprintf("%d", transaction.Sequence)}
	installArgs = append(installArgs, e.commonArgs()...)
	if err := e.runScript(ctx, powershell, install, installArgs...); err != nil {
		return fmt.Errorf("WeDecent installer failed")
	}
	if err := e.runScript(ctx, powershell, validate, e.validationArgs()...); err != nil {
		return fmt.Errorf("installed WeDecent postflight failed")
	}
	return nil
}

type windowsInstallJournal struct {
	TransactionID   string `json:"transaction_id"`
	PackageSHA256   string `json:"package_sha256"`
	ManifestSHA256  string `json:"manifest_sha256"`
	PreviousVersion string `json:"previous_version"`
	Sequence        uint64 `json:"sequence"`
	Version         string `json:"version"`
	Phase           string `json:"phase"`
}

func (e PowerShellInstallerExecutor) FinalizeCommitted(ctx context.Context, state State) error {
	if ctx == nil || state.PendingInstall != nil || state.InstalledVersion == "" {
		return fmt.Errorf("%w: committed cleanup state is unavailable or pending", ErrInstallCleanupPending)
	}
	if !filepath.IsAbs(e.InstallDir) || !filepath.IsAbs(e.StateDir) || e.ServiceName == "" {
		return fmt.Errorf("%w: absolute install and state directories plus service name are required", ErrInstallCleanupPending)
	}
	if err := e.requireElevatedContext(); err != nil {
		return fmt.Errorf("%w: %v", ErrInstallCleanupPending, err)
	}
	powershell, err := strictExecutablePath(e.PowerShellPath)
	if err != nil {
		return err
	}
	script := filepath.Join(e.InstallDir, "Recover-WeDecentInstall.ps1")
	args := []string{
		"-FinalizeCommitted",
		"-InstallDir", filepath.Clean(e.InstallDir),
		"-StateDir", filepath.Clean(e.StateDir),
		"-ServiceName", e.ServiceName,
		"-ExpectedStableSequence", fmt.Sprintf("%d", state.StableSequence),
		"-ExpectedInstalledVersion", state.InstalledVersion,
	}
	if err := e.runScript(ctx, powershell, script, args...); err != nil {
		return fmt.Errorf("%w: privileged committed backup cleanup failed", ErrInstallCleanupPending)
	}
	return nil
}

func (e PowerShellInstallerExecutor) Recover(ctx context.Context, transaction InstallTransaction) (InstallRecoveryResult, error) {
	if ctx == nil {
		return InstallRecoveryUnknown, fmt.Errorf("%w: recovery context is required", ErrInstallTransaction)
	}
	if err := transaction.validate(); err != nil || transaction.Phase != InstallPhaseRecoveryRequired {
		return InstallRecoveryUnknown, fmt.Errorf("%w: recovery transaction is not authorized", ErrInstallTransaction)
	}
	if !filepath.IsAbs(e.InstallDir) || !filepath.IsAbs(e.StateDir) || e.ServiceName == "" {
		return InstallRecoveryUnknown, fmt.Errorf("%w: absolute install and state directories plus service name are required", ErrInstallTransaction)
	}
	if err := e.requireElevatedContext(); err != nil {
		return InstallRecoveryUnknown, fmt.Errorf("%w: %v", ErrInstallRecoveryRequired, err)
	}
	powershell, err := strictExecutablePath(e.PowerShellPath)
	if err != nil {
		return InstallRecoveryUnknown, err
	}
	script := filepath.Join(e.InstallDir, "Recover-WeDecentInstall.ps1")
	args := []string{
		"-TransactionId", transaction.ID,
		"-InstallDir", filepath.Clean(e.InstallDir),
		"-StateDir", filepath.Clean(e.StateDir),
		"-ServiceName", e.ServiceName,
		"-ExpectedManifestSHA256", transaction.ManifestDigest,
		"-ExpectedPackageSHA256", transaction.PackageDigest,
		"-Sequence", fmt.Sprintf("%d", transaction.Sequence),
		"-PreviousVersion", transaction.PreviousVersion,
		"-TargetVersion", transaction.TargetVersion,
	}
	if err := e.runScript(ctx, powershell, script, args...); err != nil {
		return InstallRecoveryUnknown, fmt.Errorf("%w: privileged Windows recovery failed", ErrInstallRecoveryRequired)
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return InstallRecoveryUnknown, fmt.Errorf("%w: ProgramData is unavailable", ErrInstallRecoveryRequired)
	}
	journalPath := filepath.Join(programData, "WeDecent", "install-transactions", transaction.ID+".json")
	info, err := os.Lstat(journalPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return InstallRecoveryUnknown, fmt.Errorf("%w: recovered transaction journal is unavailable", ErrInstallRecoveryRequired)
	}
	data, err := os.ReadFile(journalPath)
	if err != nil {
		return InstallRecoveryUnknown, fmt.Errorf("%w: recovered transaction journal cannot be read", ErrInstallRecoveryRequired)
	}
	var journal windowsInstallJournal
	if err := json.Unmarshal(data, &journal); err != nil ||
		journal.TransactionID != transaction.ID ||
		journal.PackageSHA256 != transaction.PackageDigest ||
		journal.ManifestSHA256 != transaction.ManifestDigest ||
		journal.PreviousVersion != transaction.PreviousVersion ||
		journal.Sequence != transaction.Sequence ||
		journal.Version != transaction.TargetVersion {
		return InstallRecoveryUnknown, fmt.Errorf("%w: recovered journal does not match transaction", ErrInstallRecoveryRequired)
	}
	switch journal.Phase {
	case "committed":
		return InstallRecoveryApplied, nil
	case "rolled-back":
		return InstallRecoveryNotApplied, nil
	default:
		return InstallRecoveryUnknown, fmt.Errorf("%w: Windows recovery outcome remains ambiguous", ErrInstallRecoveryRequired)
	}
}

func (e PowerShellInstallerExecutor) requireElevatedContext() error {
	elevated := currentProcessElevated()
	if e.isElevated != nil {
		elevated = e.isElevated()
	}
	if !elevated {
		return fmt.Errorf("Windows installer executor requires an already elevated process; implicit UAC elevation is not supported")
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
	before, err := e.verifyExecutableDigest(ctx, powershell)
	if err != nil {
		return fmt.Errorf("verify trusted PowerShell executable: %w", err)
	}
	cmd := exec.CommandContext(ctx, powershell, commandArgs...)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	runErr := cmd.Run()
	after, verifyErr := e.verifyExecutableDigest(ctx, powershell)
	if verifyErr != nil || after != before {
		return fmt.Errorf("PowerShell executable identity changed during installer execution")
	}
	if runErr != nil {
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
