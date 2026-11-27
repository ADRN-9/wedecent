package updateinfo

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type recordedInstallerCommand struct {
	script string
	args   []string
}

func TestPowerShellInstallerExecutorRunsPreflightInstallPostflight(t *testing.T) {
	root := privateTempDir(t)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Install-WeDecent.ps1", "Test-WeDecentInstall.ps1"} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var commands []recordedInstallerCommand
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell,
		InstallDir:     `C:\Program Files\WeDecent`,
		StateDir:       `C:\ProgramData\WeDecent\agent`,
		ServiceName:    "WeDecentAgent",
		WebRelay:       "https://relay.wedecent.com",
		run: func(_ context.Context, gotPowerShell, script string, args []string) error {
			if gotPowerShell != powershell {
				t.Fatalf("PowerShell path = %q, want %q", gotPowerShell, powershell)
			}
			commands = append(commands, recordedInstallerCommand{script: filepath.Base(script), args: append([]string(nil), args...)})
			return nil
		},
	}
	if err := executor.Execute(context.Background(), executorTestTransaction("v0.4.0"), verifiedInstallerPackageForTest(t, pkgDir, "v0.4.0")); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(commands) != 3 {
		t.Fatalf("command count = %d, want 3", len(commands))
	}
	if got, want := []string{commands[0].script, commands[1].script, commands[2].script}, []string{"Test-WeDecentInstall.ps1", "Install-WeDecent.ps1", "Test-WeDecentInstall.ps1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("script order = %v, want %v", got, want)
	}
	if !containsArgPair(commands[1].args, "-BundlePath", pkgDir) {
		t.Fatalf("install args missing verified bundle path: %v", commands[1].args)
	}
	transaction := executorTestTransaction("v0.4.0")
	for _, pair := range [][2]string{
		{"-TransactionId", transaction.ID},
		{"-ExpectedPackageSHA256", transaction.PackageDigest},
		{"-ExpectedManifestSHA256", transaction.ManifestDigest},
		{"-PreviousVersion", transaction.PreviousVersion},
		{"-TransactionSequence", "1"},
	} {
		if !containsArgPair(commands[1].args, pair[0], pair[1]) {
			t.Fatalf("install args missing transaction binding %v: %v", pair, commands[1].args)
		}
	}
	for _, command := range commands {
		for _, pair := range [][2]string{
			{"-InstallDir", executor.InstallDir},
			{"-StateDir", executor.StateDir},
			{"-ServiceName", executor.ServiceName},
			{"-WebRelay", executor.WebRelay},
		} {
			if !containsArgPair(command.args, pair[0], pair[1]) {
				t.Fatalf("%s args missing %v: %v", command.script, pair, command.args)
			}
		}
	}
}

func TestPowerShellInstallerExecutorRejectsNonElevatedCallerBeforeProcessStart(t *testing.T) {
	root := t.TempDir()
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Install-WeDecent.ps1", "Test-WeDecentInstall.ps1"} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell,
		isElevated:     func() bool { return false },
		run: func(context.Context, string, string, []string) error {
			calls++
			return nil
		},
	}
	err := executor.Execute(context.Background(), executorTestTransaction("v0.4.0"), verifiedInstallerPackageForTest(t, pkgDir, "v0.4.0"))
	if err == nil || !strings.Contains(err.Error(), "already elevated") {
		t.Fatalf("non-elevated Execute() error = %v, want fail-closed elevation error", err)
	}
	if calls != 0 {
		t.Fatalf("installer commands started for non-elevated caller: %d", calls)
	}
}

func TestPowerShellInstallerExecutorPreflightFailurePreventsMutation(t *testing.T) {
	root := privateTempDir(t)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Install-WeDecent.ps1", "Test-WeDecentInstall.ps1"} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	calls := 0
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell,
		run: func(context.Context, string, string, []string) error {
			calls++
			return errors.New("preflight failed")
		},
	}
	if err := executor.Execute(context.Background(), executorTestTransaction("v0.4.0"), verifiedInstallerPackageForTest(t, pkgDir, "v0.4.0")); err == nil {
		t.Fatal("Execute() unexpectedly succeeded")
	}
	if calls != 1 {
		t.Fatalf("commands after failed preflight = %d, want 1", calls)
	}
}

func TestPowerShellInstallerExecutorRejectsUntrustedExecutablePath(t *testing.T) {
	root := privateTempDir(t)
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "Install-WeDecent.ps1"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "Test-WeDecentInstall.ps1"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := (PowerShellInstallerExecutor{PowerShellPath: "powershell.exe"}).Execute(context.Background(), executorTestTransaction("v0.4.0"), verifiedInstallerPackageForTest(t, pkgDir, "v0.4.0")); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative PowerShell error = %v", err)
	}

	target := filepath.Join(root, "real-powershell.exe")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "powershell.exe")
	if err := os.Symlink(target, link); err == nil {
		if err := (PowerShellInstallerExecutor{PowerShellPath: link}).Execute(context.Background(), executorTestTransaction("v0.4.0"), verifiedInstallerPackageForTest(t, pkgDir, "v0.4.0")); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("symlink PowerShell error = %v", err)
		}
	}
}

func TestPowerShellInstallerExecutorRejectsForgedPackageAndTransactionMismatch(t *testing.T) {
	root := privateTempDir(t)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Install-WeDecent.ps1", "Test-WeDecentInstall.ps1"} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell,
		run: func(context.Context, string, string, []string) error {
			calls++
			return nil
		},
	}
	transaction := executorTestTransaction("v0.4.0")
	forged := VerifiedInstallerPackage{Dir: pkgDir, Version: "v0.4.0"}
	if err := executor.Execute(context.Background(), transaction, forged); !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("forged package error = %v, want ErrInstallerPackage", err)
	}
	valid := verifiedInstallerPackageForTest(t, pkgDir, "v0.4.0")
	mismatch := transaction
	mismatch.PackageDigest = strings.Repeat("c", 64)
	if err := executor.Execute(context.Background(), mismatch, valid); !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("package digest mismatch error = %v, want ErrInstallerPackage", err)
	}
	unauthorized := transaction
	unauthorized.Phase = InstallPhasePending
	if err := executor.Execute(context.Background(), unauthorized, valid); !errors.Is(err, ErrInstallTransaction) {
		t.Fatalf("unauthorized phase error = %v, want ErrInstallTransaction", err)
	}
	tampered := valid
	tampered.Version = "v0.4.1"
	if err := executor.Execute(context.Background(), transaction, tampered); !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("tampered package error = %v, want ErrInstallerPackage", err)
	}
	contentBound := verifiedInstallerPackageForTest(t, pkgDir, "v0.4.0")
	if err := os.WriteFile(filepath.Join(pkgDir, "wd.exe"), []byte("modified after verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), transaction, contentBound); !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("modified package content error = %v, want ErrInstallerPackage", err)
	}
	if calls != 0 {
		t.Fatalf("PowerShell commands = %d, want 0", calls)
	}
}

func TestPowerShellInstallerExecutorRecoveryMapsDurableJournalOutcome(t *testing.T) {
	for _, test := range []struct {
		phase string
		want  InstallRecoveryResult
	}{
		{phase: "committed", want: InstallRecoveryApplied},
		{phase: "rolled-back", want: InstallRecoveryNotApplied},
	} {
		t.Run(test.phase, func(t *testing.T) {
			root := privateTempDir(t)
			t.Setenv("ProgramData", root)
			powershell := filepath.Join(root, "powershell.exe")
			if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			installDir := filepath.Join(root, "install")
			stateDir := filepath.Join(installDir, "data", "agent")
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(installDir, "Recover-WeDecentInstall.ps1")
			if err := os.WriteFile(script, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			transaction := executorTestTransaction("v0.4.0")
			transaction.Phase = InstallPhaseRecoveryRequired
			journal := windowsInstallJournal{
				TransactionID: transaction.ID, PackageSHA256: transaction.PackageDigest,
				ManifestSHA256: transaction.ManifestDigest, PreviousVersion: transaction.PreviousVersion,
				Sequence: transaction.Sequence, Version: transaction.TargetVersion, Phase: test.phase,
			}
			journalDir := filepath.Join(root, "WeDecent", "install-transactions")
			if err := os.MkdirAll(journalDir, 0o700); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(journal)
			if err != nil {
				t.Fatal(err)
			}
			journalPath := filepath.Join(journalDir, transaction.ID+".json")
			if err := os.WriteFile(journalPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			called := false
			executor := PowerShellInstallerExecutor{
				PowerShellPath: powershell, InstallDir: installDir, StateDir: stateDir, ServiceName: "WeDecentAgent",
				run: func(_ context.Context, gotPowerShell, gotScript string, args []string) error {
					called = true
					if gotPowerShell != powershell || gotScript != script {
						t.Fatalf("recovery command paths = %q, %q", gotPowerShell, gotScript)
					}
					for _, pair := range [][2]string{
						{"-TransactionId", transaction.ID},
						{"-ExpectedManifestSHA256", transaction.ManifestDigest},
						{"-ExpectedPackageSHA256", transaction.PackageDigest},
						{"-Sequence", "1"},
						{"-PreviousVersion", transaction.PreviousVersion},
						{"-TargetVersion", transaction.TargetVersion},
					} {
						if !containsArgPair(args, pair[0], pair[1]) {
							t.Fatalf("recovery args missing %v: %v", pair, args)
						}
					}
					return nil
				},
			}
			got, err := executor.Recover(context.Background(), transaction)
			if err != nil || got != test.want || !called {
				t.Fatalf("Recover() = %v, %v, called=%v; want %v", got, err, called, test.want)
			}
		})
	}
}

func TestPowerShellInstallerExecutorRecoveryRejectsMismatchedJournal(t *testing.T) {
	root := privateTempDir(t)
	t.Setenv("ProgramData", root)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	installDir := filepath.Join(root, "install")
	stateDir := filepath.Join(installDir, "data", "agent")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "Recover-WeDecentInstall.ps1"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	transaction := executorTestTransaction("v0.4.0")
	transaction.Phase = InstallPhaseRecoveryRequired
	journalDir := filepath.Join(root, "WeDecent", "install-transactions")
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(windowsInstallJournal{
		TransactionID: transaction.ID, PackageSHA256: strings.Repeat("c", 64),
		ManifestSHA256: transaction.ManifestDigest, PreviousVersion: transaction.PreviousVersion,
		Sequence: transaction.Sequence, Version: transaction.TargetVersion, Phase: "rolled-back",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journalDir, transaction.ID+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell, InstallDir: installDir, StateDir: stateDir, ServiceName: "WeDecentAgent",
		run: func(context.Context, string, string, []string) error { return nil },
	}
	if got, err := executor.Recover(context.Background(), transaction); !errors.Is(err, ErrInstallRecoveryRequired) || got != InstallRecoveryUnknown {
		t.Fatalf("Recover() = %v, %v; want unknown recovery error", got, err)
	}
}

func verifiedInstallerPackageForTest(t *testing.T, dir, version string) VerifiedInstallerPackage {
	t.Helper()
	for _, name := range installerFiles {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(path, []byte("verified fixture: "+name), 0o600); err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	pkg, err := newVerifiedInstallerPackage(dir, version, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func executorTestTransaction(version string) InstallTransaction {
	return InstallTransaction{
		ID: strings.Repeat("1", 32), Sequence: 1,
		ManifestDigest:  strings.Repeat("b", 64),
		PackageDigest:   strings.Repeat("a", 64),
		PreviousVersion: "v0.3.9", TargetVersion: version,
		Phase: InstallPhaseExecuting,
	}
}

func containsArgPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestPowerShellInstallerExecutorFinalizesOnlyCommittedState(t *testing.T) {
	root := privateTempDir(t)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	installDir := filepath.Join(root, "install")
	stateDir := filepath.Join(installDir, "data", "agent")
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(installDir, "Recover-WeDecentInstall.ps1")
	if err := os.WriteFile(script, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var command recordedInstallerCommand
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell,
		InstallDir:     installDir,
		StateDir:       stateDir,
		ServiceName:    "WeDecentAgent",
		run: func(_ context.Context, gotPowerShell, gotScript string, args []string) error {
			if gotPowerShell != powershell || gotScript != script {
				t.Fatalf("finalizer command paths = %q, %q", gotPowerShell, gotScript)
			}
			command = recordedInstallerCommand{script: filepath.Base(gotScript), args: append([]string(nil), args...)}
			return nil
		},
	}
	state := State{
		Version:          UpdateStateVersionWithInstall,
		StableSequence:   91,
		KeysetEpoch:      1,
		KeysetDigest:     strings.Repeat("a", 64),
		InstalledVersion: "v0.4.0",
	}
	if err := executor.FinalizeCommitted(context.Background(), state); err != nil {
		t.Fatalf("FinalizeCommitted() error = %v", err)
	}
	for _, arg := range []string{
		"-FinalizeCommitted",
		"-InstallDir", installDir,
		"-StateDir", stateDir,
		"-ServiceName", "WeDecentAgent",
		"-ExpectedStableSequence", "91",
		"-ExpectedInstalledVersion", "v0.4.0",
	} {
		if !containsString(command.args, arg) {
			t.Fatalf("finalizer args %v missing %q", command.args, arg)
		}
	}
	if err := executor.FinalizeCommitted(context.Background(), State{
		Version:        UpdateStateVersionWithInstall,
		PendingInstall: &InstallTransaction{Phase: InstallPhaseExecuting},
	}); err == nil {
		t.Fatal("finalizer accepted state with a pending installation")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
