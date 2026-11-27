package updateinfo

import (
	"context"
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

func testExecutorTransaction() InstallTransaction {
	return InstallTransaction{
		ID:              "0123456789abcdef0123456789abcdef",
		Sequence:        42,
		ManifestDigest:  strings.Repeat("a", 64),
		PackageDigest:   strings.Repeat("b", 64),
		PreviousVersion: "v0.3.9",
		TargetVersion:   "v0.4.0",
		Phase:           InstallPhaseExecuting,
	}
}

func testVerifiedPackage(dir string, transaction InstallTransaction) VerifiedInstallerPackage {
	files := make(map[string]string, len(installerFiles))
	for _, name := range installerFiles {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("verified fixture: "+name), 0o600); err != nil {
			panic(err)
		}
		digest, err := hashRegularFile(path)
		if err != nil {
			panic(err)
		}
		files[name] = digest
	}
	return VerifiedInstallerPackage{token: &verifiedInstallerPackageToken{
		dir: dir, version: transaction.TargetVersion,
		manifestDigest: transaction.ManifestDigest,
		packageDigest:  transaction.PackageDigest,
		files:          files,
	}}
}

func TestPowerShellInstallerExecutorRunsTransactionBoundPreflightInstallPostflight(t *testing.T) {
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
	tx := testExecutorTransaction()
	var commands []recordedInstallerCommand
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell, InstallDir: `C:\Program Files\WeDecent`,
		StateDir:    `C:\Program Files\WeDecent\data\agent`,
		ServiceName: "WeDecentAgent", WebRelay: "https://relay.wedecent.com",
		TransactionRoot: filepath.Join(root, "transactions"),
		run: func(_ context.Context, gotPowerShell, script string, args []string) error {
			if gotPowerShell != powershell {
				t.Fatalf("PowerShell path = %q, want %q", gotPowerShell, powershell)
			}
			commands = append(commands, recordedInstallerCommand{script: filepath.Base(script), args: append([]string(nil), args...)})
			return nil
		},
	}
	if err := executor.Execute(context.Background(), tx, testVerifiedPackage(pkgDir, tx)); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(commands) != 3 {
		t.Fatalf("command count = %d, want 3", len(commands))
	}
	if got, want := []string{commands[0].script, commands[1].script, commands[2].script},
		[]string{"Test-WeDecentInstall.ps1", "Install-WeDecent.ps1", "Test-WeDecentInstall.ps1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("script order = %v, want %v", got, want)
	}
	for _, pair := range [][2]string{
		{"-UpdateTransactionId", tx.ID},
		{"-ExpectedPreviousVersion", tx.PreviousVersion},
		{"-ExpectedTargetVersion", tx.TargetVersion},
		{"-ExpectedPackageSHA256", tx.PackageDigest},
		{"-UpdateTransactionRoot", executor.TransactionRoot},
	} {
		if !containsArgPair(commands[1].args, pair[0], pair[1]) {
			t.Fatalf("install args missing %v: %v", pair, commands[1].args)
		}
	}
	if !containsArgPair(commands[1].args, "-BundlePath", pkgDir) {
		t.Fatalf("install args missing bundle: %v", commands[1].args)
	}
}

func TestPowerShellInstallerExecutorRejectsForgedPackageBeforeMutation(t *testing.T) {
	root := privateTempDir(t)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	executor := PowerShellInstallerExecutor{PowerShellPath: powershell, run: func(context.Context, string, string, []string) error { calls++; return nil }}
	if err := executor.Execute(context.Background(), testExecutorTransaction(), VerifiedInstallerPackage{}); err == nil {
		t.Fatal("forged zero-value package was accepted")
	}
	if calls != 0 {
		t.Fatalf("commands after forged package = %d, want 0", calls)
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
	executor := PowerShellInstallerExecutor{PowerShellPath: powershell, run: func(context.Context, string, string, []string) error {
		calls++
		return errors.New("preflight failed")
	}}
	tx := testExecutorTransaction()
	if err := executor.Execute(context.Background(), tx, testVerifiedPackage(pkgDir, tx)); err == nil {
		t.Fatal("Execute() unexpectedly succeeded")
	}
	if calls != 1 {
		t.Fatalf("commands after failed preflight = %d, want 1", calls)
	}
}

func TestPowerShellInstallerExecutorRequiresAbsoluteAndNonSymlinkExecutable(t *testing.T) {
	root := privateTempDir(t)
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tx := testExecutorTransaction()
	if err := (PowerShellInstallerExecutor{PowerShellPath: "powershell.exe"}).Execute(context.Background(), tx, testVerifiedPackage(pkgDir, tx)); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative PowerShell path error = %v", err)
	}
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "powershell-link.exe")
	if err := os.Symlink(powershell, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := (PowerShellInstallerExecutor{PowerShellPath: link}).Execute(context.Background(), tx, testVerifiedPackage(pkgDir, tx)); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink PowerShell path error = %v", err)
	}
}

func TestPowerShellInstallerExecutorCommitRequiresTransactionScript(t *testing.T) {
	root := privateTempDir(t)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	tx := testExecutorTransaction()
	txDir := filepath.Join(root, tx.ID)
	if err := os.Mkdir(txDir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(txDir, "Install-WeDecent.ps1")
	if err := os.WriteFile(script, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var args []string
	executor := PowerShellInstallerExecutor{PowerShellPath: powershell, TransactionRoot: root, run: func(_ context.Context, _ string, gotScript string, gotArgs []string) error {
		if gotScript != script {
			t.Fatalf("script = %q, want %q", gotScript, script)
		}
		args = gotArgs
		return nil
	}}
	if err := executor.Commit(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if !containsArgPair(args, "-UpdateTransactionAction", "Commit") {
		t.Fatalf("commit args = %v", args)
	}
}


func containsArgPair(args []string, name, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name && args[i+1] == value {
			return true
		}
	}
	return false
}


func TestPowerShellInstallerExecutorRejectsModifiedVerifiedPackage(t *testing.T) {
	root := privateTempDir(t)
	powershell := filepath.Join(root, "powershell.exe")
	if err := os.WriteFile(powershell, []byte("fixture"), 0o600); err != nil { t.Fatal(err) }
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o700); err != nil { t.Fatal(err) }
	tx := testExecutorTransaction()
	pkg := testVerifiedPackage(pkgDir, tx)
	if err := os.WriteFile(filepath.Join(pkgDir, "wd-agent.exe"), []byte("attacker replacement"), 0o600); err != nil { t.Fatal(err) }
	calls := 0
	executor := PowerShellInstallerExecutor{PowerShellPath: powershell, run: func(context.Context, string, string, []string) error { calls++; return nil }}
	if err := executor.Execute(context.Background(), tx, pkg); !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("modified package error = %v, want ErrInstallerPackage", err)
	}
	if calls != 0 { t.Fatalf("executor commands = %d, want 0", calls) }
}
