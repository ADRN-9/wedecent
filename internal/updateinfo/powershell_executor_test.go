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
	if err := executor.Execute(context.Background(), VerifiedInstallerPackage{Dir: pkgDir, Version: "v0.4.0"}); err != nil {
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
	if err := executor.Execute(context.Background(), VerifiedInstallerPackage{Dir: pkgDir}); err == nil {
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

	if err := (PowerShellInstallerExecutor{PowerShellPath: "powershell.exe"}).Execute(context.Background(), VerifiedInstallerPackage{Dir: pkgDir}); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative PowerShell error = %v", err)
	}

	target := filepath.Join(root, "real-powershell.exe")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "powershell.exe")
	if err := os.Symlink(target, link); err == nil {
		if err := (PowerShellInstallerExecutor{PowerShellPath: link}).Execute(context.Background(), VerifiedInstallerPackage{Dir: pkgDir}); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("symlink PowerShell error = %v", err)
		}
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
