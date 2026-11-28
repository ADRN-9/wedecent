//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestUpdateWorkerWaitsForBothAuthenticatedLaunchers(t *testing.T) {
	mode := os.Getenv("WEDECENT_UPDATE_TEST_MODE")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	expected := os.Getenv("WEDECENT_UPDATE_TEST_EXPECTED")
	marker := os.Getenv("WEDECENT_UPDATE_TEST_MARKER")

	switch mode {
	case "worker":
		parentPID, err := strconv.ParseUint(os.Getenv("WEDECENT_UPDATE_TEST_PARENT"), 10, 32)
		if err != nil {
			os.Exit(2)
		}
		callerPID, err := strconv.ParseUint(os.Getenv("WEDECENT_UPDATE_TEST_CALLER"), 10, 32)
		if err != nil {
			os.Exit(3)
		}
		if err := waitForUpdateLaunchers(uint32(parentPID), uint32(callerPID), expected); err != nil {
			os.Exit(4)
		}
		if err := os.WriteFile(marker, []byte("worker-started"), 0o600); err != nil {
			os.Exit(5)
		}
		os.Exit(0)
	case "launcher":
		callerPID, err := strconv.ParseUint(os.Getenv("WEDECENT_UPDATE_TEST_CALLER"), 10, 32)
		if err != nil {
			os.Exit(6)
		}
		cmd := exec.Command(executable, "-test.run=^TestUpdateWorkerWaitsForBothAuthenticatedLaunchers$")
		cmd.Env = append(os.Environ(),
			"WEDECENT_UPDATE_TEST_MODE=worker",
			"WEDECENT_UPDATE_TEST_PARENT="+strconv.Itoa(os.Getpid()),
			"WEDECENT_UPDATE_TEST_CALLER="+strconv.FormatUint(callerPID, 10),
		)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			os.Exit(7)
		}
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			os.Exit(8)
		}
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || line != "READY\n" {
			_ = cmd.Process.Kill()
			os.Exit(9)
		}
		_, _ = fmt.Fprintln(os.Stdout, "READY")
		os.Exit(0)
	case "caller":
		cmd := exec.Command(executable, "-test.run=^TestUpdateWorkerWaitsForBothAuthenticatedLaunchers$")
		cmd.Env = append(os.Environ(),
			"WEDECENT_UPDATE_TEST_MODE=launcher",
			"WEDECENT_UPDATE_TEST_CALLER="+strconv.Itoa(os.Getpid()),
		)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			os.Exit(10)
		}
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			os.Exit(11)
		}
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || line != "READY\n" {
			_ = cmd.Process.Kill()
			os.Exit(12)
		}
		_, _ = fmt.Fprintln(os.Stdout, "READY")
		os.Exit(0)
	}

	if expected != "" || marker != "" {
		t.Fatal("unexpected test helper environment")
	}
	marker = filepath.Join(t.TempDir(), "worker-started")
	cmd := exec.Command(executable, "-test.run=^TestUpdateWorkerWaitsForBothAuthenticatedLaunchers$")
	cmd.Env = append(os.Environ(),
		"WEDECENT_UPDATE_TEST_MODE=caller",
		"WEDECENT_UPDATE_TEST_EXPECTED="+executable,
		"WEDECENT_UPDATE_TEST_MARKER="+marker,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "READY\n" {
		_ = cmd.Process.Kill()
		t.Fatalf("launcher readiness = %q, %v", line, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("original caller process: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(marker); err == nil && string(data) == "worker-started" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("worker did not start after both authenticated launcher processes exited")
}

// TestUpdateProcessIdentityRealProcessProbe is invoked by the privileged installer
// harness under a distinct Windows account. It exercises openExpectedProcess and
// verifyProcessLogonIdentity against the actual harness process token.
func TestUpdateProcessIdentityRealProcessProbe(t *testing.T) {
	if os.Getenv("WEDECENT_IDENTITY_PROBE") != "1" {
		return
	}
	pid, err := strconv.ParseUint(os.Getenv("WEDECENT_IDENTITY_PROBE_TARGET_PID"), 10, 32)
	if err != nil || pid == 0 {
		t.Fatal("invalid target process ID")
	}
	expectedImage := os.Getenv("WEDECENT_IDENTITY_PROBE_EXPECTED_IMAGE")
	evidencePath := os.Getenv("WEDECENT_IDENTITY_PROBE_EVIDENCE")
	expectedBoundary := os.Getenv("WEDECENT_IDENTITY_PROBE_BOUNDARY")
	if expectedImage == "" || evidencePath == "" || (expectedBoundary != "user" && expectedBoundary != "session") {
		t.Fatal("missing process identity probe configuration")
	}
	target, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatalf("open target process for identity evidence: %v", err)
	}
	var targetToken windows.Token
	if err := windows.OpenProcessToken(target, windows.TOKEN_QUERY, &targetToken); err != nil {
		_ = windows.CloseHandle(target)
		t.Fatalf("open target process token: %v", err)
	}
	targetIdentity, targetErr := updateIdentityFromToken(targetToken)
	_ = targetToken.Close()
	_ = windows.CloseHandle(target)
	if targetErr != nil {
		t.Fatalf("read target process identity: %v", targetErr)
	}
	currentIdentity, err := currentUpdateProcessIdentity()
	if err != nil {
		t.Fatalf("read probe process identity: %v", err)
	}
	switch expectedBoundary {
	case "user":
		if strings.EqualFold(targetIdentity.UserSID, currentIdentity.UserSID) {
			t.Fatal("cross-user probe did not use distinct user SIDs")
		}
	case "session":
		if !strings.EqualFold(targetIdentity.UserSID, currentIdentity.UserSID) || targetIdentity.LogonID == currentIdentity.LogonID {
			t.Fatal("cross-session probe did not use the same user SID and distinct logon LUIDs")
		}
	}
	handle, err := openExpectedProcess(uint32(pid), expectedImage)
	if handle != 0 {
		_ = windows.CloseHandle(handle)
	}
	if err == nil {
		t.Fatal("wd-agent process validator accepted a different Windows user or logon session")
	}
	if !strings.Contains(err.Error(), "different Windows user or logon session") {
		t.Fatalf("wd-agent process validator did not reach the identity rejection boundary: %v", err)
	}
	if err := os.WriteFile(evidencePath, []byte(expectedBoundary+"|"+err.Error()), 0o600); err != nil {
		t.Fatalf("write process identity evidence: %v", err)
	}
}

func TestUpdateProcessIdentityRejectsCrossUserAndLogonSession(t *testing.T) {
	base := updateProcessIdentity{
		UserSID: "S-1-5-21-1000",
		LogonID: updateLUID{LowPart: 42, HighPart: 1},
	}
	if !sameUpdateProcessIdentity(base, base) {
		t.Fatal("rejected identical Windows process identity")
	}
	crossUser := base
	crossUser.UserSID = "S-1-5-21-2000"
	if sameUpdateProcessIdentity(base, crossUser) {
		t.Fatal("accepted a different Windows user SID")
	}
	crossSession := base
	crossSession.LogonID.LowPart++
	if sameUpdateProcessIdentity(base, crossSession) {
		t.Fatal("accepted a different Windows logon session")
	}
	missingIdentity := updateProcessIdentity{LogonID: base.LogonID}
	if sameUpdateProcessIdentity(base, missingIdentity) {
		t.Fatal("accepted an ambiguous process identity without a user SID")
	}
}

func TestOpenExpectedProcessRejectsSubstitutedImage(t *testing.T) {
	if _, err := openExpectedProcess(uint32(os.Getpid()), filepath.Join(t.TempDir(), "wd-agent.exe")); err == nil {
		t.Fatal("accepted a process whose image path did not match the installed updater")
	}
}

func TestUpdateCommandRejectsCallerSuppliedTrustAndPaths(t *testing.T) {
	if err := runUpdateCommand([]string{"apply", "--install-dir", `C:Temp`}); err == nil {
		t.Fatal("accepted caller-supplied install path")
	}
	if err := runUpdateCommand([]string{"apply", "--root-key", "attacker"}); err == nil {
		t.Fatal("accepted caller-supplied update root")
	}
}

func TestInstalledUpdaterEntryPointRejectsUninstalledTestBinary(t *testing.T) {
	if err := runUpdateCommand([]string{"apply"}); err == nil {
		t.Fatal("test binary unexpectedly passed installed launcher validation")
	}
}
