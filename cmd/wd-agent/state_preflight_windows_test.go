//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func prepareWindowsPreflightTestDir(t *testing.T, broad bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if broad {
		sddl += "(A;OICI;FA;;;BU)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAgentStatePreflightAllowsPrivateWindowsDirectory(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, false)
	if err := preflightAgentState(dir); err != nil {
		t.Fatalf("private agent state unexpectedly rejected: %v", err)
	}
}

func TestAgentStatePreflightRejectsBroadACLBeforeIdentityWrites(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, true)
	for name, run := range map[string]func() error{
		"init": func() error {
			return runInit([]string{"--state", dir, "--name", "acl-test"})
		},
		"identity": func() error {
			return runIdentity([]string{"--state", dir, "--name", "acl-test"})
		},
		"enrollment-proof": func() error {
			return runEnrollmentProof([]string{"--state", dir, "--request"})
		},
		"serve": func() error {
			return runAgent(context.Background(), serveConfig{StateDir: dir, Name: "acl-test"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil || !strings.Contains(err.Error(), "agent state security preflight") {
				t.Fatalf("insecure state not rejected before identity operations: %v", err)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("state created files before ACL validation: %v", entries)
			}
			for _, file := range []string{"identity.key.dpapi", "identity.key", "identity.crt", "pairing-secret.sha256", "trusted-clients.json"} {
				_, statErr := os.Lstat(filepath.Join(dir, file))
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("%s created before ACL rejection: %v", file, statErr)
				}
			}
		})
	}
}
