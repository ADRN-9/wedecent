//go:build windows

package securefile

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidatePrivateFileOwner(t *testing.T) {
	sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateFileOwner(sid.String(), sid.String()); err != nil {
		t.Fatalf("matching owner rejected: %v", err)
	}
	if err := validatePrivateFileOwner("S-1-5-21-1-2-3-1002", sid.String()); err == nil {
		t.Fatal("mismatched owner was accepted")
	}
}

func TestValidatePrivateFileDACL(t *testing.T) {
	current, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	good := "D:(A;;FA;;;" + current.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	if err := validatePrivateFileDACL(good, current.String()); err != nil {
		t.Fatalf("valid private DACL rejected: %v", err)
	}
	bad := "D:(A;;FA;;;WD)(A;;FA;;;" + current.String() + ")"
	if err := validatePrivateFileDACL(bad, current.String()); err == nil || !strings.Contains(err.Error(), "unauthorized SID") {
		t.Fatalf("broad DACL error = %v", err)
	}
}
