//go:build windows

package winservice

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"wedecent.com/wedecent/internal/trust"
)

func TestQualifyAccountForLookup(t *testing.T) {
	tests := []struct {
		name     string
		account  string
		computer string
		want     string
	}{
		{
			name:     "local shorthand",
			account:  `.\WeDecentSvc`,
			computer: "TESTHOST",
			want:     `TESTHOST\WeDecentSvc`,
		},
		{
			name:     "qualified account",
			account:  `DOMAIN\WeDecentSvc`,
			computer: "TESTHOST",
			want:     `DOMAIN\WeDecentSvc`,
		},
		{
			name:     "trims whitespace",
			account:  `  .\WeDecentSvc  `,
			computer: "TESTHOST",
			want:     `TESTHOST\WeDecentSvc`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := qualifyAccountForLookup(tt.account, tt.computer); got != tt.want {
				t.Fatalf("qualifyAccountForLookup(%q, %q) = %q, want %q",
					tt.account, tt.computer, got, tt.want)
			}
		})
	}
}

func TestRestrictDirectoryProvisionsPrivatePairingState(t *testing.T) {
	adminSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := windows.GetCurrentProcessToken().IsMember(adminSID)
	if err != nil {
		t.Fatal(err)
	}
	if !admin {
		t.Skip("native state owner changes require an elevated installer token")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "existing-state"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestrictDirectory(state, current.Username); err != nil {
		t.Fatalf("elevated state provisioning failed: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(state, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(self.User.Sid) {
		t.Fatalf("service state owner %s, want %s", owner, self.User.Sid)
	}
	secret, err := trust.RotatePairingSecret(state)
	if err != nil {
		t.Fatalf("pairing rotation after service ACL provisioning: %v", err)
	}
	if ok, err := trust.CheckPairingSecret(state, secret); err != nil || !ok {
		t.Fatalf("provisioned state pairing secret invalid: %v, %v", ok, err)
	}
	if err := RestrictDirectory(state, current.Username); err != nil {
		t.Fatalf("finalize pairing state ownership: %v", err)
	}
	if ok, err := trust.CheckPairingSecret(state, secret); err != nil || !ok {
		t.Fatalf("service-owned state pairing secret invalid: %v, %v", ok, err)
	}
}
