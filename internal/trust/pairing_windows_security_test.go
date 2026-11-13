//go:build windows

package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidatePairingDACLFailClosed(t *testing.T) {
	const owner = "S-1-5-21-1234-5678-9012-1001"
	cases := []struct {
		name  string
		sddl  string
		valid bool
	}{
		{"private-user-admin-system", "O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"world-access", "D:P(A;;FA;;;WD)", false},
		{"authenticated-users", "D:P(A;;GR;;;AU)", false},
		{"builtin-users", "D:P(A;;FA;;;BU)", false},
		{"inherit-only-world-access", "D:AI(A;IO;FA;;;WD)(A;;FA;;;" + owner + ")", false},
		{"deny-or-callback-ace", "D:P(D;;FA;;;WD)(A;;FA;;;" + owner + ")", false},
		{"no-dacl", "O:" + owner, false},
		{"null-or-empty", "D:", false},
		{"callback-ace", "D:P(XA;;FA;;;WD)", false},
		{"missing-principal", "D:P(A;;FA;;;)", false},
		{"unterminated", "D:P(A;;FA;;;" + owner, false},
		{"read-only-current", "D:P(A;;FR;;;" + owner + ")", false},
		{"missing-current-access", "D:P(A;;FA;;;BA)", false},
		{"safe-inherited-allow", "D:AI(A;ID;FA;;;" + owner + ")(A;;FA;;;SY)", true},
		{"unsafe-inherited-allow", "D:AI(A;ID;FA;;;WD)(A;;FA;;;" + owner + ")", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePairingDACL(tc.sddl, owner)
			if (err == nil) != tc.valid {
				t.Fatalf("DACL valid=%v err=%v, want valid=%v", err == nil, err, tc.valid)
			}
		})
	}
}

func TestValidatePairingOwnerAndServiceProvisioningTransition(t *testing.T) {
	const (
		service   = "S-1-5-21-999-888-777-1001"
		installer = "S-1-5-21-999-888-777-1002"
		other     = "S-1-5-21-999-888-777-1003"
	)
	for _, tc := range []struct {
		name                string
		owner, active, root string
		admin, valid        bool
	}{
		{"user-temp-state", installer, installer, installer, false, true},
		{"installed-service-own-state", service, service, service, false, true},
		{"admin-owned-service-state", windowsAdminSID, service, windowsAdminSID, false, true},
		{"system-owned-service-state", windowsSystemSID, service, windowsSystemSID, false, true},
		{"elevated-installer-provisions-service-owner", service, installer, service, true, true},
		{"standard-user-cannot-cross-owner", service, installer, service, false, false},
		{"foreign-owner-file-denied", other, service, service, false, false},
		{"arbitrary-admin-owner-not-accepted", other, installer, service, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePairingOwner(tc.owner, tc.active, tc.root, tc.admin)
			if (err == nil) != tc.valid {
				t.Fatalf("owner validation err=%v want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestValidatePairingDACLInstalledService(t *testing.T) {
	const (
		service   = "S-1-5-21-999-888-777-1001"
		installer = "S-1-5-21-999-888-777-1002"
	)
	sddl := "D:P(A;OICI;FA;;;" + service + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if err := validatePairingDACLForPrincipal(sddl, service, service, false); err != nil {
		t.Fatalf("dedicated service ACL: %v", err)
	}
	if err := validatePairingDACLForPrincipal(sddl, installer, service, true); err != nil {
		t.Fatalf("administrator provisioning ACL: %v", err)
	}
	if err := validatePairingDACLForPrincipal(sddl, installer, service, false); err == nil {
		t.Fatal("non-admin installer accepted third-party service ACL")
	}
	if err := validatePairingDACLForPrincipal("D:P(A;;FA;;;" + service + ")(A;;FA;;;BU)", service, service, false); err == nil {
		t.Fatal("service ACL with broad users grant was accepted")
	}
}

func TestValidatePairingDACLNativeSIDIdentity(t *testing.T) {
	localAdmin, err := windows.StringToSid("LA")
	if err != nil {
		t.Fatalf("resolve local Administrator SID: %v", err)
	}
	const (
		service   = "S-1-5-21-999-888-777-1001"
		installer = "S-1-5-21-999-888-777-1002"
		other     = "S-1-5-21-999-888-777-1003"
	)
	localAdminSID := localAdmin.String()
	serviceACL := "D:P(A;;FA;;;" + service + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	localAdminACL := "D:P(A;;FA;;;LA)(A;;FA;;;SY)(A;;FA;;;BA)"
	for _, tc := range []struct {
		name              string
		sddl, active, root string
		admin, valid      bool
	}{
		{"local-administrator-own-identity", localAdminACL, localAdminSID, localAdminSID, false, true},
		{"local-administrator-numeric-equivalent", "D:P(A;;FA;;;" + localAdminSID + ")", localAdminSID, localAdminSID, false, true},
		{"ordinary-user-own-state", "D:P(A;;FA;;;" + installer + ")(A;;FA;;;SY)", installer, installer, false, true},
		{"localsystem-own-state", "D:P(A;;FA;;;SY)", windowsSystemSID, windowsSystemSID, false, true},
		{"dedicated-service-own-state", serviceACL, service, service, false, true},
		{"elevated-installer-and-service-owner", serviceACL, installer, service, true, true},
		{"standard-installer-cannot-use-service-acl", serviceACL, installer, service, false, false},
		{"admin-group-membership-does-not-authorize-local-administrator", localAdminACL, other, other, true, false},
		{"local-administrator-not-service-identity", "D:P(A;;FA;;;LA)(A;;FA;;;" + service + ")(A;;FA;;;BA)", service, service, true, false},
		{"world-unauthorized", "D:P(A;;FA;;;" + service + ")(A;;FA;;;WD)", service, service, false, false},
		{"authenticated-users-unauthorized", "D:P(A;;FA;;;" + service + ")(A;;FA;;;AU)", service, service, false, false},
		{"builtin-users-unauthorized", "D:P(A;;FA;;;" + service + ")(A;;FA;;;BU)", service, service, false, false},
		{"unrelated-numeric-sid-unauthorized", "D:P(A;;FA;;;" + service + ")(A;;FA;;;" + other + ")", service, service, false, false},
		{"unknown-trustee-rejected", "D:P(A;;FA;;;" + service + ")(A;;FA;;;XX)", service, service, false, false},
		{"inherited-world-unauthorized", "D:AI(A;ID;FA;;;WD)(A;;FA;;;" + service + ")", service, service, false, false},
		{"null-dacl-rejected", "D:NO_ACCESS_CONTROL", service, service, false, false},
		{"partial-access-rejected", "D:P(A;;FR;;;" + service + ")", service, service, false, false},
		{"malformed-ace-rejected", "D:P(A;;FA;;;" + service, service, service, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePairingDACLForPrincipal(tc.sddl, tc.active, tc.root, tc.admin)
			if (err == nil) != tc.valid {
				t.Fatalf("validatePairingDACLForPrincipal valid=%v err=%v, want %v", err == nil, err, tc.valid)
			}
		})
	}
	if err := validatePairingOwner(localAdminSID, service, service, true); err == nil {
		t.Fatal("unrelated local Administrator account was accepted as service state owner")
	}
}

// Windows can serialize an explicit numeric RID-500 trustee as LA. Validate
// the exact same native principal after the SDDL round trip.
func TestWindowsPairingLocalAdministratorSDDLRoundTrip(t *testing.T) {
	localAdmin, err := windows.StringToSid("LA")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + localAdmin.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	if err := validatePairingDACLForPrincipal(sddl, localAdmin.String(), localAdmin.String(), false); err != nil {
		t.Fatalf("native local Administrator SDDL round-trip rejected: %v", err)
	}
	t.Logf("local Administrator alias emitted by Windows SDDL serializer: %v", strings.Contains(sddl, ";;;LA)"))
}

func TestSecureWindowsPairingPathRejectsReparsePoint(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink creation unavailable: %v", err)
	}
	if err := secureWindowsPairingPath(link); err == nil {
		t.Fatal("Windows reparse-point pairing state accepted")
	}
}
