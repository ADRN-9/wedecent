//go:build windows

package trust

import "testing"

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
		service = "S-1-5-21-999-888-777-1001"
		installer = "S-1-5-21-999-888-777-1002"
		other = "S-1-5-21-999-888-777-1003"
	)
	for _, tc := range []struct {
		name string
		owner, active, root string
		admin, valid bool
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
		service = "S-1-5-21-999-888-777-1001"
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
