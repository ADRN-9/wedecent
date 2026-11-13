//go:build windows

package trust

import "testing"

func TestValidatePairingDACLFailClosed(t *testing.T) {
	const owner = "S-1-5-21-1234-5678-9012-1001"
	cases := []struct {
		name string
		sddl string
		valid bool
	}{
		{"current-user-system-admin", "O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"world-access", "D:P(A;;FA;;;WD)", false},
		{"authenticated-users", "D:P(A;;GR;;;AU)", false},
		{"builtin-users", "D:P(A;;FA;;;BU)", false},
		{"inherit-only-allow", "D:AI(A;IO;FA;;;WD)(A;;FA;;;" + owner + ")", true},
		{"deny-is-safe", "D:P(D;;FA;;;WD)(A;;FA;;;" + owner + ")", true},
		{"no-dacl", "O:" + owner, false},
		{"null-or-empty", "D:", false},
		{"callback-ace", "D:P(XA;;FA;;;WD)", false},
		{"bad-entry", "D:P(A;;FA;;;)", false},
		{"unterminated", "D:P(A;;FA;;;" + owner, false},
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
