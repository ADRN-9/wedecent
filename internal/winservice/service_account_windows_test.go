//go:build windows

package winservice

import "testing"

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
