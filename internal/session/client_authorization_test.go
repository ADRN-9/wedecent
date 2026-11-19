package session

import "testing"

func TestUsesRelayGrantEvidence(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{name: "raw relay", endpoint: "relay://127.0.0.1:18443/wd_aaaaaaaaaaaaaaaa", want: true},
		{name: "web relay", endpoint: "wsrelay://relay.example.test/wd_aaaaaaaaaaaaaaaa", want: true},
		{name: "case-insensitive web relay", endpoint: " WSRELAY://relay.example.test/wd_aaaaaaaaaaaaaaaa ", want: true},
		{name: "direct TCP", endpoint: "tcp://127.0.0.1:17443", want: false},
		{name: "Bluetooth RFCOMM", endpoint: "rfcomm://00:11:22:33:44:55:7", want: false},
		{name: "USB serial", endpoint: "serial:/dev/ttyACM0", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := usesRelayGrantEvidence(tt.endpoint); got != tt.want {
				t.Fatalf("usesRelayGrantEvidence(%q) = %v, want %v", tt.endpoint, got, tt.want)
			}
		})
	}
}
