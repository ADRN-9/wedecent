package session

import "testing"

func TestInBandAuthorizationFrameSelection(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{name: "raw relay uses authorized session frame", endpoint: "relay://127.0.0.1:18443/wd_aaaaaaaaaaaaaaaa", want: true},
		{name: "web relay uses parked session frame", endpoint: "wsrelay://relay.example.test/wd_aaaaaaaaaaaaaaaa", want: false},
		{name: "case-insensitive web relay", endpoint: " WSRELAY://relay.example.test/wd_aaaaaaaaaaaaaaaa ", want: false},
		{name: "direct TCP", endpoint: "tcp://127.0.0.1:17443", want: true},
		{name: "Bluetooth RFCOMM", endpoint: "rfcomm://00:11:22:33:44:55:7", want: true},
		{name: "USB serial", endpoint: "serial:/dev/ttyACM0", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := usesInBandAuthorization(tt.endpoint); got != tt.want {
				t.Fatalf("usesInBandAuthorization(%q) = %v, want %v", tt.endpoint, got, tt.want)
			}
		})
	}
}
