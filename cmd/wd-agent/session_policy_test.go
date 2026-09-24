package main

import (
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/session"
)

func TestParseServeConfigSessionPolicyDefaults(t *testing.T) {
	cfg, err := parseServeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionIdleTimeout != session.DefaultSessionIdleTimeout {
		t.Fatalf("idle timeout = %v, want %v", cfg.SessionIdleTimeout, session.DefaultSessionIdleTimeout)
	}
	if cfg.SessionMaxDuration != session.DefaultSessionMaxDuration {
		t.Fatalf("max duration = %v, want %v", cfg.SessionMaxDuration, session.DefaultSessionMaxDuration)
	}
	if got := cfg.sessionPolicy(); got != (session.SessionPolicy{IdleTimeout: session.DefaultSessionIdleTimeout, MaxDuration: session.DefaultSessionMaxDuration}) {
		t.Fatalf("session policy = %+v", got)
	}
}

func TestParseServeConfigSessionPolicyCanDisableLimits(t *testing.T) {
	cfg, err := parseServeConfig([]string{"--session-idle-timeout=0", "--session-max-duration=0"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionIdleTimeout != 0 || cfg.SessionMaxDuration != 0 {
		t.Fatalf("disabled policy = idle %v max %v", cfg.SessionIdleTimeout, cfg.SessionMaxDuration)
	}
}

func TestParseServeConfigRejectsInvalidSessionPolicy(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "negative idle", args: []string{"--session-idle-timeout=-1s"}, want: "must not be negative"},
		{name: "subsecond max", args: []string{"--session-max-duration=500ms"}, want: "zero or at least 1s"},
		{name: "idle exceeds max", args: []string{"--session-idle-timeout=2h", "--session-max-duration=1h"}, want: "must not exceed maximum duration"},
		{name: "over seven days", args: []string{"--session-max-duration=169h"}, want: "must not exceed 168h"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseServeConfig(tc.args)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestSessionPolicyFlagAcceptsIndependentDisable(t *testing.T) {
	cfg, err := parseServeConfig([]string{"--session-idle-timeout=0", "--session-max-duration=45m"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionIdleTimeout != 0 || cfg.SessionMaxDuration != 45*time.Minute {
		t.Fatalf("policy = idle %v max %v", cfg.SessionIdleTimeout, cfg.SessionMaxDuration)
	}
}
