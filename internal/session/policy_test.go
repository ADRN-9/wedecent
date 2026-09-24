package session

import (
	"testing"
	"time"
)

func TestSessionPolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  SessionPolicy
		wantErr bool
	}{
		{name: "defaults", policy: SessionPolicy{IdleTimeout: DefaultSessionIdleTimeout, MaxDuration: DefaultSessionMaxDuration}},
		{name: "both disabled", policy: SessionPolicy{}},
		{name: "idle disabled", policy: SessionPolicy{MaxDuration: time.Hour}},
		{name: "max disabled", policy: SessionPolicy{IdleTimeout: time.Hour}},
		{name: "negative idle", policy: SessionPolicy{IdleTimeout: -time.Second}, wantErr: true},
		{name: "subsecond idle", policy: SessionPolicy{IdleTimeout: time.Millisecond}, wantErr: true},
		{name: "negative max", policy: SessionPolicy{MaxDuration: -time.Second}, wantErr: true},
		{name: "subsecond max", policy: SessionPolicy{MaxDuration: time.Millisecond}, wantErr: true},
		{name: "over seven days", policy: SessionPolicy{MaxDuration: maxSessionPolicyDuration + time.Second}, wantErr: true},
		{name: "idle exceeds max", policy: SessionPolicy{IdleTimeout: 2 * time.Hour, MaxDuration: time.Hour}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestSessionPolicyActivityResetsOnlyIdleTimer(t *testing.T) {
	policy := SessionPolicy{IdleTimeout: 150 * time.Millisecond, MaxDuration: 350 * time.Millisecond}
	timers := newSessionPolicyTimers(policy)
	defer timers.Stop()

	time.Sleep(75 * time.Millisecond)
	timers.Activity()
	select {
	case <-timers.idleC:
		t.Fatal("idle timer fired before reset interval elapsed")
	case <-time.After(90 * time.Millisecond):
	}
	select {
	case <-timers.idleC:
	case <-time.After(150 * time.Millisecond):
		t.Fatal("idle timer did not fire after reset interval")
	}

	select {
	case <-timers.maxC:
	case <-time.After(180 * time.Millisecond):
		t.Fatal("maximum-duration timer was reset by activity")
	}
}

func TestSessionPolicyDisabledTimersHaveNilChannels(t *testing.T) {
	timers := newSessionPolicyTimers(SessionPolicy{})
	defer timers.Stop()
	if timers.idleC != nil || timers.maxC != nil {
		t.Fatalf("disabled policy produced active timer channels: idle=%v max=%v", timers.idleC, timers.maxC)
	}
	timers.Activity()
}

func TestSignalSessionActivityCoalesces(t *testing.T) {
	ch := make(chan struct{}, 1)
	signalSessionActivity(ch)
	signalSessionActivity(ch)
	if got := len(ch); got != 1 {
		t.Fatalf("activity queue length = %d, want 1", got)
	}
}
