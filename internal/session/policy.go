package session

import (
	"errors"
	"time"
)

const (
	DefaultSessionIdleTimeout = 30 * time.Minute
	DefaultSessionMaxDuration = 12 * time.Hour
	maxSessionPolicyDuration  = 7 * 24 * time.Hour
)

type SessionPolicy struct {
	IdleTimeout time.Duration
	MaxDuration time.Duration
}

func (p SessionPolicy) Validate() error {
	if err := validateSessionPolicyDuration("idle timeout", p.IdleTimeout); err != nil {
		return err
	}
	if err := validateSessionPolicyDuration("maximum duration", p.MaxDuration); err != nil {
		return err
	}
	if p.IdleTimeout > 0 && p.MaxDuration > 0 && p.IdleTimeout > p.MaxDuration {
		return errors.New("session idle timeout must not exceed maximum duration")
	}
	return nil
}

func validateSessionPolicyDuration(name string, d time.Duration) error {
	if d < 0 {
		return errors.New("session " + name + " must not be negative")
	}
	if d > 0 && d < time.Second {
		return errors.New("session " + name + " must be zero or at least 1s")
	}
	if d > maxSessionPolicyDuration {
		return errors.New("session " + name + " must not exceed 168h")
	}
	return nil
}

type sessionPolicyTimers struct {
	idleDuration time.Duration
	idle         *time.Timer
	max          *time.Timer
	idleC        <-chan time.Time
	maxC         <-chan time.Time
}

func newSessionPolicyTimers(policy SessionPolicy) *sessionPolicyTimers {
	t := &sessionPolicyTimers{idleDuration: policy.IdleTimeout}
	if policy.IdleTimeout > 0 {
		t.idle = time.NewTimer(policy.IdleTimeout)
		t.idleC = t.idle.C
	}
	if policy.MaxDuration > 0 {
		t.max = time.NewTimer(policy.MaxDuration)
		t.maxC = t.max.C
	}
	return t
}

func (t *sessionPolicyTimers) Activity() {
	if t == nil || t.idle == nil {
		return
	}
	if !t.idle.Stop() {
		select {
		case <-t.idle.C:
		default:
		}
	}
	t.idle.Reset(t.idleDuration)
}

func (t *sessionPolicyTimers) Stop() {
	if t == nil {
		return
	}
	if t.idle != nil {
		t.idle.Stop()
	}
	if t.max != nil {
		t.max.Stop()
	}
}

func signalSessionActivity(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
