//go:build windows

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
)

func TestPublicErrorConnectOutcomeUnknownBeatsTimeout(t *testing.T) {
	err := errors.Join(
		ErrConnectOutcomeUnknown,
		context.DeadlineExceeded,
		&coreclient.UnavailableError{Stage: coreclient.UnavailableStageReadResponse},
	)
	message := publicError(err)
	if !strings.Contains(message, "Connection result is uncertain") {
		t.Fatalf("publicError() = %q; want connection uncertainty", message)
	}
	if strings.Contains(message, "timed out") {
		t.Fatalf("publicError() = %q; timeout hid ambiguous outcome", message)
	}
	if !strings.Contains(message, "restart Local Core") {
		t.Fatalf("publicError() = %q; want restart guidance before retry", message)
	}
}

func TestPublicErrorTerminalWriteOutcomeUnknown(t *testing.T) {
	err := errors.Join(
		ErrTerminalWriteOutcomeUnknown,
		&coreclient.UnavailableError{Stage: coreclient.UnavailableStageReadResponse},
	)
	message := publicError(err)
	if !strings.Contains(message, "input may already have been sent") {
		t.Fatalf("publicError() = %q; want duplicate-send warning", message)
	}
	if !strings.Contains(message, "check terminal output") {
		t.Fatalf("publicError() = %q; want terminal verification guidance", message)
	}
}

func TestPublicErrorGenericUnavailableUsesRecoveryLanguage(t *testing.T) {
	message := publicError(&coreclient.UnavailableError{Stage: coreclient.UnavailableStageDial})
	if strings.Contains(message, "Start wd-core") {
		t.Fatalf("publicError() = %q; stale manual-start guidance", message)
	}
	if !strings.Contains(message, "Recovery did not complete") {
		t.Fatalf("publicError() = %q; want recovery failure guidance", message)
	}
}
