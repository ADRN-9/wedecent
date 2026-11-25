//go:build windows

package audit

import (
	"errors"

	"golang.org/x/sys/windows"
)

func authorizePairingRecoveryOperator() error {
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	ok, err := windows.GetCurrentProcessToken().IsMember(admins)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("pairing reconciliation requires an elevated administrator token")
	}
	return nil
}
