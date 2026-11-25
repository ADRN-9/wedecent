//go:build !windows

package audit

import (
	"errors"
	"os"
)

func authorizePairingRecoveryOperator() error {
	if os.Geteuid() != 0 {
		return errors.New("pairing reconciliation requires root authority")
	}
	return nil
}
