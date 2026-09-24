package main

import (
	"errors"
	"fmt"
	"io"

	"wedecent.com/wedecent/internal/updateinfo"
)

var ErrUpdateKeyUsage = errors.New("usage: wd-ui update-key status")

func runUpdateKeyCommand(args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "status" {
		return ErrUpdateKeyUsage
	}
	fingerprint, err := updateinfo.ProvisionedPublicKeyFingerprint()
	if errors.Is(err, updateinfo.ErrPublicKeyUnprovisioned) {
		_, writeErr := fmt.Fprintln(stdout, "provisioned=false")
		return writeErr
	}
	if err != nil {
		return fmt.Errorf("invalid compiled update public key: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, "provisioned=true"); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "fingerprint=sha256:%s\n", fingerprint)
	return err
}
