//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"

	"wedecent.com/wedecent/internal/guiapp"
)

func runUI(*guiapp.Controller) error {
	return errors.New("wd-ui is only supported on Windows")
}

func showFatal(err error) {
	fmt.Fprintln(os.Stderr, "wd-ui:", err)
}
