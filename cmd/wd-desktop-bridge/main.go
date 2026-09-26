package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"wedecent.com/wedecent/internal/buildinfo"
	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/desktopbridge"
)

const statusTimeout = 3 * time.Second

var errUsage = errors.New("usage: wd-desktop-bridge <status|version>")

type statusSource interface {
	desktopbridge.StatusSource
}

func main() {
	if err := run(os.Args[1:], os.Stdout, nil); err != nil {
		fmt.Fprintln(os.Stderr, "wd-desktop-bridge:", publicError(err))
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, source statusSource) error {
	if len(args) != 1 {
		return errUsage
	}
	switch args[0] {
	case "version":
		return buildinfo.Write(stdout, "wd-desktop-bridge")
	case "status":
		if source == nil {
			client, err := coreclient.New(coreclient.Config{Timeout: statusTimeout})
			if err != nil {
				return err
			}
			source = client
		}
		status, err := desktopbridge.GetStatus(context.Background(), source)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(status)
	default:
		return errUsage
	}
}

func publicError(err error) string {
	if errors.Is(err, errUsage) {
		return errUsage.Error()
	}
	if coreclient.IsUnavailable(err) || errors.Is(err, context.DeadlineExceeded) {
		return "Local Core is unavailable"
	}
	var remote *coreclient.RemoteError
	if errors.As(err, &remote) {
		return "Local Core rejected the status request"
	}
	return "Local Core status request failed"
}
