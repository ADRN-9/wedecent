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

const bridgeTimeout = 3 * time.Second

var errUsage = errors.New("usage: wd-desktop-bridge <status|inventory|version>")

type coreSource interface {
	desktopbridge.StatusSource
	desktopbridge.InventorySource
}

func main() {
	if err := run(os.Args[1:], os.Stdout, nil); err != nil {
		fmt.Fprintln(os.Stderr, "wd-desktop-bridge:", publicError(err))
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, source coreSource) error {
	if len(args) != 1 {
		return errUsage
	}
	if args[0] == "version" {
		return buildinfo.Write(stdout, "wd-desktop-bridge")
	}
	if source == nil {
		client, err := coreclient.New(coreclient.Config{Timeout: bridgeTimeout})
		if err != nil {
			return err
		}
		source = client
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(true)
	switch args[0] {
	case "status":
		status, err := desktopbridge.GetStatus(context.Background(), source)
		if err != nil {
			return err
		}
		return encoder.Encode(status)
	case "inventory":
		inventory, err := desktopbridge.GetInventory(context.Background(), source)
		if err != nil {
			return err
		}
		return encoder.Encode(inventory)
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
		return "Local Core rejected the desktop request"
	}
	return "Local Core desktop request failed"
}
