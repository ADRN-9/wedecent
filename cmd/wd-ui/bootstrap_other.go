//go:build !windows

package main

import (
	"context"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/guiapp"
)

func prepareLocalCore(_ context.Context, core *coreclient.Client) (guiapp.Core, error) {
	return core, nil
}
