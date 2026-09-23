//go:build !windows

package main

import (
	"context"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
)

func prepareLocalCore(context.Context, *coreclient.Client) error {
	return nil
}
