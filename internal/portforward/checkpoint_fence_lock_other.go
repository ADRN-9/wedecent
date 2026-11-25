//go:build !linux && !darwin && !windows

package portforward

import (
	"context"
	"errors"
	"os"
)

func openCheckpointFenceLog(string) (*os.File, error) {
	return nil, errors.New("durable fencing journal requires a supported platform lock adapter")
}

func lockCheckpointFenceLog(context.Context, *os.File) (func(), error) {
	return nil, errors.New("durable fencing journal requires a supported platform lock adapter")
}
