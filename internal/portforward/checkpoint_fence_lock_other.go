//go:build !linux

package portforward

import (
	"context"
	"errors"
	"os"
)

func openCheckpointFenceLog(string) (*os.File, error) {
	return nil, errors.New("durable fencing journal currently requires the Linux flock adapter")
}

func lockCheckpointFenceLog(context.Context, *os.File) (func(), error) {
	return nil, errors.New("durable fencing journal currently requires the Linux flock adapter")
}
