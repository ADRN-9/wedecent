//go:build !linux && !windows

package terminal

import (
	"errors"
	"os"
)

type RawState struct{}

func IsTerminal(f *os.File) bool { return false }
func MakeRaw(f *os.File) (*RawState, error) {
	return nil, errors.New("raw terminal mode unsupported on this platform")
}
func Restore(f *os.File, state *RawState) error { return nil }
func Size(f *os.File) (uint16, uint16, error)   { return 80, 24, nil }
