//go:build !linux

package terminal

import (
	"errors"
	"os"
	"os/exec"
)

type PTY struct {
	Master *os.File
	Cmd    *exec.Cmd
}

func Start(shell string, cols, rows uint16, term string) (*PTY, error) {
	return nil, errors.New("PTY server is currently implemented for Linux only; Windows ConPTY is Phase 2")
}

func (p *PTY) Resize(cols, rows uint16) error { return errors.New("unsupported") }
func (p *PTY) Close() error                   { return nil }
