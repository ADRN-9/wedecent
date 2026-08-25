//go:build !linux

package terminal

import (
	"bufio"
	"os"
	"strings"
)

// ReadPassword falls back to echoed input until native console handling lands.
func ReadPassword(f *os.File) (string, error) {
	line, err := bufio.NewReader(f).ReadString('\n')
	return strings.TrimSpace(line), err
}
