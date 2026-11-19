//go:build linux

package terminal

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestLinuxPTYDoesNotInheritPairingSecret(t *testing.T) {
	t.Setenv("WEDECENT_PAIRING_SECRET", "canary-pairing-secret")
	pty, err := Start("/bin/sh", 80, 24, "xterm")
	if err != nil {
		t.Fatal(err)
	}
	defer pty.Close()

	command := `if [ "${WEDECENT_PAIRING_SECRET+x}" = x ]; then WD_RESULT=LEAKED; else WD_RESULT=ISOLATED; fi
printf 'WD_SECRET_%s' "$WD_RESULT"
exit
`
	if _, err := pty.Write([]byte(command)); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(pty.reader)
		done <- string(data)
	}()
	select {
	case output := <-done:
		if !strings.Contains(output, "WD_SECRET_ISOLATED") || strings.Contains(output, "WD_SECRET_LEAKED") {
			t.Fatalf("PTY child environment was not isolated: %q", output)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PTY canary")
	}
	if err := pty.Wait(); err != nil {
		t.Fatalf("PTY child: %v", err)
	}
}
