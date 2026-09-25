//go:build darwin

package terminal

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDarwinPTYRoundTripResizeRawAndExit(t *testing.T) {
	pty, err := Start("/bin/sh", 91, 37, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	defer pty.Close()

	master, ok := pty.reader.(*os.File)
	if !ok {
		t.Fatalf("PTY reader type = %T, want *os.File", pty.reader)
	}
	if !IsTerminal(master) {
		t.Fatal("PTY master is not detected as a terminal")
	}
	if cols, rows, err := Size(master); err != nil {
		t.Fatal(err)
	} else if cols != 91 || rows != 37 {
		t.Fatalf("initial PTY size = %dx%d, want 91x37", cols, rows)
	}

	raw, err := MakeRaw(master)
	if err != nil {
		t.Fatalf("MakeRaw: %v", err)
	}
	if err := Restore(master, raw); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if err := pty.Resize(103, 41); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- pty.Wait() }()

	// Replace the interactive shell with a short-lived program after reporting
	// the current size. This makes child termination deterministic while still
	// exercising input through the PTY line discipline.
	if _, err := pty.Write([]byte("stty size; exec /usr/bin/printf '__WD_DONE__\\n'\n")); err != nil {
		t.Fatalf("write shell command: %v", err)
	}

	readDone := make(chan string, 1)
	readErr := make(chan error, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1024)
		for {
			n, err := pty.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if err != nil {
				text := b.String()
				if (errors.Is(err, io.EOF) || errors.Is(err, syscall.EIO)) &&
					strings.Contains(text, "41 103") &&
					strings.Contains(text, "__WD_DONE__") {
					readDone <- text
					return
				}
				readErr <- err
				return
			}
		}
	}()

	select {
	case <-readDone:
	case err := <-readErr:
		t.Fatalf("PTY read: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PTY output and closure")
	}

	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PTY child exit")
	}
}
