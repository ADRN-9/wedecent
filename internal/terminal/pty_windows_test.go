//go:build windows

package terminal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsConPTYRoundTripResizeAndExit(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	shell := filepath.Join(root, "System32", "cmd.exe")
	if _, err := os.Stat(shell); err != nil {
		t.Fatalf("stat cmd.exe: %v", err)
	}

	pty, err := Start(shell, 80, 24, "")
	if err != nil {
		t.Fatalf("start ConPTY: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = pty.Close()
		}
	}()

	if err := pty.Resize(100, 40); err != nil {
		t.Fatalf("resize ConPTY: %v", err)
	}

	const token = "WEDECENT_CONPTY_OK"
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		seen := make([]byte, 0, 8192)
		for len(seen) < 64<<10 {
			n, readErr := pty.Read(buf)
			if n > 0 {
				seen = append(seen, buf[:n]...)
				if bytes.Contains(seen, []byte(token)) {
					readDone <- nil
					return
				}
			}
			if readErr != nil {
				readDone <- fmt.Errorf("read ConPTY output before token: %w", readErr)
				return
			}
		}
		readDone <- errors.New("ConPTY output exceeded limit before token")
	}()

	// Model interactive Enter keystrokes. Windows console input uses carriage
	// return for Enter; CRLF is redirected-text line framing, not terminal input.
	commands := "@echo off\r" +
		"set WD_A=WEDECENT\r" +
		"set WD_B=CONPTY_OK\r" +
		"echo %WD_A%_%WD_B%\r" +
		"exit /b 0\r"
	if _, err := pty.Write([]byte(commands)); err != nil {
		t.Fatalf("write ConPTY input: %v", err)
	}

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		_ = pty.Close()
		closed = true
		t.Fatal("timed out waiting for ConPTY output")
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- pty.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("wait for ConPTY shell: %v", err)
		}
	case <-time.After(10 * time.Second):
		_ = pty.Close()
		closed = true
		t.Fatal("timed out waiting for ConPTY shell exit")
	}

	if err := pty.Close(); err != nil {
		t.Fatalf("close ConPTY: %v", err)
	}
	closed = true
}
