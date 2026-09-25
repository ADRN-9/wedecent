//go:build linux

package transport

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRFCOMMHardwareHarnessSyntax(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux hardware harness")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to validate hardware harness: %v", err)
	}
	path := filepath.Join("..", "..", "scripts", "test-linux-rfcomm-hardware.sh")
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("hardware harness shell syntax: %v\n%s", err, out)
	}
}
