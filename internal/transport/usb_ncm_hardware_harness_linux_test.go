//go:build linux

package transport

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUSBNCMHardwareHarnessSyntax(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux USB NCM hardware harness")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to validate USB NCM hardware harness: %v", err)
	}
	path := filepath.Join("..", "..", "scripts", "test-linux-usb-ncm-hardware.sh")
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("USB NCM hardware harness shell syntax: %v\n%s", err, out)
	}
}
