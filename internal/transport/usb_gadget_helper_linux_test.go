//go:build linux

package transport

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUSBGadgetHelperSyntax(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux USB gadget helper")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to validate USB gadget helper: %v", err)
	}
	path := filepath.Join("..", "..", "scripts", "wedecent-linux-usb-gadget.sh")
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("USB gadget helper shell syntax: %v\n%s", err, out)
	}
	if out, err := exec.Command(bash, path, "--help").CombinedOutput(); err != nil {
		t.Fatalf("USB gadget helper help path: %v\n%s", err, out)
	}
}
