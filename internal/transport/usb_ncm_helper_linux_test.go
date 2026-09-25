//go:build linux

package transport

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUSBNCMHelperSyntax(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux USB NCM helper")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to validate USB NCM helper: %v", err)
	}
	path := filepath.Join("..", "..", "scripts", "wedecent-linux-usb-ncm.sh")
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("USB NCM helper shell syntax: %v\n%s", err, out)
	}
	if out, err := exec.Command(bash, path, "--help").CombinedOutput(); err != nil {
		t.Fatalf("USB NCM helper help path: %v\n%s", err, out)
	}
}
