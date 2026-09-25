//go:build linux

package transport

import (
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func openSerialTestPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	if master == nil {
		_ = syscall.Close(fd)
		t.Fatal("create PTY master")
	}
	unlock := int32(0)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		master.Close()
		t.Fatalf("unlock PTY: %v", errno)
	}
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&n))); errno != 0 {
		master.Close()
		t.Fatalf("get PTY number: %v", errno)
	}
	return master, "/dev/pts/" + itoa(uint64(n))
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestSerialDialerLinuxPTYIOAndDeadline(t *testing.T) {
	master, slavePath := openSerialTestPTY(t)
	defer master.Close()

	conn, err := (SerialDialer{}).Dial(t.Context(), slavePath)
	if err != nil {
		t.Fatalf("dial serial PTY: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr().Network() != "serial" || conn.RemoteAddr().String() != slavePath {
		t.Fatalf("remote addr = %s/%s", conn.RemoteAddr().Network(), conn.RemoteAddr().String())
	}

	fromClient := []byte("client-to-device")
	if _, err := conn.Write(fromClient); err != nil {
		t.Fatalf("serial write: %v", err)
	}
	got := make([]byte, len(fromClient))
	if _, err := io.ReadFull(master, got); err != nil {
		t.Fatalf("master read: %v", err)
	}
	if string(got) != string(fromClient) {
		t.Fatalf("master read %q, want %q", got, fromClient)
	}

	fromDevice := []byte("device-to-client")
	if _, err := master.Write(fromDevice); err != nil {
		t.Fatalf("master write: %v", err)
	}
	got = make([]byte, len(fromDevice))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("serial read: %v", err)
	}
	if string(got) != string(fromDevice) {
		t.Fatalf("serial read %q, want %q", got, fromDevice)
	}

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	one := make([]byte, 1)
	_, err = conn.Read(one)
	if err == nil {
		t.Fatal("read without data unexpectedly succeeded")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		if netErr, ok := err.(interface{ Timeout() bool }); !ok || !netErr.Timeout() {
			t.Fatalf("deadline read error = %v", err)
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
}

func TestSerialDialerLinuxRejectsNonTTYCharacterDevice(t *testing.T) {
	if _, err := (SerialDialer{}).Dial(t.Context(), "/dev/null"); err == nil {
		t.Fatal("Dial(/dev/null) unexpectedly succeeded")
	}
}
