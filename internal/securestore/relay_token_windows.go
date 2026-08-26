//go:build windows

package securestore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	cryptProtectUIForbidden  = 0x1
	cryptProtectLocalMachine = 0x4
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32SecureStore    = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32SecureStore.NewProc("LocalFree")
	procMoveFileExW        = kernel32SecureStore.NewProc("MoveFileExW")
)

type dataBlob struct {
	Size uint32
	Data *byte
}

func StoreRelayToken(stateDir, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("relay token cannot be empty")
	}
	if strings.ContainsAny(token, "\r\n") {
		return errors.New("relay token must not contain line breaks")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	plain := []byte(token)
	defer zeroBytes(plain)
	in := blobFor(plain)
	var out dataBlob
	r1, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden|cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		return fmt.Errorf("CryptProtectData: %w", callErr)
	}
	defer localFree(out.Data)
	protected := copyBlob(out)
	if len(protected) == 0 {
		return errors.New("CryptProtectData returned empty output")
	}
	path := RelayTokenPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, protected, 0o600); err != nil {
		return fmt.Errorf("write protected relay token: %w", err)
	}
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace protected relay token: %w", err)
	}
	return nil
}

func LoadRelayToken(stateDir string) (string, error) {
	protected, err := os.ReadFile(RelayTokenPath(stateDir))
	if err != nil {
		return "", err
	}
	if len(protected) == 0 {
		return "", errors.New("protected relay token is empty")
	}
	in := blobFor(protected)
	var out dataBlob
	r1, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("CryptUnprotectData: %w", callErr)
	}
	defer localFree(out.Data)
	plain := copyBlob(out)
	if len(plain) == 0 {
		return "", errors.New("decrypted relay token is empty")
	}
	defer zeroBytes(plain)
	token := string(plain)
	if strings.ContainsAny(token, "\r\n") {
		return "", errors.New("decrypted relay token contains line breaks")
	}
	return token, nil
}

func RelayTokenPath(stateDir string) string {
	return filepath.Join(stateDir, "relay-token.dpapi")
}

func blobFor(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func copyBlob(b dataBlob) []byte {
	if b.Data == nil || b.Size == 0 {
		return nil
	}
	src := unsafe.Slice(b.Data, int(b.Size))
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

func replaceFile(source, destination string) error {
	const (
		moveFileReplaceExisting = 0x1
		moveFileWriteThrough    = 0x8
	)
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	r1, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(src)),
		uintptr(unsafe.Pointer(dst)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if r1 == 0 {
		return fmt.Errorf("MoveFileExW: %w", callErr)
	}
	return nil
}

func localFree(p *byte) {
	if p != nil {
		_, _, _ = procLocalFree.Call(uintptr(unsafe.Pointer(p)))
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
