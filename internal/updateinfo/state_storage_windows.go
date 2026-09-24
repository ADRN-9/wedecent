//go:build windows

package updateinfo

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32UpdateState = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileExW     = kernel32UpdateState.NewProc("MoveFileExW")
)

func validateStateFileInfo(_ os.FileInfo) error { return nil }
func validateStateDirInfo(_ os.FileInfo) error  { return nil }

func replaceStateFile(tmpPath, path, _ string) error {
	from, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		return fmt.Errorf("%w: encode update state temp path: %v", ErrInvalidState, err)
	}
	to, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: encode update state path: %v", ErrInvalidState, err)
	}
	r1, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(from)),
		uintptr(unsafe.Pointer(to)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if r1 == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == 0 {
			return fmt.Errorf("%w: MoveFileExW failed", ErrInvalidState)
		}
		return fmt.Errorf("%w: MoveFileExW failed: %v", ErrInvalidState, callErr)
	}
	return nil
}
