//go:build windows

package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsDeleteAccess uint32 = 0x00010000

type windowsFileDispositionInfo struct {
	DeleteFile byte
}

func verifyAndDeleteLegacyKeyByHandle(path string, protected ed25519.PrivateKey) error {
	f, legacy, err := openLegacyKeyForDeletion(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	if !legacy.Public().(ed25519.PublicKey).Equal(protected.Public().(ed25519.PublicKey)) {
		return errors.New("protected and legacy identity private keys do not match")
	}
	if err := markOpenedFileForDeletion(f); err != nil {
		return fmt.Errorf("mark redundant plaintext identity private key for deletion: %w", err)
	}
	return nil
}

func openLegacyKeyForDeletion(path string) (*os.File, ed25519.PrivateKey, error) {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, fmt.Errorf("encode legacy identity private key path: %w", err)
	}

	h, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_READ|windowsDeleteAccess,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open legacy identity private key for cleanup: %w", err)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		_ = windows.CloseHandle(h)
		return nil, nil, errors.New("wrap legacy identity private key handle")
	}
	closeWithErr := func(err error) (*os.File, ed25519.PrivateKey, error) {
		_ = f.Close()
		return nil, nil, err
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return closeWithErr(fmt.Errorf("inspect legacy identity private key handle: %w", err))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return closeWithErr(errors.New("legacy identity private key must be a regular file"))
	}

	stat, err := f.Stat()
	if err != nil {
		return closeWithErr(fmt.Errorf("stat legacy identity private key handle: %w", err))
	}
	if !stat.Mode().IsRegular() || stat.Size() < 0 || stat.Size() > maxLegacyIdentityKeyFileSize {
		return closeWithErr(errors.New("legacy identity private key has an invalid size"))
	}

	data, err := io.ReadAll(io.LimitReader(f, maxLegacyIdentityKeyFileSize+1))
	if err != nil {
		return closeWithErr(fmt.Errorf("read legacy identity private key for cleanup: %w", err))
	}
	defer zeroBytes(data)
	if len(data) > maxLegacyIdentityKeyFileSize {
		return closeWithErr(errors.New("legacy identity private key has an invalid size"))
	}
	priv, err := parseLegacyPrivateKey(data)
	if err != nil {
		return closeWithErr(err)
	}
	return f, priv, nil
}

func markOpenedFileForDeletion(f *os.File) error {
	info := windowsFileDispositionInfo{DeleteFile: 1}
	return windows.SetFileInformationByHandle(
		windows.Handle(f.Fd()),
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
}
