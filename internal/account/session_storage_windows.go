//go:build windows

package account

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	windowsSessionStorageVersion = 1
	cryptProtectUIForbidden      = 0x1
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	kernel32Account        = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree          = kernel32Account.NewProc("LocalFree")
)

type dataBlob struct {
	Size uint32
	Data *byte
}

type windowsSessionEnvelope struct {
	StorageVersion       int    `json:"storage_version"`
	Version              int    `json:"version"`
	SupabaseURL          string `json:"supabase_url"`
	PublishableKey       string `json:"publishable_key"`
	UserID               string `json:"user_id"`
	Email                string `json:"email"`
	ExpiresAt            int64  `json:"expires_at"`
	ProtectedCredentials string `json:"protected_credentials"`
}

func decodeSessionStorage(_ os.FileInfo, data []byte) (*Session, error) {
	var envelope windowsSessionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode protected account session: %w", err)
	}
	if envelope.StorageVersion == 0 {
		return nil, errors.New("legacy plaintext Windows account session is not accepted; run 'wd account login' again")
	}
	if envelope.StorageVersion != windowsSessionStorageVersion {
		return nil, fmt.Errorf("unsupported Windows account session storage version %d", envelope.StorageVersion)
	}
	encoded := strings.TrimSpace(envelope.ProtectedCredentials)
	if encoded == "" {
		return nil, errors.New("protected account session credentials are missing")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(ciphertext) == 0 {
		return nil, errors.New("protected account session credentials are invalid")
	}
	plaintext, err := dpapiUnprotect(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unprotect account session credentials: %w", err)
	}
	defer zeroBytes(plaintext)

	var session Session
	if err := json.Unmarshal(plaintext, &session); err != nil {
		return nil, errors.New("decrypted account session is invalid")
	}
	if envelope.Version != session.Version ||
		envelope.SupabaseURL != session.SupabaseURL ||
		envelope.PublishableKey != session.PublishableKey ||
		envelope.UserID != session.UserID ||
		envelope.Email != session.Email ||
		envelope.ExpiresAt != session.ExpiresAt {
		return nil, errors.New("protected account session metadata does not match the file envelope")
	}
	return &session, nil
}

func encodeSessionStorage(session *Session) ([]byte, error) {
	protectedSession, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("encode protected account session: %w", err)
	}
	defer zeroBytes(protectedSession)

	ciphertext, err := dpapiProtect(protectedSession)
	if err != nil {
		return nil, fmt.Errorf("protect account session credentials: %w", err)
	}
	defer zeroBytes(ciphertext)

	envelope := windowsSessionEnvelope{
		StorageVersion:       windowsSessionStorageVersion,
		Version:              session.Version,
		SupabaseURL:          session.SupabaseURL,
		PublishableKey:       session.PublishableKey,
		UserID:               session.UserID,
		Email:                session.Email,
		ExpiresAt:            session.ExpiresAt,
		ProtectedCredentials: base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode protected account session: %w", err)
	}
	return append(data, '\n'), nil
}

func dpapiProtect(plaintext []byte) ([]byte, error) {
	in, err := blobFromBytes(plaintext)
	if err != nil {
		return nil, err
	}
	var out dataBlob
	r1, _, callErr := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(plaintext)
	if r1 == 0 {
		return nil, windowsAPIError("CryptProtectData", callErr)
	}
	return copyAndFreeBlob(&out)
}

func dpapiUnprotect(ciphertext []byte) ([]byte, error) {
	in, err := blobFromBytes(ciphertext)
	if err != nil {
		return nil, err
	}
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
	runtime.KeepAlive(ciphertext)
	if r1 == 0 {
		return nil, windowsAPIError("CryptUnprotectData", callErr)
	}
	return copyAndFreeBlob(&out)
}

func blobFromBytes(data []byte) (dataBlob, error) {
	if len(data) == 0 {
		return dataBlob{}, errors.New("DPAPI input is empty")
	}
	if uint64(len(data)) > math.MaxUint32 {
		return dataBlob{}, errors.New("DPAPI input is too large")
	}
	return dataBlob{Size: uint32(len(data)), Data: &data[0]}, nil
}

func copyAndFreeBlob(blob *dataBlob) ([]byte, error) {
	if blob == nil || blob.Data == nil || blob.Size == 0 {
		return nil, errors.New("DPAPI returned an empty result")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(blob.Data)))
	out := make([]byte, int(blob.Size))
	copy(out, unsafe.Slice(blob.Data, int(blob.Size)))
	return out, nil
}

func windowsAPIError(name string, err error) error {
	if err == nil {
		return errors.New(name + " failed")
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New(name + " failed")
	}
	return fmt.Errorf("%s failed: %w", name, err)
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
