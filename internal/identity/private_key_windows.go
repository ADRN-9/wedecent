//go:build windows

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	identityPrivateKeyFile               = "identity.key.dpapi"
	legacyIdentityPrivateKeyFile         = "identity.key"
	maxProtectedIdentityKeyFileSize      = 64 * 1024
	maxLegacyIdentityKeyFileSize         = 16 * 1024
	protectedKeyReadRaceAttempts         = 20
	protectedKeyReadRaceDelay            = 5 * time.Millisecond
	legacyMigrationRaceAttempts          = 20
	legacyMigrationRaceDelay             = 5 * time.Millisecond
	dpapiIdentityKeyMagic                = "WEDPAPI1"
	dpapiScopeUser                  byte = 'U'
	dpapiScopeMachine               byte = 'M'
)

func loadOrCreatePrivateKey(dir string, scope keyProtectionScope) (ed25519.PrivateKey, error) {
	protectedPath := filepath.Join(dir, identityPrivateKeyFile)
	legacyPath := filepath.Join(dir, legacyIdentityPrivateKeyFile)

	priv, storedScope, err := loadProtectedPrivateKey(protectedPath)
	if err == nil {
		if scope == keyProtectionMachine && storedScope != keyProtectionMachine {
			return nil, errors.New("existing Windows identity key is user-scoped; refusing to silently change DPAPI scope")
		}
		if err := verifyAndRemoveLegacyKey(legacyPath, priv); err != nil {
			return nil, err
		}
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	legacy, protectedWinner, err := loadLegacyOrConcurrentProtectedKey(legacyPath, protectedPath, scope)
	if err == nil && protectedWinner {
		return legacy, nil
	}
	if err == nil {
		if err := persistProtectedPrivateKey(protectedPath, legacy, scope); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return nil, err
			}
			got, storedScope, loadErr := loadProtectedPrivateKey(protectedPath)
			if loadErr != nil {
				return nil, loadErr
			}
			if storedScope != scope {
				return nil, errors.New("concurrent Windows identity key has an unexpected DPAPI scope")
			}
			if !got.Public().(ed25519.PublicKey).Equal(legacy.Public().(ed25519.PublicKey)) {
				return nil, errors.New("concurrent protected identity private key does not match legacy key")
			}
			return got, nil
		}
		if err := verifyProtectedPrivateKey(protectedPath, legacy, scope); err != nil {
			return nil, err
		}
		if err := verifyAndRemoveLegacyKey(legacyPath, legacy); err != nil {
			return nil, err
		}
		return legacy, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// A concurrent migrator may have removed the plaintext key between our
	// legacy probe and this point. Prefer its protected winner before generating
	// a fresh identity.
	if got, storedScope, loadErr := loadProtectedPrivateKey(protectedPath); loadErr == nil {
		if storedScope != scope {
			return nil, errors.New("concurrent Windows identity key has an unexpected DPAPI scope")
		}
		return got, nil
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return nil, loadErr
	}

	_, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := persistProtectedPrivateKey(protectedPath, priv, scope); err != nil {
		// Another process may have won the create-exclusive race. Load its
		// authoritative key rather than ever overwriting it with our candidate.
		if errors.Is(err, os.ErrExist) {
			got, storedScope, loadErr := loadProtectedPrivateKey(protectedPath)
			if loadErr != nil {
				return nil, loadErr
			}
			if storedScope != scope {
				return nil, errors.New("concurrent Windows identity key has an unexpected DPAPI scope")
			}
			return got, nil
		}
		return nil, err
	}
	if err := verifyProtectedPrivateKey(protectedPath, priv, scope); err != nil {
		return nil, err
	}
	return priv, nil
}

func loadLegacyOrConcurrentProtectedKey(legacyPath, protectedPath string, scope keyProtectionScope) (ed25519.PrivateKey, bool, error) {
	var lastRace error
	for attempt := 0; attempt < legacyMigrationRaceAttempts; attempt++ {
		legacy, err := loadLegacyPrivateKeyIfPresent(legacyPath)
		if err == nil {
			return legacy, false, nil
		}
		if !errors.Is(err, os.ErrNotExist) && !isLegacyMigrationRace(err) {
			return nil, false, err
		}

		got, storedScope, protectedErr := loadProtectedPrivateKey(protectedPath)
		if protectedErr == nil {
			if storedScope != scope {
				return nil, false, errors.New("concurrent Windows identity key has an unexpected DPAPI scope")
			}
			return got, true, nil
		}
		if !errors.Is(protectedErr, os.ErrNotExist) {
			return nil, false, protectedErr
		}

		if errors.Is(err, os.ErrNotExist) {
			return nil, false, os.ErrNotExist
		}
		lastRace = err
		if attempt+1 < legacyMigrationRaceAttempts {
			time.Sleep(legacyMigrationRaceDelay)
		}
	}
	return nil, false, fmt.Errorf("legacy identity private key remained busy during migration: %w", lastRace)
}

func loadExistingPrivateKey(dir string) (ed25519.PrivateKey, error) {
	protectedPath := filepath.Join(dir, identityPrivateKeyFile)
	legacyPath := filepath.Join(dir, legacyIdentityPrivateKeyFile)

	priv, _, err := loadProtectedPrivateKey(protectedPath)
	if err == nil {
		legacy, legacyErr := loadLegacyPrivateKeyIfPresent(legacyPath)
		if legacyErr == nil {
			if !legacy.Public().(ed25519.PublicKey).Equal(priv.Public().(ed25519.PublicKey)) {
				return nil, errors.New("protected and legacy identity private keys do not match")
			}
		} else if !errors.Is(legacyErr, os.ErrNotExist) {
			return nil, legacyErr
		}
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return loadLegacyPrivateKey(legacyPath)
}

func identityPrivateKeyPath(dir string) string {
	return filepath.Join(dir, identityPrivateKeyFile)
}

func loadProtectedPrivateKey(path string) (ed25519.PrivateKey, keyProtectionScope, error) {
	return loadProtectedPrivateKeyWithRetry(func() (ed25519.PrivateKey, keyProtectionScope, error) {
		return loadProtectedPrivateKeyOnce(path)
	}, protectedKeyReadRaceAttempts, protectedKeyReadRaceDelay)
}

func loadProtectedPrivateKeyWithRetry(load func() (ed25519.PrivateKey, keyProtectionScope, error), attempts int, delay time.Duration) (ed25519.PrivateKey, keyProtectionScope, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastRace error
	for attempt := 0; attempt < attempts; attempt++ {
		priv, scope, err := load()
		if err == nil || !isProtectedKeyReadRace(err) {
			return priv, scope, err
		}
		lastRace = err
		if attempt+1 < attempts && delay > 0 {
			time.Sleep(delay)
		}
	}
	return nil, 0, fmt.Errorf("protected identity private key remained busy during read: %w", lastRace)
}

func loadProtectedPrivateKeyOnce(path string) (ed25519.PrivateKey, keyProtectionScope, error) {
	blob, err := readVerifiedIdentityKeyFile(path, "protected identity private key", maxProtectedIdentityKeyFileSize)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, os.ErrNotExist
		}
		return nil, 0, err
	}
	defer zeroBytes(blob)
	if len(blob) <= len(dpapiIdentityKeyMagic)+1 {
		return nil, 0, errors.New("protected identity private key has an invalid size")
	}
	return decodeProtectedPrivateKey(blob)
}

func isProtectedKeyReadRace(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func decodeProtectedPrivateKey(blob []byte) (ed25519.PrivateKey, keyProtectionScope, error) {
	prefixLen := len(dpapiIdentityKeyMagic)
	if len(blob) <= prefixLen+1 || string(blob[:prefixLen]) != dpapiIdentityKeyMagic {
		return nil, 0, errors.New("protected identity private key has an invalid format")
	}
	var scope keyProtectionScope
	switch blob[prefixLen] {
	case dpapiScopeUser:
		scope = keyProtectionUser
	case dpapiScopeMachine:
		scope = keyProtectionMachine
	default:
		return nil, 0, errors.New("protected identity private key has an invalid DPAPI scope")
	}
	der, err := dpapiUnprotect(blob[prefixLen+1:])
	if err != nil {
		return nil, 0, fmt.Errorf("unprotect identity private key: %w", err)
	}
	defer zeroBytes(der)
	priv, err := parsePrivateKeyDER(der)
	if err != nil {
		return nil, 0, err
	}
	return priv, scope, nil
}

func persistProtectedPrivateKey(path string, priv ed25519.PrivateKey, scope keyProtectionScope) error {
	der, err := marshalPrivateKeyDER(priv)
	if err != nil {
		return err
	}
	defer zeroBytes(der)
	ciphertext, err := dpapiProtect(der, scope)
	if err != nil {
		return fmt.Errorf("protect identity private key: %w", err)
	}

	scopeByte, err := dpapiScopeByte(scope)
	if err != nil {
		return err
	}
	blob := make([]byte, 0, len(dpapiIdentityKeyMagic)+1+len(ciphertext))
	blob = append(blob, dpapiIdentityKeyMagic...)
	blob = append(blob, scopeByte)
	blob = append(blob, ciphertext...)
	if len(blob) > maxProtectedIdentityKeyFileSize {
		return errors.New("protected identity private key exceeds maximum size")
	}
	return publishProtectedPrivateKey(path, blob)
}

func publishProtectedPrivateKey(path string, blob []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create protected identity private key temp file: %w", err)
	}
	tempPath := f.Name()
	published := false
	defer func() {
		_ = f.Close()
		if !published {
			_ = os.Remove(tempPath)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("secure protected identity private key temp permissions: %w", err)
	}
	if _, err := f.Write(blob); err != nil {
		return fmt.Errorf("write protected identity private key temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync protected identity private key temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close protected identity private key temp file: %w", err)
	}

	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return fmt.Errorf("encode protected identity private key temp path: %w", err)
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode protected identity private key path: %w", err)
	}
	if err := windows.MoveFile(from, to); err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("publish protected identity private key: %w", os.ErrExist)
		}
		return fmt.Errorf("publish protected identity private key: %w", err)
	}
	published = true
	return nil
}

func verifyProtectedPrivateKey(path string, expected ed25519.PrivateKey, expectedScope keyProtectionScope) error {
	got, scope, err := loadProtectedPrivateKey(path)
	if err != nil {
		return err
	}
	if scope != expectedScope {
		return errors.New("protected identity private key scope changed during write")
	}
	if !got.Public().(ed25519.PublicKey).Equal(expected.Public().(ed25519.PublicKey)) {
		return errors.New("protected identity private key verification failed")
	}
	return nil
}

func verifyAndRemoveLegacyKey(path string, protected ed25519.PrivateKey) error {
	var lastRace error
	for attempt := 0; attempt < legacyMigrationRaceAttempts; attempt++ {
		err := verifyAndRemoveLegacyKeyOnce(path, protected)
		if err == nil {
			return nil
		}
		if !isLegacyMigrationRace(err) {
			return err
		}
		lastRace = err
		if attempt+1 < legacyMigrationRaceAttempts {
			time.Sleep(legacyMigrationRaceDelay)
		}
	}
	return fmt.Errorf("legacy identity private key remained busy during cleanup: %w", lastRace)
}

func verifyAndRemoveLegacyKeyOnce(path string, protected ed25519.PrivateKey) error {
	return verifyAndDeleteLegacyKeyByHandle(path, protected)
}

func isLegacyMigrationRace(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

func loadLegacyPrivateKeyIfPresent(path string) (ed25519.PrivateKey, error) {
	priv, err := loadLegacyPrivateKey(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	return priv, err
}

func loadLegacyPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := readVerifiedIdentityKeyFile(path, "legacy identity private key", maxLegacyIdentityKeyFileSize)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(data)
	return parseLegacyPrivateKey(data)
}

func readVerifiedIdentityKeyFile(path, label string, maxSize int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", label, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", label)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened %s: %w", label, err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("re-stat %s path: %w", label, err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("%s path changed while opening", label)
	}
	if opened.Size() < 0 || opened.Size() > maxSize {
		return nil, fmt.Errorf("%s has an invalid size", label)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(data)) > maxSize {
		zeroBytes(data)
		return nil, fmt.Errorf("%s has an invalid size", label)
	}
	return data, nil
}

func unwrapPathError(err error) error {
	for err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return pathErr.Err
		}
		return err
	}
	return nil
}

func dpapiScopeByte(scope keyProtectionScope) (byte, error) {
	switch scope {
	case keyProtectionUser:
		return dpapiScopeUser, nil
	case keyProtectionMachine:
		return dpapiScopeMachine, nil
	default:
		return 0, errors.New("invalid identity key protection scope")
	}
}

func dpapiProtect(plain []byte, scope keyProtectionScope) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("cannot protect an empty identity key")
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN)
	if scope == keyProtectionMachine {
		flags |= windows.CRYPTPROTECT_LOCAL_MACHINE
	} else if scope != keyProtectionUser {
		return nil, errors.New("invalid identity key protection scope")
	}
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, flags, &out); err != nil {
		return nil, err
	}
	runtime.KeepAlive(plain)
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Data == nil || out.Size == 0 {
		return nil, errors.New("DPAPI returned an empty protected key")
	}
	ciphertext := make([]byte, int(out.Size))
	copy(ciphertext, unsafe.Slice(out.Data, int(out.Size)))
	return ciphertext, nil
}

func dpapiUnprotect(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("protected identity key payload is empty")
	}
	in := windows.DataBlob{Size: uint32(len(ciphertext)), Data: &ciphertext[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	runtime.KeepAlive(ciphertext)
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Data == nil || out.Size == 0 {
		return nil, errors.New("DPAPI returned an empty private key")
	}
	native := unsafe.Slice(out.Data, int(out.Size))
	plain := make([]byte, len(native))
	copy(plain, native)
	zeroBytes(native)
	return plain, nil
}
