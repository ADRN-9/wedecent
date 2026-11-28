//go:build windows

package scmbroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	seFileObject             = 1
	ownerSecurityInformation = 0x1
	daclSecurityInformation  = 0x4
	sddlRevision1            = 1
)

var (
	advapiPublisherPolicy        = syscall.NewLazyDLL("advapi32.dll")
	procGetNamedSecurityInfo     = advapiPublisherPolicy.NewProc("GetNamedSecurityInfoW")
	procConvertSDToStringSD      = advapiPublisherPolicy.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	kernelPublisherPolicy        = syscall.NewLazyDLL("kernel32.dll")
	procLocalFreePublisherPolicy = kernelPublisherPolicy.NewProc("LocalFree")
)

type publisherPolicy struct {
	Schema              uint32 `json:"schema"`
	PublisherThumbprint string `json:"publisher_thumbprint"`
}

var publisherThumbprintPattern = regexp.MustCompile(`^[A-F0-9]{40}$`)

// loadPublisherPolicy reads the single production publisher pin from a
// machine-protected location. The installer must provision this file and its
// ACLs from an independently authenticated release-publisher certificate.
func loadPublisherPolicy() (publisherPolicy, error) {
	var zero publisherPolicy
	programData := os.Getenv("ProgramData")
	if !filepath.IsAbs(programData) || strings.TrimSpace(programData) == "" {
		return zero, errors.New("ProgramData is unavailable or not absolute")
	}
	productRoot := filepath.Join(programData, "WeDecent")
	root := filepath.Join(productRoot, "broker")
	path := filepath.Join(root, "publisher-policy.json")
	for _, item := range []struct {
		path string
		dir  bool
	}{{productRoot, true}, {root, true}, {path, false}} {
		info, err := os.Lstat(item.path)
		if err != nil {
			return zero, fmt.Errorf("inspect protected publisher policy path: %w", err)
		}
		if item.dir && !info.IsDir() || !item.dir && !info.Mode().IsRegular() {
			return zero, errors.New("publisher policy path has an unexpected filesystem type")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return zero, errors.New("publisher policy path must not be a reparse point or symlink")
		}
		name, err := windows.UTF16PtrFromString(item.path)
		if err != nil {
			return zero, err
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return zero, errors.New("publisher policy path contains a reparse point")
		}
		if err := verifyPublisherPolicyACL(item.path, item.dir); err != nil {
			return zero, err
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return zero, fmt.Errorf("open protected publisher policy: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 4096 {
		return zero, errors.New("publisher policy is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return zero, errors.New("publisher policy could not be read within size limit")
	}
	return decodePublisherPolicy(data)
}

func decodePublisherPolicy(data []byte) (publisherPolicy, error) {
	var zero publisherPolicy
	if err := rejectDuplicateKeys(data); err != nil {
		return zero, fmt.Errorf("publisher policy has duplicate or malformed JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy publisherPolicy
	if err := decoder.Decode(&policy); err != nil {
		return zero, fmt.Errorf("publisher policy schema: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return zero, errors.New("publisher policy contains trailing data")
	}
	if policy.Schema != 1 || !publisherThumbprintPattern.MatchString(policy.PublisherThumbprint) {
		return zero, errors.New("publisher policy schema or signer thumbprint is invalid")
	}
	return policy, nil
}

func verifyPublisherPolicyACL(path string, directory bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var owner, dacl, descriptor uintptr
	result, _, _ := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(name)),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		0,
		uintptr(unsafe.Pointer(&dacl)),
		0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if result != 0 {
		return fmt.Errorf("read publisher policy owner/DACL: %w", syscall.Errno(result))
	}
	defer procLocalFreePublisherPolicy.Call(descriptor)

	var sddl *uint16
	var length uint32
	ok, _, callErr := procConvertSDToStringSD.Call(
		descriptor,
		sddlRevision1,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&sddl)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ok == 0 {
		return fmt.Errorf("convert publisher policy ACL: %w", callErr)
	}
	defer procLocalFreePublisherPolicy.Call(uintptr(unsafe.Pointer(sddl)))
	actual := windows.UTF16PtrToString(sddl)

	serviceSID, err := brokerServiceSID("WeDecentSCMBroker")
	if err != nil {
		return err
	}
	expected := "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;" + serviceSID + ")"
	if directory {
		expected = "O:BAD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GR;;;" + serviceSID + ")"
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("publisher policy ACL is not the exact protected allow-list: %s", actual)
	}
	return nil
}
