//go:build windows

package scmbroker

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wtdUIChoiceNone                         = 2
	wtdRevokeWholeChain                     = 1
	wtdChoiceFile                           = 1
	wtdStateActionVerify                    = 1
	wtdStateActionClose                     = 2
	wtdRevocationCheckChainExcludeRoot      = 0x80
	certSHA1HashPropID                      = 3
)

var (
	wintrustDLL                         = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust                  = wintrustDLL.NewProc("WinVerifyTrust")
	procWTHelperProvDataFromStateData   = wintrustDLL.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = wintrustDLL.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain   = wintrustDLL.NewProc("WTHelperGetProvCertFromChain")
	crypt32DLL                          = syscall.NewLazyDLL("crypt32.dll")
	procCertGetCertificateContextProperty = crypt32DLL.NewProc("CertGetCertificateContextProperty")
)

type winTrustGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type winTrustFileInfo struct {
	Size       uint32
	FilePath   *uint16
	File       windows.Handle
	KnownSubject *winTrustGUID
}

type winTrustData struct {
	Size                 uint32
	PolicyCallbackData   uintptr
	SIPClientData        uintptr
	UIChoice             uint32
	RevocationChecks     uint32
	UnionChoice          uint32
	FileInfo             *winTrustFileInfo
	StateAction          uint32
	StateData            windows.Handle
	URLReference         *uint16
	ProviderFlags        uint32
	UIContext            uint32
	SignatureSettings    uintptr
}

type winTrustProviderSigner struct {
	Size             uint32
	VerifyAsOf       windows.Filetime
	CertChainCount   uint32
	CertChain        uintptr
	SignerType       uint32
	Signer           uintptr
	Error            uint32
	CounterCount     uint32
	CounterSigners   uintptr
	ChainContext     uintptr
}

type winTrustProviderCert struct {
	Size                 uint32
	Certificate          uintptr
	Commercial           uint32
	TrustedRoot          uint32
	SelfSigned           uint32
	TestCertificate      uint32
	RevokedReason        uint32
	Confidence           uint32
	Error                uint32
	TrustListContext     uintptr
	TrustListSignerCert  uint32
	CTL                  uintptr
	CTLError              uint32
	Cyclic               uint32
	ChainElement         uintptr
}

// verifyAuthenticodePublisher validates the PE's Authenticode signature using
// the Windows trust provider and returns the SHA-1 certificate thumbprint.
// The caller MUST compare it to a separately provisioned, protected allowlist.
func verifyAuthenticodePublisher(path string) (string, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return "", errors.New("broker publisher verification requires an absolute executable path")
	}
	clean := filepath.Clean(path)
	filePath, err := windows.UTF16PtrFromString(clean)
	if err != nil {
		return "", fmt.Errorf("encode executable path: %w", err)
	}
	action := winTrustGUID{
		Data1: 0x00AAC56B,
		Data2: 0xCD44,
		Data3: 0x11D0,
		Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
	}
	fileInfo := winTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(winTrustFileInfo{})),
		FilePath: filePath,
		File:     windows.InvalidHandle,
	}
	data := winTrustData{
		Size:             uint32(unsafe.Sizeof(winTrustData{})),
		UIChoice:         wtdUIChoiceNone,
		RevocationChecks: wtdRevokeWholeChain,
		UnionChoice:      wtdChoiceFile,
		FileInfo:         &fileInfo,
		StateAction:      wtdStateActionVerify,
		ProviderFlags:    wtdRevocationCheckChainExcludeRoot,
	}
	status, _, _ := procWinVerifyTrust.Call(
		uintptr(windows.InvalidHandle),
		uintptr(unsafe.Pointer(&action)),
		uintptr(unsafe.Pointer(&data)),
	)
	if status != 0 {
		data.StateAction = wtdStateActionClose
		_, _, _ = procWinVerifyTrust.Call(
			uintptr(windows.InvalidHandle),
			uintptr(unsafe.Pointer(&action)),
			uintptr(unsafe.Pointer(&data)),
		)
		return "", fmt.Errorf("WinVerifyTrust rejected broker executable (HRESULT 0x%08X)", uint32(status))
	}
	defer func() {
		data.StateAction = wtdStateActionClose
		_, _, _ = procWinVerifyTrust.Call(
			uintptr(windows.InvalidHandle),
			uintptr(unsafe.Pointer(&action)),
			uintptr(unsafe.Pointer(&data)),
		)
	}()

	providerData, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(data.StateData))
	if providerData == 0 {
		return "", errors.New("WinVerifyTrust returned no provider state")
	}
	providerSigner, _, _ := procWTHelperGetProvSignerFromChain.Call(providerData, 0, 0, 0)
	if providerSigner == 0 {
		return "", errors.New("WinVerifyTrust returned no primary signer")
	}
	providerCert, _, _ := procWTHelperGetProvCertFromChain.Call(providerSigner, 0)
	if providerCert == 0 {
		return "", errors.New("WinVerifyTrust returned no signer certificate")
	}
	cert := (*winTrustProviderCert)(unsafe.Pointer(providerCert)).Certificate
	if cert == 0 {
		return "", errors.New("WinVerifyTrust signer certificate context is missing")
	}
	var hash [20]byte
	hashSize := uint32(len(hash))
	ok, _, callErr := procCertGetCertificateContextProperty.Call(
		cert,
		certSHA1HashPropID,
		uintptr(unsafe.Pointer(&hash[0])),
		uintptr(unsafe.Pointer(&hashSize)),
	)
	if ok == 0 || hashSize != uint32(len(hash)) {
		return "", fmt.Errorf("read Authenticode signer certificate thumbprint: %w", callErr)
	}
	return strings.ToUpper(hex.EncodeToString(hash[:])), nil
}
