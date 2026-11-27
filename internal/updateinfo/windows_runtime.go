//go:build windows

package updateinfo

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsUpdateRootFilename = "update-root.json"
	windowsUpdateRootSchema   = 1
)

var (
	windowsPublisherPattern = regexp.MustCompile("^[A-Fa-f0-9]{40}$")
	winTrustDLL             = syscall.NewLazyDLL("wintrust.dll")
	winVerifyTrustProc      = winTrustDLL.NewProc("WinVerifyTrust")
)

type WindowsUpdateRoot struct {
	Schema                 int    `json:"schema"`
	RootKeyID              string `json:"root_key_id"`
	RootPublicKey          string `json:"root_public_key"`
	AuthenticodeThumbprint string `json:"authenticode_thumbprint"`
}

type windowsInstallerMetadata struct {
	Schema      int    `json:"schema"`
	Product     string `json:"product"`
	Version     string `json:"version"`
	ServiceName string `json:"service_name"`
	InstallDir  string `json:"install_dir"`
	StateDir    string `json:"state_dir"`
}

type winTrustFileInfo struct {
	Size         uint32
	FilePath     *uint16
	FileHandle   windows.Handle
	KnownSubject *windows.GUID
}

type winTrustData struct {
	Size               uint32
	PolicyCallbackData uintptr
	SIPClientData      uintptr
	UIChoice           uint32
	RevocationChecks   uint32
	UnionChoice        uint32
	FileInfo           *winTrustFileInfo
	StateAction        uint32
	StateData          windows.Handle
	URLReference       *uint16
	ProviderFlags      uint32
	UIContext          uint32
	SignatureSettings  uintptr
}

var genericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

// ValidateInstalledUpdateLauncher is safe to call from the unelevated desktop.
func ValidateInstalledUpdateLauncher() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve installed updater executable")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve installed updater path")
	}
	installDir := filepath.Dir(executable)
	if !strings.EqualFold(filepath.Base(executable), "wd-agent.exe") ||
		!strings.EqualFold(filepath.Base(installDir), "WeDecent") {
		return fmt.Errorf("updater must run from the installed WeDecent directory")
	}
	if err := validateTrustedSystemPath(executable); err != nil {
		return err
	}
	root, err := loadWindowsUpdateRoot(filepath.Join(installDir, windowsUpdateRootFilename))
	if err != nil {
		return err
	}
	powershell, err := windowsPowerShellPath()
	if err != nil {
		return err
	}
	psDigest, err := verifyWindowsPowerShellExecutable(context.Background(), powershell)
	if err != nil {
		return err
	}
	if err := verifyAuthenticodePublisher(context.Background(), powershell, executable, "", root.AuthenticodeThumbprint); err != nil {
		return fmt.Errorf("verify installed updater publisher: %w", err)
	}
	after, err := hashRegularFile(powershell)
	if err != nil || after != psDigest {
		return fmt.Errorf("Windows PowerShell changed during publisher verification")
	}
	return nil
}

// ApplyInstalledWindowsStable is the elevated, argument-free update entrypoint.
func ApplyInstalledWindowsStable(ctx context.Context) error {
	if ctx == nil || !currentProcessElevated() {
		return fmt.Errorf("stable updater requires an elevated Windows process")
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve updater executable")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve updater executable path")
	}
	installDir := filepath.Dir(executable)
	if !strings.EqualFold(filepath.Base(executable), "wd-agent.exe") ||
		!strings.EqualFold(filepath.Base(installDir), "WeDecent") {
		return fmt.Errorf("updater must run from the installed WeDecent directory")
	}
	if err := validateTrustedSystemPath(executable); err != nil {
		return err
	}
	root, err := loadWindowsUpdateRoot(filepath.Join(installDir, windowsUpdateRootFilename))
	if err != nil {
		return err
	}

	programData := os.Getenv("ProgramData")
	if programData == "" {
		return fmt.Errorf("ProgramData is unavailable")
	}
	metadataPath := filepath.Join(programData, "WeDecent", "installer.json")
	if err := validateWindowsProtectedAdminFile(metadataPath); err != nil {
		return fmt.Errorf("validate protected installer metadata: %w", err)
	}
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("read protected installer metadata")
	}
	var metadata windowsInstallerMetadata
	if err := decodeStrictJSON(metadataBytes, &metadata); err != nil ||
		metadata.Schema != 1 || metadata.Product != "WeDecent" ||
		metadata.Version == "" || !keyIDPattern.MatchString(metadata.ServiceName) ||
		!filepath.IsAbs(metadata.InstallDir) || !filepath.IsAbs(metadata.StateDir) ||
		!strings.EqualFold(filepath.Clean(metadata.InstallDir), filepath.Clean(installDir)) {
		return fmt.Errorf("protected installer metadata is invalid or does not match this installation")
	}
	if err := validateTrustedSystemPath(metadata.StateDir); err != nil {
		return fmt.Errorf("validate protected updater state ancestors: %w", err)
	}

	publicKey, err := DecodePublicKey([]byte(root.RootPublicKey))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("provisioned stable update root key is invalid")
	}
	stateStore := NewStateStore(StatePath(metadata.StateDir))
	state, err := stateStore.Load()
	if err != nil {
		return fmt.Errorf("load protected update state: %w", err)
	}
	if state.InstalledVersion == "" || state.InstalledVersion != metadata.Version {
		return fmt.Errorf("protected installed version does not match installer metadata")
	}

	powershell, err := windowsPowerShellPath()
	if err != nil {
		return err
	}
	if _, err := verifyWindowsPowerShellExecutable(ctx, powershell); err != nil {
		return err
	}
	executor := PowerShellInstallerExecutor{
		PowerShellPath: powershell,
		InstallDir:     metadata.InstallDir,
		StateDir:       metadata.StateDir,
		ServiceName:    metadata.ServiceName,
		verifyExecutable: func(ctx context.Context, path string) (string, error) {
			return verifyWindowsPowerShellExecutable(ctx, path)
		},
	}
	verifier := func(verifyCtx context.Context, path string) error {
		before, err := verifyWindowsPowerShellExecutable(verifyCtx, powershell)
		if err != nil {
			return err
		}
		if err := verifyAuthenticodePublisher(verifyCtx, powershell, path, "", root.AuthenticodeThumbprint); err != nil {
			return err
		}
		after, err := hashRegularFile(powershell)
		if err != nil || after != before {
			return fmt.Errorf("Windows PowerShell changed during Authenticode verification")
		}
		return nil
	}
	client := DiscoveryClient{RootKeyID: root.RootKeyID, RootPublicKey: publicKey, State: stateStore}
	stagingDir := filepath.Join(installDir, "update-staging")
	if err := ensurePrivateStateDir(stagingDir); err != nil {
		return fmt.Errorf("prepare protected installer staging: %w", err)
	}
	manifest, err := client.ApplyStable(
		ctx, state.InstalledVersion, state.StableSequence,
		InstallerClient{}, stagingDir, MaxInstallerArchiveBytes, verifier, executor,
	)
	if err != nil {
		return fmt.Errorf("stable update failed closed: %w", err)
	}
	fmt.Fprintf(os.Stdout, "WeDecent updated to %s (stable sequence %d).
", manifest.Version, manifest.Sequence)
	return nil
}

func loadWindowsUpdateRoot(path string) (WindowsUpdateRoot, error) {
	var zero WindowsUpdateRoot
	if err := validateTrustedSystemPath(path); err != nil {
		return zero, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("stable update trust root is not provisioned")
	}
	var root WindowsUpdateRoot
	if err := decodeStrictJSON(data, &root); err != nil ||
		root.Schema != windowsUpdateRootSchema ||
		!keyIDPattern.MatchString(root.RootKeyID) ||
		!windowsPublisherPattern.MatchString(root.AuthenticodeThumbprint) {
		return zero, fmt.Errorf("stable update trust root is malformed")
	}
	if _, err := DecodePublicKey([]byte(root.RootPublicKey)); err != nil {
		return zero, fmt.Errorf("stable update root public key is invalid")
	}
	root.AuthenticodeThumbprint = strings.ToUpper(root.AuthenticodeThumbprint)
	return root, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func validateTrustedSystemPath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve protected path")
	}
	if _, err := validateUpdateStateAncestorChain(absolute, updateStateSystemSID, false); err != nil {
		return err
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return fmt.Errorf("protected path is unavailable or a reparse point")
	}
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return fmt.Errorf("encode protected path")
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("protected path is a reparse point")
	}
	if !info.IsDir() {
		sd, err := windows.GetNamedSecurityInfo(absolute, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || sd == nil {
			return fmt.Errorf("read protected file security")
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil {
			return fmt.Errorf("protected file owner is unavailable")
		}
		if err := validateUpdateStateAncestorOwner(owner.String(), updateStateSystemSID); err != nil {
			return fmt.Errorf("protected file owner is not trusted")
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil {
			return fmt.Errorf("protected file requires an explicit DACL")
		}
		if err := validateUpdateStateAncestorDACL(sd.String(), updateStateSystemSID); err != nil {
			return fmt.Errorf("protected file ACL is unsafe: %w", err)
		}
	}
	return nil
}

func validateWindowsProtectedAdminFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("protected metadata file is unavailable or unsafe")
	}
	return validateWindowsUpdateStatePath(path, info, false)
}

func windowsPowerShellPath() (string, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		return "", fmt.Errorf("SystemRoot is unavailable")
	}
	path := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if err := validateTrustedSystemPath(path); err != nil {
		return "", fmt.Errorf("validate system PowerShell path: %w", err)
	}
	return path, nil
}

func verifyWindowsPowerShellExecutable(ctx context.Context, path string) (string, error) {
	expected, err := windowsPowerShellPath()
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(filepath.Clean(path), filepath.Clean(expected)) {
		return "", fmt.Errorf("PowerShell must be the protected Windows system executable")
	}
	before, err := hashRegularFile(expected)
	if err != nil {
		return "", fmt.Errorf("hash Windows PowerShell executable")
	}
	if err := winVerifyTrustFile(expected); err != nil {
		return "", fmt.Errorf("Windows PowerShell Authenticode trust verification failed")
	}
	if ctx != nil {
		if err := verifyAuthenticodePublisher(ctx, expected, expected, "Microsoft Windows", ""); err != nil {
			return "", fmt.Errorf("Windows PowerShell publisher identity is invalid")
		}
	}
	after, err := hashRegularFile(expected)
	if err != nil || after != before {
		return "", fmt.Errorf("Windows PowerShell changed during trust verification")
	}
	return before, nil
}

func winVerifyTrustFile(path string) error {
	filePath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fileInfo := winTrustFileInfo{FilePath: filePath}
	fileInfo.Size = uint32(unsafe.Sizeof(fileInfo))
	data := winTrustData{
		UIChoice: 2, UnionChoice: 1, FileInfo: &fileInfo,
		ProviderFlags: 0x80 | 0x1000,
	}
	data.Size = uint32(unsafe.Sizeof(data))
	result, _, _ := winVerifyTrustProc.Call(^uintptr(0),
		uintptr(unsafe.Pointer(&genericVerifyV2)), uintptr(unsafe.Pointer(&data)))
	if result != 0 {
		return fmt.Errorf("WinVerifyTrust returned 0x%08x", uint32(result))
	}
	return nil
}

func verifyAuthenticodePublisher(ctx context.Context, powershell, target, expectedSubject, expectedThumbprint string) error {
	if ctx == nil || powershell == "" || target == "" {
		return fmt.Errorf("Authenticode verification context is incomplete")
	}
	script := "$ErrorActionPreference = 'Stop'
" +
		"$s = Get-AuthenticodeSignature -LiteralPath $env:WEDECENT_AUTHENTICODE_FILE
" +
		"if ($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate) { exit 31 }
" +
		"if ($env:WEDECENT_AUTHENTICODE_THUMBPRINT) {
" +
		"  $actual = ($s.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
" +
		"  if ($actual -cne $env:WEDECENT_AUTHENTICODE_THUMBPRINT) { exit 32 }
" +
		"}
" +
		"if ($env:WEDECENT_AUTHENTICODE_SUBJECT) {
" +
		"  $subject = $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
" +
		"  if ($subject -cne $env:WEDECENT_AUTHENTICODE_SUBJECT) { exit 33 }
" +
		"}
"
	command := exec.CommandContext(ctx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "AllSigned", "-Command", script)
	command.Env = append(os.Environ(),
		"WEDECENT_AUTHENTICODE_FILE="+target,
		"WEDECENT_AUTHENTICODE_THUMBPRINT="+strings.ToUpper(expectedThumbprint),
		"WEDECENT_AUTHENTICODE_SUBJECT="+expectedSubject,
	)
	if err := command.Run(); err != nil {
		return fmt.Errorf("Authenticode publisher check failed")
	}
	return nil
}

func init() {
	_ = winVerifyTrustProc.Find()
}
