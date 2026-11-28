//go:build windows

package scmbroker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"wedecent.com/wedecent/internal/winservice"
)

const brokerServiceName = "WeDecentSCMBroker"

// InstallService installs the broker only after the binary's signer matches
// the independently provisioned publisher policy. It never invents a trust pin.
func InstallService(executable string) error {
	if !filepath.IsAbs(executable) {
		return errors.New("broker service executable path must be absolute")
	}
	executable = filepath.Clean(executable)
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("broker service executable is missing, non-regular, or a symlink")
	}
	name, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("broker service executable must not be a reparse point")
	}
	thumbprint, err := verifyAuthenticodePublisher(executable)
	if err != nil {
		return fmt.Errorf("verify broker service executable: %w", err)
	}
	policy, err := loadPublisherPolicy()
	if err != nil {
		return fmt.Errorf("load broker service publisher policy: %w", err)
	}
	if thumbprint != policy.PublisherThumbprint {
		return errors.New("broker service executable is not signed by the provisioned WeDecent publisher")
	}

	if err := winservice.Install(winservice.InstallOptions{
		Name:        brokerServiceName,
		DisplayName: "WeDecent SCM Broker",
		Description: "Privileged, fail-closed WeDecent service broker",
		Account:     "NT AUTHORITY\\LocalService",
		Executable:  executable,
		Automatic:   true,
	}); err != nil {
		return fmt.Errorf("install broker service: %w", err)
	}
	rollback := func(cause error) error {
		_ = winservice.Stop(brokerServiceName)
		_ = winservice.Uninstall(brokerServiceName)
		return cause
	}
	if err := winservice.EnableServiceSID(brokerServiceName); err != nil {
		return rollback(fmt.Errorf("enable broker service SID: %w", err))
	}
	if err := winservice.RestrictService(brokerServiceName); err != nil {
		return rollback(fmt.Errorf("restrict broker service object: %w", err))
	}
	if err := winservice.Start(brokerServiceName); err != nil {
		return rollback(fmt.Errorf("start broker service: %w", err))
	}
	return nil
}

// UninstallService stops and removes only the fixed WeDecent broker service.
func UninstallService() error {
	if err := winservice.Stop(brokerServiceName); err != nil {
		return fmt.Errorf("stop broker service: %w", err)
	}
	if err := winservice.Uninstall(brokerServiceName); err != nil {
		return fmt.Errorf("uninstall broker service: %w", err)
	}
	return nil
}
