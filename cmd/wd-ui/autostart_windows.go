//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const (
	autostartRunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	autostartValueName  = "WeDecent"
)

type registryAutostartStore struct{}

func platformEnableAutostart() error {
	return enableAutostartWith(registryAutostartStore{}, currentAutostartExecutable)
}

func platformDisableAutostart() error {
	return disableAutostartWith(registryAutostartStore{})
}

func platformAutostartStatus() (autostartStatus, error) {
	return autostartStatusWith(registryAutostartStore{}, currentAutostartExecutable)
}

func (registryAutostartStore) Get() (string, bool, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, autostartRunKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer key.Close()

	value, _, err := key.GetStringValue(autostartValueName)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (registryAutostartStore) Set(value string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, autostartRunKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(autostartValueName, value)
}

func (registryAutostartStore) Delete() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, autostartRunKeyPath, registry.SET_VALUE)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()

	err = key.DeleteValue(autostartValueName)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return err
}

func currentAutostartExecutable() (string, error) {
	return resolveAutostartExecutable(os.Executable, filepath.EvalSymlinks, os.Stat)
}

func resolveAutostartExecutable(executable executablePathFunc, eval evalSymlinksFunc, stat func(string) (os.FileInfo, error)) (string, error) {
	if executable == nil || eval == nil || stat == nil {
		return "", ErrAutostartExecutable
	}
	path, err := executable()
	if err != nil || strings.TrimSpace(path) == "" {
		return "", ErrAutostartExecutable
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", ErrAutostartExecutable
	}
	path, err = eval(path)
	if err != nil || !filepath.IsAbs(path) {
		return "", ErrAutostartExecutable
	}
	info, err := stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrAutostartExecutable
	}
	return filepath.Clean(path), nil
}
