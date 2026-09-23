package main

import (
	"errors"
	"path/filepath"
	"strings"
)

var ErrCorePath = errors.New("Local Core executable is unavailable")

type executablePathFunc func() (string, error)
type evalSymlinksFunc func(string) (string, error)

func siblingExecutablePath(executable executablePathFunc, eval evalSymlinksFunc, name string) (string, error) {
	if executable == nil || eval == nil || strings.TrimSpace(name) == "" || filepath.Base(name) != name {
		return "", ErrCorePath
	}
	path, err := executable()
	if err != nil || strings.TrimSpace(path) == "" {
		return "", ErrCorePath
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", ErrCorePath
	}
	path, err = eval(path)
	if err != nil || !filepath.IsAbs(path) {
		return "", ErrCorePath
	}
	return filepath.Join(filepath.Dir(path), name), nil
}
