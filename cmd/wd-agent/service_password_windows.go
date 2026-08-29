//go:build windows

package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

const maxServicePasswordBytes = 4096

func readServicePassword(r io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, maxServicePasswordBytes+1))
	password, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	password = strings.TrimRight(password, "\r\n")
	if len(password) > maxServicePasswordBytes {
		return "", errors.New("service account password is too long")
	}
	return password, nil
}
