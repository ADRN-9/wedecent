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
	br, ok := r.(*bufio.Reader)
	if !ok { br = bufio.NewReaderSize(io.LimitReader(r, maxServicePasswordBytes+2), maxServicePasswordBytes+2) }
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) { _, err = br.ReadSlice('\n') }
		return "", errors.New("service credential is too long")
	}
	if err != nil && !errors.Is(err, io.EOF) { return "", err }
	line = []byte(strings.TrimRight(string(line), "\r\n"))
	if len(line) > maxServicePasswordBytes { return "", errors.New("service credential is too long") }
	return string(line), nil
}

func readServiceCredential(reader *bufio.Reader) (string, error) {
	var mode uint32
	if ok, _, _ := procGetConsoleMode.Call(uintptr(os.Stdin.Fd()), uintptr(unsafe.Pointer(&mode))); ok != 0 {
		return readHiddenLine("Recovery authority bearer token: ")
	}
	return readServicePassword(reader)
}
