//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	rawEnableProcessedInput            uint32 = 0x0001
	rawEnableLineInput                 uint32 = 0x0002
	rawEnableEchoInput                 uint32 = 0x0004
	rawEnableProcessedOutput           uint32 = 0x0001
	rawEnableVirtualTerminalProcessing uint32 = 0x0004
	rawEnableVirtualTerminalInput      uint32 = 0x0200
)

var (
	kernel32Raw                   = syscall.NewLazyDLL("kernel32.dll")
	rawGetConsoleMode             = kernel32Raw.NewProc("GetConsoleMode")
	rawSetConsoleMode             = kernel32Raw.NewProc("SetConsoleMode")
	rawGetConsoleScreenBufferInfo = kernel32Raw.NewProc("GetConsoleScreenBufferInfo")
)

type RawState struct {
	inputMode  uint32
	outputMode uint32
	output     *os.File
}

type rawCoord struct {
	X int16
	Y int16
}

type rawSmallRect struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

type rawConsoleScreenBufferInfo struct {
	Size              rawCoord
	CursorPosition    rawCoord
	Attributes        uint16
	Window            rawSmallRect
	MaximumWindowSize rawCoord
}

func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	_, err := rawConsoleMode(f)
	return err == nil
}

func Size(_ *os.File) (uint16, uint16, error) {
	output, err := openConsoleOutput()
	if err != nil {
		return 0, 0, err
	}
	defer output.Close()

	var info rawConsoleScreenBufferInfo
	ok, _, callErr := rawGetConsoleScreenBufferInfo.Call(
		uintptr(syscall.Handle(output.Fd())),
		uintptr(unsafe.Pointer(&info)),
	)
	if ok == 0 {
		return 0, 0, fmt.Errorf("get console screen buffer info: %w", normalizeWindowsCallError(callErr))
	}
	return rawWindowSize(info)
}

func MakeRaw(input *os.File) (*RawState, error) {
	inputMode, err := rawConsoleMode(input)
	if err != nil {
		return nil, fmt.Errorf("get console input mode: %w", err)
	}

	output, err := openConsoleOutput()
	if err != nil {
		return nil, err
	}

	outputMode, err := rawConsoleMode(output)
	if err != nil {
		output.Close()
		return nil, fmt.Errorf("get console output mode: %w", err)
	}

	if err := rawSetMode(output, rawOutputMode(outputMode)); err != nil {
		output.Close()
		return nil, fmt.Errorf("enable virtual terminal output: %w", err)
	}

	if err := rawSetMode(input, rawInputMode(inputMode)); err != nil {
		_ = rawSetMode(output, outputMode)
		output.Close()
		return nil, fmt.Errorf("enable raw virtual terminal input: %w", err)
	}

	return &RawState{
		inputMode:  inputMode,
		outputMode: outputMode,
		output:     output,
	}, nil
}

func Restore(input *os.File, state *RawState) error {
	if state == nil {
		return nil
	}

	var restoreErr error
	if input != nil {
		restoreErr = errors.Join(restoreErr, rawSetMode(input, state.inputMode))
	}
	if state.output != nil {
		restoreErr = errors.Join(restoreErr, rawSetMode(state.output, state.outputMode))
		restoreErr = errors.Join(restoreErr, state.output.Close())
		state.output = nil
	}
	return restoreErr
}

func rawInputMode(mode uint32) uint32 {
	mode &^= rawEnableProcessedInput | rawEnableLineInput | rawEnableEchoInput
	mode |= rawEnableVirtualTerminalInput
	return mode
}

func rawOutputMode(mode uint32) uint32 {
	return mode | rawEnableProcessedOutput | rawEnableVirtualTerminalProcessing
}

func rawConsoleMode(f *os.File) (uint32, error) {
	if f == nil {
		return 0, errors.New("console file is nil")
	}
	var mode uint32
	ok, _, callErr := rawGetConsoleMode.Call(
		uintptr(syscall.Handle(f.Fd())),
		uintptr(unsafe.Pointer(&mode)),
	)
	if ok == 0 {
		return 0, normalizeWindowsCallError(callErr)
	}
	return mode, nil
}

func rawSetMode(f *os.File, mode uint32) error {
	if f == nil {
		return errors.New("console file is nil")
	}
	ok, _, callErr := rawSetConsoleMode.Call(
		uintptr(syscall.Handle(f.Fd())),
		uintptr(mode),
	)
	if ok == 0 {
		return normalizeWindowsCallError(callErr)
	}
	return nil
}

func openConsoleOutput() (*os.File, error) {
	output, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open console output: %w", err)
	}
	return output, nil
}

func rawWindowSize(info rawConsoleScreenBufferInfo) (uint16, uint16, error) {
	cols := int(info.Window.Right) - int(info.Window.Left) + 1
	rows := int(info.Window.Bottom) - int(info.Window.Top) + 1
	if cols <= 0 || rows <= 0 || cols > 65535 || rows > 65535 {
		return 0, 0, errors.New("console reported an invalid window size")
	}
	return uint16(cols), uint16(rows), nil
}

func normalizeWindowsCallError(err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return syscall.EINVAL
	}
	return err
}
