//go:build windows

package terminal

import "testing"

func TestRawInputMode(t *testing.T) {
	const unrelated uint32 = 0x0010
	old := rawEnableProcessedInput |
		rawEnableLineInput |
		rawEnableEchoInput |
		unrelated

	got := rawInputMode(old)
	if got&rawEnableProcessedInput != 0 {
		t.Fatal("processed input remained enabled")
	}
	if got&rawEnableLineInput != 0 {
		t.Fatal("line input remained enabled")
	}
	if got&rawEnableEchoInput != 0 {
		t.Fatal("echo input remained enabled")
	}
	if got&rawEnableVirtualTerminalInput == 0 {
		t.Fatal("virtual terminal input was not enabled")
	}
	if got&unrelated == 0 {
		t.Fatal("unrelated input mode flags were not preserved")
	}
}

func TestRawOutputMode(t *testing.T) {
	const unrelated uint32 = 0x0002
	got := rawOutputMode(unrelated)

	if got&rawEnableProcessedOutput == 0 {
		t.Fatal("processed output was not enabled")
	}
	if got&rawEnableVirtualTerminalProcessing == 0 {
		t.Fatal("virtual terminal processing was not enabled")
	}
	if got&unrelated == 0 {
		t.Fatal("unrelated output mode flags were not preserved")
	}
}

func TestRawWindowSize(t *testing.T) {
	info := rawConsoleScreenBufferInfo{
		Window: rawSmallRect{Left: 10, Top: 5, Right: 89, Bottom: 28},
	}
	cols, rows, err := rawWindowSize(info)
	if err != nil {
		t.Fatal(err)
	}
	if cols != 80 || rows != 24 {
		t.Fatalf("size = %dx%d, want 80x24", cols, rows)
	}
}

func TestRawWindowSizeRejectsInvalidWindow(t *testing.T) {
	info := rawConsoleScreenBufferInfo{
		Window: rawSmallRect{Left: 10, Top: 5, Right: 9, Bottom: 28},
	}
	if _, _, err := rawWindowSize(info); err == nil {
		t.Fatal("expected invalid window size error")
	}
}
