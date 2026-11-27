//go:build windows

package updateinfo

import "golang.org/x/sys/windows"

func windowsCurrentProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
