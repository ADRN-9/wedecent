//go:build windows

package updateinfo

import "golang.org/x/sys/windows"

func currentProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
