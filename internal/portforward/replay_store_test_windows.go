//go:build windows

package portforward

import "golang.org/x/sys/windows"

func setReplayTestDirectoryOwner(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		nil,
		nil,
	)
}
