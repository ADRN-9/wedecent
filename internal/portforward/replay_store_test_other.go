//go:build !windows

package portforward

func setReplayTestDirectoryOwner(string) error {
	return nil
}
