//go:build !linux && !windows

package session

func watchResize(fn func()) func() {
	return func() {}
}
