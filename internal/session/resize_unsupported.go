//go:build !linux && !windows && !darwin

package session

func watchResize(fn func()) func() {
	return func() {}
}
