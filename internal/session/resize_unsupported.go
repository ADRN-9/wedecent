//go:build !linux

package session

func watchResize(fn func()) func() {
	return func() {}
}
