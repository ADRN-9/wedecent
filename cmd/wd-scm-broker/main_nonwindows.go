//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "WeDecent SCM broker is supported only on Windows")
	os.Exit(2)
}
