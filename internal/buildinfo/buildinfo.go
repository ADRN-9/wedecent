package buildinfo

import (
	"fmt"
	"io"
	"runtime"
	"strings"
)

var (
	Version = "dev"
	Commit  = "unknown"
	BuiltAt = "unknown"
)

type Info struct {
	Version  string
	Commit   string
	BuiltAt  string
	Go       string
	Platform string
}

func Current() Info {
	return Info{
		Version:  normalized(Version, "dev"),
		Commit:   normalized(Commit, "unknown"),
		BuiltAt:  normalized(BuiltAt, "unknown"),
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func Write(w io.Writer, product string) error {
	if w == nil {
		return fmt.Errorf("version output writer is nil")
	}
	product = strings.TrimSpace(product)
	if product == "" {
		product = "wedecent"
	}
	info := Current()
	_, err := fmt.Fprintf(w,
		"%s %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s\n",
		product, info.Version, info.Commit, info.BuiltAt, info.Go, info.Platform,
	)
	return err
}

func normalized(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
