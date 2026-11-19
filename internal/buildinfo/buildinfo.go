package buildinfo

import (
	"fmt"
	"io"
	"runtime"
	"strings"
)

var (
	Version      = "dev"
	Commit       = "unknown"
	BuiltAt      = "unknown"
	SourceSHA256 = "unknown"
)

type Info struct {
	Version      string
	Commit       string
	BuiltAt      string
	SourceSHA256 string
	Go           string
	Platform     string
}

func Current() Info {
	return Info{
		Version:      normalized(Version, "dev"),
		Commit:       normalized(Commit, "unknown"),
		BuiltAt:      normalized(BuiltAt, "unknown"),
		SourceSHA256: normalized(SourceSHA256, "unknown"),
		Go:           runtime.Version(),
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
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
		"%s %s\ncommit: %s\nbuilt: %s\nsource_sha256: %s\ngo: %s\nplatform: %s\n",
		product, info.Version, info.Commit, info.BuiltAt, info.SourceSHA256, info.Go, info.Platform,
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
