package buildinfo

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestCurrentNormalizesEmptyInjectedValues(t *testing.T) {
	oldVersion, oldCommit, oldBuiltAt := Version, Commit, BuiltAt
	t.Cleanup(func() {
		Version, Commit, BuiltAt = oldVersion, oldCommit, oldBuiltAt
	})

	Version, Commit, BuiltAt = "", " ", "\t"
	info := Current()
	if info.Version != "dev" || info.Commit != "unknown" || info.BuiltAt != "unknown" {
		t.Fatalf("unexpected normalized info: %+v", info)
	}
	if info.Go != runtime.Version() {
		t.Fatalf("Go = %q, want %q", info.Go, runtime.Version())
	}
	if info.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("Platform = %q", info.Platform)
	}
}

func TestWriteIncludesReleaseMetadata(t *testing.T) {
	oldVersion, oldCommit, oldBuiltAt := Version, Commit, BuiltAt
	t.Cleanup(func() {
		Version, Commit, BuiltAt = oldVersion, oldCommit, oldBuiltAt
	})

	Version = "0.3.0-rc.1"
	Commit = "0123456789abcdef"
	BuiltAt = "2026-08-27T00:00:00Z"

	var out bytes.Buffer
	if err := Write(&out, "wd"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wd 0.3.0-rc.1\n",
		"commit: 0123456789abcdef\n",
		"built: 2026-08-27T00:00:00Z\n",
		"go: " + runtime.Version() + "\n",
		"platform: " + runtime.GOOS + "/" + runtime.GOARCH + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q does not contain %q", out.String(), want)
		}
	}
}
