package main

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/session"
)

func TestParseServeConfigFileTransferDisabledByDefault(t *testing.T) {
	cfg, err := parseServeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.fileTransferConfigured() {
		t.Fatalf("file transfer unexpectedly configured: %#v", cfg)
	}
}

func TestParseServeConfigRejectsPartialFileTransfer(t *testing.T) {
	root := t.TempDir()
	tooLarge := strconv.FormatUint(session.MaxFileTransferStoreBytes+1, 10)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "root only", args: []string{"--file-root=" + root}, want: "file-upload"},
		{name: "upload only", args: []string{"--file-upload"}, want: "file-root"},
		{name: "missing limit", args: []string{"--file-root=" + root, "--file-upload"}, want: "file-max-bytes"},
		{name: "limit only", args: []string{"--file-max-bytes=1024"}, want: "file-root"},
		{name: "relative root", args: []string{"--file-root=relative", "--file-download", "--file-max-bytes=1024"}, want: "absolute"},
		{name: "oversized limit", args: []string{"--file-root=" + root, "--file-download", "--file-max-bytes=" + tooLarge}, want: "file-max-bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseServeConfig(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestOpenAgentFileTransferRuntime(t *testing.T) {
	cfg := serveConfig{
		FileTransferRoot:          t.TempDir(),
		FileTransferAllowUpload:   true,
		FileTransferAllowDownload: true,
		FileTransferMaxBytes:      1 << 20,
	}
	runtime, err := openAgentFileTransferRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil || !runtime.Ready() {
		t.Fatal("file transfer runtime is not ready")
	}
	defer runtime.Store.Close()

	if err := runtime.Authorize(context.Background(), "peer-1", session.FileTransferUpload, "incoming/file.txt"); err != nil {
		t.Fatalf("upload authorization failed: %v", err)
	}
	if err := runtime.Authorize(context.Background(), "peer-1", session.FileTransferDownload, "outgoing/file.txt"); err != nil {
		t.Fatalf("download authorization failed: %v", err)
	}
}

func TestOpenAgentFileTransferRuntimeDisabled(t *testing.T) {
	runtime, err := openAgentFileTransferRuntime(serveConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		t.Fatal("disabled config created a file transfer runtime")
	}
}
