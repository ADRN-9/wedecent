package protocol

import (
	"strings"
	"testing"
)

func TestFileTransferCapabilityAndKindsRemainFailClosedUntilRuntime(t *testing.T) {
	if SupportedCapability(CapabilityFileTransferV1) {
		t.Fatal("file transfer capability advertised before authoritative runtime exists")
	}
	for _, kind := range []StreamKind{StreamKindFileUpload, StreamKindFileDownload} {
		open := StreamOpen{Kind: kind, InitialWindow: 1}
		if err := ValidateStreamOpen(MinTypedStreamID, open); err == nil {
			t.Fatalf("terminal typed-stream validator accepted reserved file kind %q", kind)
		}
	}
}

func TestValidateFileUploadOpen(t *testing.T) {
	size := uint64(0)
	valid := FileUploadOpen{
		Path:         "releases/build.tar",
		ExpectedSize: &size,
		SHA256:       strings.Repeat("ab", 32),
		Existing:     FileExistingFail,
	}
	if err := ValidateFileUploadOpen(valid); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		open FileUploadOpen
	}{
		{name: "absolute", open: FileUploadOpen{Path: "/etc/passwd", Existing: FileExistingFail}},
		{name: "parent", open: FileUploadOpen{Path: "safe/../escape", Existing: FileExistingFail}},
		{name: "dot", open: FileUploadOpen{Path: "safe/./file", Existing: FileExistingFail}},
		{name: "empty segment", open: FileUploadOpen{Path: "safe//file", Existing: FileExistingFail}},
		{name: "backslash", open: FileUploadOpen{Path: `safe\\file`, Existing: FileExistingFail}},
		{name: "drive", open: FileUploadOpen{Path: "C:/temp/file", Existing: FileExistingFail}},
		{name: "control", open: FileUploadOpen{Path: "safe/fi\nle", Existing: FileExistingFail}},
		{name: "missing existing policy", open: FileUploadOpen{Path: "safe/file"}},
		{name: "unknown existing policy", open: FileUploadOpen{Path: "safe/file", Existing: "merge"}},
		{name: "uppercase digest", open: FileUploadOpen{Path: "safe/file", Existing: FileExistingFail, SHA256: strings.Repeat("AB", 32)}},
		{name: "short digest", open: FileUploadOpen{Path: "safe/file", Existing: FileExistingFail, SHA256: "00"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateFileUploadOpen(tc.open); err == nil {
				t.Fatalf("accepted invalid upload metadata: %#v", tc.open)
			}
		})
	}
}

func TestValidateFileDownloadOpen(t *testing.T) {
	if err := ValidateFileDownloadOpen(FileDownloadOpen{Path: "logs/current.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFileDownloadOpen(FileDownloadOpen{Path: "../secret"}); err == nil {
		t.Fatal("accepted parent traversal")
	}
}

func TestFileTransferMetadataStrictJSON(t *testing.T) {
	var upload FileUploadOpen
	if err := ParseTypedStreamJSON([]byte(`{"path":"safe/file","existing":"fail","unexpected":true}`), &upload); err == nil {
		t.Fatal("accepted unknown upload metadata field")
	}
	if err := ParseTypedStreamJSON([]byte(`{"path":"safe/file","existing":"fail"} {}`), &upload); err == nil {
		t.Fatal("accepted trailing upload metadata JSON")
	}
}

func TestFileTransferPathLengthBound(t *testing.T) {
	if err := ValidateFileDownloadOpen(FileDownloadOpen{Path: strings.Repeat("a", MaxFileTransferPathBytes)}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFileDownloadOpen(FileDownloadOpen{Path: strings.Repeat("a", MaxFileTransferPathBytes+1)}); err == nil {
		t.Fatal("accepted oversized path")
	}
}
