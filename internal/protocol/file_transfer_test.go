package protocol

import (
	"strings"
	"testing"
)

func TestFileTransferCapabilityIsSupportedButTerminalValidatorRemainsStrict(t *testing.T) {
	if !SupportedCapability(CapabilityFileTransferV1) {
		t.Fatal("file transfer capability is not marked supported")
	}
	for _, kind := range []StreamKind{StreamKindFileUpload, StreamKindFileDownload} {
		open := StreamOpen{Kind: kind, InitialWindow: 1}
		if err := ValidateStreamOpen(MinTypedStreamID, open); err == nil {
			t.Fatalf("terminal typed-stream validator accepted file kind %q", kind)
		}
	}
}

func TestParseFileUploadStreamOpen(t *testing.T) {
	size := uint64(7)
	want := FileUploadOpen{
		Path:         "incoming/file.txt",
		ExpectedSize: &size,
		SHA256:       strings.Repeat("ab", 32),
		Existing:     FileExistingFail,
	}
	metadata, err := JSON(want)
	if err != nil {
		t.Fatal(err)
	}
	open := StreamOpen{
		Kind:          StreamKindFileUpload,
		Metadata:      metadata,
		InitialWindow: 64 << 10,
	}
	got, err := ParseFileUploadStreamOpen(MinTypedStreamID, open)
	if err != nil {
		t.Fatalf("valid upload stream rejected: %v", err)
	}
	if got.Path != want.Path || got.ExpectedSize == nil || *got.ExpectedSize != size || got.SHA256 != want.SHA256 || got.Existing != want.Existing {
		t.Fatalf("parsed upload = %#v, want %#v", got, want)
	}

	invalid := []struct {
		name string
		open StreamOpen
	}{
		{"reserved ID", open},
		{"wrong kind", StreamOpen{Kind: StreamKindFileDownload, Metadata: metadata, InitialWindow: 1}},
		{"terminal fields", StreamOpen{Kind: StreamKindFileUpload, Cols: 80, Metadata: metadata, InitialWindow: 1}},
		{"missing metadata", StreamOpen{Kind: StreamKindFileUpload, InitialWindow: 1}},
		{"oversized metadata", StreamOpen{Kind: StreamKindFileUpload, Metadata: make([]byte, MaxTypedStreamOpenMetadata+1), InitialWindow: 1}},
		{"zero window", StreamOpen{Kind: StreamKindFileUpload, Metadata: metadata}},
		{"unknown metadata field", StreamOpen{Kind: StreamKindFileUpload, Metadata: []byte("{\"path\":\"safe/file\",\"existing\":\"fail\",\"extra\":true}"), InitialWindow: 1}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			streamID := MinTypedStreamID
			if tc.name == "reserved ID" {
				streamID = 0
			}
			if _, err := ParseFileUploadStreamOpen(streamID, tc.open); err == nil {
				t.Fatal("accepted invalid upload stream open")
			}
		})
	}
}

func TestParseFileDownloadStreamOpen(t *testing.T) {
	metadata := []byte("{\"path\":\"logs/current.txt\"}")
	open := StreamOpen{Kind: StreamKindFileDownload, Metadata: metadata, InitialWindow: 1}
	got, err := ParseFileDownloadStreamOpen(MinTypedStreamID, open)
	if err != nil {
		t.Fatalf("valid download stream rejected: %v", err)
	}
	if got.Path != "logs/current.txt" {
		t.Fatalf("parsed download path = %q", got.Path)
	}
	if _, err := ParseFileDownloadStreamOpen(MinTypedStreamID, StreamOpen{
		Kind:          StreamKindFileDownload,
		Metadata:      []byte("{\"path\":\"../secret\"}"),
		InitialWindow: 1,
	}); err == nil {
		t.Fatal("accepted traversal in download stream metadata")
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
		{name: "backslash", open: FileUploadOpen{Path: `safe\file`, Existing: FileExistingFail}},
		{name: "drive", open: FileUploadOpen{Path: "C:/temp/file", Existing: FileExistingFail}},
		{name: "alternate data stream", open: FileUploadOpen{Path: "safe/file:secret", Existing: FileExistingFail}},
		{name: "windows wildcard", open: FileUploadOpen{Path: "safe/*.txt", Existing: FileExistingFail}},
		{name: "reserved device", open: FileUploadOpen{Path: "safe/NUL.txt", Existing: FileExistingFail}},
		{name: "reserved numbered device", open: FileUploadOpen{Path: "safe/com1.log", Existing: FileExistingFail}},
		{name: "trailing dot", open: FileUploadOpen{Path: "safe/file.", Existing: FileExistingFail}},
		{name: "trailing space", open: FileUploadOpen{Path: "safe/file ", Existing: FileExistingFail}},
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
	if err := ParseTypedStreamJSON([]byte("{\"path\":\"safe/file\",\"existing\":\"fail\",\"unexpected\":true}"), &upload); err == nil {
		t.Fatal("accepted unknown upload metadata field")
	}
	if err := ParseTypedStreamJSON([]byte("{\"path\":\"safe/file\",\"existing\":\"fail\"} {}"), &upload); err == nil {
		t.Fatal("accepted trailing upload metadata JSON")
	}
	if err := ParseTypedStreamJSON([]byte("{\"path\":\"safe/file\",\"existing\":\"fail\"}"), &upload); err != nil {
		t.Fatalf("rejected valid upload metadata JSON: %v", err)
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
