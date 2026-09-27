package protocol

import (
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	StreamKindFileUpload   StreamKind = "file-upload"
	StreamKindFileDownload StreamKind = "file-download"

	MaxFileTransferPathBytes = 1024
)

type FileExistingPolicy string

const (
	FileExistingFail    FileExistingPolicy = "fail"
	FileExistingReplace FileExistingPolicy = "replace"
)

// FileUploadOpen is capability-specific metadata for a file-upload stream.
// Protocol validation is not authorization; the authoritative agent must
// separately authorize the authenticated peer before opening storage.
type FileUploadOpen struct {
	Path         string             `json:"path"`
	ExpectedSize *uint64            `json:"expected_size,omitempty"`
	SHA256       string             `json:"sha256,omitempty"`
	Existing     FileExistingPolicy `json:"existing"`
}

// FileDownloadOpen is capability-specific metadata for a file-download stream.
// The authoritative agent must still apply authorization and filesystem policy
// before opening this path.
type FileDownloadOpen struct {
	Path string `json:"path"`
}

func ParseFileUploadStreamOpen(streamID uint32, open StreamOpen) (FileUploadOpen, error) {
	if err := validateFileStreamEnvelope(streamID, open, StreamKindFileUpload); err != nil {
		return FileUploadOpen{}, err
	}
	var metadata FileUploadOpen
	if err := ParseTypedStreamJSON(open.Metadata, &metadata); err != nil {
		return FileUploadOpen{}, err
	}
	if err := ValidateFileUploadOpen(metadata); err != nil {
		return FileUploadOpen{}, err
	}
	return metadata, nil
}

func ParseFileDownloadStreamOpen(streamID uint32, open StreamOpen) (FileDownloadOpen, error) {
	if err := validateFileStreamEnvelope(streamID, open, StreamKindFileDownload); err != nil {
		return FileDownloadOpen{}, err
	}
	var metadata FileDownloadOpen
	if err := ParseTypedStreamJSON(open.Metadata, &metadata); err != nil {
		return FileDownloadOpen{}, err
	}
	if err := ValidateFileDownloadOpen(metadata); err != nil {
		return FileDownloadOpen{}, err
	}
	return metadata, nil
}

func validateFileStreamEnvelope(streamID uint32, open StreamOpen, want StreamKind) error {
	if err := validateStreamOpenWindow(streamID, open); err != nil {
		return err
	}
	if open.Kind != want {
		return errors.New("file stream kind does not match operation")
	}
	if open.Cols != 0 || open.Rows != 0 || open.Term != "" {
		return errors.New("file stream contains terminal-only fields")
	}
	if len(open.Metadata) == 0 || len(open.Metadata) > MaxTypedStreamOpenMetadata {
		return errors.New("file stream metadata is out of range")
	}
	return nil
}

func ValidateFileUploadOpen(open FileUploadOpen) error {
	if err := validateFileTransferPath(open.Path); err != nil {
		return err
	}
	switch open.Existing {
	case FileExistingFail, FileExistingReplace:
	default:
		return errors.New("file upload existing-destination policy is invalid")
	}
	if open.SHA256 != "" && !validSHA256Hex(open.SHA256) {
		return errors.New("file upload SHA-256 digest is invalid")
	}
	return nil
}

func ValidateFileDownloadOpen(open FileDownloadOpen) error {
	return validateFileTransferPath(open.Path)
}

func validateFileTransferPath(path string) error {
	if path == "" || len(path) > MaxFileTransferPathBytes || !utf8.ValidString(path) {
		return errors.New("file transfer path is out of range")
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.ContainsAny(path, `\<>:"|?*`) {
		return errors.New("file transfer path must be canonical and relative")
	}
	for _, r := range path {
		if r == 0 || unicode.IsControl(r) {
			return errors.New("file transfer path contains a control character")
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") || windowsReservedFileName(part) {
			return errors.New("file transfer path contains a non-canonical segment")
		}
	}
	return nil
}

func windowsReservedFileName(part string) bool {
	base := part
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
