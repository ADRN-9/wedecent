package protocol

import (
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
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

// FileUploadOpen is capability-specific metadata for a future file-upload
// stream. It is defined separately from StreamOpen so terminal-only runtimes
// cannot accidentally accept file metadata as a terminal open operation.
type FileUploadOpen struct {
	Path         string             `json:"path"`
	ExpectedSize *uint64            `json:"expected_size,omitempty"`
	SHA256       string             `json:"sha256,omitempty"`
	Existing     FileExistingPolicy `json:"existing"`
}

// FileDownloadOpen is capability-specific metadata for a future file-download
// stream. The authoritative agent must still apply its filesystem policy before
// opening this path; protocol validation alone is not authorization.
type FileDownloadOpen struct {
	Path string `json:"path"`
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
	if path == "" || len(path) > MaxFileTransferPathBytes {
		return errors.New("file transfer path is out of range")
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "\\") {
		return errors.New("file transfer path must be canonical and relative")
	}
	if len(path) >= 2 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' {
		return errors.New("file transfer path must not use a drive prefix")
	}
	for _, r := range path {
		if r == 0 || unicode.IsControl(r) {
			return errors.New("file transfer path contains a control character")
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("file transfer path contains a non-canonical segment")
		}
	}
	return nil
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
