//go:build !windows

package account

import (
	"encoding/json"
	"fmt"
	"os"
)

func decodeSessionStorage(info os.FileInfo, data []byte) (*Session, error) {
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("account session permissions are too broad: %o (want 600)", info.Mode().Perm())
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("decode account session: %w", err)
	}
	return &session, nil
}

func encodeSessionStorage(session *Session) ([]byte, error) {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode account session: %w", err)
	}
	return append(data, '\n'), nil
}
