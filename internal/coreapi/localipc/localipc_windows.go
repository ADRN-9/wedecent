//go:build windows

package localipc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os/user"
	"strings"

	winio "github.com/Microsoft/go-winio"
)

const windowsPipePrefix = `\\.\pipe\WeDecent.Core.v1.`

// Endpoint returns the current user's local Core API named-pipe path.
func Endpoint() (string, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", err
	}
	return pipeNameForSID(sid)
}

// Listen creates a local-only named pipe whose DACL grants access only to the
// current Windows user. go-winio rejects remote named-pipe clients.
func Listen() (net.Listener, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	name, err := pipeNameForSID(sid)
	if err != nil {
		return nil, err
	}
	sddl, err := securityDescriptorForSID(sid)
	if err != nil {
		return nil, err
	}

	listener, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		MessageMode:        false,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("core local ipc: listen: %w", err)
	}
	return listener, nil
}

// Dial connects to the current user's local Core API named pipe.
func Dial(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := Endpoint()
	if err != nil {
		return nil, err
	}
	conn, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("core local ipc: dial: %w", err)
	}
	return conn, nil
}

func currentUserSID() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("core local ipc: resolve current user: %w", err)
	}
	sid := strings.TrimSpace(current.Uid)
	if !validSIDText(sid) {
		return "", fmt.Errorf("%w: invalid current-user SID", ErrUnsafeEndpoint)
	}
	return sid, nil
}

func pipeNameForSID(sid string) (string, error) {
	sid = strings.TrimSpace(sid)
	if !validSIDText(sid) {
		return "", fmt.Errorf("%w: invalid SID", ErrUnsafeEndpoint)
	}
	digest := sha256.Sum256([]byte(sid))
	return windowsPipePrefix + hex.EncodeToString(digest[:12]), nil
}

func securityDescriptorForSID(sid string) (string, error) {
	sid = strings.TrimSpace(sid)
	if !validSIDText(sid) {
		return "", fmt.Errorf("%w: invalid SID", ErrUnsafeEndpoint)
	}
	return "D:P(A;;GA;;;" + sid + ")", nil
}

func validSIDText(sid string) bool {
	if len(sid) < 5 || len(sid) > 256 || !strings.HasPrefix(sid, "S-") {
		return false
	}
	parts := strings.Split(sid[2:], "-")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
