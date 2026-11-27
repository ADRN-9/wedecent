//go:build windows

package updateinfo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsUpdateRootStrictSchema(t *testing.T) {
	_, publicKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := WindowsUpdateRoot{
		Schema: windowsUpdateRootSchema,
		RootKeyID: "stable-root",
		RootPublicKey: strings.TrimSpace(string(encoded)),
		AuthenticodeThumbprint: strings.Repeat("A", 40),
	}
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	var decoded WindowsUpdateRoot
	if err := decodeStrictJSON(data, &decoded); err != nil {
		t.Fatalf("decode valid root: %v", err)
	}
	if decoded.RootKeyID != root.RootKeyID || decoded.RootPublicKey != root.RootPublicKey {
		t.Fatalf("decoded root differs: %#v", decoded)
	}
	if err := decodeStrictJSON(append(data, []byte(`{"unexpected":true}`)...), &decoded); err == nil {
		t.Fatal("accepted trailing JSON value")
	}
	unknown := strings.TrimSuffix(string(data), "}") + ",\"unexpected\":true}"
	if err := decodeStrictJSON([]byte(unknown), &decoded); err == nil {
		t.Fatal("accepted unknown trust-root field")
	}
}

func TestWindowsPowerShellUsesTrustedSystemBinaryAndPublisher(t *testing.T) {
	path, err := windowsPowerShellPath()
	if err != nil {
		t.Fatalf("resolve protected system PowerShell: %v", err)
	}
	digest, err := verifyWindowsPowerShellExecutable(context.Background(), path)
	if err != nil {
		t.Fatalf("verify system PowerShell Authenticode publisher and digest: %v", err)
	}
	if len(digest) != 64 {
		t.Fatalf("PowerShell SHA-256 length = %d, want 64", len(digest))
	}
}

func TestWindowsPowerShellRejectsSubstitutedExecutablePath(t *testing.T) {
	if _, err := verifyWindowsPowerShellExecutable(context.Background(), filepath.Join(t.TempDir(), "powershell.exe")); err == nil {
		t.Fatal("accepted caller-controlled PowerShell path")
	}
}
