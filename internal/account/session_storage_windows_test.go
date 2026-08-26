//go:build windows

package account

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsSessionStorageUsesDPAPIRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	session := validSession("https://example.supabase.co", time.Now().Add(time.Hour).Unix())
	session.AccessToken = "access-token-plaintext-sentinel"
	session.RefreshToken = "refresh-token-plaintext-sentinel"

	if err := Save(path, session); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(session.AccessToken)) || bytes.Contains(data, []byte(session.RefreshToken)) {
		t.Fatal("Windows account session persisted a plaintext token")
	}
	if !bytes.Contains(data, []byte(`"protected_credentials"`)) {
		t.Fatal("Windows account session is missing protected credentials")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AccessToken != session.AccessToken || loaded.RefreshToken != session.RefreshToken {
		t.Fatalf("round trip tokens do not match")
	}
	if loaded.UserID != session.UserID || loaded.Email != session.Email || loaded.ExpiresAt != session.ExpiresAt {
		t.Fatalf("round trip metadata does not match: %#v", loaded)
	}
}

func TestWindowsSessionStorageRejectsCorruptedDPAPIBlob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	session := validSession("https://example.supabase.co", time.Now().Add(time.Hour).Unix())
	if err := Save(path, session); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope windowsSessionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.ProtectedCredentials) < 8 {
		t.Fatal("protected credential blob is unexpectedly short")
	}
	last := len(envelope.ProtectedCredentials) - 2
	if envelope.ProtectedCredentials[last] == 'A' {
		envelope.ProtectedCredentials = envelope.ProtectedCredentials[:last] + "B" + envelope.ProtectedCredentials[last+1:]
	} else {
		envelope.ProtectedCredentials = envelope.ProtectedCredentials[:last] + "A" + envelope.ProtectedCredentials[last+1:]
	}
	data, err = json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "unprotect account session credentials") {
		t.Fatalf("error = %v", err)
	}
}

func TestWindowsSessionStorageRejectsTamperedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	session := validSession("https://example.supabase.co", time.Now().Add(time.Hour).Unix())
	if err := Save(path, session); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope windowsSessionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.SupabaseURL = "https://attacker.example"
	data, err = json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "metadata does not match") {
		t.Fatalf("error = %v", err)
	}
}

func TestWindowsSessionStorageRejectsLegacyPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	session := validSession("https://example.supabase.co", time.Now().Add(time.Hour).Unix())
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	if err == nil || !strings.Contains(err.Error(), "legacy plaintext Windows account session") {
		t.Fatalf("error = %v", err)
	}
}
