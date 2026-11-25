package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"crypto/tls"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func httpRecoveryAuthorityFixture(t *testing.T) (RecoveryAuthorityTrust, ed25519.PrivateKey, map[string]ed25519.PrivateKey) {
	t.Helper()
	primaryPublic, primaryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := RecoveryAuthorityTrust{PrimaryKey: primaryPublic, WitnessKeys: make(map[string]ed25519.PublicKey), Quorum: 2}
	private := make(map[string]ed25519.PrivateKey)
	for _, id := range []string{"one", "two", "three"} {
		public, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		trust.WitnessKeys[id], private[id] = public, key
	}
	return trust, primaryPrivate, private
}

func TestHTTPRecoveryAuthorityUsesPinnedTLS13AndPrimarySigning(t *testing.T) {
	trust, primaryPrivate, _ := httpRecoveryAuthorityFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("authority request did not negotiate TLS 1.3")
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != recoveryAuthorityAPIPrefix+"/archives/sign" {
			http.Error(w, "wrong endpoint", http.StatusNotFound)
			return
		}
		var request struct {
			Payload []byte `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		response := struct {
			KeyID     string `json:"key_id"`
			Signature []byte `json:"signature"`
		}{KeyID: recoveryPrimaryKeyID(trust.PrimaryKey), Signature: ed25519.Sign(primaryPrivate, request.Payload)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	certificate := server.Certificate()
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	authority, err := NewHTTPRecoveryAuthority(server.URL, hex.EncodeToString(pin[:]), "test-token", trust)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	authority.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool

	payload := []byte("pairing recovery archive digest binding")
	keyID, signature, err := authority.SignArchive(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != recoveryPrimaryKeyID(trust.PrimaryKey) || authority.VerifyArchive(context.Background(), keyID, payload, signature) != nil {
		t.Fatal("primary-signed archive did not verify against pinned public key")
	}
	if err := authority.VerifyArchive(context.Background(), keyID, []byte("different archive"), signature); err == nil {
		t.Fatal("archive signature verified against different payload")
	}
}

func TestHTTPRecoveryAuthorityRejectsWrongSPKIPin(t *testing.T) {
	trust, _, _ := httpRecoveryAuthorityFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()
	wrongPin := sha256.Sum256([]byte("not the server SPKI"))
	authority, err := NewHTTPRecoveryAuthority(server.URL, hex.EncodeToString(wrongPin[:]), "test-token", trust)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	authority.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	if _, _, err := authority.SignArchive(context.Background(), []byte("payload")); err == nil {
		t.Fatal("authority with mismatched SPKI pin was accepted")
	}
}

func TestHTTPRecoveryAuthorityRejectsUnpinnedOrNonHTTPSConfiguration(t *testing.T) {
	trust, _, _ := httpRecoveryAuthorityFixture(t)
	pin := sha256.Sum256([]byte("pin"))
	for _, tc := range []struct {
		name, endpoint, token string
		pin                   string
	}{
		{name: "http", endpoint: "http://authority.example", pin: hex.EncodeToString(pin[:]), token: "token"},
		{name: "missing token", endpoint: "https://authority.example", pin: hex.EncodeToString(pin[:])},
		{name: "invalid pin", endpoint: "https://authority.example", pin: "not-a-pin", token: "token"},
		{name: "path override", endpoint: "https://authority.example/v1", pin: hex.EncodeToString(pin[:]), token: "token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHTTPRecoveryAuthority(tc.endpoint, tc.pin, tc.token, trust); err == nil {
				t.Fatal("unsafe authority configuration was accepted")
			}
		})
	}
}

func TestLoadRecoveryAuthorityTrustRequiresPinnedUniqueEd25519Keys(t *testing.T) {
	trust, _, _ := httpRecoveryAuthorityFixture(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "recovery-trust.json")
	encoded := struct {
		PrimaryKey string            `json:"primary_key"`
		Witnesses  map[string]string `json:"witnesses"`
		Quorum     int               `json:"quorum"`
	}{PrimaryKey: base64.StdEncoding.EncodeToString(trust.PrimaryKey), Witnesses: make(map[string]string), Quorum: trust.Quorum}
	for id, key := range trust.WitnessKeys {
		encoded.Witnesses[id] = base64.StdEncoding.EncodeToString(key)
	}
	data, err := json.Marshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRecoveryAuthorityTrust(file)
	if err != nil || loaded.Validate() != nil {
		t.Fatalf("valid trust file rejected: %v", err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryAuthorityTrust(file); err == nil {
		t.Fatal("group/world writable trust file accepted")
	}
}
