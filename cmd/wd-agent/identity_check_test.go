package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

func TestLoadIdentityForCheckIsReadOnlyAndVerifiesKeyCertificatePair(t *testing.T) {
	stateDir := t.TempDir()
	original, err := identity.Ensure(stateDir, "migration-test")
	if err != nil {
		t.Fatal(err)
	}
	keyName := "identity.key"
	if _, err := os.Stat(filepath.Join(stateDir, "identity.key.dpapi")); err == nil {
		keyName = "identity.key.dpapi"
	}
	keyPath := filepath.Join(stateDir, keyName)
	beforeKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeCert, err := os.ReadFile(filepath.Join(stateDir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := loadIdentityForCheck(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != original.ID || !loaded.PublicKey.Equal(original.PublicKey) {
		t.Fatal("read-only identity check changed device identity")
	}
	afterKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	afterCert, err := os.ReadFile(filepath.Join(stateDir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(beforeKey) != string(afterKey) || string(beforeCert) != string(afterCert) {
		t.Fatal("identity-check modified key or certificate material")
	}

	otherDir := t.TempDir()
	if _, err := identity.Ensure(otherDir, "different-identity"); err != nil {
		t.Fatal(err)
	}
	otherCert, err := os.ReadFile(filepath.Join(otherDir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "identity.crt"), otherCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityForCheck(stateDir); err == nil {
		t.Fatal("identity-check accepted a certificate belonging to another private key")
	}
}

func TestLoadIdentityForCheckDoesNotCreateMissingState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := loadIdentityForCheck(missing); err == nil {
		t.Fatal("identity-check accepted missing state")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("identity-check created missing state: %v", err)
	}
}

func TestLoadIdentityForCheckRejectsMissingCertificateWithoutMutation(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := identity.Ensure(stateDir, "missing-certificate"); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(stateDir, "identity.key")
	if _, err := os.Stat(filepath.Join(stateDir, "identity.key.dpapi")); err == nil {
		keyPath = filepath.Join(stateDir, "identity.key.dpapi")
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(stateDir, "identity.crt")
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityForCheck(stateDir); err == nil {
		t.Fatal("identity-check accepted an identity with a missing certificate")
	}
	if _, err := os.Lstat(certPath); !os.IsNotExist(err) {
		t.Fatalf("identity-check recreated the missing certificate: %v", err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("identity-check modified existing private key material")
	}
}

func TestLoadIdentityForCheckRejectsInvalidMaterialWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, stateDir string)
	}{
		{
			name: "missing certificate",
			mutate: func(t *testing.T, stateDir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(stateDir, "identity.crt")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing private key",
			mutate: func(t *testing.T, stateDir string) {
				t.Helper()
				for _, name := range []string{"identity.key.dpapi", "identity.key"} {
					path := filepath.Join(stateDir, name)
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "mismatched certificate and private key",
			mutate: func(t *testing.T, stateDir string) {
				t.Helper()
				otherDir := t.TempDir()
				if _, err := identity.Ensure(otherDir, "different-identity"); err != nil {
					t.Fatal(err)
				}
				certificate, err := os.ReadFile(filepath.Join(otherDir, "identity.crt"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(stateDir, "identity.crt"), certificate, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed certificate",
			mutate: func(t *testing.T, stateDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(stateDir, "identity.crt"), []byte("not a certificate"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsupported identity algorithm",
			mutate: func(t *testing.T, stateDir string) {
				t.Helper()
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				template := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					Subject:      pkix.Name{CommonName: "unsupported-algorithm"},
					NotBefore:    now.Add(-time.Minute),
					NotAfter:     now.Add(time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
				}
				der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
				if err != nil {
					t.Fatal(err)
				}
				certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
				if err := os.WriteFile(filepath.Join(stateDir, "identity.crt"), certificate, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateDir := t.TempDir()
			if _, err := identity.Ensure(stateDir, "migration-rejection-test"); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, stateDir)

			before := snapshotIdentityCheckFiles(t, stateDir)
			if _, err := loadIdentityForCheck(stateDir); err == nil {
				t.Fatal("identity-check accepted invalid identity material")
			}
			after := snapshotIdentityCheckFiles(t, stateDir)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejected identity-check created, renewed, replaced, or deleted identity material")
			}
		})
	}
}

func snapshotIdentityCheckFiles(t *testing.T, stateDir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatalf("unexpected non-regular identity entry %q", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(stateDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = data
	}
	return snapshot
}
