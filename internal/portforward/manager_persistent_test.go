package portforward

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func TestManagerBuildsDeviceScopedPersistentVerifierFromConfig(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(ManagerConfig{
		LocalDeviceID:          testInitiator,
		ReplayPath:             filepath.Join(t.TempDir(), "portforward-replay.json"),
		AuthorizationPublicKey: publicKey,
		PermissionAuthorizer:   allowPortForwardPermission{},
		Connector:              &pipeConnector{},
		Audit:                  &memoryAudit{},
		Limits:                 managerTestLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, ok := manager.verifier.(*AuthorizationVerifier)
	if !ok {
		t.Fatalf("manager verifier type = %T, want persistent AuthorizationVerifier", manager.verifier)
	}
	if _, ok := verifier.Replay.(*FileReplay); !ok {
		t.Fatalf("manager replay type = %T, want FileReplay", verifier.Replay)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}
