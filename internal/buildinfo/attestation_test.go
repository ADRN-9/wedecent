package buildinfo

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestAgentBuildIdentitySignatureBindsDeviceAndNonce(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	attestation, err := SignIdentity("wd_aaaaaaaaaaaaaaaa", privateKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIdentity(publicKey, "wd_aaaaaaaaaaaaaaaa", nonce, attestation); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIdentity(publicKey, "wd_bbbbbbbbbbbbbbbb", nonce, attestation); err == nil {
		t.Fatal("accepted build identity for another device")
	}
	if err := VerifyIdentity(publicKey, "wd_aaaaaaaaaaaaaaaa", nonce+"x", attestation); err == nil {
		t.Fatal("accepted a replayed build identity challenge")
	}
	attestation.Commit = "tampered"
	if err := VerifyIdentity(publicKey, "wd_aaaaaaaaaaaaaaaa", nonce, attestation); err == nil {
		t.Fatal("accepted tampered build metadata")
	}
}

func TestVerifyAgentBuildIdentityRejectsMalformedNonceAndSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	attestation, err := SignIdentity("wd_aaaaaaaaaaaaaaaa", privateKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIdentity(publicKey, "wd_aaaaaaaaaaaaaaaa", "not-a-nonce", attestation); err == nil {
		t.Fatal("accepted malformed challenge")
	}
	attestation.Signature = "not-a-signature"
	if err := VerifyIdentity(publicKey, "wd_aaaaaaaaaaaaaaaa", nonce, attestation); err == nil {
		t.Fatal("accepted malformed signature")
	}
}

var _ = protocol.AgentBuildIdentity{}
