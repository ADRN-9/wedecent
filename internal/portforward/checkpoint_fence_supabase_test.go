package portforward

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func c203AuthorityJWT(actorID string) string {
	encode := base64.RawURLEncoding.EncodeToString
	header := encode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	claims, _ := json.Marshal(map[string]any{
		"role": "wedecent_checkpoint_authority",
		"sub": actorID,
		"iat": now,
		"exp": now + 240,
	})
	return header + "." + encode(claims) + ".test-signature"
}

func c197Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func c197Ack(t *testing.T, token CheckpointFenceToken, id string, privateKey ed25519.PrivateKey) CheckpointFenceAcknowledgement {
	t.Helper()
	digest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		t.Fatal(err)
	}
	ack := CheckpointFenceAcknowledgement{
		WitnessID: id, TokenSHA256: digest, Generation: token.Generation,
		Action: token.Action, OperationID: token.OperationID,
		WitnessKeyID:      checkpointProviderKeyID(privateKey.Public().(ed25519.PublicKey)),
		CommittedAtUnixMS: token.ExpiresAtUnixMS - 1,
	}
	ack.Signature = ed25519.Sign(privateKey, checkpointFenceAcknowledgementMessage(ack))
	return ack
}

func TestSupabaseCheckpointFencePrimaryRequiresIndependentTrustKeys(t *testing.T) {
	primaryPublic, primaryPrivate := c197Key(t)
	headPublic, _ := c197Key(t)
	revocationPublic, _ := c197Key(t)
	witnesses := make([]CheckpointFenceWitnessTrust, 3)
	for i, id := range []string{"witness-a", "witness-b", "witness-c"} {
		publicKey, _ := c197Key(t)
		witnesses[i] = CheckpointFenceWitnessTrust{ID: id, PublicKey: publicKey}
	}
	config := SupabaseCheckpointFenceConfig{
		Hostname: "localhost", Port: 443, SPKISHA256Pins: strings.Repeat("a", 64),
		AuthorityJWT: c203AuthorityJWT("11111111-1111-4111-8111-111111111111"), ActorID: "11111111-1111-4111-8111-111111111111",
		PrimarySigner: primaryPrivate, CheckpointHeadKey: headPublic,
		RevocationAuthorizationKey: revocationPublic,
		WitnessSetVersion:          "c197-test", Witnesses: witnesses,
	}
	primary, err := NewSupabaseCheckpointFencePrimary(config)
	if err != nil {
		t.Fatalf("valid pinned primary config rejected: %v", err)
	}
	if primary.CheckpointAuthorityKeyID() != checkpointProviderKeyID(headPublic) {
		t.Fatal("primary authority key ID mismatch")
	}
	config.CheckpointHeadKey = primaryPublic
	if _, err := NewSupabaseCheckpointFencePrimary(config); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("primary/checkpoint-head key reuse accepted: %v", err)
	}
	config.CheckpointHeadKey = headPublic
	config.RevocationAuthorizationKey = primaryPublic
	if _, err := NewSupabaseCheckpointFencePrimary(config); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("revocation proof key reused primary signing key: %v", err)
	}
	config.RevocationAuthorizationKey = revocationPublic
	config.Witnesses[0].PublicKey = revocationPublic
	if _, err := NewSupabaseCheckpointFencePrimary(config); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("witness reused revocation authorization key: %v", err)
	}
	config.Witnesses[0].PublicKey = primaryPublic
	if _, err := NewSupabaseCheckpointFencePrimary(config); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("witness reused primary signing key: %v", err)
	}
	config.Witnesses[0].PublicKey = headPublic
	if _, err := NewSupabaseCheckpointFencePrimary(config); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("witness reused checkpoint-head signing key: %v", err)
	}
	config.Witnesses[0].PublicKey = witnesses[1].PublicKey
	if _, err := NewSupabaseCheckpointFencePrimary(config); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("duplicate witness key accepted: %v", err)
	}
}

func TestSupabaseCheckpointFencePrimaryVerifiesStrictWitnessQuorum(t *testing.T) {
	token, primaryPrivate := validFenceToken(t, CheckpointFenceFinalize)
	primary := &SupabaseCheckpointFencePrimary{
		primaryKey:        primaryPrivate.Public().(ed25519.PublicKey),
		witnesses:         make(map[string]ed25519.PublicKey),
		witnessSetVersion: token.WitnessSetVersion,
		witnessIDs:        append([]string(nil), token.WitnessIDs...),
		quorum:            2,
		now:               func() time.Time { return time.UnixMilli(1000) },
	}
	private := make(map[string]ed25519.PrivateKey)
	for _, id := range token.WitnessIDs {
		publicKey, privateKey := c197Key(t)
		primary.witnesses[id] = publicKey
		private[id] = privateKey
	}
	first := c197Ack(t, token, token.WitnessIDs[0], private[token.WitnessIDs[0]])
	second := c197Ack(t, token, token.WitnessIDs[1], private[token.WitnessIDs[1]])
	if err := primary.verifyAcknowledgements(token, []CheckpointFenceAcknowledgement{first, second}); err != nil {
		t.Fatalf("valid quorum rejected: %v", err)
	}
	rotatedSet := token
	rotatedSet.WitnessSetVersion = "rotated-witness-set"
	if err := primary.verifyAcknowledgements(rotatedSet, []CheckpointFenceAcknowledgement{first, second}); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("acknowledgements from a stale witness set accepted: %v", err)
	}
	wrongSet := token
	wrongSet.WitnessIDs = append([]string(nil), token.WitnessIDs[:2]...)
	if err := primary.verifyAcknowledgements(wrongSet, []CheckpointFenceAcknowledgement{first, second}); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("acknowledgements from a different configured witness set accepted: %v", err)
	}
	if err := primary.verifyAcknowledgements(token, []CheckpointFenceAcknowledgement{first}); !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("insufficient quorum accepted: %v", err)
	}
	duplicate := second
	duplicate.WitnessID = first.WitnessID
	duplicate.WitnessKeyID = first.WitnessKeyID
	duplicate.Signature = ed25519.Sign(private[first.WitnessID], checkpointFenceAcknowledgementMessage(duplicate))
	if err := primary.verifyAcknowledgements(token, []CheckpointFenceAcknowledgement{first, duplicate}); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("duplicate witness accepted: %v", err)
	}
	forged := second
	forged.OperationID = "different-operation"
	if err := primary.verifyAcknowledgements(token, []CheckpointFenceAcknowledgement{first, forged}); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("forged operation binding accepted: %v", err)
	}
	stale := second
	stale.TokenSHA256 = sha256.Sum256([]byte("stale-token"))
	stale.Signature = ed25519.Sign(private[stale.WitnessID], checkpointFenceAcknowledgementMessage(stale))
	if err := primary.verifyAcknowledgements(token, []CheckpointFenceAcknowledgement{first, stale}); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("stale token acknowledgement accepted: %v", err)
	}
	expired := second
	expired.CommittedAtUnixMS = token.ExpiresAtUnixMS + 1
	expired.Signature = ed25519.Sign(private[expired.WitnessID], checkpointFenceAcknowledgementMessage(expired))
	if err := primary.verifyAcknowledgements(token, []CheckpointFenceAcknowledgement{first, expired}); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("expired acknowledgement accepted: %v", err)
	}
	unknown := second
	unknown.WitnessID = "unconfigured-witness"
	unknown.Signature = ed25519.Sign(private[second.WitnessID], checkpointFenceAcknowledgementMessage(unknown))
	if err := primary.verifyAcknowledgements(token, []CheckpointFenceAcknowledgement{first, unknown}); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("unknown witness accepted: %v", err)
	}
}

func TestSupabaseCheckpointFenceWireRoundTripPreservesSignedFields(t *testing.T) {
	token, _ := validFenceToken(t, CheckpointFenceFinalize)
	wire, err := checkpointFenceTokenToWire(token)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := checkpointFenceTokenFromWire(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !sameCheckpointFenceToken(token, decoded) {
		t.Fatal("token wire round trip changed signed fields")
	}
	revokeToken, _ := validFenceToken(t, CheckpointFenceRevoke)
	revokeWire, err := checkpointFenceTokenToWire(revokeToken)
	if err != nil {
		t.Fatal(err)
	}
	revokeEncoded, err := json.Marshal(revokeWire)
	if err != nil {
		t.Fatal(err)
	}
	revokeDecoded, err := checkpointFenceTokenFromWire(revokeEncoded)
	if err != nil || !sameCheckpointFenceToken(revokeToken, revokeDecoded) ||
		!bytes.Equal(revokeToken.AuthorizationProof, revokeDecoded.AuthorizationProof) {
		t.Fatalf("revocation proof wire round trip changed signed fields: %v", err)
	}
	legacySignatureWire := revokeWire
	legacySignatureWire.AuthorizationProof = strings.Repeat("A", 86) + "=="
	legacySignatureJSON, err := json.Marshal(legacySignatureWire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointFenceTokenFromWire(legacySignatureJSON); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("signature-only legacy proof accepted without its validity envelope: %v", err)
	}
	unknownFields := append(bytes.TrimSuffix(encoded, []byte("}")), []byte(`,"untrusted":true}`)...)
	if _, err := checkpointFenceTokenFromWire(unknownFields); err == nil {
		t.Fatal("token with an unsigned unknown field was accepted")
	}
	if _, err := checkpointFenceTokenFromWire(append(encoded, []byte(`{}`)...)); err == nil {
		t.Fatal("token with trailing JSON was accepted")
	}
	_, witnessPrivate := c197Key(t)
	ack := c197Ack(t, token, token.WitnessIDs[0], witnessPrivate)
	ackBytes, err := json.Marshal(checkpointFenceAckToWire(ack))
	if err != nil {
		t.Fatal(err)
	}
	var ackWire checkpointFenceAckWire
	if err := json.Unmarshal(ackBytes, &ackWire); err != nil {
		t.Fatal(err)
	}
	decodedAck, err := checkpointFenceAckFromWire(ackWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedAck.WitnessID != ack.WitnessID || decodedAck.TokenSHA256 != ack.TokenSHA256 ||
		decodedAck.Generation != ack.Generation || decodedAck.Action != ack.Action ||
		decodedAck.OperationID != ack.OperationID || decodedAck.WitnessKeyID != ack.WitnessKeyID ||
		decodedAck.CommittedAtUnixMS != ack.CommittedAtUnixMS || !bytes.Equal(decodedAck.Signature, ack.Signature) {
		t.Fatal("acknowledgement wire round trip changed signed fields")
	}
}

func TestSupabaseCheckpointFencePrimaryVerifiesOperationBoundRevocationProof(t *testing.T) {
	revocationPublic, revocationPrivate := c197Key(t)
	now := time.UnixMilli(1000)
	primary := &SupabaseCheckpointFencePrimary{
		revocationAuthorizationKey: revocationPublic,
		now:                        func() time.Time { return now },
	}
	endpoint := CheckpointEndpoint{
		DeviceID: "wd_gggggggggggggggg", AccountID: "11111111-1111-4111-8111-111111111111",
		OrganizationID: "22222222-2222-4222-8222-222222222222", RevocationEpoch: 8,
	}
	next := endpoint.RevocationEpoch + 1
	operationID, err := CheckpointRevocationOperationID(endpoint, next)
	if err != nil {
		t.Fatal(err)
	}
	participants := []CheckpointEndpoint{endpoint}
	issuedAt, expiresAt := int64(900), int64(1800)
	message, err := CheckpointRevocationAuthorizationMessage(CheckpointRevocationAuthorizationRequest{
		Endpoint: endpoint, NextEpoch: next, OperationID: operationID, Participants: participants,
		IssuedAtUnixMS: issuedAt, ExpiresAtUnixMS: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(revocationPrivate, message)
	proof, err := EncodeCheckpointRevocationAuthorizationProof(issuedAt, expiresAt, signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(proof)
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, participants, proof, digest); err != nil {
		t.Fatalf("valid operation-bound proof rejected: %v", err)
	}
	malformed := append([]byte(nil), proof...)
	malformed[0] ^= 0x01
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, participants, malformed, sha256.Sum256(malformed)); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("malformed proof envelope accepted: %v", err)
	}
	staleEndpoint := endpoint
	staleEndpoint.RevocationEpoch++
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, []CheckpointEndpoint{staleEndpoint}, proof, digest); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("proof for an old revocation epoch accepted: %v", err)
	}
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID+"0", participants, proof, digest); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("proof replayed against another operation: %v", err)
	}
	mutated := append([]byte(nil), proof...)
	mutated[len(mutated)-1] ^= 0x80
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, participants, mutated, sha256.Sum256(mutated)); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("forged proof accepted: %v", err)
	}
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, participants, proof, sha256.Sum256([]byte("wrong"))); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("proof digest mismatch accepted: %v", err)
	}
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, []CheckpointEndpoint{endpoint, endpoint}, proof, digest); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("mismatched participant vector accepted: %v", err)
	}
	if err := primary.verifyRevocationAuthorization(CheckpointFenceFinalize, operationID, participants, proof, digest); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("revocation proof accepted for finalize action: %v", err)
	}
	expiredMessage, err := CheckpointRevocationAuthorizationMessage(CheckpointRevocationAuthorizationRequest{
		Endpoint: endpoint, NextEpoch: next, OperationID: operationID, Participants: participants,
		IssuedAtUnixMS: 900, ExpiresAtUnixMS: 999,
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredSignature := ed25519.Sign(revocationPrivate, expiredMessage)
	expiredProof, err := EncodeCheckpointRevocationAuthorizationProof(900, 999, expiredSignature)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, participants, expiredProof, sha256.Sum256(expiredProof)); !errors.Is(err, ErrCheckpointFenceExpired) {
		t.Fatalf("expired authorization proof accepted: %v", err)
	}
	futureMessage, err := CheckpointRevocationAuthorizationMessage(CheckpointRevocationAuthorizationRequest{
		Endpoint: endpoint, NextEpoch: next, OperationID: operationID, Participants: participants,
		IssuedAtUnixMS: 40000, ExpiresAtUnixMS: 50000,
	})
	if err != nil {
		t.Fatal(err)
	}
	futureSignature := ed25519.Sign(revocationPrivate, futureMessage)
	futureProof, err := EncodeCheckpointRevocationAuthorizationProof(40000, 50000, futureSignature)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.verifyRevocationAuthorization(CheckpointFenceRevoke, operationID, participants, futureProof, sha256.Sum256(futureProof)); !errors.Is(err, ErrCheckpointFenceExpired) {
		t.Fatalf("future-dated authorization proof accepted: %v", err)
	}
}
func TestSupabaseCheckpointFencePrimaryLegacyMethodsFailClosed(t *testing.T) {
	var primary SupabaseCheckpointFencePrimary
	if _, err := primary.ReserveFence(t.Context(), CheckpointFenceRequest{}); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("non-atomic reserve unexpectedly available: %v", err)
	}
	if err := primary.CommitFence(t.Context(), CheckpointFenceToken{}, nil); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("non-atomic commit unexpectedly available: %v", err)
	}
}
