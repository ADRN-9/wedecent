package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto"
	"crypto/x509"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"mime"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

const (
	recoveryAuthorityAPIPrefix = "/v1/pairing-recovery"
	maxRecoveryAuthorityBody   = 1 << 20
)

// HTTPRecoveryAuthority is a client for an independently administered
// recovery-authority service. Signing and checkpoint commits remain remote;
// this client never loads or exports private signing keys.
type HTTPRecoveryAuthority struct {
	baseURL string
	token   string
	trust   RecoveryAuthorityTrust
	client  *http.Client
}

// NewHTTPRecoveryAuthority requires a public HTTPS endpoint, a SHA-256 pin of
// the leaf certificate SPKI, an authentication token, and independently
// provisioned public trust anchors. Normal WebPKI validation remains enabled.
func NewHTTPRecoveryAuthority(endpoint, spkiSHA256, token string, trust RecoveryAuthorityTrust) (*HTTPRecoveryAuthority, error) {
	return newHTTPRecoveryAuthority(endpoint, spkiSHA256, token, nil, trust)
}

// NewHTTPRecoveryAuthorityForDevice authenticates the agent with its existing
// Ed25519 device certificate in addition to the short-lived service token.
func NewHTTPRecoveryAuthorityForDevice(endpoint, spkiSHA256, token string, deviceCertificate tls.Certificate, trust RecoveryAuthorityTrust) (*HTTPRecoveryAuthority, error) {
	if len(deviceCertificate.Certificate) == 0 || deviceCertificate.PrivateKey == nil {
		return nil, errors.New("recovery authority requires a device client certificate and private key")
	}
	leaf := deviceCertificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(deviceCertificate.Certificate[0])
		if err != nil {
			return nil, errors.New("recovery authority device certificate is invalid")
		}
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		return nil, errors.New("recovery authority client certificate must be a currently valid Ed25519 certificate")
	}
	signer, ok := deviceCertificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("recovery authority client identity is not a crypto.Signer")
	}
	signerPublic, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(signerPublic, publicKey) {
		return nil, errors.New("recovery authority client certificate and private key do not match")
	}
	return newHTTPRecoveryAuthority(endpoint, spkiSHA256, token, &deviceCertificate, trust)
}

func newHTTPRecoveryAuthority(endpoint, spkiSHA256, token string, deviceCertificate *tls.Certificate, trust RecoveryAuthorityTrust) (*HTTPRecoveryAuthority, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("recovery authority endpoint must be an origin-only HTTPS URL")
	}
	pin, err := hex.DecodeString(strings.TrimSpace(spkiSHA256))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("recovery authority SPKI pin must be 64 hexadecimal characters")
	}
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("recovery authority bearer token is required")
	}
	if err := trust.Validate(); err != nil {
		return nil, fmt.Errorf("recovery authority trust: %w", err)
	}
	var expectedPin [sha256.Size]byte
	copy(expectedPin[:], pin)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrRecoveryAuthorityUnavailable
			}
			actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(actual[:], expectedPin[:]) != 1 {
				return errors.New("recovery authority SPKI pin mismatch")
			}
			return nil
		},
	}
	if deviceCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*deviceCertificate}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HTTPRecoveryAuthority{baseURL: strings.TrimSuffix(parsed.String(), "/"), token: token,
		trust: trust, client: client}, nil
}

func (a *HTTPRecoveryAuthority) SignArchive(ctx context.Context, payload []byte) (string, []byte, error) {
	var response struct {
		KeyID     string `json:"key_id"`
		Signature []byte `json:"signature"`
	}
	request := struct {
		Payload []byte `json:"payload"`
	}{Payload: payload}
	if err := a.post(ctx, recoveryAuthorityAPIPrefix+"/archives/sign", request, &response); err != nil {
		return "", nil, err
	}
	if response.KeyID != recoveryPrimaryKeyID(a.trust.PrimaryKey) || len(response.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(a.trust.PrimaryKey, payload, response.Signature) {
		return "", nil, ErrRecoveryCheckpointConflict
	}
	return response.KeyID, response.Signature, nil
}

func (a *HTTPRecoveryAuthority) VerifyArchive(_ context.Context, keyID string, payload, signature []byte) error {
	if a == nil || keyID != recoveryPrimaryKeyID(a.trust.PrimaryKey) ||
		len(signature) != ed25519.SignatureSize || !ed25519.Verify(a.trust.PrimaryKey, payload, signature) {
		return ErrRecoveryCheckpointConflict
	}
	return nil
}

func (a *HTTPRecoveryAuthority) LoadCheckpoint(ctx context.Context, scope string) (RecoveryCheckpoint, error) {
	if scope == "" || len(scope) > 256 {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointConflict
	}
	var checkpoint RecoveryCheckpoint
	endpoint := recoveryAuthorityAPIPrefix + "/checkpoints?scope=" + url.QueryEscape(scope)
	if err := a.get(ctx, endpoint, &checkpoint); err != nil {
		return RecoveryCheckpoint{}, err
	}
	if checkpoint.Scope != scope {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointConflict
	}
	if checkpoint.Generation > 0 {
		if err := a.VerifyCheckpoint(ctx, checkpoint); err != nil {
			return RecoveryCheckpoint{}, err
		}
	} else if !emptyRecoveryCheckpoint(checkpoint) {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointConflict
	}
	return checkpoint, nil
}

func (a *HTTPRecoveryAuthority) CommitCheckpoint(ctx context.Context, request RecoveryCheckpointRequest) (RecoveryCheckpoint, error) {
	var checkpoint RecoveryCheckpoint
	if err := a.post(ctx, recoveryAuthorityAPIPrefix+"/checkpoints/commit", request, &checkpoint); err != nil {
		return RecoveryCheckpoint{}, err
	}
	if err := validateRecoveryAuthorityReceipt(request, checkpoint, a.trust); err != nil {
		return RecoveryCheckpoint{}, err
	}
	return checkpoint, nil
}

func (a *HTTPRecoveryAuthority) VerifyCheckpoint(_ context.Context, checkpoint RecoveryCheckpoint) error {
	if a == nil || checkpoint.Generation == 0 {
		return ErrRecoveryCheckpointConflict
	}
	request, err := NewRecoveryCheckpointRequest(checkpoint.Scope, checkpoint.Generation-1,
		checkpoint.PreviousDigest, checkpoint.StateDigest)
	if err != nil || request.OperationID != checkpoint.OperationID {
		return ErrRecoveryCheckpointConflict
	}
	return ValidateRecoveryCheckpointWithTrust(request, checkpoint, a.trust)
}

func (a *HTTPRecoveryAuthority) MigrateLegacyArchive(ctx context.Context, migration LegacyRecoveryMigrationRequest) (RecoveryCheckpoint, error) {
	var checkpoint RecoveryCheckpoint
	if err := a.post(ctx, recoveryAuthorityAPIPrefix+"/migrations", migration, &checkpoint); err != nil {
		return RecoveryCheckpoint{}, err
	}
	request, err := NewRecoveryCheckpointRequest(migration.Scope, migration.ExpectedGeneration,
		checkpoint.PreviousDigest, checkpoint.StateDigest)
	if err != nil || checkpoint.OperationID != request.OperationID {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointConflict
	}
	if err := ValidateRecoveryCheckpointWithTrust(request, checkpoint, a.trust); err != nil {
		return RecoveryCheckpoint{}, err
	}
	return checkpoint, nil
}

func validateRecoveryAuthorityReceipt(request RecoveryCheckpointRequest, checkpoint RecoveryCheckpoint, trust RecoveryAuthorityTrust) error {
	if checkpoint.Scope != request.Scope || checkpoint.Generation != request.Generation ||
		checkpoint.PreviousDigest != request.PreviousDigest || checkpoint.StateDigest != request.StateDigest ||
		checkpoint.OperationID != request.OperationID {
		return ErrRecoveryCheckpointConflict
	}
	return ValidateRecoveryCheckpointWithTrust(request, checkpoint, trust)
}

func (a *HTTPRecoveryAuthority) get(ctx context.Context, endpoint string, output any) error {
	return a.do(ctx, http.MethodGet, endpoint, nil, output)
}

func (a *HTTPRecoveryAuthority) post(ctx context.Context, endpoint string, input, output any) error {
	return a.do(ctx, http.MethodPost, endpoint, input, output)
}

func (a *HTTPRecoveryAuthority) do(ctx context.Context, method, endpoint string, input, output any) error {
	if a == nil || a.client == nil || ctx == nil {
		return ErrRecoveryAuthorityUnavailable
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return ErrRecoveryCheckpointConflict
		}
		body = bytes.NewReader(encoded)
	}
	u, err := url.Parse(a.baseURL)
	if err != nil {
		return ErrRecoveryAuthorityUnavailable
	}
	relative, err := url.Parse(endpoint)
	if err != nil || relative.IsAbs() || relative.Host != "" || !strings.HasPrefix(relative.Path, "/") {
		return ErrRecoveryAuthorityUnavailable
	}
	u.Path = path.Join(u.Path, relative.Path)
	u.RawQuery = relative.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return ErrRecoveryAuthorityUnavailable
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: authenticated TLS request failed: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		return ErrRecoveryCheckpointStale
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%w: authority service returned HTTP %d", ErrRecoveryAuthorityUnavailable, response.StatusCode)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return ErrRecoveryAuthorityUnavailable
	}
	limited := io.LimitReader(response.Body, maxRecoveryAuthorityBody+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) == 0 || len(data) > maxRecoveryAuthorityBody {
		return ErrRecoveryAuthorityUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrRecoveryAuthorityUnavailable
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrRecoveryAuthorityUnavailable
	}
	return nil
}

type recoveryAuthorityTrustFile struct {
	PrimaryKey string            `json:"primary_key"`
	Witnesses  map[string]string `json:"witnesses"`
	Quorum     int               `json:"quorum"`
}

// LoadRecoveryAuthorityTrust reads only a regular, non-symlink trust file that
// is not writable by group or other users.
func LoadRecoveryAuthorityTrust(file string) (RecoveryAuthorityTrust, error) {
	var empty RecoveryAuthorityTrust
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return empty, errors.New("recovery authority trust file is missing, unsafe, or group/world writable")
	}
	opened, err := os.Open(file)
	if err != nil {
		return empty, err
	}
	defer opened.Close()
	current, err := opened.Stat()
	if err != nil || !os.SameFile(info, current) {
		return empty, errors.New("recovery authority trust file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(opened, 64<<10+1))
	if err != nil || len(data) == 0 || len(data) > 64<<10 {
		return empty, errors.New("recovery authority trust file size invalid")
	}
	var fileData recoveryAuthorityTrustFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fileData); err != nil {
		return empty, errors.New("recovery authority trust file invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return empty, errors.New("recovery authority trust file has trailing data")
	}
	primary, err := base64.StdEncoding.DecodeString(fileData.PrimaryKey)
	if err != nil || len(primary) != ed25519.PublicKeySize {
		return empty, errors.New("recovery authority primary key must be base64 Ed25519 public key")
	}
	trust := RecoveryAuthorityTrust{PrimaryKey: ed25519.PublicKey(primary), WitnessKeys: make(map[string]ed25519.PublicKey),
		Quorum: fileData.Quorum}
	for id, encoded := range fileData.Witnesses {
		key, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil || len(key) != ed25519.PublicKeySize {
			return empty, fmt.Errorf("recovery authority witness %q has invalid public key", id)
		}
		trust.WitnessKeys[id] = ed25519.PublicKey(key)
	}
	if err := trust.Validate(); err != nil {
		return empty, err
	}
	return trust, nil
}
