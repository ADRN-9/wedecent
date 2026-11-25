package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
)

type recoveryAuthority struct {
	mu             sync.Mutex
	token          string
	primaryPublic  ed25519.PublicKey
	primaryPrivate ed25519.PrivateKey
	witnesses      map[string]ed25519.PrivateKey
	heads          map[string]audit.RecoveryCheckpoint
}

func main() {
	listen := flag.String("listen", "127.0.0.1:17445", "loopback HTTPS listen address")
	trustFile := flag.String("trust-file", "", "write public recovery trust anchors")
	caFile := flag.String("ca-file", "", "write local test CA certificate")
	pinFile := flag.String("pin-file", "", "write leaf SPKI SHA-256 pin")
	token := flag.String("token", "smoke-token", "test-only bearer token")
	flag.Parse()
	if *trustFile == "" || *caFile == "" || *pinFile == "" || *token == "" {
		log.Fatal("trust-file, ca-file, pin-file and token are required")
	}

	authority, trustJSON, err := newRecoveryAuthority(*token)
	if err != nil {
		log.Fatal(err)
	}
	certificate, caPEM, pin, err := newServerCertificate()
	if err != nil {
		log.Fatal(err)
	}
	if err := writePrivateFile(*trustFile, trustJSON); err != nil {
		log.Fatal(err)
	}
	if err := writePrivateFile(*caFile, caPEM); err != nil {
		log.Fatal(err)
	}
	if err := writePrivateFile(*pinFile, []byte(pin)); err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:    *listen,
		Handler: authority.handler(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAnyClientCert,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("test recovery authority listening on %s", *listen)
	if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func newRecoveryAuthority(token string) (*recoveryAuthority, []byte, error) {
	primaryPublic, primaryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	witnesses := make(map[string]ed25519.PrivateKey, 3)
	witnessPublic := make(map[string]string, 3)
	for _, id := range []string{"smoke-a", "smoke-b", "smoke-c"} {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			return nil, nil, keyErr
		}
		witnesses[id] = privateKey
		witnessPublic[id] = base64.StdEncoding.EncodeToString(publicKey)
	}
	trustJSON, err := json.Marshal(struct {
		PrimaryKey string            `json:"primary_key"`
		Witnesses  map[string]string `json:"witnesses"`
		Quorum     int               `json:"quorum"`
	}{
		PrimaryKey: base64.StdEncoding.EncodeToString(primaryPublic),
		Witnesses:  witnessPublic,
		Quorum:     2,
	})
	if err != nil {
		return nil, nil, err
	}
	return &recoveryAuthority{
		token: token, primaryPublic: primaryPublic, primaryPrivate: primaryPrivate,
		witnesses: witnesses, heads: make(map[string]audit.RecoveryCheckpoint),
	}, trustJSON, nil
}

func newServerCertificate() (tls.Certificate, []byte, string, error) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "WeDecent smoke test CA"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, serverPublic, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	serverCert, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	pin := sha256.Sum256(serverCert.RawSubjectPublicKeyInfo)
	pair := tls.Certificate{
		Certificate: [][]byte{serverDER, caDER},
		PrivateKey:  serverPrivate,
		Leaf:        serverCert,
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return pair, caPEM, hex.EncodeToString(pin[:]), nil
}

func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (a *recoveryAuthority) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pairing-recovery/checkpoints", a.checkpoint)
	mux.HandleFunc("/v1/pairing-recovery/archives/sign", a.signArchive)
	mux.HandleFunc("/v1/pairing-recovery/checkpoints/commit", a.commit)
	mux.HandleFunc("/v1/pairing-recovery/migrations", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "legacy migration is intentionally unsupported by the smoke authority", http.StatusForbidden)
	})
	return mux
}

func (a *recoveryAuthority) authorize(w http.ResponseWriter, r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "device client certificate required", http.StatusUnauthorized)
		return false
	}
	cert := r.TLS.PeerCertificates[0]
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) ||
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
		http.Error(w, "invalid device certificate", http.StatusUnauthorized)
		return false
	}
	_ = publicKey
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		http.Error(w, "invalid bearer token", http.StatusUnauthorized)
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return true
}

func (a *recoveryAuthority) checkpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorize(w, r) {
		return
	}
	scope := r.URL.Query().Get("scope")
	if scope == "" || len(scope) > 256 {
		http.Error(w, "invalid scope", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	head, ok := a.heads[scope]
	a.mu.Unlock()
	if !ok {
		head = audit.RecoveryCheckpoint{Scope: scope}
	}
	_ = json.NewEncoder(w).Encode(head)
}

func (a *recoveryAuthority) signArchive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorize(w, r) {
		return
	}
	var request struct {
		Payload []byte `json:"payload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		http.Error(w, "invalid signing request", http.StatusBadRequest)
		return
	}
	digest := sha256.Sum256(a.primaryPublic)
	keyID := "ed25519:" + hex.EncodeToString(digest[:])
	_ = json.NewEncoder(w).Encode(struct {
		KeyID     string `json:"key_id"`
		Signature []byte `json:"signature"`
	}{KeyID: keyID, Signature: ed25519.Sign(a.primaryPrivate, request.Payload)})
}

func (a *recoveryAuthority) commit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorize(w, r) {
		return
	}
	var request audit.RecoveryCheckpointRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		http.Error(w, "invalid checkpoint request", http.StatusBadRequest)
		return
	}
	expected, err := audit.NewRecoveryCheckpointRequest(request.Scope, request.ExpectedGeneration,
		request.PreviousDigest, request.StateDigest)
	if err != nil || expected != request {
		http.Error(w, "invalid checkpoint commitment", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	head, ok := a.heads[request.Scope]
	if !ok {
		head = audit.RecoveryCheckpoint{Scope: request.Scope}
	}
	if head.OperationID == request.OperationID && head.StateDigest == request.StateDigest {
		_ = json.NewEncoder(w).Encode(head)
		return
	}
	if head.Generation != request.ExpectedGeneration || head.StateDigest != request.PreviousDigest {
		http.Error(w, "stale checkpoint", http.StatusConflict)
		return
	}

	digest := sha256.Sum256(a.primaryPublic)
	checkpoint := audit.RecoveryCheckpoint{
		Scope: request.Scope, Generation: request.Generation,
		StateDigest: request.StateDigest, PreviousDigest: request.PreviousDigest,
		OperationID: request.OperationID, SignerKeyID: "ed25519:" + hex.EncodeToString(digest[:]),
	}
	message, err := audit.RecoveryCheckpointSigningBytes(checkpoint)
	if err != nil {
		http.Error(w, "invalid checkpoint", http.StatusBadRequest)
		return
	}
	checkpoint.Signature = ed25519.Sign(a.primaryPrivate, message)
	ids := make([]string, 0, len(a.witnesses))
	for id := range a.witnesses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		checkpoint.Witnesses = append(checkpoint.Witnesses, audit.RecoveryCheckpointWitness{
			ID: id, Signature: ed25519.Sign(a.witnesses[id], message),
		})
	}
	a.heads[request.Scope] = checkpoint
	_ = json.NewEncoder(w).Encode(checkpoint)
}
