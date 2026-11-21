package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayauth"
)

const processE2ETimeout = 30 * time.Second

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type managedProcess struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	output  *lockedBuffer
	done    chan struct{}
	mu      sync.Mutex
	waitErr error
}

func startManagedProcess(name string, args []string, dir string, env []string, withStdin bool) (*managedProcess, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	output := &lockedBuffer{}
	cmd.Stdout = output
	cmd.Stderr = output

	var stdin io.WriteCloser
	var err error
	if withStdin {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
	}
	process := &managedProcess{cmd: cmd, stdin: stdin, output: output, done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		err := cmd.Wait()
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		close(process.done)
	}()
	return process, nil
}

func (p *managedProcess) wait(timeout time.Duration) (error, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.waitErr, true
	case <-timer.C:
		return nil, false
	}
}

func (p *managedProcess) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *managedProcess) stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil || p.exited() {
		return
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	if _, ok := p.wait(3 * time.Second); ok {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.wait(3 * time.Second)
}

func (p *managedProcess) waitForOutput(value string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(p.output.String(), value) {
			return nil
		}
		if p.exited() {
			p.mu.Lock()
			err := p.waitErr
			p.mu.Unlock()
			return fmt.Errorf("process exited before output %q: %v\n%s", value, err, p.output.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for output %q\n%s", value, p.output.String())
}

func (p *managedProcess) waitForOutputCount(value string, count int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Count(p.output.String(), value) >= count {
			return nil
		}
		if p.exited() {
			p.mu.Lock()
			err := p.waitErr
			p.mu.Unlock()
			return fmt.Errorf("process exited before %d occurrences of %q: %v\n%s", count, value, err, p.output.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %d occurrences of %q\n%s", count, value, p.output.String())
}

func (p *managedProcess) writeInput(value string) error {
	if p.stdin == nil {
		return errors.New("process has no stdin pipe")
	}
	_, err := io.WriteString(p.stdin, value)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Cloudflare Worker process integration:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	workerDir := filepath.Join(root, "cloudflare", "relay-worker")
	wrangler := filepath.Join(workerDir, "node_modules", ".bin", "wrangler")
	if _, err := os.Stat(wrangler); err != nil {
		return fmt.Errorf("pinned Wrangler CLI is missing; install cloudflare/relay-worker dependencies first: %w", err)
	}

	tmp, err := os.MkdirTemp("", "wedecent-worker-process-e2e-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	wd := filepath.Join(tmp, "wd")
	agentBinary := filepath.Join(tmp, "wd-agent")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if output, err := runCommand(ctx, root, nil, "go", "build", "-trimpath", "-buildvcs=false", "-o", wd, "./cmd/wd"); err != nil {
		return fmt.Errorf("build wd: %w\n%s", err, output)
	}
	if output, err := runCommand(ctx, root, nil, "go", "build", "-trimpath", "-buildvcs=false", "-o", agentBinary, "./cmd/wd-agent"); err != nil {
		return fmt.Errorf("build wd-agent: %w\n%s", err, output)
	}

	certPath, keyPath, roots, err := writeLocalTLSCertificate(tmp)
	if err != nil {
		return err
	}
	tlsClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
	}
	workerPort, err := freePort()
	if err != nil {
		return err
	}
	agentPort, err := freePort()
	if err != nil {
		return err
	}
	relayURL := fmt.Sprintf("https://127.0.0.1:%d", workerPort)
	persistDir := filepath.Join(tmp, "worker-persistence")
	if err := os.MkdirAll(persistDir, 0o700); err != nil {
		return err
	}

	grantPrivate, grantPublicSPKI, grantKID, err := newGrantSigner()
	if err != nil {
		return err
	}
	devVarsPath := filepath.Join(workerDir, ".dev.vars")
	if err := writePrivateFile(devVarsPath, "WEDECENT_CONNECTION_GRANT_PUBLIC_SPKI_B64="+grantPublicSPKI+"\n"); err != nil {
		return fmt.Errorf("write temporary Worker verifier configuration: %w", err)
	}
	defer os.Remove(devVarsPath)

	worker, err := startWorker(wrangler, workerDir, workerPort, keyPath, certPath, persistDir)
	if err != nil {
		return err
	}
	defer worker.stop()
	if err := waitWorkerReady(tlsClient, relayURL, worker, 30*time.Second); err != nil {
		return err
	}

	agentState := filepath.Join(tmp, "agent-state")
	initOutput, err := runCommand(ctx, root, nil, agentBinary, "init", "--state", agentState, "--name", "worker-process-agent")
	if err != nil {
		return fmt.Errorf("initialize agent identity: %w\n%s", err, initOutput)
	}
	agentID, err := labeledValue(initOutput, "Device ID:")
	if err != nil {
		return err
	}
	fingerprint, err := labeledValue(initOutput, "Fingerprint:")
	if err != nil {
		return err
	}
	pairSecret, err := labeledValue(initOutput, "Pair secret:")
	if err != nil {
		return err
	}
	pairSecretA := filepath.Join(tmp, "pair-secret-a")
	if err := writePrivateFile(pairSecretA, pairSecret+"\n"); err != nil {
		return err
	}

	agentEnv := []string{"SSL_CERT_FILE=" + certPath}
	agent, err := startManagedProcess(agentBinary, []string{
		"serve", "--state", agentState, "--name", "worker-process-agent",
		"--listen", net.JoinHostPort("127.0.0.1", strconv.Itoa(agentPort)),
		"--web-relay", relayURL, "--relay-slots", "2", "--shell", "/bin/sh",
	}, root, agentEnv, false)
	if err != nil {
		return fmt.Errorf("start independent Go agent process: %w", err)
	}
	defer agent.stop()
	if err := agent.waitForOutputCount("web relay slot parked", 2, 30*time.Second); err != nil {
		return fmt.Errorf("agent did not register two Worker relay slots: %w", err)
	}

	clientAState := filepath.Join(tmp, "client-a-state")
	clientBState := filepath.Join(tmp, "client-b-state")
	clientAID, err := initializeClient(wd, root, clientAState, "worker-process-client-a")
	if err != nil {
		return err
	}
	clientBID, err := initializeClient(wd, root, clientBState, "worker-process-client-b")
	if err != nil {
		return err
	}

	directEndpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(agentPort))
	if output, err := runCommand(ctx, root, nil, wd, "pair",
		"--state", clientAState, "--name", "worker-process-client-a",
		"--endpoint", directEndpoint, "--fingerprint", fingerprint,
		"--pairing-secret-file", pairSecretA,
	); err != nil {
		return fmt.Errorf("pair independent client A: %w\n%s", err, output)
	}
	secretOutput, err := runCommand(ctx, root, nil, agentBinary, "pairing-secret", "--state", agentState)
	if err != nil {
		return fmt.Errorf("rotate one-time pairing secret for client B: %w\n%s", err, secretOutput)
	}
	pairSecretB := filepath.Join(tmp, "pair-secret-b")
	if err := writePrivateFile(pairSecretB, strings.TrimSpace(secretOutput)+"\n"); err != nil {
		return err
	}
	if output, err := runCommand(ctx, root, nil, wd, "pair",
		"--state", clientBState, "--name", "worker-process-client-b",
		"--endpoint", directEndpoint, "--fingerprint", fingerprint,
		"--pairing-secret-file", pairSecretB,
	); err != nil {
		return fmt.Errorf("pair independent client B: %w\n%s", err, output)
	}

	grantA, err := issueConnectionGrant(grantPrivate, grantKID, clientAID, agentID)
	if err != nil {
		return err
	}
	grantB, err := issueConnectionGrant(grantPrivate, grantKID, clientBID, agentID)
	if err != nil {
		return err
	}
	grantAPath := filepath.Join(tmp, "grant-a.jwt")
	grantBPath := filepath.Join(tmp, "grant-b.jwt")
	if err := writePrivateFile(grantAPath, grantA.Token+"\n"); err != nil {
		return err
	}
	if err := writePrivateFile(grantBPath, grantB.Token+"\n"); err != nil {
		return err
	}

	clientA, err := startClient(wd, root, clientAState, relayURL, grantAPath, agentID, certPath)
	if err != nil {
		return fmt.Errorf("start independent Go client A: %w", err)
	}
	defer clientA.stop()
	auditPath := filepath.Join(agentState, "audit.jsonl")
	if _, err := waitForAudit(auditPath, func(events []audit.Event) bool {
		return hasEvent(events, "terminal.session_opened", clientAID, "")
	}, 20*time.Second); err != nil {
		return fmt.Errorf("client A did not establish a terminal session: %w\n%s", err, clientA.output.String())
	}
	if err := clientA.writeInput("printf 'WEDECENT_%s_READY\\n' A\n"); err != nil {
		return err
	}
	if err := clientA.waitForOutput("WEDECENT_A_READY", 15*time.Second); err != nil {
		return fmt.Errorf("client A terminal did not execute its marker: %w", err)
	}

	clientAIdentity, err := identity.Ensure(clientAState, "worker-process-client-a")
	if err != nil {
		return fmt.Errorf("load client A identity for replay proof: %w", err)
	}
	if err := assertWorkerReplayRejected(relayURL, agentID, clientAIdentity, grantA, roots); err != nil {
		return fmt.Errorf("Worker Durable Object replay rejection: %w", err)
	}

	clientB, err := startClient(wd, root, clientBState, relayURL, grantBPath, agentID, certPath)
	if err != nil {
		return fmt.Errorf("start independent Go client B: %w", err)
	}
	defer clientB.stop()
	if _, err := waitForAudit(auditPath, func(events []audit.Event) bool {
		return hasEvent(events, "terminal.session_opened", clientAID, "") &&
			hasEvent(events, "terminal.session_opened", clientBID, "")
	}, 20*time.Second); err != nil {
		return fmt.Errorf("two independent terminal sessions were not established: %w\nA=%s\nB=%s", err, clientA.output.String(), clientB.output.String())
	}
	if err := clientB.writeInput("printf 'WEDECENT_%s_READY\\n' B\n"); err != nil {
		return err
	}
	if err := clientB.waitForOutput("WEDECENT_B_READY", 15*time.Second); err != nil {
		return fmt.Errorf("client B terminal did not execute its marker: %w", err)
	}

	revokeOutput, err := runCommand(ctx, root, nil, agentBinary, "clients", "revoke", "--state", agentState, clientAID)
	if err != nil {
		return fmt.Errorf("revoke only client A: %w\n%s", err, revokeOutput)
	}
	if _, ok := clientA.wait(15 * time.Second); !ok {
		return fmt.Errorf("revoked client A process remained connected\n%s", clientA.output.String())
	}
	if clientB.exited() {
		return fmt.Errorf("independent client B exited after client A revocation: %s", clientB.output.String())
	}
	if err := clientB.writeInput("printf 'WEDECENT_%s_STILL_ACTIVE\\n' B\n"); err != nil {
		return fmt.Errorf("write to client B after client A revocation: %w", err)
	}
	if err := clientB.waitForOutput("WEDECENT_B_STILL_ACTIVE", 15*time.Second); err != nil {
		return fmt.Errorf("independent client B did not survive selective revocation: %w", err)
	}

	events, err := waitForAudit(auditPath, func(events []audit.Event) bool {
		return hasEvent(events, "trust.client_revoke", clientAID, "success") &&
			hasEvent(events, "terminal.stream_closed", clientAID, "client_revoked") &&
			hasEvent(events, "terminal.session_terminated", clientAID, "client_revoked") &&
			hasEvent(events, "terminal.session_closed", clientAID, "client_revoked")
	}, 20*time.Second)
	if err != nil {
		return fmt.Errorf("revocation audit outcomes are incomplete: %w", err)
	}
	if hasEvent(events, "terminal.session_closed", clientBID, "") {
		return errors.New("independent client B was closed during client A revocation")
	}

	agentIdentity, err := identity.Ensure(agentState, "worker-process-agent")
	if err != nil {
		return fmt.Errorf("load agent identity for grant evidence: %w", err)
	}
	if err := verifyGrantEvidence(tlsClient, relayURL, agentIdentity, agentID, clientAID, grantA); err != nil {
		return fmt.Errorf("read client A grant evidence from Worker Durable Object: %w", err)
	}
	if err := verifyGrantEvidence(tlsClient, relayURL, agentIdentity, agentID, clientBID, grantB); err != nil {
		return fmt.Errorf("read client B grant evidence from Worker Durable Object: %w", err)
	}

	if err := clientB.writeInput("exit\n"); err != nil {
		return err
	}
	if _, ok := clientB.wait(10 * time.Second); !ok {
		return fmt.Errorf("client B did not exit after its terminal shell was closed: %s", clientB.output.String())
	}
	agent.stop()
	worker.stop()

	if countFiles(persistDir) == 0 {
		return errors.New("Wrangler did not persist any local Durable Object storage files")
	}

	worker, err = startWorker(wrangler, workerDir, workerPort, keyPath, certPath, persistDir)
	if err != nil {
		return err
	}
	defer worker.stop()
	if err := waitWorkerReady(tlsClient, relayURL, worker, 30*time.Second); err != nil {
		return fmt.Errorf("restarted Worker did not become ready: %w", err)
	}
	if err := verifyGrantEvidence(tlsClient, relayURL, agentIdentity, agentID, clientAID, grantA); err != nil {
		return fmt.Errorf("client A Durable Object evidence did not survive Worker restart: %w", err)
	}
	if err := verifyGrantEvidence(tlsClient, relayURL, agentIdentity, agentID, clientBID, grantB); err != nil {
		return fmt.Errorf("client B Durable Object evidence did not survive Worker restart: %w", err)
	}

	fmt.Printf("Worker/DO process integration passed: agent=%s clients=%s,%s replay=rejected selective_revocation=verified do_storage=persistent\n", agentID, clientAID, clientBID)
	return nil
}

func startWorker(wrangler, workerDir string, port int, keyPath, certPath, persistDir string) (*managedProcess, error) {
	return startManagedProcess(wrangler, []string{
		"dev", "--local", "--local-protocol", "https", "--ip", "127.0.0.1", "--port", strconv.Itoa(port),
		"--https-key-path", keyPath, "--https-cert-path", certPath,
		"--persist-to", persistDir, "--log-level", "error",
	}, workerDir, nil, false)
}

func waitWorkerReady(client *http.Client, relayURL string, worker *managedProcess, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if worker.exited() {
			worker.mu.Lock()
			err := worker.waitErr
			worker.mu.Unlock()
			return fmt.Errorf("Wrangler exited before readiness: %v\n%s", err, worker.output.String())
		}
		request, _ := http.NewRequest(http.MethodGet, relayURL+"/healthz", nil)
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("local Worker/DO readiness timed out\n%s", worker.output.String())
}

func initializeClient(wd, root, state, name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), processE2ETimeout)
	defer cancel()
	output, err := runCommand(ctx, root, nil, wd, "identity", "--state", state, "--name", name)
	if err != nil {
		return "", fmt.Errorf("initialize %s identity: %w\n%s", name, err, output)
	}
	fields := strings.Fields(output)
	if len(fields) < 3 || !strings.HasPrefix(fields[0], "wd_") {
		return "", fmt.Errorf("unexpected %s identity output: %s", name, output)
	}
	return fields[0], nil
}

func startClient(wd, root, state, relayURL, grantPath, targetID, certPath string) (*managedProcess, error) {
	return startManagedProcess(wd, []string{
		"connect", "--state", state, "--web-relay", relayURL,
		"--connection-grant-file", grantPath, "--lan-timeout", "0", targetID,
	}, root, []string{"SSL_CERT_FILE=" + certPath}, true)
}

func runCommand(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	output := &lockedBuffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	return output.String(), err
}

func labeledValue(output, label string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, label) {
			value := strings.TrimSpace(strings.TrimPrefix(line, label))
			if value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("missing %q in command output: %s", label, output)
}

func writePrivateFile(path, value string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(file, value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func writeLocalTLSCertificate(dir string) (string, string, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "WeDecent local Worker process test"},
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return "", "", nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", nil, err
	}
	certPath := filepath.Join(dir, "worker-local.crt")
	keyPath := filepath.Join(dir, "worker-local.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		return "", "", nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		return "", "", nil, err
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return "", "", nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certPath, keyPath, roots, nil
}

func newGrantSigner() (ed25519.PrivateKey, string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", "", err
	}
	publicX := base64.RawURLEncoding.EncodeToString(publicKey)
	canonicalJWK := fmt.Sprintf("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"%s\"}", publicX)
	digest := sha256.Sum256([]byte(canonicalJWK))
	return privateKey, base64.StdEncoding.EncodeToString(spki), base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

type connectionGrantHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid"`
}

type connectionGrantClaims struct {
	GrantID        string  `json:"grant_id"`
	OrganizationID *string `json:"organization_id"`
	ClientDeviceID string  `json:"client_device_id"`
	TargetDeviceID string  `json:"target_device_id"`
	Permission     string  `json:"permission"`
	Issuer         string  `json:"iss"`
	Audience       string  `json:"aud"`
	Subject        string  `json:"sub"`
	JTI            string  `json:"jti"`
	IssuedAt       int64   `json:"iat"`
	ExpiresAt      int64   `json:"exp"`
}

type issuedGrant struct {
	Token string
	JTI   string
}

func issueConnectionGrant(privateKey ed25519.PrivateKey, kid, clientID, targetID string) (issuedGrant, error) {
	grantID, err := newUUID()
	if err != nil {
		return issuedGrant{}, err
	}
	jti, err := newUUID()
	if err != nil {
		return issuedGrant{}, err
	}
	now := time.Now().Unix()
	header, err := json.Marshal(connectionGrantHeader{Alg: "EdDSA", Typ: "JWT", KID: kid})
	if err != nil {
		return issuedGrant{}, err
	}
	claims, err := json.Marshal(connectionGrantClaims{
		GrantID: grantID, ClientDeviceID: clientID, TargetDeviceID: targetID,
		Permission: "terminal.connect", Issuer: "wedecent-control-plane",
		Audience: "wedecent-relay", Subject: "0b7729e9-95bf-4591-80f4-3f0616e57751",
		JTI: jti, IssuedAt: now, ExpiresAt: now + 90,
	})
	if err != nil {
		return issuedGrant{}, err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature := ed25519.Sign(privateKey, []byte(input))
	return issuedGrant{Token: input + "." + base64.RawURLEncoding.EncodeToString(signature), JTI: jti}, nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func readAuditEvents(path string) ([]audit.Event, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var events []audit.Event
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
			events = append(events, event)
		}
	}
	return events, scanner.Err()
}

func waitForAudit(path string, predicate func([]audit.Event) bool, timeout time.Duration) ([]audit.Event, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		events, err := readAuditEvents(path)
		if err != nil {
			return nil, err
		}
		if predicate(events) {
			return events, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	events, _ := readAuditEvents(path)
	return events, fmt.Errorf("timed out waiting for required audit outcomes; observed %d events", len(events))
}

func hasEvent(events []audit.Event, eventType, peerID, reasonOrOutcome string) bool {
	for _, event := range events {
		if event.Type != eventType || event.PeerID != peerID {
			continue
		}
		if eventType == "trust.client_revoke" {
			if event.Outcome == reasonOrOutcome {
				return true
			}
			continue
		}
		if event.Reason == reasonOrOutcome {
			return true
		}
	}
	return false
}

type grantEvidence struct {
	JTI                string `json:"jti"`
	ClientDeviceID     string `json:"client_device_id"`
	TargetDeviceID     string `json:"target_device_id"`
	Flow               string `json:"flow"`
	Permission         string `json:"permission"`
	ValidationOutcome  string `json:"validation_outcome"`
	ConsumptionOutcome string `json:"consumption_outcome"`
	ValidationEvent struct {
		Type string `json:"type"`
		Outcome string `json:"outcome"`
	} `json:"validation_event"`
	ConsumptionEvent struct {
		Type string `json:"type"`
		Outcome string `json:"outcome"`
	} `json:"consumption_event"`
}

func assertWorkerReplayRejected(relayURL, targetID string, clientIdentity *identity.Identity, grant issuedGrant, roots *x509.CertPool) error {
	ticket, err := relayauth.Issue(clientIdentity, targetID, "client", 0, time.Now())
	if err != nil {
		return err
	}
	u, err := url.Parse(relayURL)
	if err != nil || u.Host == "" {
		return errors.New("invalid local Worker URL")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", u.Host, &tls.Config{
		RootCAs: roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	request := fmt.Sprintf(
		"GET /v1/stream/%s?role=client HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer %s\r\nX-WeDecent-Connection-Grant: %s\r\n\r\n",
		targetID, u.Host, key, ticket, grant.Token,
	)
	if _, err := io.WriteString(conn, request); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2048))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusConflict || !strings.Contains(string(body), "Connection grant already used") {
		return fmt.Errorf("replayed grant returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func verifyGrantEvidence(client *http.Client, relayURL string, agentIdentity *identity.Identity, targetID, expectedClientID string, grant issuedGrant) error {
	ticket, err := relayauth.Issue(agentIdentity, targetID, "authorize", 0, time.Now())
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, relayURL+"/v1/grant-evidence/"+targetID+"/"+grant.JTI, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+ticket)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("evidence endpoint returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var evidence grantEvidence
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&evidence); err != nil {
		return err
	}
	if evidence.JTI != grant.JTI ||
		evidence.ClientDeviceID != expectedClientID ||
		evidence.TargetDeviceID != targetID ||
		evidence.Flow != "relay" ||
		evidence.Permission != "terminal.connect" ||
		evidence.ValidationOutcome != "accepted" ||
		evidence.ConsumptionOutcome != "consumed" ||
		evidence.ValidationEvent.Type != "authorization.validation" ||
		evidence.ValidationEvent.Outcome != "accepted" ||
		evidence.ConsumptionEvent.Type != "authorization.consumption" ||
		evidence.ConsumptionEvent.Outcome != "consumed" {
		return fmt.Errorf("invalid durable grant evidence: %#v", evidence)
	}
	return nil
}

func countFiles(dir string) int {
	count := 0
	_ = filepath.WalkDir(dir, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			count++
		}
		return nil
	})
	return count
}
