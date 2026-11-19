package identity

import (
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"strings"
	"testing"
)

func TestClientTLSReportsPreciseFingerprintMismatch(t *testing.T) {
	id, err := Ensure(t.TempDir(), "fingerprint-mismatch")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrong := []byte(fingerprint)
	if wrong[len("SHA256:")] == '0' {
		wrong[len("SHA256:")] = '1'
	} else {
		wrong[len("SHA256:")] = '0'
	}
	state := tls.ConnectionState{
		NegotiatedProtocol: "wedecent/1",
		PeerCertificates:   []*x509.Certificate{id.Leaf},
	}
	err = ClientTLS(id, string(wrong)).VerifyConnection(state)
	if err == nil || !strings.Contains(err.Error(), "device fingerprint mismatch") {
		t.Fatalf("wrong fingerprint error = %v", err)
	}
}

func TestProtocolVersionCompatibilityTerminalTLS(t *testing.T) {
	id, err := Ensure(t.TempDir(), "compat-device")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	server := ServerTLS(id)
	if server.MinVersion != tls.VersionTLS13 {
		t.Fatalf("ServerTLS().MinVersion = %d, want TLS 1.3", server.MinVersion)
	}
	if !reflect.DeepEqual(server.NextProtos, []string{"wedecent/1"}) {
		t.Fatalf("ServerTLS().NextProtos = %q, want [wedecent/1]", server.NextProtos)
	}

	client := ClientTLS(id, fingerprint)
	if client.MinVersion != tls.VersionTLS13 {
		t.Fatalf("ClientTLS().MinVersion = %d, want TLS 1.3", client.MinVersion)
	}
	if !reflect.DeepEqual(client.NextProtos, []string{"wedecent/1"}) {
		t.Fatalf("ClientTLS().NextProtos = %q, want [wedecent/1]", client.NextProtos)
	}

	valid := tls.ConnectionState{
		NegotiatedProtocol: "wedecent/1",
		PeerCertificates:   []*x509.Certificate{id.Leaf},
	}
	if err := client.VerifyConnection(valid); err != nil {
		t.Fatalf("VerifyConnection(v1) error: %v", err)
	}
	if _, err := PeerCertificate(valid); err != nil {
		t.Fatalf("PeerCertificate(v1) error: %v", err)
	}

	for _, negotiated := range []string{"", "wedecent/0", "wedecent/2"} {
		state := valid
		state.NegotiatedProtocol = negotiated
		if err := client.VerifyConnection(state); err == nil {
			t.Fatalf("VerifyConnection(%q) unexpectedly succeeded", negotiated)
		}
		if _, err := PeerCertificate(state); err == nil {
			t.Fatalf("PeerCertificate(%q) unexpectedly succeeded", negotiated)
		}
	}
}
