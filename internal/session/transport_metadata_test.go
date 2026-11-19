package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

func TestTransportMetadataAuditLabel(t *testing.T) {
	tests := []struct {
		name           string
		in             TransportMetadata
		want           string
		wantProvenance string
		ok             bool
	}{
		{"direct TCP", TransportMetadata{Kind: TransportDirectTCP}, "direct_tcp", "listener_adapter", true},
		{"Bluetooth RFCOMM", TransportMetadata{Kind: TransportBluetoothRFCOMM}, "bluetooth_rfcomm", "listener_adapter", true},
		{"USB CDC-ACM", TransportMetadata{Kind: TransportUSBCDCACM}, "usb_cdc_acm", "listener_adapter", true},
		{"relay", TransportMetadata{Kind: TransportRelay}, "relay", "listener_adapter", true},
		{"USB NCM underlying direct TCP", TransportMetadata{Kind: TransportDirectTCP, Underlying: UnderlyingUSBNCM}, "direct_tcp+usb_ncm", "operator_config_assertion", true},
		{"missing kind", TransportMetadata{}, "", "", false},
		{"unknown kind", TransportMetadata{Kind: "lan"}, "", "", false},
		{"NCM cannot underlay RFCOMM", TransportMetadata{Kind: TransportBluetoothRFCOMM, Underlying: UnderlyingUSBNCM}, "", "", false},
		{"NCM cannot underlay relay", TransportMetadata{Kind: TransportRelay, Underlying: UnderlyingUSBNCM}, "", "", false},
		{"unknown underlying", TransportMetadata{Kind: TransportDirectTCP, Underlying: "ethernet"}, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.auditLabel()
			if tt.ok {
				if err != nil || got != tt.want {
					t.Fatalf("auditLabel() = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("auditLabel() = %q, want validation error", got)
			}
		})
	}
}

func TestServeConnWithTransportRejectsInvalidMetadata(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&Server{}).ServeConnWithTransport(serverSide, TransportMetadata{Kind: "spoofed"})
	}()

	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := clientSide.Read(one[:]); err == nil {
		t.Fatal("invalid transport metadata allowed a session to proceed")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not close invalid transport connection")
	}
}

func pairingWireRequestWithTransport(
	t *testing.T,
	server *Server,
	client *identity.Identity,
	serverFingerprint string,
	secret string,
	metadata TransportMetadata,
) (protocol.Frame, error) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.ServeConnWithTransport(serverSide, metadata)
	}()

	conn := tls.Client(clientSide, identity.ClientTLS(client, serverFingerprint))
	defer func() {
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("pairing server failed to exit")
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.HandshakeContext(context.Background()); err != nil {
		return protocol.Frame{}, err
	}
	payload, err := protocol.JSON(protocol.PairRequest{
		PairingSecret: secret, ClientID: client.ID, ClientName: "transport-audit-test",
	})
	if err != nil {
		return protocol.Frame{}, err
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairRequest, Payload: payload}); err != nil {
		return protocol.Frame{}, err
	}
	return protocol.ReadFrame(conn)
}

func TestServerPairingAuditUsesExplicitTransportMetadata(t *testing.T) {
	tests := []struct {
		name           string
		metadata       TransportMetadata
		want           string
		wantProvenance string
	}{
		{"direct TCP", TransportMetadata{Kind: TransportDirectTCP}, "direct_tcp", "listener_adapter"},
		{"Bluetooth RFCOMM", TransportMetadata{Kind: TransportBluetoothRFCOMM}, "bluetooth_rfcomm", "listener_adapter"},
		{"USB CDC-ACM", TransportMetadata{Kind: TransportUSBCDCACM}, "usb_cdc_acm", "listener_adapter"},
		{"USB NCM over direct TCP", TransportMetadata{Kind: TransportDirectTCP, Underlying: UnderlyingUSBNCM}, "direct_tcp+usb_ncm", "operator_config_assertion"},
		{"relay", TransportMetadata{Kind: TransportRelay}, "relay", "listener_adapter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverIdentity, err := identity.Ensure(t.TempDir(), "server")
			if err != nil {
				t.Fatal(err)
			}
			clientIdentity, err := identity.Ensure(t.TempDir(), "client")
			if err != nil {
				t.Fatal(err)
			}
			serverFingerprint, err := identity.FingerprintPublicKey(serverIdentity.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			stateDir := t.TempDir()
			preparePairingSessionTestDir(t, stateDir)
			store, err := trust.Open(filepath.Join(stateDir, "trusted-clients.json"))
			if err != nil {
				t.Fatal(err)
			}
			secret, err := trust.RotatePairingSecret(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			server := &Server{Identity: serverIdentity, Trust: store, StateDir: stateDir}
			frame, err := pairingWireRequestWithTransport(t, server, clientIdentity, serverFingerprint, secret, tt.metadata)
			if err != nil || frame.Type != protocol.TypePairResponse {
				t.Fatalf("pairing over explicit transport: frame=%d err=%v", frame.Type, err)
			}

			file, err := os.Open(filepath.Join(stateDir, audit.FileName))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var pending, success bool
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				var event audit.Event
				if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
					t.Fatal(err)
				}
				if event.PeerID != clientIdentity.ID {
					continue
				}
				if event.Type == "pairing.request" && event.Outcome == "pending" {
					pending = true
					if event.Transport != tt.want || event.TransportProvenance != tt.wantProvenance {
						t.Fatalf("pending attribution = %q/%q, want %q/%q", event.Transport, event.TransportProvenance, tt.want, tt.wantProvenance)
					}
				}
				if event.Type == "pairing.trust_added" && event.Outcome == "success" {
					success = true
					if event.Transport != tt.want || event.TransportProvenance != tt.wantProvenance {
						t.Fatalf("success attribution = %q/%q, want %q/%q", event.Transport, event.TransportProvenance, tt.want, tt.wantProvenance)
					}
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if !pending || !success {
				t.Fatalf("missing pairing audit outcomes: pending=%v success=%v", pending, success)
			}
		})
	}
}
