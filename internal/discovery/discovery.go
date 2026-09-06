package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

const multicastAddr = "239.255.77.68:37768"

type signedAnnouncement struct {
	Version   int    `json:"version"`
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	Port      int    `json:"port"`
	PublicKey string `json:"public_key"`
	UnixTime  int64  `json:"unix_time"`
	Signature string `json:"signature"`
}

type Result struct {
	DeviceID    string
	Name        string
	Endpoint    string
	Fingerprint string
}

var ErrTrustedIdentityMismatch = errors.New("discovery: trusted device identity mismatch")

// FindTrusted waits for a signed LAN advertisement for deviceID whose full
// public-key fingerprint matches the already-trusted fingerprint. Other
// devices are ignored. A matching device ID with a different fingerprint is
// treated as a hard identity error rather than a routing hint.
func FindTrusted(ctx context.Context, deviceID, expectedFingerprint string) (Result, bool, error) {
	expectedFingerprint, err := identity.ParseFingerprint(expectedFingerprint)
	if err != nil {
		return Result{}, false, fmt.Errorf("%w: trusted fingerprint is invalid", ErrTrustedIdentityMismatch)
	}
	if strings.TrimSpace(deviceID) == "" {
		return Result{}, false, errors.New("discovery: trusted device ID is required")
	}

	results, errs := Discover(ctx)
	for results != nil || errs != nil {
		select {
		case <-ctx.Done():
			return Result{}, false, nil
		case result, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			match, err := matchTrustedResult(result, deviceID, expectedFingerprint)
			if err != nil {
				return Result{}, false, err
			}
			if match {
				return result, true, nil
			}
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				return Result{}, false, err
			}
		}
	}
	return Result{}, false, nil
}

func matchTrustedResult(result Result, deviceID, expectedFingerprint string) (bool, error) {
	if result.DeviceID != deviceID {
		return false, nil
	}
	got, err := identity.ParseFingerprint(result.Fingerprint)
	if err != nil {
		return false, fmt.Errorf("%w: discovered fingerprint is invalid", ErrTrustedIdentityMismatch)
	}
	if got != expectedFingerprint {
		return false, fmt.Errorf("%w for %s", ErrTrustedIdentityMismatch, deviceID)
	}
	return true, nil
}

func Advertise(ctx context.Context, id *identity.Identity, port int) error {
	addr, err := net.ResolveUDPAddr("udp4", multicastAddr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		if err := sendAnnouncement(conn, id, port); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func Discover(ctx context.Context) (<-chan Result, <-chan error) {
	out := make(chan Result)
	errCh := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errCh)
		addr, err := net.ResolveUDPAddr("udp4", multicastAddr)
		if err != nil {
			errCh <- err
			return
		}
		conn, err := net.ListenMulticastUDP("udp4", nil, addr)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadBuffer(64 << 10)
		seen := map[string]bool{}
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, src, err := conn.ReadFromUDP(buf)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			if err != nil {
				errCh <- err
				return
			}
			res, err := verifyAnnouncement(buf[:n], src.IP)
			if err != nil || seen[res.DeviceID] {
				continue
			}
			seen[res.DeviceID] = true
			select {
			case out <- res:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errCh
}

func sendAnnouncement(conn *net.UDPConn, id *identity.Identity, port int) error {
	a := signedAnnouncement{
		Version: 1, DeviceID: id.ID, Name: id.Name, Port: port,
		PublicKey: base64.RawStdEncoding.EncodeToString(id.PublicKey), UnixTime: time.Now().Unix(),
	}
	msg := signingBytes(a)
	a.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(id.PrivateKey, msg))
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

func verifyAnnouncement(data []byte, ip net.IP) (Result, error) {
	var a signedAnnouncement
	if err := json.Unmarshal(data, &a); err != nil {
		return Result{}, err
	}
	if a.Version != 1 || a.Port < 1 || a.Port > 65535 || time.Since(time.Unix(a.UnixTime, 0)) > 30*time.Second || time.Until(time.Unix(a.UnixTime, 0)) > 30*time.Second {
		return Result{}, fmt.Errorf("invalid or stale announcement")
	}
	pub, err := base64.RawStdEncoding.DecodeString(a.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return Result{}, fmt.Errorf("invalid public key")
	}
	sig, err := base64.RawStdEncoding.DecodeString(a.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), signingBytes(a), sig) {
		return Result{}, fmt.Errorf("invalid signature")
	}
	if identity.DeviceID(ed25519.PublicKey(pub)) != a.DeviceID {
		return Result{}, fmt.Errorf("device ID mismatch")
	}
	fp, err := identity.FingerprintPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return Result{}, err
	}
	return Result{DeviceID: a.DeviceID, Name: a.Name, Endpoint: net.JoinHostPort(ip.String(), strconv.Itoa(a.Port)), Fingerprint: fp}, nil
}

func signingBytes(a signedAnnouncement) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%d\x00%s\x00%d", a.Version, a.DeviceID, a.Name, a.Port, a.PublicKey, a.UnixTime)
	return h.Sum(nil)
}
