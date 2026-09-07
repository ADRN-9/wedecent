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

	writers, err := openMulticastWriters(addr)
	if err != nil {
		return err
	}
	defer func() { closeUDPConns(writers) }()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	refresh := time.NewTicker(15 * time.Second)
	defer refresh.Stop()

	for {
		if err := sendAnnouncement(writers, id, port); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-refresh.C:
			updated, err := openMulticastWriters(addr)
			if err != nil {
				continue
			}
			closeUDPConns(writers)
			writers = updated
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
		listeners, err := openMulticastListeners(addr)
		if err != nil {
			errCh <- err
			return
		}
		defer closeUDPConns(listeners)

		type packet struct {
			data []byte
			ip   net.IP
		}
		packets := make(chan packet, len(listeners)*2)
		failures := make(chan error, len(listeners))
		for _, conn := range listeners {
			conn := conn
			_ = conn.SetReadBuffer(64 << 10)
			go func() {
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
						select {
						case failures <- err:
						case <-ctx.Done():
						}
						return
					}
					data := append([]byte(nil), buf[:n]...)
					select {
					case packets <- packet{data: data, ip: append(net.IP(nil), src.IP...)}:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		seen := map[string]bool{}
		active := len(listeners)
		var lastErr error
		for active > 0 {
			select {
			case <-ctx.Done():
				return
			case p := <-packets:
				res, err := verifyAnnouncement(p.data, p.ip)
				if err != nil || seen[res.DeviceID] {
					continue
				}
				seen[res.DeviceID] = true
				select {
				case out <- res:
				case <-ctx.Done():
					return
				}
			case err := <-failures:
				active--
				lastErr = err
			}
		}
		if lastErr != nil {
			errCh <- lastErr
		}
	}()
	return out, errCh
}

func openMulticastWriters(addr *net.UDPAddr) ([]*net.UDPConn, error) {
	ifaces, err := multicastIPv4Interfaces()
	if err != nil {
		return nil, err
	}

	var conns []*net.UDPConn
	var openErrs []error
	for i := range ifaces {
		ips, err := interfaceIPv4Addrs(&ifaces[i])
		if err != nil {
			openErrs = append(openErrs, fmt.Errorf("%s: %w", ifaces[i].Name, err))
			continue
		}
		for _, ip := range ips {
			conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: ip}, addr)
			if err != nil {
				openErrs = append(openErrs, fmt.Errorf("%s/%s: %w", ifaces[i].Name, ip, err))
				continue
			}
			if err := setIPv4MulticastInterface(conn, ip); err != nil {
				_ = conn.Close()
				openErrs = append(openErrs, fmt.Errorf("%s/%s: set multicast interface: %w", ifaces[i].Name, ip, err))
				continue
			}
			conns = append(conns, conn)
		}
	}
	if len(conns) > 0 {
		return conns, nil
	}

	if len(openErrs) == 0 {
		return nil, errors.New("discovery: no usable IPv4 multicast writers")
	}
	return nil, errors.Join(openErrs...)
}

func openMulticastListeners(addr *net.UDPAddr) ([]*net.UDPConn, error) {
	ifaces, err := multicastIPv4Interfaces()
	if err != nil {
		return nil, err
	}

	var conns []*net.UDPConn
	var openErrs []error
	for i := range ifaces {
		conn, err := net.ListenMulticastUDP("udp4", &ifaces[i], addr)
		if err != nil {
			openErrs = append(openErrs, fmt.Errorf("%s: %w", ifaces[i].Name, err))
			continue
		}
		conns = append(conns, conn)
	}
	if len(conns) > 0 {
		return conns, nil
	}

	if len(openErrs) == 0 {
		return nil, errors.New("discovery: no usable IPv4 multicast listeners")
	}
	return nil, errors.Join(openErrs...)
}

func multicastIPv4Interfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]net.Interface, 0, len(ifaces))
	for _, ifi := range ifaces {
		if !usableMulticastInterface(ifi) {
			continue
		}
		ips, err := interfaceIPv4Addrs(&ifi)
		if err != nil || len(ips) == 0 {
			continue
		}
		out = append(out, ifi)
	}
	return out, nil
}

func usableMulticastInterface(ifi net.Interface) bool {
	return ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagLoopback == 0 && ifi.Flags&net.FlagMulticast != 0
}

func interfaceIPv4Addrs(ifi *net.Interface) ([]net.IP, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			parsed, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			ip = parsed
		}
		ip = ip.To4()
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		ips = append(ips, append(net.IP(nil), ip...))
	}
	return ips, nil
}

func closeUDPConns(conns []*net.UDPConn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func sendAnnouncement(conns []*net.UDPConn, id *identity.Identity, port int) error {
	data, err := announcementBytes(id, port)
	if err != nil {
		return err
	}
	var writeErrs []error
	sent := 0
	for _, conn := range conns {
		if _, err := conn.Write(data); err != nil {
			writeErrs = append(writeErrs, err)
			continue
		}
		sent++
	}
	if sent > 0 {
		return nil
	}
	if len(writeErrs) == 0 {
		return errors.New("discovery: no multicast writers are available")
	}
	return errors.Join(writeErrs...)
}

func announcementBytes(id *identity.Identity, port int) ([]byte, error) {
	a := signedAnnouncement{
		Version: 1, DeviceID: id.ID, Name: id.Name, Port: port,
		PublicKey: base64.RawStdEncoding.EncodeToString(id.PublicKey), UnixTime: time.Now().Unix(),
	}
	msg := signingBytes(a)
	a.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(id.PrivateKey, msg))
	return json.Marshal(a)
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
