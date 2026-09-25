package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type discoverSource func(context.Context) (<-chan Result, <-chan error)

// FindPairCandidate observes the full bounded discovery window before selecting
// a first-pair LAN routing hint. This is intentional: returning on the first
// advertisement would hide later conflicting or ambiguous candidates.
func FindPairCandidate(ctx context.Context, deviceID, expectedFingerprint string) (Result, error) {
	return collectPairCandidate(ctx, deviceID, expectedFingerprint, DiscoverPairCandidates)
}

func collectPairCandidate(ctx context.Context, deviceID, expectedFingerprint string, source discoverSource) (Result, error) {
	results, errs := source(ctx)
	var candidates []Result
	for results != nil || errs != nil {
		select {
		case <-ctx.Done():
			return SelectPairCandidate(candidates, deviceID, expectedFingerprint)
		case result, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			candidates = append(candidates, result)
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				return Result{}, err
			}
		}
	}
	return SelectPairCandidate(candidates, deviceID, expectedFingerprint)
}

// DiscoverPairCandidates is the first-pair candidate feed. Unlike Discover,
// it preserves distinct endpoint/fingerprint tuples for the same device ID so
// ambiguity and identity conflicts cannot be hidden by device-ID deduplication.
func DiscoverPairCandidates(ctx context.Context) (<-chan Result, <-chan error) {
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
				if err != nil {
					continue
				}
				key := strings.Join([]string{res.DeviceID, res.Fingerprint, res.Endpoint}, "\x00")
				if seen[key] {
					continue
				}
				seen[key] = true
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
			errCh <- fmt.Errorf("discovery: pair candidate listeners failed: %w", lastErr)
		}
	}()
	return out, errCh
}
