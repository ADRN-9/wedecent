package identity

import (
	"crypto/x509"
	"fmt"
	"time"
)

const (
	concurrentCertificateLoadAttempts   = 100
	concurrentCertificateLoadRetryDelay = 5 * time.Millisecond
)

// loadConcurrentlyCreatedCertificate is used after this process loses an
// exclusive first-creation race for identity.crt. The winner publishes a fully
// synced temporary file atomically; the bounded retry also tolerates delayed
// visibility on filesystems that do not immediately expose the new directory
// entry. Every attempt still uses strict PEM, self-signature and path checks.
func loadConcurrentlyCreatedCertificate(path string) (*x509.Certificate, error) {
	var lastErr error
	for attempt := 0; attempt < concurrentCertificateLoadAttempts; attempt++ {
		cert, err := loadCertificate(path)
		if err == nil {
			return cert, nil
		}
		lastErr = err
		if attempt+1 < concurrentCertificateLoadAttempts {
			time.Sleep(concurrentCertificateLoadRetryDelay)
		}
	}
	return nil, fmt.Errorf(
		"identity certificate did not become readable after concurrent creation: %w",
		lastErr,
	)
}
