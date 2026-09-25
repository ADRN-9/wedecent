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

// loadConcurrentlyCreatedCertificate is used only after this process lost an
// exclusive first-creation race for identity.crt. The winning creator opens the
// final path before writing and syncing the small certificate, so a loser can
// briefly observe an incomplete file. Reconcile for a short bounded window;
// every attempt still goes through the normal strict PEM, self-signature and
// path-identity checks in loadCertificate.
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
