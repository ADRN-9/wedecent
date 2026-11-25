package identity

import (
	"bytes"
	"errors"
)

// ProtectExisting migrates legacy Windows key storage to the configured
// platform protection scope without issuing or renewing the device certificate.
func ProtectExisting(dir string) (*Identity, error) {
	before, err := Load(dir)
	if err != nil {
		return nil, err
	}
	if before.Leaf == nil {
		return nil, errors.New("existing identity certificate is unavailable")
	}
	certificate := append([]byte(nil), before.Leaf.Raw...)
	publicKey := append([]byte(nil), before.PublicKey...)
	id := before.ID

	if _, err := loadOrCreatePrivateKey(dir, defaultKeyProtectionScope()); err != nil {
		return nil, err
	}
	after, err := Load(dir)
	if err != nil {
		return nil, err
	}
	if after.ID != id || !bytes.Equal(after.PublicKey, publicKey) ||
		after.Leaf == nil || !bytes.Equal(after.Leaf.Raw, certificate) {
		return nil, errors.New("platform key protection changed device identity or certificate")
	}
	return after, nil
}
