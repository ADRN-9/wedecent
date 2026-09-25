package identity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type keyProtectionScope uint8

const (
	keyProtectionUser keyProtectionScope = iota + 1
	keyProtectionMachine
)

func parseLegacyPrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid identity private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse identity private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not Ed25519")
	}
	return priv, nil
}

func marshalLegacyPrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func marshalPrivateKeyDER(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return der, nil
}

func parsePrivateKeyDER(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse identity private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not Ed25519")
	}
	return priv, nil
}

func tlsCertificateFor(leaf *x509.Certificate, signer crypto.Signer) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  signer,
		Leaf:        leaf,
	}
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
