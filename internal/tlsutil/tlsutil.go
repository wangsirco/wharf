// Package tlsutil creates self-signed certificates and pins them by fingerprint.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoadOrCreate returns a certificate from certFile/keyFile, generating a
// self-signed one (10 years) if they don't exist.
func LoadOrCreate(certFile, keyFile, commonName string) (tls.Certificate, error) {
	if _, err := os.Stat(certFile); err != nil {
		if err := generate(certFile, keyFile, commonName); err != nil {
			return tls.Certificate{}, err
		}
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func generate(certFile, keyFile, cn string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"OWP"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn, "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(certFile), 0o700)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Fingerprint is the hex SHA-256 of the leaf certificate (DER).
func Fingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	h := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(h[:])
}

// PinnedConfig accepts exactly the certificate with the given fingerprint
// (colons/case ignored), regardless of CA or hostname.
func PinnedConfig(fingerprint string) *tls.Config {
	want := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			h := sha256.Sum256(raw[0])
			if hex.EncodeToString(h[:]) != want {
				return errors.New("agent certificate fingerprint mismatch")
			}
			return nil
		},
	}
}
