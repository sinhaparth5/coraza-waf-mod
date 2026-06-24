package services

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const certsRootDir = "certs/services"

var unsafeNameChars = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func certDir(name string) string {
	return filepath.Join(certsRootDir, unsafeNameChars.ReplaceAllString(name, "_"))
}

// SaveCustomCert validates an uploaded cert+key PEM pair and writes them to
// disk under certs/services/<name>/ — the key file is written 0600, never
// stored in the database. Returns the file paths and the leaf certificate's
// expiry so the UI can show it.
func SaveCustomCert(name string, certPEM, keyPEM []byte) (certPath, keyPath string, expiresAt time.Time, err error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid cert/key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}

	dir := certDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", time.Time{}, fmt.Errorf("create cert dir: %w", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", time.Time{}, fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", time.Time{}, fmt.Errorf("write key: %w", err)
	}
	return certPath, keyPath, leaf.NotAfter, nil
}

// LoadCertificate reads a cert+key pair from disk for TLS handshake use.
func LoadCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
