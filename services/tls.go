package services

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const certsRootDir = "certs/services"
const certPoolRootDir = "certs/pool"

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

// ParseCertInfo decodes the first PEM certificate block and returns the list
// of domain names it covers (SANs, falling back to the CN) plus its expiry.
func ParseCertInfo(certPEM []byte) (domains []string, expiresAt time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, time.Time{}, fmt.Errorf("no PEM block found in certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	domains = leaf.DNSNames
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = []string{leaf.Subject.CommonName}
	}
	return domains, leaf.NotAfter, nil
}

// CertCoversHost reports whether the leaf certificate in certPEM is valid for
// host (exact SAN or wildcard match). The returned error is x509's own
// hostname mismatch message, which lists the names the cert actually covers —
// suitable for showing directly in the UI. A non-standard port on host is
// ignored for matching.
func CertCoversHost(certPEM []byte, host string) error {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("no PEM block found in certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	if err := leaf.VerifyHostname(host); err != nil {
		// Legacy CN-only certs: VerifyHostname ignores the Common Name, so
		// accept an exact/wildcard CN match before rejecting.
		if len(leaf.DNSNames) == 0 && hostMatchesPattern(leaf.Subject.CommonName, host) {
			return nil
		}
		return err
	}
	return nil
}

// hostMatchesPattern matches host against a certificate name pattern,
// supporting a single leading "*." wildcard label.
func hostMatchesPattern(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(host)
	if pattern == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		if i := strings.Index(host, "."); i > 0 {
			return host[i+1:] == rest
		}
	}
	return false
}

// SavePoolCert validates the cert+key pair and writes them into the shared
// certificate pool at certs/pool/<id>/. The key file is written mode 0600.
func SavePoolCert(id int64, certPEM, keyPEM []byte) (certPath, keyPath string, err error) {
	if _, err2 := tls.X509KeyPair(certPEM, keyPEM); err2 != nil {
		return "", "", fmt.Errorf("invalid cert/key pair: %w", err2)
	}
	dir := filepath.Join(certPoolRootDir, strconv.FormatInt(id, 10))
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create cert dir: %w", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write cert: %w", err)
	}
	if err = os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}
	return certPath, keyPath, nil
}

// DeletePoolCert removes the on-disk directory for the given pool cert ID.
func DeletePoolCert(id int64) {
	os.RemoveAll(filepath.Join(certPoolRootDir, strconv.FormatInt(id, 10)))
}
