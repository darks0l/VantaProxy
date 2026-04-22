package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultMaxCertCacheSize is the default maximum number of entries in the TLS certificate LRU cache.
const DefaultMaxCertCacheSize = 10000

// EnsureCACertificate checks whether the CA cert and key files exist at the
// given paths. If both are missing, it generates a self-signed CA and writes
// the files. If only one exists, it returns an error (inconsistent state).
func EnsureCACertificate(certPath, keyPath string) error {
	certExists, certErr := fileExists(certPath)
	keyExists, keyErr := fileExists(keyPath)
	if certErr != nil {
		return fmt.Errorf("check CA certificate: %w", certErr)
	}
	if keyErr != nil {
		return fmt.Errorf("check CA key: %w", keyErr)
	}

	if certExists && keyExists {
		return nil
	}
	if certExists != keyExists {
		return fmt.Errorf("CA certificate and key are inconsistent: cert=%s (exists=%t), key=%s (exists=%t)",
			certPath, certExists, keyPath, keyExists)
	}

	for _, dir := range []string{filepath.Dir(certPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	slog.Info("generating CA certificate (4096-bit RSA, this may take a few seconds)...")

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "CrabTrap CA",
			Organization: []string{"CrabTrap"},
		},
		// Back-date by 1 hour to tolerate clock skew on client machines.
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Restrict to signing leaf certs only (no intermediate CAs).
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tmpKey := keyPath + ".tmp"
	tmpCert := certPath + ".tmp"

	// Remove stale temp files from a prior crashed run.
	os.Remove(tmpKey)
	os.Remove(tmpCert)

	if err := writeFileExclusive(tmpKey, keyPEM, 0600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	if err := writeFileExclusive(tmpCert, certPEM, 0644); err != nil {
		os.Remove(tmpKey)
		return fmt.Errorf("write CA certificate: %w", err)
	}

	// Rename cert first, then key. If the key rename fails we can roll back
	// the cert; the reverse order leaves an orphaned key with no rollback path.
	if err := os.Rename(tmpCert, certPath); err != nil {
		os.Remove(tmpCert)
		os.Remove(tmpKey)
		return fmt.Errorf("install CA certificate: %w", err)
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		os.Remove(certPath)
		os.Remove(tmpKey)
		return fmt.Errorf("install CA key: %w", err)
	}

	slog.Warn("generated new CA certificate — clients must trust this CA for HTTPS interception",
		"cert", certPath, "key", keyPath)
	return nil
}

// writeFileExclusive writes data to path atomically using O_CREATE|O_EXCL,
// failing if the file already exists (race with another process).
func writeFileExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		os.Remove(path)
		return closeErr
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// TLSManager manages TLS certificates for MITM proxy
type TLSManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caCertPath string
	certCache  *lruCache[*tls.Certificate]
	certGroup  singleflight.Group
}

// NewTLSManager creates a new TLS manager with the given CA certificate and key
func NewTLSManager(caCertPath, caKeyPath string) (*TLSManager, error) {
	// Load CA certificate
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load CA private key
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	// Try PKCS1 first
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA private key: %w", err)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA private key is not RSA")
		}
	}

	return &TLSManager{
		caCert:    caCert,
		caKey:     caKey,
		caCertPath: caCertPath,
		certCache: newLRUCache[*tls.Certificate](DefaultMaxCertCacheSize),
	}, nil
}

// SetMaxCertCacheSize replaces the certificate cache with a new one of the
// given size. Must be called before serving requests.
func (tm *TLSManager) SetMaxCertCacheSize(size int) {
	tm.certCache = newLRUCache[*tls.Certificate](size)
}

// CACertPath returns the path to the CA certificate file.
func (tm *TLSManager) CACertPath() string {
	return tm.caCertPath
}

// GetCertificate returns a certificate for the given host, generating it if necessary.
// Concurrent requests for the same host are deduplicated via singleflight so that
// only one goroutine generates the (expensive) RSA key pair and certificate.
func (tm *TLSManager) GetCertificate(host string) (*tls.Certificate, error) {
	// Normalize hostname to prevent cache exhaustion via case variants
	// (e.g., "Example.COM" vs "example.com") and trailing-dot FQDN variants
	// (e.g., "example.com." vs "example.com"). Per RFC 4343, DNS names are
	// case-insensitive, and a trailing dot is the fully-qualified form of
	// the same name, so all variants should share one cache entry.
	host = strings.ToLower(host)
	host = strings.TrimRight(host, ".")

	// Strip brackets from IPv6 literals (e.g., "[::1]" -> "::1").
	// net.SplitHostPort in the handler strips brackets when a port is present,
	// but bare bracketed IPv6 addresses without a port may arrive here intact.
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}

	if host == "" {
		return nil, errors.New("TLS ClientHello with empty or dot-only SNI rejected")
	}

	if cert, ok := tm.certCache.Get(host); ok {
		return cert, nil
	}

	v, err, _ := tm.certGroup.Do(host, func() (interface{}, error) {
		// Double-check: another goroutine may have populated the cache.
		if cert, ok := tm.certCache.Get(host); ok {
			return cert, nil
		}
		cert, err := tm.generateCertificate(host)
		if err != nil {
			return nil, err
		}
		tm.certCache.Put(host, cert)
		return cert, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

// generateCertificate creates a new certificate for the given host
func (tm *TLSManager) generateCertificate(host string) (*tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"CrabTrap"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Per RFC 5280, IP addresses must be placed in the IPAddresses SAN field,
	// not in DNSNames. Placing an IP in DNSNames causes TLS verification
	// failure in compliant clients (Go, browsers) and pollutes the cert cache
	// with unusable certificates.
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// Sign certificate with CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, tm.caCert, &privateKey.PublicKey, tm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create tls.Certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return cert, nil
}
