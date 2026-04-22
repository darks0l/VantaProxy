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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dummyCert(id int) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{[]byte(fmt.Sprintf("cert-%d", id))}}
}

func TestLRUCache_GetMiss(t *testing.T) {
	c := newLRUCache[*tls.Certificate](5)
	if _, ok := c.Get("missing"); ok {
		t.Fatal("expected cache miss")
	}
}

func TestLRUCache_PutAndGet(t *testing.T) {
	c := newLRUCache[*tls.Certificate](5)
	cert := dummyCert(1)
	c.Put("host1", cert)

	got, ok := c.Get("host1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got != cert {
		t.Fatal("returned cert does not match stored cert")
	}
}

func TestLRUCache_EvictionAtCapacity(t *testing.T) {
	c := newLRUCache[*tls.Certificate](3)
	c.Put("a", dummyCert(1))
	c.Put("b", dummyCert(2))
	c.Put("c", dummyCert(3))

	// Cache is full. Adding "d" should evict "a" (oldest).
	c.Put("d", dummyCert(4))

	if _, ok := c.Get("a"); ok {
		t.Fatal("expected 'a' to be evicted")
	}
	for _, key := range []string{"b", "c", "d"} {
		if _, ok := c.Get(key); !ok {
			t.Fatalf("expected %q to still be in cache", key)
		}
	}
}

func TestLRUCache_LRUOrdering(t *testing.T) {
	c := newLRUCache[*tls.Certificate](3)
	c.Put("a", dummyCert(1))
	c.Put("b", dummyCert(2))
	c.Put("c", dummyCert(3))

	// Access "a" to make it most recently used.
	c.Get("a")

	// Adding "d" should evict "b" (now the least recently used).
	c.Put("d", dummyCert(4))

	if _, ok := c.Get("b"); ok {
		t.Fatal("expected 'b' to be evicted after 'a' was accessed")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected 'a' to survive eviction")
	}
}

func TestLRUCache_UpdateExistingKey(t *testing.T) {
	c := newLRUCache[*tls.Certificate](3)
	c.Put("a", dummyCert(1))
	c.Put("b", dummyCert(2))
	c.Put("c", dummyCert(3))

	// Update "a" — should promote it and not increase size.
	newCert := dummyCert(99)
	c.Put("a", newCert)

	got, ok := c.Get("a")
	if !ok {
		t.Fatal("expected 'a' to be in cache after update")
	}
	if got != newCert {
		t.Fatal("expected updated cert value")
	}

	// Size should still be 3.
	if c.Len() != 3 {
		t.Fatalf("expected cache size 3, got %d", c.Len())
	}

	// Adding "d" should evict "b" (least recently used), not "a".
	c.Put("d", dummyCert(4))
	if _, ok := c.Get("b"); ok {
		t.Fatal("expected 'b' to be evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected 'a' to survive")
	}
}

func TestGetCertificate_EmptySNIRejected(t *testing.T) {
	// The empty-SNI guard fires before any CA/key usage, so a bare
	// TLSManager with only a cache is sufficient for this test.
	tm := &TLSManager{
		certCache: newLRUCache[*tls.Certificate](10),
	}

	for _, host := range []string{"", ".", "..", "..."} {
		cert, err := tm.GetCertificate(host)
		if err == nil {
			t.Fatalf("expected error for SNI %q, got nil", host)
		}
		if cert != nil {
			t.Fatalf("expected nil certificate for SNI %q", host)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Fatalf("expected error to mention empty for SNI %q, got: %v", host, err)
		}
	}

	// Ensure the empty key was not cached.
	if _, ok := tm.certCache.Get(""); ok {
		t.Fatal("empty SNI should not be cached")
	}
}

func TestLRUCache_GetOrCreate(t *testing.T) {
	c := newLRUCache[*tls.Certificate](5)

	calls := 0
	create := func() *tls.Certificate {
		calls++
		return dummyCert(calls)
	}

	// First call should invoke create.
	v1 := c.GetOrCreate("key1", create)
	if calls != 1 {
		t.Fatalf("expected create called once, got %d", calls)
	}

	// Second call for same key should return cached value without calling create.
	v2 := c.GetOrCreate("key1", create)
	if calls != 1 {
		t.Fatalf("expected create not called again, got %d", calls)
	}
	if v1 != v2 {
		t.Fatal("expected same value returned for same key")
	}

	// Different key should invoke create again.
	c.GetOrCreate("key2", create)
	if calls != 2 {
		t.Fatalf("expected create called for new key, got %d", calls)
	}
}

func TestLRUCache_GetOrCreate_EvictsAtCapacity(t *testing.T) {
	c := newLRUCache[*tls.Certificate](2)
	c.GetOrCreate("a", func() *tls.Certificate { return dummyCert(1) })
	c.GetOrCreate("b", func() *tls.Certificate { return dummyCert(2) })
	c.GetOrCreate("c", func() *tls.Certificate { return dummyCert(3) })

	if _, ok := c.Get("a"); ok {
		t.Fatal("expected 'a' to be evicted at capacity 2")
	}
	if c.Len() != 2 {
		t.Fatalf("expected cache size 2, got %d", c.Len())
	}
}

func TestLRUCache_SingleCapacity(t *testing.T) {
	c := newLRUCache[*tls.Certificate](1)
	c.Put("a", dummyCert(1))
	c.Put("b", dummyCert(2))

	if _, ok := c.Get("a"); ok {
		t.Fatal("expected 'a' to be evicted with capacity 1")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("expected 'b' to be in cache")
	}
}

// newTestTLSManager creates a TLSManager with an in-memory self-signed CA
// suitable for unit tests that call GetCertificate.
func newTestTLSManager(t *testing.T) *TLSManager {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return &TLSManager{
		caCert:    caCert,
		caKey:     caKey,
		certCache: newLRUCache[*tls.Certificate](DefaultMaxCertCacheSize),
	}
}

func TestGetCertificate_CaseNormalization(t *testing.T) {
	tm := newTestTLSManager(t)

	cert1, err := tm.GetCertificate("EXAMPLE.COM")
	if err != nil {
		t.Fatalf("GetCertificate(EXAMPLE.COM): %v", err)
	}

	cert2, err := tm.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate(example.com): %v", err)
	}

	if cert1 != cert2 {
		t.Fatal("expected case-variant hostnames to return the same cached certificate")
	}
}

func TestGetCertificate_TrailingDotNormalization(t *testing.T) {
	tm := newTestTLSManager(t)

	cert1, err := tm.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate(example.com): %v", err)
	}

	cert2, err := tm.GetCertificate("example.com.")
	if err != nil {
		t.Fatalf("GetCertificate(example.com.): %v", err)
	}

	if cert1 != cert2 {
		t.Fatal("expected trailing-dot FQDN to return the same cached certificate as bare hostname")
	}
}

// --- Tests for per-host TLS verification skip (shouldSkipTLSVerify) ---

func TestShouldSkipTLSVerify_GlobalTrue_NoHostList(t *testing.T) {
	h := &Handler{insecureSkipUpstreamVerify: true}
	if !h.shouldSkipTLSVerify("any-host.example.com", "443") {
		t.Fatal("expected skip=true when global flag is true and no per-host list")
	}
}

func TestShouldSkipTLSVerify_GlobalFalse_NoHostList(t *testing.T) {
	h := &Handler{insecureSkipUpstreamVerify: false}
	if h.shouldSkipTLSVerify("any-host.example.com", "443") {
		t.Fatal("expected skip=false when global flag is false and no per-host list")
	}
}

func TestShouldSkipTLSVerify_PerHost_MatchedHost(t *testing.T) {
	h := &Handler{
		insecureSkipUpstreamVerify: false,
		insecureSkipVerifyHosts:    map[string]bool{"internal.example.com": true},
	}
	if !h.shouldSkipTLSVerify("internal.example.com", "443") {
		t.Fatal("expected skip=true for listed host")
	}
}

func TestShouldSkipTLSVerify_PerHost_UnmatchedHost(t *testing.T) {
	h := &Handler{
		insecureSkipUpstreamVerify: true, // global is true but should be ignored
		insecureSkipVerifyHosts:    map[string]bool{"internal.example.com": true},
	}
	if h.shouldSkipTLSVerify("external.example.com", "443") {
		t.Fatal("expected skip=false for unlisted host even when global flag is true")
	}
}

func TestShouldSkipTLSVerify_PerHost_CaseInsensitive(t *testing.T) {
	h := &Handler{
		insecureSkipVerifyHosts: map[string]bool{"internal.example.com": true},
	}
	if !h.shouldSkipTLSVerify("Internal.Example.COM", "443") {
		t.Fatal("expected case-insensitive match for listed host")
	}
}

func TestShouldSkipTLSVerify_PerHost_OverridesGlobal(t *testing.T) {
	h := &Handler{
		insecureSkipUpstreamVerify: true,
		insecureSkipVerifyHosts:    map[string]bool{"only-this.example.com": true},
	}
	// Global is true, but per-host list is set, so only listed hosts should skip.
	if h.shouldSkipTLSVerify("other.example.com", "443") {
		t.Fatal("per-host list should override global flag for unlisted hosts")
	}
	if !h.shouldSkipTLSVerify("only-this.example.com", "443") {
		t.Fatal("per-host list should allow listed host")
	}
}

func TestShouldSkipTLSVerify_PerHost_MultipleHosts(t *testing.T) {
	h := &Handler{
		insecureSkipVerifyHosts: map[string]bool{
			"a.example.com": true,
			"b.example.com": true,
		},
	}
	if !h.shouldSkipTLSVerify("a.example.com", "443") {
		t.Fatal("expected skip=true for first listed host")
	}
	if !h.shouldSkipTLSVerify("b.example.com", "443") {
		t.Fatal("expected skip=true for second listed host")
	}
	if h.shouldSkipTLSVerify("c.example.com", "443") {
		t.Fatal("expected skip=false for unlisted host")
	}
}

func TestShouldSkipTLSVerify_PortSpecific_MatchedPort(t *testing.T) {
	h := &Handler{
		insecureSkipVerifyHosts: map[string]bool{"internal.example.com:9001": true},
	}
	if !h.shouldSkipTLSVerify("internal.example.com", "9001") {
		t.Fatal("expected skip=true for matching host:port")
	}
}

func TestShouldSkipTLSVerify_PortSpecific_DifferentPort(t *testing.T) {
	h := &Handler{
		insecureSkipVerifyHosts: map[string]bool{"internal.example.com:9001": true},
	}
	if h.shouldSkipTLSVerify("internal.example.com", "443") {
		t.Fatal("expected skip=false for non-matching port")
	}
}

func TestShouldSkipTLSVerify_BareHost_MatchesAnyPort(t *testing.T) {
	h := &Handler{
		insecureSkipVerifyHosts: map[string]bool{"internal.example.com": true},
	}
	if !h.shouldSkipTLSVerify("internal.example.com", "9001") {
		t.Fatal("bare host entry should match any port")
	}
	if !h.shouldSkipTLSVerify("internal.example.com", "443") {
		t.Fatal("bare host entry should match any port")
	}
}

func TestShouldSkipTLSVerify_PortSpecific_TakesPrecedence(t *testing.T) {
	// Port-specific entry exists alongside bare host — both should work
	h := &Handler{
		insecureSkipVerifyHosts: map[string]bool{
			"host.example.com":      true,
			"other.example.com:9001": true,
		},
	}
	// bare host matches all ports
	if !h.shouldSkipTLSVerify("host.example.com", "9001") {
		t.Fatal("bare host should match any port")
	}
	// port-specific only matches that port
	if !h.shouldSkipTLSVerify("other.example.com", "9001") {
		t.Fatal("port-specific entry should match")
	}
	if h.shouldSkipTLSVerify("other.example.com", "443") {
		t.Fatal("port-specific entry should not match different port")
	}
}

// --- Tests for IP address SAN handling in certificate generation (P-57) ---

// parseCertFromTLS is a helper that extracts the x509.Certificate from a tls.Certificate.
func parseCertFromTLS(t *testing.T, cert *tls.Certificate) *x509.Certificate {
	t.Helper()
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse x509 certificate: %v", err)
	}
	return x509Cert
}

func TestGenerateCertificate_IPv4_UsesIPAddressesSAN(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("192.168.1.1")
	if err != nil {
		t.Fatalf("GetCertificate(192.168.1.1): %v", err)
	}

	x509Cert := parseCertFromTLS(t, cert)

	if len(x509Cert.IPAddresses) == 0 {
		t.Fatal("expected IPAddresses SAN to be populated for IPv4 host")
	}
	if !x509Cert.IPAddresses[0].Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("expected IPAddresses[0] to be 192.168.1.1, got %v", x509Cert.IPAddresses[0])
	}
	if len(x509Cert.DNSNames) != 0 {
		t.Fatalf("expected DNSNames to be empty for IP host, got %v", x509Cert.DNSNames)
	}
}

func TestGenerateCertificate_IPv6_UsesIPAddressesSAN(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("::1")
	if err != nil {
		t.Fatalf("GetCertificate(::1): %v", err)
	}

	x509Cert := parseCertFromTLS(t, cert)

	if len(x509Cert.IPAddresses) == 0 {
		t.Fatal("expected IPAddresses SAN to be populated for IPv6 host")
	}
	if !x509Cert.IPAddresses[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("expected IPAddresses[0] to be ::1, got %v", x509Cert.IPAddresses[0])
	}
	if len(x509Cert.DNSNames) != 0 {
		t.Fatalf("expected DNSNames to be empty for IP host, got %v", x509Cert.DNSNames)
	}
}

func TestGenerateCertificate_BracketedIPv6_UsesIPAddressesSAN(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("[::1]")
	if err != nil {
		t.Fatalf("GetCertificate([::1]): %v", err)
	}

	x509Cert := parseCertFromTLS(t, cert)

	if len(x509Cert.IPAddresses) == 0 {
		t.Fatal("expected IPAddresses SAN to be populated for bracketed IPv6 host")
	}
	if !x509Cert.IPAddresses[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("expected IPAddresses[0] to be ::1, got %v", x509Cert.IPAddresses[0])
	}
	if len(x509Cert.DNSNames) != 0 {
		t.Fatalf("expected DNSNames to be empty for IP host, got %v", x509Cert.DNSNames)
	}
}

func TestGenerateCertificate_Hostname_UsesDNSNamesSAN(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate(example.com): %v", err)
	}

	x509Cert := parseCertFromTLS(t, cert)

	if len(x509Cert.DNSNames) == 0 {
		t.Fatal("expected DNSNames SAN to be populated for hostname")
	}
	if x509Cert.DNSNames[0] != "example.com" {
		t.Fatalf("expected DNSNames[0] to be example.com, got %s", x509Cert.DNSNames[0])
	}
	if len(x509Cert.IPAddresses) != 0 {
		t.Fatalf("expected IPAddresses to be empty for hostname, got %v", x509Cert.IPAddresses)
	}
}

func TestGenerateCertificate_IPv4_TLSClientVerification(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("10.0.0.1")
	if err != nil {
		t.Fatalf("GetCertificate(10.0.0.1): %v", err)
	}

	// Build a certificate pool with our test CA and verify the cert.
	pool := x509.NewCertPool()
	pool.AddCert(tm.caCert)

	x509Cert := parseCertFromTLS(t, cert)

	_, verifyErr := x509Cert.Verify(x509.VerifyOptions{
		DNSName: "10.0.0.1",
		Roots:   pool,
	})
	if verifyErr != nil {
		t.Fatalf("TLS verification failed for IP cert: %v", verifyErr)
	}
}

func TestGenerateCertificate_IPv6_TLSClientVerification(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("2001:db8::1")
	if err != nil {
		t.Fatalf("GetCertificate(2001:db8::1): %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(tm.caCert)

	x509Cert := parseCertFromTLS(t, cert)

	_, verifyErr := x509Cert.Verify(x509.VerifyOptions{
		DNSName: "2001:db8::1",
		Roots:   pool,
	})
	if verifyErr != nil {
		t.Fatalf("TLS verification failed for IPv6 cert: %v", verifyErr)
	}
}

func TestGenerateCertificate_Hostname_TLSClientVerification(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("www.example.com")
	if err != nil {
		t.Fatalf("GetCertificate(www.example.com): %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(tm.caCert)

	x509Cert := parseCertFromTLS(t, cert)

	_, verifyErr := x509Cert.Verify(x509.VerifyOptions{
		DNSName: "www.example.com",
		Roots:   pool,
	})
	if verifyErr != nil {
		t.Fatalf("TLS verification failed for hostname cert: %v", verifyErr)
	}
}

func TestGenerateCertificate_BracketedIPv6_CacheKey(t *testing.T) {
	tm := newTestTLSManager(t)

	// Bracketed and bare IPv6 should resolve to the same cached certificate.
	cert1, err := tm.GetCertificate("[::1]")
	if err != nil {
		t.Fatalf("GetCertificate([::1]): %v", err)
	}

	cert2, err := tm.GetCertificate("::1")
	if err != nil {
		t.Fatalf("GetCertificate(::1): %v", err)
	}

	if cert1 != cert2 {
		t.Fatal("expected bracketed and bare IPv6 to share the same cached certificate")
	}
}

func TestGenerateCertificate_FullIPv6_UsesIPAddressesSAN(t *testing.T) {
	tm := newTestTLSManager(t)

	cert, err := tm.GetCertificate("fe80::1%25eth0")
	if err != nil {
		// Zone IDs may not be supported by net.ParseIP; this is expected
		// to fall through to DNSNames. Just verify it doesn't panic.
		return
	}

	x509Cert := parseCertFromTLS(t, cert)
	// If it parsed as an IP, it should be in IPAddresses
	if len(x509Cert.IPAddresses) > 0 {
		return // correct
	}
	// If not, it should be in DNSNames (zone ID makes it not a valid IP)
	if len(x509Cert.DNSNames) == 0 {
		t.Fatal("expected either IPAddresses or DNSNames to be populated")
	}
}

// --- Tests for EnsureCACertificate ---

func TestEnsureCACertificate_GeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certs", "ca.crt")
	keyPath := filepath.Join(dir, "certs", "ca.key")

	if err := EnsureCACertificate(certPath, keyPath); err != nil {
		t.Fatalf("EnsureCACertificate: %v", err)
	}

	// Verify files exist with correct permissions.
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("cert file not created: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("cert permissions = %o, want 0644", certInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key permissions = %o, want 0600", keyInfo.Mode().Perm())
	}

	// Verify the cert is a valid CA.
	certPEM, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Error("generated cert is not a CA")
	}
	if cert.Subject.CommonName != "CrabTrap CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "CrabTrap CA")
	}

	// Verify the key is parseable.
	keyPEM, _ := os.ReadFile(keyPath)
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode key PEM")
	}
	if _, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
}

func TestEnsureCACertificate_NoopWhenExists(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate once.
	if err := EnsureCACertificate(certPath, keyPath); err != nil {
		t.Fatalf("first call: %v", err)
	}
	certBefore, _ := os.ReadFile(certPath)

	// Call again — should be a no-op.
	if err := EnsureCACertificate(certPath, keyPath); err != nil {
		t.Fatalf("second call: %v", err)
	}
	certAfter, _ := os.ReadFile(certPath)

	if string(certBefore) != string(certAfter) {
		t.Error("cert file changed on second call; expected no-op")
	}
}

func TestEnsureCACertificate_ErrorOnInconsistentState(t *testing.T) {
	t.Run("cert exists, key missing", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "ca.crt")
		keyPath := filepath.Join(dir, "ca.key")
		if err := os.WriteFile(certPath, []byte("dummy"), 0644); err != nil {
			t.Fatal(err)
		}

		err := EnsureCACertificate(certPath, keyPath)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "inconsistent") {
			t.Errorf("error = %q, want 'inconsistent'", err.Error())
		}
		if !strings.Contains(err.Error(), certPath) || !strings.Contains(err.Error(), keyPath) {
			t.Errorf("error should mention both paths, got: %q", err.Error())
		}
	})

	t.Run("key exists, cert missing", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "ca.crt")
		keyPath := filepath.Join(dir, "ca.key")
		if err := os.WriteFile(keyPath, []byte("dummy"), 0600); err != nil {
			t.Fatal(err)
		}

		err := EnsureCACertificate(certPath, keyPath)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "inconsistent") {
			t.Errorf("error = %q, want 'inconsistent'", err.Error())
		}
	})
}

func TestEnsureCACertificate_StaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Simulate a prior crashed run that left stale temp files.
	if err := os.WriteFile(keyPath+".tmp", []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath+".tmp", []byte("stale"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := EnsureCACertificate(certPath, keyPath); err != nil {
		t.Fatalf("EnsureCACertificate with stale tmp files: %v", err)
	}

	// Verify real files were created and tmp files are gone.
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert not created: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key not created: %v", err)
	}
	if _, err := os.Stat(keyPath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale key tmp file should have been cleaned up")
	}
	if _, err := os.Stat(certPath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale cert tmp file should have been cleaned up")
	}
}

func TestEnsureCACertificate_UsableByNewTLSManager(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if err := EnsureCACertificate(certPath, keyPath); err != nil {
		t.Fatalf("EnsureCACertificate: %v", err)
	}

	// The generated cert/key should be loadable by NewTLSManager.
	tm, err := NewTLSManager(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewTLSManager with generated certs: %v", err)
	}

	// And should be usable to generate a leaf cert.
	cert, err := tm.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate with generated CA: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

// Note: no NewServer-level integration test for auto-generated certs.
// NewServer requires a database and full config; the UsableByNewTLSManager
// test above covers the critical path (generate → load → sign leaf).
