package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/darksol/Vanta/internal/approval"
	"github.com/darksol/Vanta/internal/audit"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// IPv4 loopback
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.255.255.255", "127.255.255.255", true},

		// "This network" (0.0.0.0/8) — routes to loopback on Linux
		{"this-network 0.0.0.0", "0.0.0.0", true},
		{"this-network 0.1.2.3", "0.1.2.3", true},

		// RFC 1918
		{"rfc1918-10 10.0.0.1", "10.0.0.1", true},
		{"rfc1918-10 10.255.255.255", "10.255.255.255", true},
		{"rfc1918-172 172.16.0.1", "172.16.0.1", true},
		{"rfc1918-172 172.31.255.255", "172.31.255.255", true},
		{"rfc1918-172 outside 172.32.0.1", "172.32.0.1", false},
		{"rfc1918-192 192.168.0.1", "192.168.0.1", true},
		{"rfc1918-192 192.168.255.255", "192.168.255.255", true},

		// Link-local
		{"link-local 169.254.0.1", "169.254.0.1", true},
		{"link-local 169.254.169.254", "169.254.169.254", true}, // AWS metadata

		// Carrier-Grade NAT (RFC 6598)
		{"cgnat 100.64.0.1", "100.64.0.1", true},
		{"cgnat 100.127.255.255", "100.127.255.255", true},
		{"cgnat outside 100.128.0.1", "100.128.0.1", false},

		// Public IPs — should NOT be blocked
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 203.0.113.1", "203.0.113.1", false},

		// IPv6 loopback
		{"ipv6-loopback ::1", "::1", true},

		// IPv6 unspecified — SSRF bypass vector, must always be blocked
		{"ipv6-unspecified ::", "::", true},

		// IPv6 unique local (ULA)
		{"ipv6-ula fd00::1", "fd00::1", true},
		{"ipv6-ula fc00::1", "fc00::1", true},

		// IPv6 link-local
		{"ipv6-link-local fe80::1", "fe80::1", true},

		// IPv6 public — should NOT be blocked
		{"ipv6-public 2001:4860:4860::8888", "2001:4860:4860::8888", false},

		// NAT64 Well-Known Prefix (64:ff9b::/96, RFC 6052) — embeds IPv4 in last 4 bytes
		{"nat64-loopback 64:ff9b::7f00:1", "64:ff9b::7f00:1", true},        // encodes 127.0.0.1
		{"nat64-private-10 64:ff9b::a00:1", "64:ff9b::a00:1", true},        // encodes 10.0.0.1
		{"nat64-private-192 64:ff9b::c0a8:1", "64:ff9b::c0a8:1", true},     // encodes 192.168.0.1
		{"nat64-private-172 64:ff9b::ac10:1", "64:ff9b::ac10:1", true},     // encodes 172.16.0.1
		{"nat64-link-local 64:ff9b::a9fe:fea9", "64:ff9b::a9fe:fea9", true}, // encodes 169.254.254.169 (link-local)

		// 6to4 addressing (2002::/16, RFC 3056) — embeds IPv4 in bytes 2-5
		{"6to4-loopback 2002:7f00:0001::", "2002:7f00:0001::", true},        // encodes 127.0.0.1
		{"6to4-private-10 2002:0a00:0001::", "2002:0a00:0001::", true},      // encodes 10.0.0.1
		{"6to4-private-192 2002:c0a8:0001::", "2002:c0a8:0001::", true},     // encodes 192.168.0.1
		{"6to4-link-local 2002:a9fe:fea9::", "2002:a9fe:fea9::", true},      // encodes 169.254.254.169

		// NAT64/6to4 encoding PUBLIC IPs — should NOT be blocked
		{"nat64-public 64:ff9b::0808:0808", "64:ff9b::0808:0808", false},    // encodes 8.8.8.8
		{"6to4-public 2002:0808:0808::", "2002:0808:0808::", false},          // encodes 8.8.8.8
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isBlockedIP(ip, nil)
			if got != tt.blocked {
				t.Errorf("isBlockedIP(%s, nil) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestIsBlockedIP_AllowedCIDRs(t *testing.T) {
	_, allow10, _ := net.ParseCIDR("10.0.0.0/8")
	_, allow172, _ := net.ParseCIDR("172.16.5.0/24")
	allowed := []*net.IPNet{allow10, allow172}

	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Normally blocked, but allowed by 10.0.0.0/8
		{"allowed 10.0.0.1", "10.0.0.1", false},
		{"allowed 10.255.255.255", "10.255.255.255", false},

		// Normally blocked, allowed by 172.16.5.0/24
		{"allowed 172.16.5.1", "172.16.5.1", false},
		{"allowed 172.16.5.254", "172.16.5.254", false},

		// Normally blocked, NOT in allowed CIDRs
		{"still-blocked 172.16.6.1", "172.16.6.1", true},
		{"still-blocked 192.168.1.1", "192.168.1.1", true},
		{"still-blocked 127.0.0.1", "127.0.0.1", true},

		// Unspecified address is always blocked, even if in allowed CIDR
		{"unspecified-always-blocked 0.0.0.0", "0.0.0.0", true},
		{"unspecified-ipv6-always-blocked ::", "::", true},

		// Public IPs — still not blocked
		{"public 8.8.8.8", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isBlockedIP(ip, allowed)
			if got != tt.blocked {
				t.Errorf("isBlockedIP(%s, allowed) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestExtractEmbeddedIPv4(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string // empty means nil expected
	}{
		{"nat64 loopback", "64:ff9b::7f00:1", "127.0.0.1"},
		{"nat64 10.0.0.1", "64:ff9b::a00:1", "10.0.0.1"},
		{"nat64 8.8.8.8", "64:ff9b::0808:0808", "8.8.8.8"},
		{"6to4 loopback", "2002:7f00:0001::", "127.0.0.1"},
		{"6to4 10.0.0.1", "2002:0a00:0001::", "10.0.0.1"},
		{"6to4 8.8.8.8", "2002:0808:0808::", "8.8.8.8"},
		{"regular ipv6", "2001:4860:4860::8888", ""},
		{"regular ipv4", "192.168.1.1", ""},
		{"ipv6 loopback", "::1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := extractEmbeddedIPv4(ip)
			if tt.expected == "" {
				if got != nil {
					t.Errorf("extractEmbeddedIPv4(%s) = %s, want nil", tt.ip, got)
				}
			} else {
				if got == nil {
					t.Fatalf("extractEmbeddedIPv4(%s) = nil, want %s", tt.ip, tt.expected)
				}
				if got.String() != tt.expected {
					t.Errorf("extractEmbeddedIPv4(%s) = %s, want %s", tt.ip, got, tt.expected)
				}
			}
		})
	}
}

func TestIsBlockedIP_NAT64_6to4_AllowedCIDRs(t *testing.T) {
	// Even if the NAT64/6to4 range is in allowedCIDRs, the embedded IPv4
	// should still be checked against the blocklist (defense-in-depth).
	_, allowNAT64, _ := net.ParseCIDR("64:ff9b::/96")
	_, allow6to4, _ := net.ParseCIDR("2002::/16")
	allowed := []*net.IPNet{allowNAT64, allow6to4}

	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// NAT64 range is allowed, but embedded 127.0.0.1 is still blocked
		{"nat64-allowed-but-embedded-loopback", "64:ff9b::7f00:1", true},
		// 6to4 range is allowed, but embedded 10.0.0.1 is still blocked
		{"6to4-allowed-but-embedded-private", "2002:0a00:0001::", true},
		// NAT64 range is allowed, embedded 8.8.8.8 is public — not blocked
		{"nat64-allowed-embedded-public", "64:ff9b::0808:0808", false},
		// 6to4 range is allowed, embedded 8.8.8.8 is public — not blocked
		{"6to4-allowed-embedded-public", "2002:0808:0808::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isBlockedIP(ip, allowed)
			if got != tt.blocked {
				t.Errorf("isBlockedIP(%s, allowed) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

// TestAllowedPrivateCIDRs_HandlerWiring verifies the full path from string
// CIDR slices through handler setup to actual HTTP client behavior: a backend
// on 127.0.0.1 is reachable when loopback is in the allowlist, and blocked
// when it is not.
func TestAllowedPrivateCIDRs_HandlerWiring(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	mgr := approval.NewManager()
	mgr.SetMode("passthrough")

	auditLogger, err := audit.NewLogger("stdout")
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	t.Run("blocked without allowlist", func(t *testing.T) {
		handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), nil, true)
		// No allowedPrivateCIDRs — loopback should be blocked.
		handler.initClient()
		proxyServer := httptest.NewServer(handler)
		defer proxyServer.Close()

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: func(r *http.Request) (*url.URL, error) {
					return url.Parse(proxyServer.URL)
				},
			},
		}
		resp, err := client.Get(backend.URL + "/test")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()
		// Expect 403 (SSRF blocked) or 502 (dial failure), not 200.
		if resp.StatusCode == http.StatusOK {
			t.Errorf("Expected request to loopback to be blocked, got %d", resp.StatusCode)
		}
	})

	t.Run("allowed with loopback in allowlist", func(t *testing.T) {
		handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), nil, true)
		// Parse CIDRs from strings, same as proxy.Start() does from config.
		for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("bad CIDR %q: %v", cidr, err)
			}
			handler.allowedPrivateCIDRs = append(handler.allowedPrivateCIDRs, network)
		}
		handler.initClient()
		proxyServer := httptest.NewServer(handler)
		defer proxyServer.Close()

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: func(r *http.Request) (*url.URL, error) {
					return url.Parse(proxyServer.URL)
				},
			},
		}
		resp, err := client.Get(backend.URL + "/test")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 with loopback allowed, got %d", resp.StatusCode)
		}
	})

	t.Run("selective allowlist only permits listed CIDRs", func(t *testing.T) {
		handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), nil, true)
		// Allow only 10.0.0.0/8 — loopback (127.0.0.1) should still be blocked.
		_, network, _ := net.ParseCIDR("10.0.0.0/8")
		handler.allowedPrivateCIDRs = []*net.IPNet{network}
		handler.initClient()
		proxyServer := httptest.NewServer(handler)
		defer proxyServer.Close()

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: func(r *http.Request) (*url.URL, error) {
					return url.Parse(proxyServer.URL)
				},
			},
		}
		resp, err := client.Get(backend.URL + "/test")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("Expected loopback to be blocked when only 10.0.0.0/8 is allowed, got %d", resp.StatusCode)
		}
	})
}
