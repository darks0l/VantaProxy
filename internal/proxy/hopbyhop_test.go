package proxy

import (
	"net/http"
	"testing"
)

func TestStripHopByHopHeaders_Standard(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authenticate", "Basic")
	h.Set("Proxy-Authorization", "Bearer xyz")
	h.Set("TE", "trailers")
	h.Set("Trailer", "X-Checksum")
	h.Set("Upgrade", "h2c")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Content-Type", "application/json")
	h.Set("X-Custom", "value")

	stripHopByHopHeaders(h, false)

	// Standard hop-by-hop headers should be removed.
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Upgrade", "Proxy-Connection"} {
		if v := h.Get(name); v != "" {
			t.Errorf("expected %q to be stripped, got %q", name, v)
		}
	}

	// End-to-end headers should be preserved.
	if v := h.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type should be preserved, got %q", v)
	}
	if v := h.Get("X-Custom"); v != "value" {
		t.Errorf("X-Custom should be preserved, got %q", v)
	}
}

func TestStripHopByHopHeaders_ConnectionDesignated(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Internal-Auth, X-Secret")
	h.Set("X-Internal-Auth", "admin")
	h.Set("X-Secret", "s3cret")
	h.Set("X-Normal", "keep")

	stripHopByHopHeaders(h, false)

	// Headers designated by Connection should be stripped.
	if v := h.Get("X-Internal-Auth"); v != "" {
		t.Errorf("X-Internal-Auth should be stripped, got %q", v)
	}
	if v := h.Get("X-Secret"); v != "" {
		t.Errorf("X-Secret should be stripped, got %q", v)
	}

	// Non-designated headers should be preserved.
	if v := h.Get("X-Normal"); v != "keep" {
		t.Errorf("X-Normal should be preserved, got %q", v)
	}
}

func TestStripHopByHopHeaders_WebSocket(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "websocket")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Bearer xyz")
	h.Set("Sec-WebSocket-Key", "dGVzdA==")

	stripHopByHopHeaders(h, true)

	// Connection should be preserved as "Upgrade" for WebSocket.
	if v := h.Get("Connection"); v != "Upgrade" {
		t.Errorf("Connection should be 'Upgrade' for WebSocket, got %q", v)
	}

	// Upgrade header should be preserved for WebSocket.
	if v := h.Get("Upgrade"); v != "websocket" {
		t.Errorf("Upgrade should be preserved for WebSocket, got %q", v)
	}

	// Other hop-by-hop headers should still be stripped.
	if v := h.Get("Keep-Alive"); v != "" {
		t.Errorf("Keep-Alive should be stripped, got %q", v)
	}
	if v := h.Get("Proxy-Authorization"); v != "" {
		t.Errorf("Proxy-Authorization should be stripped, got %q", v)
	}

	// WebSocket-specific headers should be preserved.
	if v := h.Get("Sec-WebSocket-Key"); v != "dGVzdA==" {
		t.Errorf("Sec-WebSocket-Key should be preserved, got %q", v)
	}
}

func TestStripHopByHopHeaders_WebSocket_ConnectionDesignated(t *testing.T) {
	// Connection designates both Upgrade and a custom header.
	h := http.Header{}
	h.Set("Connection", "Upgrade, X-Smuggled")
	h.Set("Upgrade", "websocket")
	h.Set("X-Smuggled", "evil")
	h.Set("X-Legit", "ok")

	stripHopByHopHeaders(h, true)

	// Upgrade should be preserved (WebSocket exemption).
	if v := h.Get("Upgrade"); v != "websocket" {
		t.Errorf("Upgrade should be preserved, got %q", v)
	}

	// X-Smuggled was designated by Connection, so should be stripped.
	if v := h.Get("X-Smuggled"); v != "" {
		t.Errorf("X-Smuggled should be stripped, got %q", v)
	}

	// Connection should be normalized to "Upgrade".
	if v := h.Get("Connection"); v != "Upgrade" {
		t.Errorf("Connection should be 'Upgrade', got %q", v)
	}

	// Non-designated header preserved.
	if v := h.Get("X-Legit"); v != "ok" {
		t.Errorf("X-Legit should be preserved, got %q", v)
	}
}

func TestStripHopByHopHeaders_EmptyHeaders(t *testing.T) {
	h := http.Header{}
	// Should not panic on empty headers.
	stripHopByHopHeaders(h, false)
	stripHopByHopHeaders(h, true)
}

func TestStripHopByHopHeaders_MultipleConnectionValues(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "X-Foo")
	h.Add("Connection", "X-Bar")
	h.Set("X-Foo", "foo")
	h.Set("X-Bar", "bar")
	h.Set("X-Baz", "baz")

	stripHopByHopHeaders(h, false)

	if v := h.Get("X-Foo"); v != "" {
		t.Errorf("X-Foo should be stripped, got %q", v)
	}
	if v := h.Get("X-Bar"); v != "" {
		t.Errorf("X-Bar should be stripped, got %q", v)
	}
	if v := h.Get("X-Baz"); v != "baz" {
		t.Errorf("X-Baz should be preserved, got %q", v)
	}
}
