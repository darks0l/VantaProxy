package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSSEChannel_NoCORSHeaders(t *testing.T) {
	ch := NewSSEChannel("test")

	// Create a request with a short-lived context so the handler returns quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/admin/events", nil)
	rec := httptest.NewRecorder()

	// ServeHTTPForUser runs until context is cancelled.
	ch.ServeHTTPForUser(rec, req, "user-1")

	resp := rec.Result()
	defer resp.Body.Close()

	// Content-Type should be text/event-stream (SSE still works).
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}

	// Must NOT have CORS headers.
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("expected no Access-Control-Allow-Origin header on SSE, got %q", v)
	}
}

func TestSSEChannel_SameOriginWorks(t *testing.T) {
	ch := NewSSEChannel("test")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/admin/events", nil)
	rec := httptest.NewRecorder()

	ch.ServeHTTPForUser(rec, req, "user-1")

	resp := rec.Result()
	defer resp.Body.Close()

	// Should get 200 with SSE content.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Body should contain the initial connected message.
	body := rec.Body.String()
	if len(body) == 0 {
		t.Error("expected SSE body with connected message, got empty")
	}
}
