package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSSEChannel_ReplacedClientExitsPromptly verifies that when a second
// connection for the same user replaces an existing one, the old goroutine
// terminates promptly (no CPU spin loop) and the new connection continues
// to function correctly.
func TestSSEChannel_ReplacedClientExitsPromptly(t *testing.T) {
	ch := NewSSEChannel("test")

	// --- Client A: first connection for user-1 ---
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	reqA, _ := http.NewRequestWithContext(ctxA, http.MethodGet, "/admin/events", nil)
	recA := httptest.NewRecorder()

	var wgA sync.WaitGroup
	wgA.Add(1)
	go func() {
		defer wgA.Done()
		ch.ServeHTTPForUser(recA, reqA, "user-1")
	}()

	// Wait for client A to register.
	waitForClients(t, ch, 1)

	// --- Client B: second connection for the same user, replaces A ---
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	reqB, _ := http.NewRequestWithContext(ctxB, http.MethodGet, "/admin/events", nil)
	recB := httptest.NewRecorder()

	var wgB sync.WaitGroup
	wgB.Add(1)
	go func() {
		defer wgB.Done()
		ch.ServeHTTPForUser(recB, reqB, "user-1")
	}()

	// Wait for client B to register (client count stays 1 because B replaces A).
	// Give a moment for setClient to run.
	time.Sleep(50 * time.Millisecond)

	// Client A's goroutine should exit promptly because its messages channel
	// was closed by setClient. If the spin loop bug is present, this will
	// time out.
	done := make(chan struct{})
	go func() {
		wgA.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Client A exited promptly -- good.
	case <-time.After(2 * time.Second):
		t.Fatal("client A goroutine did not exit after being replaced; likely stuck in spin loop")
	}

	// --- Verify client B still functions ---
	// Send a notification targeted at user-1 and confirm B receives it.
	err := ch.Notify(Event{
		Type:         EventAuditEntry,
		TargetUserID: "user-1",
	})
	if err != nil {
		t.Fatalf("Notify failed: %v", err)
	}

	// Give client B a moment to receive and write the message.
	time.Sleep(50 * time.Millisecond)

	// Stop client B so we can safely read its response body.
	// httptest.ResponseRecorder is not goroutine-safe, so we must wait
	// for the goroutine to finish before calling recB.Body.String().
	cancelB()
	wgB.Wait()

	bodyB := recB.Body.String()
	if !strings.Contains(bodyB, "event: audit_entry") {
		t.Errorf("client B did not receive the notification; body: %q", bodyB)
	}
}

// waitForClients polls until the channel has the expected number of clients
// or a timeout is reached.
func waitForClients(t *testing.T, ch *SSEChannel, expected int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ch.ClientCount() == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d client(s); have %d", expected, ch.ClientCount())
}
