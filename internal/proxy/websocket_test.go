package proxy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/darksol/Vanta/internal/admin"
	"github.com/darksol/Vanta/internal/audit"
	"github.com/darksol/Vanta/internal/judge"
	"github.com/darksol/Vanta/pkg/types"
)

// computeAcceptKey computes the Sec-WebSocket-Accept value per RFC 6455.
func computeAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-5AB5DC085B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsEchoServer returns an httptest.Server that accepts WebSocket upgrades and
// echoes all data back. Uses raw HTTP — no WebSocket library needed.
func wsEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		key := r.Header.Get("Sec-WebSocket-Key")
		accept := computeAcceptKey(key)

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		conn.Write([]byte(resp))

		// Echo all data until close.
		io.Copy(conn, conn)
	}))
}

// wsRejectServer returns an httptest.Server that rejects WebSocket upgrades with 403.
func wsRejectServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
}

// trackingHandler wraps an http.Handler with a WaitGroup so tests can
// deterministically wait for all in-flight requests (including WebSocket
// relay goroutines) to finish before tearing down shared resources.
type trackingHandler struct {
	http.Handler
	wg sync.WaitGroup
}

func (h *trackingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.wg.Add(1)
	defer h.wg.Done()
	h.Handler.ServeHTTP(w, r)
}

func (h *trackingHandler) Wait() { h.wg.Wait() }

// wsTestEnv bundles a proxy handler with cleanup that waits for in-flight
// relay goroutines before closing the audit logger.
type wsTestEnv struct {
	Handler     *trackingHandler
	AuditFile   string // path to the JSONL audit log
	auditLogger *audit.Logger
}

// Close waits for all in-flight handlers to finish, then closes the audit
// logger. Call after all client connections and the proxy server are closed.
func (e *wsTestEnv) Close() {
	e.Handler.Wait()
	e.auditLogger.Close()
}

// newWSTestEnv creates a proxy Handler in passthrough mode for WebSocket tests.
// Callers must defer env.Close() BEFORE deferring proxy server and connection closes
// so that cleanup runs in the right order (LIFO): close conn → close server → env.Close.
func newWSTestEnv(t *testing.T) *wsTestEnv {
	t.Helper()
	mgr := newTestManager(t)
	mgr.SetMode("passthrough")
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := audit.NewLogger(auditFile)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), nil, true)
	// Test backends run on 127.0.0.1; allow private networks so the SSRF
	// filter does not block connections to loopback test servers.
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	return &wsTestEnv{
		Handler:     &trackingHandler{Handler: handler},
		AuditFile:   auditFile,
		auditLogger: auditLogger,
	}
}

// wsConn wraps a net.Conn with a bufio.Reader so that bytes buffered
// during the HTTP response parse are not lost on subsequent reads.
type wsConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *wsConn) Read(b []byte) (int, error) { return c.br.Read(b) }

// dialWebSocketViaProxy connects to the proxy, sends a WebSocket upgrade for
// targetURL, and returns a connection (with buffered reader) and the upgrade response.
func dialWebSocketViaProxy(t *testing.T, proxyAddr, targetURL string) (*wsConn, *http.Response) {
	t.Helper()
	parsed, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	host := parsed.Host
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	wsKey := base64.StdEncoding.EncodeToString([]byte("test-websocket-key!"))
	reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: %s\r\n\r\n",
		path, host, wsKey)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		conn.Close()
		t.Fatalf("write upgrade request: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		t.Fatalf("read upgrade response: %v", err)
	}

	// Clear the handshake deadline so relay reads don't inherit it.
	conn.SetDeadline(time.Time{})

	return &wsConn{Conn: conn, br: br}, resp
}

func TestWebSocketUpgrade_PlainHTTP_Approved(t *testing.T) {
	backend := wsEchoServer(t)
	defer backend.Close()

	env := newWSTestEnv(t)
	defer env.Close() // runs last (LIFO): after conn and server close
	proxyServer := httptest.NewServer(env.Handler)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	// Connect to proxy and send WebSocket upgrade targeting the backend.
	conn, resp := dialWebSocketViaProxy(t, proxyAddr, backend.URL+"/ws")
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("expected Upgrade: websocket header, got %q", resp.Header.Get("Upgrade"))
	}

	// Send data and verify echo.
	msg := []byte("hello websocket")
	_, err := conn.Write(msg)
	if err != nil {
		t.Fatalf("write to websocket: %v", err)
	}

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read from websocket: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestWebSocketUpgrade_PlainHTTP_Denied(t *testing.T) {
	backend := wsEchoServer(t)
	defer backend.Close()

	// Create handler with gateway auth required — requests without valid
	// gateway token get 407.
	const testUserID = "ws-deny-test@example.com"
	mgr := newTestManager(t)
	mgr.SetMode("passthrough")
	ensureUser(t, testUserID)

	auditLogger, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), admin.NewPGUserStore(testPool), true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	tracked := &trackingHandler{Handler: handler}
	defer func() { tracked.Wait(); auditLogger.Close() }()
	proxyServer := httptest.NewServer(tracked)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	// Send WebSocket upgrade without gateway auth token — expect 407.
	conn, resp := dialWebSocketViaProxy(t, proxyAddr, backend.URL+"/ws")
	defer conn.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %d", resp.StatusCode)
	}
}

func TestWebSocketUpgrade_UpstreamRejects(t *testing.T) {
	backend := wsRejectServer(t)
	defer backend.Close()

	env := newWSTestEnv(t)
	defer env.Close()
	proxyServer := httptest.NewServer(env.Handler)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	conn, resp := dialWebSocketViaProxy(t, proxyAddr, backend.URL+"/ws")
	defer conn.Close()

	// Backend returns 403, proxy should relay it.
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestWebSocketUpgrade_BiDirectional(t *testing.T) {
	// Backend that sends data to the client then reads a response.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected websocket", http.StatusBadRequest)
			return
		}
		hijacker := w.(http.Hijacker)
		conn, _, _ := hijacker.Hijack()
		defer conn.Close()

		key := r.Header.Get("Sec-WebSocket-Key")
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		conn.Write([]byte(resp))

		// Server sends first, then reads.
		conn.Write([]byte("server-hello"))

		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if string(buf[:n]) != "client-hello" {
			conn.Write([]byte("MISMATCH"))
		} else {
			conn.Write([]byte("ok"))
		}
		// Backend closes connection after exchange, which terminates the relay.
	}))
	defer backend.Close()

	env := newWSTestEnv(t)
	defer env.Close()
	proxyServer := httptest.NewServer(env.Handler)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")
	conn, resp := dialWebSocketViaProxy(t, proxyAddr, backend.URL+"/ws")
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	// Set a deadline for the relay exchange so the test doesn't hang.
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read server's initial message.
	buf := make([]byte, len("server-hello"))
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read server message: %v", err)
	}
	if string(buf) != "server-hello" {
		t.Fatalf("expected 'server-hello', got %q", string(buf))
	}

	// Send client response.
	_, err = conn.Write([]byte("client-hello"))
	if err != nil {
		t.Fatalf("write client message: %v", err)
	}

	// Read server's confirmation.
	buf = make([]byte, len("ok"))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read confirmation: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("expected 'ok', got %q", string(buf))
	}
}

func TestWebSocketUpgrade_HTTPS_CONNECT(t *testing.T) {
	// Start a TLS backend that accepts WebSocket upgrades and echoes data.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		hijacker := w.(http.Hijacker)
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		key := r.Header.Get("Sec-WebSocket-Key")
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		conn.Write([]byte(resp))
		io.Copy(conn, conn)
	}))
	defer backend.Close()

	// Start a full proxy server with TLS MITM support.
	cfg := getTestConfig()
	proxyServer := newTestServer(t, cfg)
	go proxyServer.Start()
	defer proxyServer.Shutdown(context.Background())
	time.Sleep(100 * time.Millisecond)

	proxyAddr := fmt.Sprintf("localhost:%d", cfg.Proxy.Port)

	// Parse the backend's HTTPS address.
	backendURL, _ := url.Parse(backend.URL)

	// Step 1: CONNECT tunnel through the proxy.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backendURL.Host, backendURL.Host)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: expected 200, got %d", resp.StatusCode)
	}

	// Step 2: TLS handshake over the tunnel (trust the proxy's MITM cert).
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	// Step 3: Send WebSocket upgrade over the TLS connection.
	host := backendURL.Host
	wsKey := base64.StdEncoding.EncodeToString([]byte("test-wss-key-here!"))
	reqStr := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: %s\r\n\r\n",
		host, wsKey)

	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = tlsConn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	tlsBr := bufio.NewReader(tlsConn)
	wsResp, err := http.ReadResponse(tlsBr, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if wsResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", wsResp.StatusCode)
	}

	// Clear deadline for the relay.
	tlsConn.SetDeadline(time.Time{})

	// Step 4: Verify bidirectional data over the WebSocket.
	msg := []byte("hello wss")
	_, err = tlsConn.Write(msg)
	if err != nil {
		t.Fatalf("write to wss: %v", err)
	}

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(tlsBr, buf)
	if err != nil {
		t.Fatalf("read from wss: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

// TestWebSocketUpgrade_AbsoluteFormRequest tests that WebSocket upgrades work
// when the client sends an absolute-form request line (GET http://host/ws HTTP/1.1),
// which is what real explicit-proxy clients send per RFC 7230 §5.3.2.
func TestWebSocketUpgrade_AbsoluteFormRequest(t *testing.T) {
	backend := wsEchoServer(t)
	defer backend.Close()

	env := newWSTestEnv(t)
	defer env.Close()
	proxyServer := httptest.NewServer(env.Handler)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	// Dial the proxy directly and send an absolute-form request line.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	parsed, _ := url.Parse(backend.URL)
	wsKey := base64.StdEncoding.EncodeToString([]byte("abs-form-key-test!"))
	// Absolute-form: GET http://host:port/ws HTTP/1.1
	reqStr := fmt.Sprintf("GET %s/ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: %s\r\n\r\n",
		backend.URL, parsed.Host, wsKey)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte(reqStr))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	conn.SetDeadline(time.Time{})

	// Verify bidirectional echo works.
	msg := []byte("absolute-form-echo")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(br, buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

// TestWebSocketUpgrade_AuditEntry verifies that the audit log records the
// WEBSOCKET operation value and 101 status for approved WebSocket upgrades.
func TestWebSocketUpgrade_AuditEntry(t *testing.T) {
	backend := wsEchoServer(t)
	defer backend.Close()

	env := newWSTestEnv(t)
	defer env.Close()
	proxyServer := httptest.NewServer(env.Handler)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	conn, resp := dialWebSocketViaProxy(t, proxyAddr, backend.URL+"/ws")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	// Exchange data so the relay runs, then close to trigger the audit entry.
	conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	io.ReadFull(conn, buf)
	conn.Close()

	// Wait for handler to finish and flush the audit log.
	env.Handler.Wait()
	env.auditLogger.Close()

	entries := readWSAuditEntries(t, env.AuditFile)
	if len(entries) == 0 {
		t.Fatal("no audit entries written")
	}

	found := false
	for _, e := range entries {
		if e.Operation == "WEBSOCKET" {
			found = true
			if e.ResponseStatus != 101 {
				t.Errorf("expected response_status 101, got %d", e.ResponseStatus)
			}
			if e.Decision != "approved" {
				t.Errorf("expected decision 'approved', got %q", e.Decision)
			}
			if e.Method != "GET" {
				t.Errorf("expected method GET, got %q", e.Method)
			}
			break
		}
	}
	if !found {
		ops := make([]string, len(entries))
		for i, e := range entries {
			ops[i] = e.Operation
		}
		t.Fatalf("no audit entry with operation WEBSOCKET; got operations: %v", ops)
	}
}

// readWSAuditEntries reads JSONL audit entries from a file.
// Duplicated from integration_test.go to avoid cross-file coupling.
func readWSAuditEntries(t *testing.T, path string) []types.AuditEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entries []types.AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e types.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse audit entry %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

// TestWebSocketUpgrade_StaticDenyRule verifies that a static deny rule in an
// LLM policy blocks WebSocket upgrades to matched URLs, while allowing upgrades
// to non-matched URLs.
func TestWebSocketUpgrade_StaticDenyRule(t *testing.T) {
	backend := wsEchoServer(t)
	defer backend.Close()

	truncateTestTables(t)

	// Set up an LLM-mode manager with a controllable judge that allows by default.
	mgr := newTestManager(t)
	spy := &llmJudgeSpy{}
	spy.setAllow("allowed by policy")
	mgr.SetJudge(judge.NewLLMJudge(spy), "llm", "deny")

	// Seed a user with a static deny rule for /blocked.
	const userID = "ws-static-deny-user"
	denyPolicyID := seedLLMPolicyWithRules(t, "ws-deny-policy", "allow everything", []types.StaticRule{
		{Methods: []string{"GET"}, URLPattern: backend.URL + "/blocked", MatchType: "prefix", Action: "deny"},
	})
	ensureUser(t, userID)
	_, err := testPool.Exec(context.Background(), `
		UPDATE users SET llm_policy_id = $1 WHERE id = $2
	`, denyPolicyID, userID)
	if err != nil {
		t.Fatalf("assign policy: %v", err)
	}
	gatToken := seedGatewayAuthChannel(t, userID)

	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := audit.NewLogger(auditFile)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), admin.NewPGUserStore(testPool), true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	tracked := &trackingHandler{Handler: handler}
	defer func() { tracked.Wait(); auditLogger.Close() }()
	proxyServer := httptest.NewServer(tracked)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	sendUpgrade := func(t *testing.T, path string) (*wsConn, *http.Response) {
		t.Helper()
		parsed, _ := url.Parse(backend.URL)
		conn, dialErr := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if dialErr != nil {
			t.Fatalf("dial proxy: %v", dialErr)
		}
		wsKey := base64.StdEncoding.EncodeToString([]byte("static-deny-key!!"))
		reqStr := fmt.Sprintf("GET %s%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Proxy-Authorization: Basic %s\r\n\r\n",
			backend.URL, path, parsed.Host, wsKey,
			base64.StdEncoding.EncodeToString([]byte(gatToken+":")))
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(reqStr))
		br := bufio.NewReader(conn)
		resp, readErr := http.ReadResponse(br, nil)
		if readErr != nil {
			conn.Close()
			t.Fatalf("read response: %v", readErr)
		}
		conn.SetDeadline(time.Time{})
		return &wsConn{Conn: conn, br: br}, resp
	}

	// WebSocket upgrade to /blocked should be denied by the static rule.
	conn, resp := sendUpgrade(t, "/blocked")
	conn.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for denied path, got %d", resp.StatusCode)
	}

	// WebSocket upgrade to /ws should be allowed (judge approves).
	conn2, resp2 := sendUpgrade(t, "/ws")
	defer conn2.Close()
	if resp2.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 for allowed path, got %d", resp2.StatusCode)
	}

	// Verify echo works on the allowed connection.
	msg := []byte("policy-echo")
	conn2.Write(msg)
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn2, buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

// TestWebSocketUpgrade_SlowClient verifies that a slow client (one that stops
// reading data) causes only the slow direction to be torn down within the
// write timeout, rather than hanging for the full 30-minute idle timeout and
// killing the upstream connection.
//
// This is the core regression test for P-59: "WebSocket Slow Client Kills Upstream".
func TestWebSocketUpgrade_SlowClient(t *testing.T) {
	// Shorten timeouts so the test runs in ~2 seconds instead of 30 minutes.
	origWriteTimeout := wsWriteTimeout
	origIdleTimeout := wsIdleTimeout
	origDrainTimeout := wsDrainTimeout
	wsWriteTimeout = 500 * time.Millisecond
	wsIdleTimeout = 10 * time.Second // long enough that idle timeout does NOT fire
	wsDrainTimeout = 500 * time.Millisecond
	defer func() {
		wsWriteTimeout = origWriteTimeout
		wsIdleTimeout = origIdleTimeout
		wsDrainTimeout = origDrainTimeout
	}()

	// upstreamDone is closed when the upstream (backend) connection finishes.
	// We use this to verify that the upstream is NOT torn down prematurely
	// while the slow client is stalling.
	upstreamDone := make(chan time.Time, 1)

	// Backend continuously writes data to the client side of the WebSocket.
	// It records when its connection ends so we can verify timing.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		hijacker := w.(http.Hijacker)
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() {
			conn.Close()
			upstreamDone <- time.Now()
		}()

		key := r.Header.Get("Sec-WebSocket-Key")
		accept := computeAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		conn.Write([]byte(resp))

		// Continuously write data. When the proxy tears down the connection
		// due to the slow client, this write will fail and the goroutine exits.
		payload := make([]byte, 4096)
		for i := range payload {
			payload[i] = 'X'
		}
		for {
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
	}))
	defer backend.Close()

	env := newWSTestEnv(t)
	defer env.Close()
	proxyServer := httptest.NewServer(env.Handler)
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	// Connect through the proxy and complete the WebSocket upgrade.
	conn, resp := dialWebSocketViaProxy(t, proxyAddr, backend.URL+"/ws")
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	// Read a small amount to confirm the relay is working.
	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("initial read failed (relay not working): n=%d err=%v", n, err)
	}

	// Now simulate a slow/stalled client: stop reading entirely.
	// The proxy's write buffer to this client will fill up, blocking the
	// wsRelayWriter.Write call. The per-write deadline should fire and
	// tear down the slow direction.
	startStall := time.Now()

	// Wait for the upstream connection to be closed. With the fix, this
	// should happen after ~wsWriteTimeout (500ms) + wsDrainTimeout (500ms).
	// Without the fix, it would take wsIdleTimeout (30 minutes).
	select {
	case endTime := <-upstreamDone:
		elapsed := endTime.Sub(startStall)
		// Should complete well under the idle timeout. Allow generous
		// headroom (5s) for CI slowness, but the point is it must NOT
		// take 30 minutes (or even 10s, the shortened idle timeout).
		maxExpected := 5 * time.Second
		if elapsed > maxExpected {
			t.Errorf("slow client teardown took %v, expected under %v (write timeout is %v)",
				elapsed, maxExpected, wsWriteTimeout)
		}
		t.Logf("upstream closed after %v (write timeout=%v, drain timeout=%v)",
			elapsed, wsWriteTimeout, wsDrainTimeout)
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for upstream to close; slow client blocked the relay " +
			"for too long (the write timeout did not fire)")
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		upgrade    string
		want       bool
	}{
		{"valid", "Upgrade", "websocket", true},
		{"case insensitive", "upgrade", "WebSocket", true},
		{"comma separated", "keep-alive, Upgrade", "websocket", true},
		{"missing upgrade header", "Upgrade", "", false},
		{"missing connection header", "", "websocket", false},
		{"wrong upgrade protocol", "Upgrade", "h2c", false},
		{"no headers", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "http://example.com", nil)
			if tt.connection != "" {
				r.Header.Set("Connection", tt.connection)
			}
			if tt.upgrade != "" {
				r.Header.Set("Upgrade", tt.upgrade)
			}
			if got := isWebSocketUpgrade(r); got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}
