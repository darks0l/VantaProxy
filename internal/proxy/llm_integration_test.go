package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/darksol/Vanta/internal/admin"
	"github.com/darksol/Vanta/internal/approval"
	"github.com/darksol/Vanta/internal/audit"
	"github.com/darksol/Vanta/internal/judge"
	"github.com/darksol/Vanta/internal/llm"
	"github.com/darksol/Vanta/internal/llmpolicy"
	"github.com/darksol/Vanta/internal/notifications"
	"github.com/darksol/Vanta/pkg/types"
)

// --------------------------------------------------------------------------
// Controllable adapter (implements llm.Adapter, records requests)
// --------------------------------------------------------------------------

// llmJudgeSpy is a controllable llm.Adapter that records every completion call.
type llmJudgeSpy struct {
	mu       sync.Mutex
	respText string
	respErr  error
	calls    []llm.Request
}

func (s *llmJudgeSpy) Complete(_ context.Context, req llm.Request) (llm.Response, error) {
	s.mu.Lock()
	s.calls = append(s.calls, req)
	text, err := s.respText, s.respErr
	s.mu.Unlock()
	return llm.Response{Text: text}, err
}

func (s *llmJudgeSpy) ModelID() string { return "test" }

func (s *llmJudgeSpy) setAllow(reason string) {
	s.mu.Lock()
	s.respText = `{"decision":"ALLOW","reason":"` + reason + `"}`
	s.respErr = nil
	s.mu.Unlock()
}

func (s *llmJudgeSpy) setDeny(reason string) {
	s.mu.Lock()
	s.respText = `{"decision":"DENY","reason":"` + reason + `"}`
	s.respErr = nil
	s.mu.Unlock()
}

func (s *llmJudgeSpy) setError(err error) {
	s.mu.Lock()
	s.respErr = err
	s.mu.Unlock()
}

func (s *llmJudgeSpy) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *llmJudgeSpy) lastRequest() llm.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return llm.Request{}
	}
	return s.calls[len(s.calls)-1]
}

// --------------------------------------------------------------------------
// Constants for LLM tests
// --------------------------------------------------------------------------

const (
	llmUserID         = "llm-alice"
	llmPolicy         = "Allow read-only GitHub access only. Deny any write operations."
	llmNoPromptUserID = "llm-noprompt"
)

// --------------------------------------------------------------------------
// Test environment
// --------------------------------------------------------------------------

type llmTestEnv struct {
	backend        *httptest.Server
	proxy          *httptest.Server
	adminServer    *httptest.Server
	spy            *llmJudgeSpy // the underlying adapter; use with judge.NewLLMJudge(env.spy)
	auditReader    admin.AuditReaderIface
	mgr            *approval.Manager
	gatToken       string // gateway auth token for llmUserID
	gatNoPromptTok string // gateway auth token for llmNoPromptUserID (no policy prompt)
	policyID       string // llm_policy_id assigned to llmUserID
}

// newLLMTestEnv assembles proxy + admin servers wired with a controllable judge.
// The judge starts configured to ALLOW with fallback set to fallbackMode.
func newLLMTestEnv(t *testing.T, fallbackMode string) *llmTestEnv {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"method": r.Method,
			"path":   r.URL.Path,
			"body":   string(body),
		})
	}))

	spy := &llmJudgeSpy{}
	spy.setAllow("allowed by policy")

	mgr := newTestManager(t)
	mgr.SetJudge(judge.NewLLMJudge(spy), "llm", fallbackMode)

	// Seed the LLM test user's policy prompt and gateway auth token.
	policyID := seedUser(t, llmUserID, llmPolicy)
	gatToken := seedGatewayAuthChannel(t, llmUserID)

	// Seed a second user with no policy prompt (for no-prompt fallback tests).
	ensureUser(t, llmNoPromptUserID)
	gatNoPromptTok := seedGatewayAuthChannel(t, llmNoPromptUserID)

	userResolver := admin.NewPGUserStore(testPool)

	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := audit.NewLogger(auditFile)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	auditReader := newPGAuditReader()

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), userResolver, true)
	handler.llmResponseWriter = newPGEvalStore()
	// Test backends run on 127.0.0.1; allow private networks so the SSRF
	// filter does not block connections to loopback test servers.
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	proxyServer := httptest.NewServer(handler)

	sseChannel := notifications.NewSSEChannel("web")
	apiInstance := admin.NewAPI(auditReader, nil, sseChannel, &integrationAdminValidator{}, nil)
	apiInstance.SetLLMPolicyStore(llmpolicy.NewPGStore(testPool))
	adminMux := http.NewServeMux()
	apiInstance.RegisterRoutes(adminMux)
	adminServer := httptest.NewServer(adminMux)

	t.Cleanup(func() {
		backend.Close()
		proxyServer.Close()
		adminServer.Close()
		auditLogger.Close()
	})

	return &llmTestEnv{
		backend:        backend,
		proxy:          proxyServer,
		adminServer:    adminServer,
		spy:            spy,
		auditReader:    auditReader,
		mgr:            mgr,
		gatToken:       gatToken,
		gatNoPromptTok: gatNoPromptTok,
		policyID:       policyID,
	}
}

// do makes a proxied request carrying the dummy Authorization token and gateway auth token.
// Pass bodyStr="" for no body.
func (e *llmTestEnv) do(t *testing.T, method, targetURL, bodyStr string) *http.Response {
	t.Helper()
	proxyURL, _ := url.Parse(e.proxy.URL)
	proxyURL.User = url.UserPassword(e.gatToken, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	var bodyReader io.Reader
	if bodyStr != "" {
		bodyReader = bytes.NewBufferString(bodyStr)
	}
	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bodyStr != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, targetURL, err)
	}
	return resp
}

// doWithoutCreds makes a proxied request for a user with no policy prompt configured.
// Gateway auth is still required; this uses the no-prompt user's token.
func (e *llmTestEnv) doWithoutCreds(t *testing.T, method, targetURL string) *http.Response {
	t.Helper()
	proxyURL, _ := url.Parse(e.proxy.URL)
	proxyURL.User = url.UserPassword(e.gatNoPromptTok, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, targetURL, err)
	}
	return resp
}


// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestLLMIntegration_Allow verifies that a judge ALLOW decision forwards the
// request to the backend and returns a 200.
func TestLLMIntegration_Allow(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("read access is fine")

	resp := env.do(t, "POST", env.backend.URL+"/api/data", `{"key":"value"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if env.spy.callCount() != 1 {
		t.Errorf("expected judge called once, got %d", env.spy.callCount())
	}
}

// TestLLMIntegration_Deny verifies that a judge DENY decision returns 403 and
// the backend is never reached.
func TestLLMIntegration_Deny(t *testing.T) {
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	spy := &llmJudgeSpy{}
	spy.setDeny("write operations are not allowed")

	mgr := newTestManager(t)
	mgr.SetJudge(judge.NewLLMJudge(spy), "llm", "deny")
	seedUser(t, llmUserID, llmPolicy)
	gatToken := seedGatewayAuthChannel(t, llmUserID)

	userResolver := admin.NewPGUserStore(testPool)
	auditLogger, _ := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	defer auditLogger.Close()

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), userResolver, true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	proxyURL.User = url.UserPassword(gatToken, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	req, _ := http.NewRequest("POST", backend.URL+"/api/data", bytes.NewBufferString(`{}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if backendCalled {
		t.Error("backend should not be called on DENY")
	}
	if spy.callCount() != 1 {
		t.Errorf("expected judge called once, got %d", spy.callCount())
	}
}

// TestLLMIntegration_GETAlsoEvaluated verifies that GET requests go through the
// judge in LLM mode.
func TestLLMIntegration_GETAlsoEvaluated(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("reads are fine")

	resp := env.do(t, "GET", env.backend.URL+"/api/users", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if env.spy.callCount() != 1 {
		t.Errorf("expected GET to be evaluated by judge, got %d calls", env.spy.callCount())
	}
	req := env.spy.lastRequest()
	if len(req.Messages) == 0 || !strings.Contains(req.Messages[0].Content, `"method":"GET"`) {
		t.Errorf("expected method GET in adapter request user message")
	}
}

// TestLLMIntegration_GETDenied verifies that a GET can be blocked by the judge.
func TestLLMIntegration_GETDenied(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setDeny("no reads allowed")

	resp := env.do(t, "GET", env.backend.URL+"/api/users", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for denied GET, got %d", resp.StatusCode)
	}
}

// TestLLMIntegration_NoCaching verifies that identical requests each trigger a
// fresh judge call — the approval cache is bypassed in LLM mode.
func TestLLMIntegration_NoCaching(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("ok")

	const N = 3
	for i := range N {
		resp := env.do(t, "POST", env.backend.URL+"/api/data", `{"key":"value"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
	}

	if env.spy.callCount() != N {
		t.Errorf("expected judge called %d times (no caching), got %d", N, env.spy.callCount())
	}
}

// TestLLMIntegration_PolicyPromptPassedToJudge verifies that the policy prompt
// stored in the credential store for the requesting user is passed to the judge.
func TestLLMIntegration_PolicyPromptPassedToJudge(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("ok")

	resp := env.do(t, "GET", env.backend.URL+"/api/repos", "")
	defer resp.Body.Close()

	req := env.spy.lastRequest()
	if !strings.Contains(req.System, llmPolicy) {
		t.Errorf("expected policy prompt %q in system message, got: %s", llmPolicy, req.System)
	}
}

// TestLLMIntegration_FallbackDeny verifies that when the judge returns an error
// and fallback_mode=deny, the request is blocked with a 403.
func TestLLMIntegration_FallbackDeny(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setError(errors.New("bedrock unavailable"))

	resp := env.do(t, "POST", env.backend.URL+"/api/data", `{}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 on fallback=deny, got %d", resp.StatusCode)
	}
}

// TestLLMIntegration_NoPromptFallbackDeny verifies that a request with no
// credentials (and therefore no policy prompt) is blocked when fallback=deny.
func TestLLMIntegration_NoPromptFallbackDeny(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("should not be reached")

	// Request without any Authorization header — no user identified, no policy prompt.
	resp := env.doWithoutCreds(t, "POST", env.backend.URL+"/api/data")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when no prompt and fallback=deny, got %d", resp.StatusCode)
	}
	if env.spy.callCount() != 0 {
		t.Errorf("judge should not be called when there is no policy prompt, got %d calls", env.spy.callCount())
	}
}

// TestLLMIntegration_FallbackPassthrough verifies that when the judge errors and
// fallback_mode=passthrough, the request is allowed through immediately.
func TestLLMIntegration_FallbackPassthrough(t *testing.T) {
	env := newLLMTestEnv(t, "passthrough")
	env.spy.setError(errors.New("bedrock unavailable"))

	resp := env.do(t, "POST", env.backend.URL+"/api/data", `{}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on fallback=passthrough, got %d", resp.StatusCode)
	}
}

// TestLLMIntegration_NoPromptFallbackPassthrough verifies that a request with no
// policy prompt is allowed through when fallback=passthrough.
func TestLLMIntegration_NoPromptFallbackPassthrough(t *testing.T) {
	env := newLLMTestEnv(t, "passthrough")
	env.spy.setAllow("should not be reached")

	resp := env.doWithoutCreds(t, "POST", env.backend.URL+"/api/data")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 when no prompt and fallback=passthrough, got %d", resp.StatusCode)
	}
	if env.spy.callCount() != 0 {
		t.Errorf("judge should not be called when there is no policy prompt, got %d calls", env.spy.callCount())
	}
}

// TestLLMIntegration_AuditChannelIsLLM verifies that the audit log records
// channel="llm" and approved_by="llm" for decisions made by the judge.
func TestLLMIntegration_AuditChannelIsLLM(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("approved by policy")

	resp := env.do(t, "POST", env.backend.URL+"/api/resource", `{"x":1}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Give the audit logger a moment to flush the entry.
	time.Sleep(50 * time.Millisecond)

	entries := env.auditReader.Query(admin.AuditFilter{Limit: 10})
	if len(entries) == 0 {
		t.Fatal("no audit entries recorded")
	}
	e := entries[0]
	if e.Channel != "llm" {
		t.Errorf("expected channel=llm in audit, got %q", e.Channel)
	}
	if e.ApprovedBy != "llm" {
		t.Errorf("expected approved_by=llm in audit, got %q", e.ApprovedBy)
	}
	if e.Decision != "approved" {
		t.Errorf("expected decision=approved in audit, got %q", e.Decision)
	}
}

// TestLLMIntegration_AuditDeniedChannelIsLLM verifies audit entries for DENY
// decisions also carry channel="llm".
func TestLLMIntegration_AuditDeniedChannelIsLLM(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setDeny("not permitted")

	resp := env.do(t, "DELETE", env.backend.URL+"/api/resource", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	time.Sleep(50 * time.Millisecond)

	entries := env.auditReader.Query(admin.AuditFilter{Limit: 10})
	if len(entries) == 0 {
		t.Fatal("no audit entries recorded")
	}
	e := entries[0]
	if e.Channel != "llm" {
		t.Errorf("expected channel=llm for denied request, got %q", e.Channel)
	}
}

// TestLLMIntegration_JudgeReceivesCorrectMethodAndURL verifies that the judge
// sees the original HTTP method and target URL of each proxied request.
func TestLLMIntegration_JudgeReceivesCorrectMethodAndURL(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("ok")

	targetURL := env.backend.URL + "/specific/path"
	resp := env.do(t, "PATCH", targetURL, `{"field":"val"}`)
	defer resp.Body.Close()

	req := env.spy.lastRequest()
	if len(req.Messages) == 0 {
		t.Fatal("expected messages in adapter request")
	}
	content := req.Messages[0].Content
	if !strings.Contains(content, `"method":"PATCH"`) {
		t.Errorf("expected judge to see method=PATCH in user message, got: %s", content)
	}
	if !strings.Contains(content, `"url":"`+targetURL+`"`) {
		t.Errorf("expected judge to see URL=%q in user message, got: %s", targetURL, content)
	}
}

// TestAuditLog_LLMApproval verifies that when the LLM judge approves a request,
// the audit_log row in PostgreSQL contains the correct decision, channel,
// approved_by, user_id, llm_response_id, and that reason is populated via JOIN.
func TestAuditLog_LLMApproval(t *testing.T) {
	const judgeReason = "request is a safe read-only operation"

	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow(judgeReason)

	resp := env.do(t, "POST", env.backend.URL+"/api/data", `{"x":1}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	time.Sleep(50 * time.Millisecond)

	entries := env.auditReader.Query(admin.AuditFilter{Limit: 5})
	if len(entries) == 0 {
		t.Fatal("no audit entries found in database after LLM approval")
	}
	e := entries[0]

	if e.UserID != llmUserID {
		t.Errorf("user_id: want %q, got %q", llmUserID, e.UserID)
	}
	if e.Method != "POST" {
		t.Errorf("method: want POST, got %q", e.Method)
	}
	if e.Decision != "approved" {
		t.Errorf("decision: want approved, got %q", e.Decision)
	}
	if e.Channel != "llm" {
		t.Errorf("channel: want llm, got %q", e.Channel)
	}
	if e.ApprovedBy != "llm" {
		t.Errorf("approved_by: want llm, got %q", e.ApprovedBy)
	}
	// llm_reason populated via JOIN to llm_responses.
	if e.LLMReason != judgeReason {
		t.Errorf("llm_reason (via JOIN): want %q, got %q", judgeReason, e.LLMReason)
	}
	// llm_response_id must be set since the proxy now persists llm_responses rows.
	if e.LLMResponseID == "" {
		t.Error("llm_response_id: should be set after LLM approval")
	}
	if e.ResponseStatus != http.StatusOK {
		t.Errorf("response_status: want 200, got %d", e.ResponseStatus)
	}
	if e.CacheHit {
		t.Error("cache_hit: want false for first LLM-approved request")
	}
	if e.LLMPolicyID != env.policyID {
		t.Errorf("llm_policy_id: want %q, got %q", env.policyID, e.LLMPolicyID)
	}
}

// --------------------------------------------------------------------------
// LLM Policy admin API tests
// --------------------------------------------------------------------------

// policyAdminDo fires an authenticated request against the policy admin server.
func policyAdminDo(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, url, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatalf("policyAdminDo: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+integrationAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("policyAdminDo %s %s: %v", method, url, err)
	}
	return resp
}

// newPolicyAdminServer returns a minimal admin server wired with a real PG policy store.
func newPolicyAdminServer(t *testing.T) *httptest.Server {
	t.Helper()
	truncateTestTables(t)
	sseChannel := notifications.NewSSEChannel("web")
	apiInstance := admin.NewAPI(newPGAuditReader(), nil, sseChannel, &integrationAdminValidator{}, nil)
	apiInstance.SetLLMPolicyStore(llmpolicy.NewPGStore(testPool))
	mux := http.NewServeMux()
	apiInstance.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLLMPolicyAPI_CreateAndGet(t *testing.T) {
	srv := newPolicyAdminServer(t)

	// Create a policy.
	body := `{"name":"read-only","prompt":"Allow GET only","provider":"bedrock-anthropic","model":"claude-3"}`
	resp := policyAdminDo(t, http.MethodPost, srv.URL+"/admin/llm-policies", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, b)
	}

	var created map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("expected non-empty id in response")
	}
	if created["name"] != "read-only" {
		t.Errorf("name: want %q, got %v", "read-only", created["name"])
	}
	if created["prompt"] != "Allow GET only" {
		t.Errorf("prompt: want %q, got %v", "Allow GET only", created["prompt"])
	}
	if created["provider"] != "bedrock-anthropic" {
		t.Errorf("provider: want %q, got %v", "bedrock-anthropic", created["provider"])
	}
	if created["model"] != "claude-3" {
		t.Errorf("model: want %q, got %v", "claude-3", created["model"])
	}
	if _, ok := created["forked_from"]; ok {
		t.Errorf("expected no forked_from on new policy, got %v", created["forked_from"])
	}

	// Fetch by ID.
	getResp := policyAdminDo(t, http.MethodGet, srv.URL+"/admin/llm-policies/"+id, "")
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", getResp.StatusCode)
	}

	var fetched map[string]interface{}
	json.NewDecoder(getResp.Body).Decode(&fetched)
	if fetched["id"] != id {
		t.Errorf("id: want %q, got %v", id, fetched["id"])
	}
}

func TestLLMPolicyAPI_List(t *testing.T) {
	srv := newPolicyAdminServer(t)

	// Create two policies.
	for _, name := range []string{"policy-a", "policy-b"} {
		resp := policyAdminDo(t, http.MethodPost, srv.URL+"/admin/llm-policies", `{"name":"`+name+`","prompt":"p"}`)
		resp.Body.Close()
	}

	listResp := policyAdminDo(t, http.MethodGet, srv.URL+"/admin/llm-policies", "")
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", listResp.StatusCode)
	}

	var policies []map[string]interface{}
	json.NewDecoder(listResp.Body).Decode(&policies)
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestLLMPolicyAPI_Fork(t *testing.T) {
	srv := newPolicyAdminServer(t)

	// Create parent.
	resp := policyAdminDo(t, http.MethodPost, srv.URL+"/admin/llm-policies",
		`{"name":"parent","prompt":"original prompt","model":"claude-2"}`)
	var parent map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&parent)
	resp.Body.Close()
	parentID, _ := parent["id"].(string)

	// Fork creates a draft with the parent's content; editing happens in the draft editor.
	forkResp := policyAdminDo(t, http.MethodPost, srv.URL+"/admin/llm-policies/"+parentID+"/fork",
		`{"name":"child"}`)
	defer forkResp.Body.Close()
	if forkResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(forkResp.Body)
		t.Fatalf("expected 201, got %d: %s", forkResp.StatusCode, b)
	}

	var child map[string]interface{}
	json.NewDecoder(forkResp.Body).Decode(&child)

	childID, _ := child["id"].(string)
	if childID == "" || childID == parentID {
		t.Errorf("fork should produce a new distinct ID, got %q", childID)
	}
	if child["forked_from"] != parentID {
		t.Errorf("forked_from: want %q, got %v", parentID, child["forked_from"])
	}
	if child["name"] != "child" {
		t.Errorf("name: want %q, got %v", "child", child["name"])
	}
	if child["status"] != "draft" {
		t.Errorf("status: want draft, got %v", child["status"])
	}
	// Prompt and model should be inherited from parent.
	if child["prompt"] != "original prompt" {
		t.Errorf("prompt: want parent's prompt, got %v", child["prompt"])
	}
	if child["model"] != "claude-2" {
		t.Errorf("model: want %q (inherited), got %v", "claude-2", child["model"])
	}
}

func TestLLMPolicyAPI_GetNotFound(t *testing.T) {
	srv := newPolicyAdminServer(t)

	resp := policyAdminDo(t, http.MethodGet, srv.URL+"/admin/llm-policies/llmpol_doesnotexist", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestLLMPolicyAPI_ForkNotFound(t *testing.T) {
	srv := newPolicyAdminServer(t)

	resp := policyAdminDo(t, http.MethodPost, srv.URL+"/admin/llm-policies/llmpol_doesnotexist/fork",
		`{"name":"child"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 forking non-existent parent, got %d", resp.StatusCode)
	}
}

func TestLLMPolicyAPI_CreateMissingName(t *testing.T) {
	srv := newPolicyAdminServer(t)

	resp := policyAdminDo(t, http.MethodPost, srv.URL+"/admin/llm-policies", `{"prompt":"no name here"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 when name is missing, got %d", resp.StatusCode)
	}
}

// TestStaticRule_Integration verifies the full path: a policy with static rules
// is stored in the DB, loaded via GetLLMPolicyForUser, and requests matching
// the rule are decided without calling the judge, while
// non-matching requests are forwarded to the judge as normal (channel="llm").
func TestPassthroughRule_Integration(t *testing.T) {
	env := newLLMTestEnv(t, "deny")

	// Create a separate user with a policy that has a passthrough rule for GET requests.
	const ptUserID = "llm-static-rule-user"
	passthroughPolicyID := seedLLMPolicyWithRules(t, "static-allow-policy", "deny everything", []types.StaticRule{
		{Methods: []string{"GET"}, URLPattern: env.backend.URL + "/", MatchType: "prefix", Action: "allow"},
	})
	ensureUser(t, ptUserID)
	_, err := testPool.Exec(context.Background(), `
		UPDATE users SET llm_policy_id = $1 WHERE id = $2
	`, passthroughPolicyID, ptUserID)
	if err != nil {
		t.Fatalf("assign policy to passthrough user: %v", err)
	}
	ptGatToken := seedGatewayAuthChannel(t, ptUserID)

	doAs := func(method, targetURL, bodyStr string) *http.Response {
		t.Helper()
		proxyURL, _ := url.Parse(env.proxy.URL)
		proxyURL.User = url.UserPassword(ptGatToken, "")
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   10 * time.Second,
		}
		var bodyReader io.Reader
		if bodyStr != "" {
			bodyReader = bytes.NewBufferString(bodyStr)
		}
		req, _ := http.NewRequest(method, targetURL, bodyReader)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, targetURL, err)
		}
		return resp
	}

	// GET matches the passthrough rule — judge must not be called, request forwarded.
	callsBefore := env.spy.callCount()
	resp := doAs("GET", env.backend.URL+"/api/data", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET passthrough: expected 200, got %d", resp.StatusCode)
	}
	if env.spy.callCount() != callsBefore {
		t.Errorf("GET passthrough: judge should not be called, got %d new calls", env.spy.callCount()-callsBefore)
	}

	// POST does not match the rule (method mismatch) — judge must be called.
	env.spy.setAllow("post is fine")
	callsBefore = env.spy.callCount()
	resp = doAs("POST", env.backend.URL+"/api/data", `{}`)
	resp.Body.Close()
	if env.spy.callCount() != callsBefore+1 {
		t.Errorf("POST non-passthrough: expected judge called once, got %d new calls", env.spy.callCount()-callsBefore)
	}

	// Check the audit log: GET entry should have channel="policy", POST should have channel="llm".
	time.Sleep(50 * time.Millisecond)
	entries := env.auditReader.Query(admin.AuditFilter{UserID: ptUserID, Limit: 10})
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 audit entries for passthrough user, got %d", len(entries))
	}

	byMethod := map[string]types.AuditEntry{}
	for _, e := range entries {
		byMethod[e.Method] = e
	}

	getEntry, ok := byMethod["GET"]
	if !ok {
		t.Fatal("no GET audit entry found")
	}
	if getEntry.Channel != "llm" {
		t.Errorf("GET channel: want %q, got %q", "llm", getEntry.Channel)
	}
	if getEntry.ApprovedBy != "llm-static-rule" {
		t.Errorf("GET approved_by: want %q, got %q", "llm-static-rule", getEntry.ApprovedBy)
	}
	if getEntry.LLMPolicyID != passthroughPolicyID {
		t.Errorf("GET llm_policy_id: want %q, got %q", passthroughPolicyID, getEntry.LLMPolicyID)
	}

	postEntry, ok := byMethod["POST"]
	if !ok {
		t.Fatal("no POST audit entry found")
	}
	if postEntry.Channel != "llm" {
		t.Errorf("POST channel: want %q, got %q", "llm", postEntry.Channel)
	}
}

// TestStaticDenyRule_Integration verifies that a policy with a deny static rule blocks
// matching requests immediately (judge not called, response is 403), while non-matching
// requests are forwarded to the judge as normal.
func TestStaticDenyRule_Integration(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)

	env := newLLMTestEnv(t, "deny")

	const denyUserID = "llm-static-deny-user"
	denyPolicyID := seedLLMPolicyWithRules(t, "static-deny-policy", "allow everything", []types.StaticRule{
		{Methods: []string{"DELETE"}, URLPattern: env.backend.URL + "/", MatchType: "prefix", Action: "deny"},
	})
	ensureUser(t, denyUserID)
	_, err := testPool.Exec(context.Background(), `
		UPDATE users SET llm_policy_id = $1 WHERE id = $2
	`, denyPolicyID, denyUserID)
	if err != nil {
		t.Fatalf("assign policy to deny user: %v", err)
	}
	denyGatToken := seedGatewayAuthChannel(t, denyUserID)

	doAs := func(method, targetURL, bodyStr string) *http.Response {
		t.Helper()
		proxyURL, _ := url.Parse(env.proxy.URL)
		proxyURL.User = url.UserPassword(denyGatToken, "")
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   10 * time.Second,
		}
		var bodyReader io.Reader
		if bodyStr != "" {
			bodyReader = bytes.NewBufferString(bodyStr)
		}
		req, _ := http.NewRequest(method, targetURL, bodyReader)
		resp, respErr := client.Do(req)
		if respErr != nil {
			t.Fatalf("%s %s: %v", method, targetURL, respErr)
		}
		return resp
	}

	// DELETE matches the deny rule — judge must not be called, request blocked (403).
	callsBefore := env.spy.callCount()
	resp := doAs("DELETE", env.backend.URL+"/api/resource/1", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE deny: expected 403, got %d", resp.StatusCode)
	}
	if env.spy.callCount() != callsBefore {
		t.Errorf("DELETE deny: judge should not be called, got %d new calls", env.spy.callCount()-callsBefore)
	}

	// GET does not match the deny rule — judge must be called (env allows by default).
	env.spy.setAllow("get is fine")
	callsBefore = env.spy.callCount()
	resp = doAs("GET", env.backend.URL+"/api/resource/1", "")
	resp.Body.Close()
	if env.spy.callCount() != callsBefore+1 {
		t.Errorf("GET non-deny: expected judge called once, got %d new calls", env.spy.callCount()-callsBefore)
	}

	// Check audit log entries.
	time.Sleep(50 * time.Millisecond)
	entries := env.auditReader.Query(admin.AuditFilter{UserID: denyUserID, Limit: 10})
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 audit entries for deny user, got %d", len(entries))
	}

	byMethod := map[string]types.AuditEntry{}
	for _, e := range entries {
		byMethod[e.Method] = e
	}

	delEntry, ok := byMethod["DELETE"]
	if !ok {
		t.Fatal("no DELETE audit entry found")
	}
	if delEntry.Decision != "denied" {
		t.Errorf("DELETE decision: want %q, got %q", "denied", delEntry.Decision)
	}
	if delEntry.ApprovedBy != "llm-static-rule" {
		t.Errorf("DELETE approved_by: want %q, got %q", "llm-static-rule", delEntry.ApprovedBy)
	}
	if delEntry.LLMPolicyID != denyPolicyID {
		t.Errorf("DELETE llm_policy_id: want %q, got %q", denyPolicyID, delEntry.LLMPolicyID)
	}

	getEntry, ok := byMethod["GET"]
	if !ok {
		t.Fatal("no GET audit entry found")
	}
	if getEntry.Channel != "llm" {
		t.Errorf("GET channel: want %q, got %q", "llm", getEntry.Channel)
	}
}

func TestLLMPolicyAPI_NoStoreReturns503(t *testing.T) {
	truncateTestTables(t)
	sseChannel := notifications.NewSSEChannel("web")
	// No policy store wired, but auth must pass to reach the 503.
	apiInstance := admin.NewAPI(newPGAuditReader(), nil, sseChannel, &integrationAdminValidator{}, nil)
	mux := http.NewServeMux()
	apiInstance.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{"/admin/llm-policies", "/admin/llm-policies/some-id"} {
		resp := policyAdminDo(t, http.MethodGet, srv.URL+path, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("GET %s: expected 503, got %d", path, resp.StatusCode)
		}
	}
}

// --------------------------------------------------------------------------
// Content-Encoding bypass tests (P-01)
// --------------------------------------------------------------------------

// gzipCompress returns the gzip-compressed form of data.
// extractJudgeBody parses the JSON user message from the judge and returns the
// "body" field value. This is needed because the user message is now a JSON
// object, so nested JSON in the body is escaped (e.g. `{\"key\":\"val\"}`).
func extractJudgeBody(t *testing.T, userMsg string) string {
	t.Helper()
	var msg struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(userMsg), &msg); err != nil {
		t.Fatalf("failed to parse judge user message as JSON: %v", err)
	}
	return msg.Body
}

func gzipCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// zlibCompress returns the zlib-wrapped (RFC 1950) compressed form of data.
// This is the correct format for HTTP "deflate" Content-Encoding.
func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// rawDeflateCompress returns raw DEFLATE (RFC 1951) compressed data.
// Some non-conformant clients send this format with Content-Encoding: deflate.
func rawDeflateCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// TestLLMIntegration_GzipRequestBodyDecompressed verifies that when a request
// is sent with Content-Encoding: gzip, the LLM judge receives the decompressed
// plaintext body (not binary garbage) and the Content-Encoding header is
// stripped from the eval headers. The upstream must still receive the original
// compressed body unchanged.
func TestLLMIntegration_GzipRequestBodyDecompressed(t *testing.T) {
	plaintext := `{"action":"delete","resource":"prod-db"}`
	compressed := gzipCompress(t, []byte(plaintext))

	// Track what the upstream actually receives.
	var upstreamBody []byte
	var upstreamCE string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCE = r.Header.Get("Content-Encoding")
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	spy := &llmJudgeSpy{}
	spy.setAllow("ok")

	mgr := newTestManager(t)
	mgr.SetJudge(judge.NewLLMJudge(spy), "llm", "deny")
	seedUser(t, llmUserID, llmPolicy)
	gatToken := seedGatewayAuthChannel(t, llmUserID)

	userResolver := admin.NewPGUserStore(testPool)
	auditLogger, _ := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	defer auditLogger.Close()

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), userResolver, true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	proxyURL.User = url.UserPassword(gatToken, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequest("POST", backend.URL+"/api/data", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// 1. The judge must have been called with the decompressed body.
	if spy.callCount() != 1 {
		t.Fatalf("expected judge called once, got %d", spy.callCount())
	}
	judgeReq := spy.lastRequest()
	userMsg := judgeReq.Messages[0].Content
	judgeBody := extractJudgeBody(t, userMsg)
	if judgeBody != plaintext {
		t.Errorf("judge should see decompressed plaintext body %q, got: %q", plaintext, judgeBody)
	}

	// 2. The Content-Encoding and Content-Length headers must NOT appear in the eval headers.
	if strings.Contains(userMsg, "Content-Encoding") {
		t.Errorf("Content-Encoding header should be stripped from eval headers, got:\n%s", userMsg)
	}
	if strings.Contains(userMsg, "Content-Length") {
		t.Errorf("Content-Length header should be stripped from eval headers (reflects compressed size), got:\n%s", userMsg)
	}

	// 3. The upstream must have received the original compressed body unchanged.
	if !bytes.Equal(upstreamBody, compressed) {
		t.Errorf("upstream should receive original compressed body (%d bytes), got %d bytes", len(compressed), len(upstreamBody))
	}
	if upstreamCE != "gzip" {
		t.Errorf("upstream Content-Encoding should be 'gzip', got %q", upstreamCE)
	}
}

// TestLLMIntegration_DeflateZlibRequestBodyDecompressed verifies the primary
// zlib (RFC 1950) deflate path — the correct format for HTTP "deflate".
func TestLLMIntegration_DeflateZlibRequestBodyDecompressed(t *testing.T) {
	plaintext := `{"action":"drop-table","table":"users"}`
	compressed := zlibCompress(t, []byte(plaintext))

	var upstreamBody []byte
	var upstreamCE string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCE = r.Header.Get("Content-Encoding")
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	spy := &llmJudgeSpy{}
	spy.setAllow("ok")

	mgr := newTestManager(t)
	mgr.SetJudge(judge.NewLLMJudge(spy), "llm", "deny")
	seedUser(t, llmUserID, llmPolicy)
	gatToken := seedGatewayAuthChannel(t, llmUserID)

	userResolver := admin.NewPGUserStore(testPool)
	auditLogger, _ := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	defer auditLogger.Close()

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), userResolver, true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	proxyURL.User = url.UserPassword(gatToken, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequest("POST", backend.URL+"/api/data", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "deflate")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if spy.callCount() != 1 {
		t.Fatalf("expected judge called once, got %d", spy.callCount())
	}
	judgeReq := spy.lastRequest()
	userMsg := judgeReq.Messages[0].Content
	judgeBody := extractJudgeBody(t, userMsg)
	if judgeBody != plaintext {
		t.Errorf("judge should see decompressed plaintext body %q, got: %q", plaintext, judgeBody)
	}
	if strings.Contains(userMsg, "Content-Encoding") {
		t.Errorf("Content-Encoding header should be stripped from eval headers, got:\n%s", userMsg)
	}
	if !bytes.Equal(upstreamBody, compressed) {
		t.Errorf("upstream should receive original compressed body (%d bytes), got %d bytes", len(compressed), len(upstreamBody))
	}
	if upstreamCE != "deflate" {
		t.Errorf("upstream Content-Encoding should be 'deflate', got %q", upstreamCE)
	}
}

// TestLLMIntegration_DeflateRawRequestBodyDecompressed verifies the raw DEFLATE
// (RFC 1951) fallback path — used by non-conformant clients.
func TestLLMIntegration_DeflateRawRequestBodyDecompressed(t *testing.T) {
	plaintext := `{"action":"drop-table","table":"users"}`
	compressed := rawDeflateCompress(t, []byte(plaintext))

	// Track what the upstream actually receives.
	var upstreamBody []byte
	var upstreamCE string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCE = r.Header.Get("Content-Encoding")
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	spy := &llmJudgeSpy{}
	spy.setAllow("ok")

	mgr := newTestManager(t)
	mgr.SetJudge(judge.NewLLMJudge(spy), "llm", "deny")
	seedUser(t, llmUserID, llmPolicy)
	gatToken := seedGatewayAuthChannel(t, llmUserID)

	userResolver := admin.NewPGUserStore(testPool)
	auditLogger, _ := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	defer auditLogger.Close()

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), userResolver, true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	proxyURL.User = url.UserPassword(gatToken, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequest("POST", backend.URL+"/api/data", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "deflate")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Judge must see decompressed body.
	if spy.callCount() != 1 {
		t.Fatalf("expected judge called once, got %d", spy.callCount())
	}
	judgeReq := spy.lastRequest()
	userMsg := judgeReq.Messages[0].Content
	judgeBody := extractJudgeBody(t, userMsg)
	if judgeBody != plaintext {
		t.Errorf("judge should see decompressed plaintext body %q, got: %q", plaintext, judgeBody)
	}
	if strings.Contains(userMsg, "Content-Encoding") {
		t.Errorf("Content-Encoding header should be stripped from eval headers, got:\n%s", userMsg)
	}

	// The upstream must have received the original compressed body unchanged.
	if !bytes.Equal(upstreamBody, compressed) {
		t.Errorf("upstream should receive original compressed body (%d bytes), got %d bytes", len(compressed), len(upstreamBody))
	}
	if upstreamCE != "deflate" {
		t.Errorf("upstream Content-Encoding should be 'deflate', got %q", upstreamCE)
	}
}

// brotliCompress returns the brotli-compressed form of data.
func brotliCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, brotli.DefaultCompression)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// TestLLMIntegration_BrotliRequestBodyDecompressed verifies the same behaviour
// as gzip but with Content-Encoding: br.
func TestLLMIntegration_BrotliRequestBodyDecompressed(t *testing.T) {
	plaintext := `{"action":"wipe","scope":"everything"}`
	compressed := brotliCompress(t, []byte(plaintext))

	var upstreamBody []byte
	var upstreamCE string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCE = r.Header.Get("Content-Encoding")
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	spy := &llmJudgeSpy{}
	spy.setAllow("ok")

	mgr := newTestManager(t)
	mgr.SetJudge(judge.NewLLMJudge(spy), "llm", "deny")
	seedUser(t, llmUserID, llmPolicy)
	gatToken := seedGatewayAuthChannel(t, llmUserID)

	userResolver := admin.NewPGUserStore(testPool)
	auditLogger, _ := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	defer auditLogger.Close()

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), userResolver, true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	proxyURL.User = url.UserPassword(gatToken, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequest("POST", backend.URL+"/api/data", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "br")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// The judge must have been called with the decompressed body.
	if spy.callCount() != 1 {
		t.Fatalf("expected judge called once, got %d", spy.callCount())
	}
	judgeReq := spy.lastRequest()
	userMsg := judgeReq.Messages[0].Content
	judgeBody := extractJudgeBody(t, userMsg)
	if judgeBody != plaintext {
		t.Errorf("judge should see decompressed plaintext body %q, got: %q", plaintext, judgeBody)
	}
	if strings.Contains(userMsg, "Content-Encoding") {
		t.Errorf("Content-Encoding header should be stripped from eval headers, got:\n%s", userMsg)
	}

	// The upstream must have received the original compressed body unchanged.
	if !bytes.Equal(upstreamBody, compressed) {
		t.Errorf("upstream should receive original compressed body (%d bytes), got %d bytes", len(compressed), len(upstreamBody))
	}
	if upstreamCE != "br" {
		t.Errorf("upstream Content-Encoding should be 'br', got %q", upstreamCE)
	}
}

// TestLLMIntegration_UncompressedRequestUnchanged verifies that requests
// without Content-Encoding are passed through to the judge as-is.
func TestLLMIntegration_UncompressedRequestUnchanged(t *testing.T) {
	env := newLLMTestEnv(t, "deny")
	env.spy.setAllow("ok")

	plaintext := `{"safe":"data"}`
	resp := env.do(t, "POST", env.backend.URL+"/api/data", plaintext)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	judgeReq := env.spy.lastRequest()
	userMsg := judgeReq.Messages[0].Content
	judgeBody := extractJudgeBody(t, userMsg)
	if judgeBody != plaintext {
		t.Errorf("judge should see original plaintext body %q, got: %q", plaintext, judgeBody)
	}
}
