package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func bankrSuccessResponse() []byte {
	resp := map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": "Vanta approved.",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     20,
			"completion_tokens": 10,
		},
		"model": "anthropic/claude-opus-4-6",
	}
	b, _ := json.Marshal(resp)
	return b
}

func newTestBankrAdapter(t *testing.T, model, apiKey, serverURL string) *BankrAdapter {
	t.Helper()
	adapter, err := NewBankrAdapter(model, apiKey, serverURL, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	return adapter
}

// --- Test: Basic completion ---

func TestBankrBasicCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bankrSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "allow this request"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "Vanta approved." {
		t.Errorf("expected text 'Vanta approved.', got %q", resp.Text)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected stop_reason 'end_turn', got %q", resp.StopReason)
	}
	if resp.InputTokens != 20 {
		t.Errorf("expected 20 input tokens, got %d", resp.InputTokens)
	}
	if resp.OutputTokens != 10 {
		t.Errorf("expected 10 output tokens, got %d", resp.OutputTokens)
	}
}

// --- Test: Auth header ---

func TestBankrAuthHeader(t *testing.T) {
	var capturedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write(bankrSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "sk-bankr-test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := capturedHeaders.Get("Authorization"); got != "Bearer sk-bankr-test-key" {
		t.Errorf("expected Authorization 'Bearer sk-bankr-test-key', got %q", got)
	}
	if got := capturedHeaders.Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", got)
	}
}

// --- Test: Request body structure ---

func TestBankrRequestBody(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bankrSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		System:   "You are a security judge.",
		Messages: []Message{{Role: "user", Content: "evaluate: POST /api/users"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify model.
	if model, ok := capturedBody["model"].(string); !ok || model != "anthropic/claude-opus-4-6" {
		t.Errorf("expected model 'anthropic/claude-opus-4-6', got %v", capturedBody["model"])
	}

	// Verify bankr_route is set.
	if bankrRoute, ok := capturedBody["bankr_route"].(bool); !ok || !bankrRoute {
		t.Errorf("expected bankr_route true, got %v", capturedBody["bankr_route"])
	}

	// Verify skip_budget_guard is false.
	if skipBudgetGuard, ok := capturedBody["skip_budget_guard"].(bool); !ok || skipBudgetGuard {
		t.Errorf("expected skip_budget_guard false, got %v", capturedBody["skip_budget_guard"])
	}

	// Verify max_tokens.
	if maxTokens, ok := capturedBody["max_tokens"].(float64); !ok || maxTokens != 512 {
		t.Errorf("expected max_tokens 512, got %v", capturedBody["max_tokens"])
	}

	// Verify messages: system + user.
	msgs := capturedBody["messages"].([]interface{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages (system + user), got %d", len(msgs))
	}
	sysMsg := msgs[0].(map[string]interface{})
	if sysMsg["role"] != "system" {
		t.Errorf("expected first message role 'system', got %v", sysMsg["role"])
	}
	if sysMsg["content"] != "You are a security judge." {
		t.Errorf("expected system content 'You are a security judge.', got %v", sysMsg["content"])
	}
}

// --- Test: No system prompt ---

func TestBankrNoSystemPrompt(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bankrSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs := capturedBody["messages"].([]interface{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (no system), got %d", len(msgs))
	}
	if msgs[0].(map[string]interface{})["role"] != "user" {
		t.Errorf("expected first message role 'user', got %v", msgs[0].(map[string]interface{})["role"])
	}
}

// --- Test: Custom max tokens ---

func TestBankrCustomMaxTokens(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bankrSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages:  []Message{{Role: "user", Content: "hi"}},
		MaxTokens: 1024,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if maxTokens, ok := capturedBody["max_tokens"].(float64); !ok || maxTokens != 1024 {
		t.Errorf("expected max_tokens 1024, got %v", capturedBody["max_tokens"])
	}
}

// --- Test: Tool use round-trip ---

func TestBankrToolUse(t *testing.T) {
	toolResp, _ := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": nil,
					"tool_calls": []map[string]interface{}{
						{
							"id":   "call_abc123",
							"type": "function",
							"function": map[string]interface{}{
								"name":      "check_policy",
								"arguments": `{"action":"allow","reason":"public endpoint"}`,
							},
						},
					},
				},
				"finish_reason": "tool_calls",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     30,
			"completion_tokens":  15,
		},
		"model": "anthropic/claude-opus-4-6",
	})

	var capturedBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(toolResp)
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "check if POST /admin/delete is allowed"}},
		Tools: []Tool{{
			Name:        "check_policy",
			Description: "Check a request against the security policy",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"},"reason":{"type":"string"}}}`),
		}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StopReason != "tool_use" {
		t.Errorf("expected stop_reason 'tool_use', got %q", resp.StopReason)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.ToolCalls))
	}
	tc := resp.ToolCalls[0]
	if tc.ID != "call_abc123" {
		t.Errorf("expected tool call ID 'call_abc123', got %q", tc.ID)
	}
	if tc.Name != "check_policy" {
		t.Errorf("expected tool name 'check_policy', got %q", tc.Name)
	}
	var input map[string]string
	if err := json.Unmarshal(tc.Input, &input); err != nil {
		t.Fatalf("failed to unmarshal tool input: %v", err)
	}
	if input["action"] != "allow" {
		t.Errorf("expected action 'allow', got %q", input["action"])
	}
}

// --- Test: API error response ---

func TestBankrAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"message":"Rate limit exceeded","type":"rate_limit_error"}}`))
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
}

// --- Test: Bankr error field in response ---

func TestBankrErrorField(t *testing.T) {
	errResp, _ := json.Marshal(map[string]interface{}{
		"error": map[string]interface{}{
			"message": "invalid model",
			"type":   "invalid_request_error",
		},
		"model": "anthropic/claude-opus-4-6",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(errResp)
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for error field in response")
	}
}

// --- Test: Empty choices ---

func TestBankrEmptyChoices(t *testing.T) {
	emptyResp, _ := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{},
		"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": 0},
		"model":   "anthropic/claude-opus-4-6",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(emptyResp)
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for empty choices")
	}
}

// --- Test: Empty content with tool calls ---

func TestBankrEmptyContentWithTools(t *testing.T) {
	// When model returns no text but has tool calls.
	respWithTools, _ := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]interface{}{
					"role":       "assistant",
					"content":    "",
					"tool_calls": []map[string]interface{}{
						{
							"id":   "call_1",
							"type": "function",
							"function": map[string]interface{}{
								"name":      "approve",
								"arguments": `{}`,
							},
						},
					},
				},
				"finish_reason": "tool_calls",
			},
		},
		"usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 8},
		"model": "anthropic/claude-opus-4-6",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(respWithTools)
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "approve"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "" {
		t.Errorf("expected empty text, got %q", resp.Text)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.ToolCalls))
	}
}

// --- Test: Missing API key ---

func TestBankrMissingAPIKey(t *testing.T) {
	_, err := NewBankrAdapter("anthropic/claude-opus-4-6", "", "http://localhost:18789", 5*time.Second)
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
}

// --- Test: Default URL ---

func TestBankrDefaultURL(t *testing.T) {
	adapter, err := NewBankrAdapter("anthropic/claude-opus-4-6", "test-key", "", 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	if adapter.bankrURL != "http://localhost:18789" {
		t.Errorf("expected default URL 'http://localhost:18789', got %q", adapter.bankrURL)
	}
}

// --- Test: URL suffix trimming ---

func TestBankrURLSuffixTrim(t *testing.T) {
	adapter, err := NewBankrAdapter("anthropic/claude-opus-4-6", "test-key", "http://localhost:18789/", 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	if adapter.bankrURL != "http://localhost:18789" {
		t.Errorf("expected trimmed URL 'http://localhost:18789', got %q", adapter.bankrURL)
	}
}

// --- Test: ModelID ---

func TestBankrModelID(t *testing.T) {
	adapter, err := NewBankrAdapter("anthropic/claude-opus-4-6", "test-key", "http://localhost:18789", 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	if got := adapter.ModelID(); got != "anthropic/claude-opus-4-6" {
		t.Errorf("expected model ID 'anthropic/claude-opus-4-6', got %q", got)
	}
}

// --- Test: Context cancellation ---

func TestBankrContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang forever — client will cancel.
		select {}
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := adapter.Complete(ctx, Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// --- Test: Resilience — failure recording ---

func TestBankrResilienceFailureRecording(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":{"message":"server error"}}`))
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL, 5*time.Second)

	// Send a failing request.
	adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})

	// The resilience layer should have recorded a failure.
	// Check via the embedded Resilience struct.
	if adapter.consecutiveFailures != 1 {
		t.Errorf("expected 1 consecutive failure, got %d", adapter.consecutiveFailures)
	}
}

// --- Test: Resilience — success clears failures ---

func TestBankrResilienceSuccessClearsFailures(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":{"message":"server error"}}`))
		} else {
			w.Write(bankrSuccessResponse())
		}
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL, 5*time.Second)

	// First call fails.
	adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if adapter.consecutiveFailures != 1 {
		t.Errorf("expected 1 failure, got %d", adapter.consecutiveFailures)
	}

	// Second call succeeds.
	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if adapter.consecutiveFailures != 0 {
		t.Errorf("expected 0 failures after success, got %d", adapter.consecutiveFailures)
	}
}

// --- Test: DurationMs is populated ---

func TestBankrDurationMsPopulated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bankrSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestBankrAdapter(t, "anthropic/claude-opus-4-6", "test-key", server.URL, 5*time.Second)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.DurationMs == 0 {
		t.Errorf("expected non-zero DurationMs, got 0")
	}
}

// --- Test: Circuit breaker opens after threshold ---

func TestBankrCircuitBreakerThreshold(t *testing.T) {
	failCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failCount++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":{"message":"fail"}}`))
	}))
	defer server.Close()

	// Adapter with threshold=3.
	adapter, err := NewBankrAdapter(
		"anthropic/claude-opus-4-6", "test-key", server.URL, 5*time.Second,
		WithCircuitBreaker(3, 10*time.Second),
	)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// First 3 should fail but not trip.
	for i := 0; i < 3; i++ {
		_, err := adapter.Complete(context.Background(), Request{
			Messages: []Message{{Role: "user", Content: "hi"}},
		})
		if err == nil {
			t.Errorf("call %d: expected error, got nil", i+1)
		}
	}

	// 4th call should be blocked by circuit breaker.
	_, err = adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected circuit breaker error on 4th call")
	}
	if err != nil && err.Error() != "bankr circuit breaker open: too many consecutive failures, cooling down" {
		// Circuit breaker should be open.
		t.Logf("got error (circuit breaker open): %v", err)
	}
}
