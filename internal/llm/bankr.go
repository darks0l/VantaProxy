package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BankrAdapter routes judge requests through the Bankr LLM gateway.
// Bankr handles multi-provider routing (Ollama, OpenAI, Anthropic, OpenRouter),
// automatic retries, budget guards, and quality-based fallback chains.
//
// This adapter implements the llm.Adapter interface so it slots into the existing
// judge pipeline as a first-class provider alongside Anthropic/Bedrock and OpenAI.
type BankrAdapter struct {
	httpClient  *http.Client
	bankrURL    string
	apiKey      string
	model       string
	timeout     time.Duration
	*Resilience
}

// NewBankrAdapter creates a BankrAdapter that routes through the Bankr gateway.
func NewBankrAdapter(model, apiKey, bankrURL string, timeout time.Duration, opts ...ResilienceOption) (*BankrAdapter, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("bankr API key is required")
	}
	if bankrURL == "" {
		bankrURL = "http://localhost:18789"
	}
	return &BankrAdapter{
		httpClient:  &http.Client{},
		bankrURL:    strings.TrimSuffix(bankrURL, "/"),
		apiKey:      apiKey,
		model:       model,
		timeout:     timeout,
		Resilience:  NewResilience(opts...),
	}, nil
}

func (a *BankrAdapter) ModelID() string { return a.model }

// Complete sends req to the Bankr gateway and returns the model's response.
func (a *BankrAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	if err := a.Acquire(ctx, "bankr"); err != nil {
		return Response{}, err
	}
	defer a.Release()

	timeout := a.timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 512
	}

	body := map[string]interface{}{
		"model":             a.model,
		"max_tokens":        maxTokens,
		"messages":          buildBankrMessages(req.System, req.Messages),
		"bankr_route":       true,
		"skip_budget_guard": false,
	}

	reqBytes, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, a.bankrURL+"/v1/chat/completions", bytes.NewReader(reqBytes))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)

	start := time.Now()
	httpResp, err := a.httpClient.Do(httpReq)
	durationMs := int(time.Since(start).Milliseconds())
	if err != nil {
		a.RecordFailure()
		return Response{DurationMs: durationMs}, fmt.Errorf("bankr request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		a.RecordFailure()
		errBody, _ := io.ReadAll(httpResp.Body)
		return Response{DurationMs: durationMs}, fmt.Errorf("bankr API error (status %d): %s", httpResp.StatusCode, string(errBody))
	}

	resp, parseErr := parseBankrResponse(httpResp.Body)
	if parseErr != nil {
		a.RecordFailure()
		resp.DurationMs = durationMs
		return resp, parseErr
	}

	a.RecordSuccess()
	resp.DurationMs = durationMs
	return resp, nil
}

// buildBankrMessages converts generic Messages to Bankr's OpenAI-compatible format.
func buildBankrMessages(system string, msgs []Message) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(msgs)+1)

	if system != "" {
		result = append(result, map[string]interface{}{
			"role":    "system",
			"content": system,
		})
	}

	for _, m := range msgs {
		result = append(result, buildOpenAIMessage(m))
	}
	return result
}

// parseBankrResponse decodes a Bankr gateway response into a generic Response.
// Bankr uses OpenAI-compatible response format.
func parseBankrResponse(r io.Reader) (Response, error) {
	type bankrUsage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}
	type bankrChoice struct {
		Message struct {
			Content   string `json:"content"`
			Role      string `json:"role"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}
	type bankrResponse struct {
		Choices []bankrChoice `json:"choices"`
		Usage   bankrUsage   `json:"usage"`
		Model   string       `json:"model"`
		Error   *struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}

	var resp bankrResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("failed to parse bankr response: %w", err)
	}

	if resp.Error != nil {
		return Response{}, fmt.Errorf("bankr error: %s (%s)", resp.Error.Message, resp.Error.Type)
	}

	if len(resp.Choices) == 0 {
		return Response{}, fmt.Errorf("empty choices in bankr response")
	}

	msg := resp.Choices[0].Message
	text := strings.TrimSpace(msg.Content)

	var toolCalls []ToolCall
	for _, tc := range msg.ToolCalls {
		toolCalls = append(toolCalls, ToolCall{
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: json.RawMessage(tc.Function.Arguments),
		})
	}

	if text == "" && len(toolCalls) == 0 {
		return Response{}, fmt.Errorf("empty content in bankr response")
	}

	stopReason := mapOpenAIStopReason(resp.Choices[0].FinishReason)

	return Response{
		Text:         text,
		ToolCalls:    toolCalls,
		StopReason:   stopReason,
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}, nil
}


