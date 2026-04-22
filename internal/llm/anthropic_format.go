package llm

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// buildAnthropicMessage converts an llm.Message to the Anthropic content format.
// Simple text messages use a plain string; tool call/result messages use content arrays.
// This format is shared by both the Bedrock and direct Anthropic adapters.
func buildAnthropicMessage(m Message) (map[string]interface{}, error) {
	role := m.Role
	if role == "tool" {
		role = "user" // Anthropic uses "user" role for tool results
	}

	if m.ToolResult != nil {
		block := map[string]interface{}{
			"type":        "tool_result",
			"tool_use_id": m.ToolResult.ToolCallID,
			"content":     m.ToolResult.Content,
		}
		if m.ToolResult.IsError {
			block["is_error"] = true
		}
		return map[string]interface{}{
			"role":    "user",
			"content": []interface{}{block},
		}, nil
	}

	if len(m.ToolCalls) > 0 {
		var blocks []interface{}
		if m.Content != "" {
			blocks = append(blocks, map[string]interface{}{"type": "text", "text": m.Content})
		}
		for _, tc := range m.ToolCalls {
			blocks = append(blocks, map[string]interface{}{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Name,
				"input": tc.Input,
			})
		}
		return map[string]interface{}{"role": "assistant", "content": blocks}, nil
	}

	// Simple text message.
	return map[string]interface{}{"role": role, "content": m.Content}, nil
}

// buildAnthropicTools converts generic Tool definitions to Anthropic tool format.
func buildAnthropicTools(tools []Tool) []map[string]interface{} {
	result := make([]map[string]interface{}, len(tools))
	for i, t := range tools {
		result[i] = map[string]interface{}{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": t.InputSchema,
		}
	}
	return result
}

// parseAnthropicResponse parses an Anthropic Messages API response body into
// a generic Response. Used by the Bedrock adapter which receives []byte from the SDK.
// DurationMs is NOT set by this function — the caller should set it.
func parseAnthropicResponse(body []byte) (Response, error) {
	var parsed anthropicRespBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Response{}, fmt.Errorf("failed to parse anthropic response: %w", err)
	}
	return buildResponseFromAnthropic(parsed)
}

// parseAnthropicResponseStream decodes an Anthropic Messages API response directly
// from a reader into a generic Response, without buffering the entire body.
// DurationMs is NOT set by this function — the caller should set it.
func parseAnthropicResponseStream(r io.Reader) (Response, error) {
	var parsed anthropicRespBody
	if err := json.NewDecoder(r).Decode(&parsed); err != nil {
		return Response{}, fmt.Errorf("failed to parse anthropic response: %w", err)
	}
	return buildResponseFromAnthropic(parsed)
}

type anthropicContentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type anthropicUsageBlock struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicRespBody struct {
	Content    []anthropicContentBlock `json:"content"`
	Usage      anthropicUsageBlock     `json:"usage"`
	StopReason string                  `json:"stop_reason"`
}

func buildResponseFromAnthropic(resp anthropicRespBody) (Response, error) {
	var textParts []string
	var toolCalls []ToolCall
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			if block.Text != "" {
				textParts = append(textParts, block.Text)
			}
		case "tool_use":
			toolCalls = append(toolCalls, ToolCall{
				ID:    block.ID,
				Name:  block.Name,
				Input: block.Input,
			})
		}
	}

	if len(textParts) == 0 && len(toolCalls) == 0 {
		return Response{}, fmt.Errorf("empty content in model response")
	}

	return Response{
		Text:         strings.Join(textParts, ""),
		ToolCalls:    toolCalls,
		StopReason:   resp.StopReason,
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}, nil
}
