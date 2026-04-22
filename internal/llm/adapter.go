package llm

import (
	"context"
	"encoding/json"
)

// Tool defines a function the model can invoke.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"` // JSON Schema object
}

// ToolCall is a tool invocation returned by the model in a response.
type ToolCall struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"` // raw JSON matching the tool's input schema
}

// ToolResult is the outcome of executing a tool, sent back as a user turn.
type ToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Content    string `json:"content"`
	IsError    bool   `json:"is_error,omitempty"`
}

// Message is a single turn in a conversation.
// For plain text turns set Role and Content.
// For assistant turns with tool invocations, also set ToolCalls.
// For tool result turns, set Role="tool" and ToolResult.
type Message struct {
	Role       string      // "user" | "assistant" | "tool"
	Content    string      // text content (may be empty when ToolCalls is set)
	ToolCalls  []ToolCall  // set when the assistant invokes tools
	ToolResult *ToolResult // set when returning a tool result (role="tool")
}

// Request is the input to an LLM completion call.
type Request struct {
	System           string
	Messages         []Message
	Tools            []Tool // optional; when non-empty the model may return ToolCalls
	MaxTokens        int
	CacheSystemPrompt bool // if true, mark the system prompt for provider-side caching
}

// Response is the output of an LLM completion call.
type Response struct {
	Text         string
	ToolCalls    []ToolCall // populated when StopReason == "tool_use"
	StopReason   string     // "end_turn" | "tool_use"
	InputTokens  int
	OutputTokens int
	DurationMs   int
}

// Adapter abstracts LLM transport so packages stay provider-agnostic.
type Adapter interface {
	Complete(ctx context.Context, req Request) (Response, error)
	ModelID() string
}
