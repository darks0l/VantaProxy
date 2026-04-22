package llm

import "context"

// TestAdapter is a controllable Adapter for use in tests.
type TestAdapter struct {
	Fn func(Request) (Response, error)
}

func (a *TestAdapter) Complete(_ context.Context, req Request) (Response, error) {
	return a.Fn(req)
}

func (a *TestAdapter) ModelID() string { return "test" }
