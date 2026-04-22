package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/darksol/Vanta/pkg/types"
)

func TestSanitizeUTF8(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "valid ascii",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "valid multibyte utf8",
			input: "café résumé 日本語",
			want:  "café résumé 日本語",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "null byte replaced",
			input: "hello\x00world",
			want:  "hello\uFFFDworld",
		},
		{
			name:  "multiple null bytes",
			input: "\x00ab\x00c\x00",
			want:  "\uFFFDab\uFFFDc\uFFFD",
		},
		{
			name:  "invalid utf8 byte",
			input: "hello\x80world",
			want:  "hello\uFFFDworld",
		},
		{
			name:  "invalid continuation sequence",
			input: "a\xff\xfeb",
			want:  "a\uFFFD\uFFFDb",
		},
		{
			name:  "mix of null and invalid utf8",
			input: "ok\x00\x80ok",
			want:  "ok\uFFFD\uFFFDok",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeUTF8(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeUTF8(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// seedAuditEntryFor inserts a minimal audit_log row and returns its DB-assigned ID.
func seedAuditEntryFor(t *testing.T, method, url, decision string) string {
	t.Helper()
	reader := NewPGAuditReader(testPool)
	reader.Add(types.AuditEntry{
		Timestamp: time.Now(),
		RequestID: "req_" + method + "_" + url,
		Method:    method,
		URL:       url,
		Operation: "READ",
		Decision:  decision,
	})
	entries := reader.Query(AuditFilter{Method: method, Limit: 1})
	if len(entries) == 0 {
		t.Fatalf("seedAuditEntryFor: failed to retrieve seeded entry")
	}
	return entries[0].ID
}

func TestQueryBatched_AllEntries(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	for i := 0; i < 15; i++ {
		seedAuditEntryFor(t, "GET", "/api/x", "approved")
	}

	reader := NewPGAuditReader(testPool)
	var collected []types.AuditEntry
	batchCount := 0

	err := reader.QueryBatched(context.Background(), AuditFilter{}, 5, func(batch []types.AuditEntry) error {
		batchCount++
		collected = append(collected, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("QueryBatched: %v", err)
	}
	if len(collected) != 15 {
		t.Errorf("collected %d entries, want 15", len(collected))
	}
	if batchCount != 3 {
		t.Errorf("batchCount = %d, want 3", batchCount)
	}
}

func TestQueryBatched_RespectsFilter(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	seedAuditEntryFor(t, "GET", "/api/approved", "approved")
	seedAuditEntryFor(t, "GET", "/api/approved2", "approved")
	seedAuditEntryFor(t, "GET", "/api/denied", "denied")

	reader := NewPGAuditReader(testPool)
	var collected []types.AuditEntry

	err := reader.QueryBatched(context.Background(), AuditFilter{Decision: "approved"}, 10, func(batch []types.AuditEntry) error {
		collected = append(collected, batch...)
		return nil
	})
	if err != nil {
		t.Fatalf("QueryBatched: %v", err)
	}
	if len(collected) != 2 {
		t.Errorf("collected %d entries, want 2 (only approved)", len(collected))
	}
	for _, e := range collected {
		if e.Decision != "approved" {
			t.Errorf("entry decision = %q, want approved", e.Decision)
		}
	}
}

func TestQueryBatched_ContextCancel(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	for i := 0; i < 10; i++ {
		seedAuditEntryFor(t, "GET", "/api/x", "approved")
	}

	reader := NewPGAuditReader(testPool)
	ctx, cancel := context.WithCancel(context.Background())
	batchCount := 0

	err := reader.QueryBatched(ctx, AuditFilter{}, 5, func(batch []types.AuditEntry) error {
		batchCount++
		cancel() // cancel after first batch
		return nil
	})
	// Should have stopped after the first batch (second batch returns ctx error)
	if batchCount != 1 {
		t.Errorf("batchCount = %d, want 1 (cancelled after first)", batchCount)
	}
	if err == nil {
		t.Error("expected non-nil error after context cancel")
	}
}

func TestQueryBatched_EmptyResult(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	reader := NewPGAuditReader(testPool)
	called := false

	err := reader.QueryBatched(context.Background(), AuditFilter{Decision: "nonexistent"}, 10, func(batch []types.AuditEntry) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("QueryBatched: %v", err)
	}
	if called {
		t.Error("callback should not be called for empty result")
	}
}

func TestQueryBatched_FnError_StopsIteration(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	for i := 0; i < 10; i++ {
		seedAuditEntryFor(t, "GET", "/api/x", "approved")
	}

	reader := NewPGAuditReader(testPool)
	sentinel := errors.New("stop")
	batchCount := 0

	err := reader.QueryBatched(context.Background(), AuditFilter{}, 5, func(batch []types.AuditEntry) error {
		batchCount++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
	if batchCount != 1 {
		t.Errorf("batchCount = %d, want 1", batchCount)
	}
}
