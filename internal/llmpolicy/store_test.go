package llmpolicy_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/darksol/Vanta/internal/dbtest"
	"github.com/darksol/Vanta/internal/llmpolicy"
	"github.com/darksol/Vanta/pkg/types"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup, err := dbtest.Setup()
	if err != nil {
		slog.Error("llmpolicy TestMain", "error", err)
		os.Exit(1)
	}
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func truncate(t *testing.T) {
	t.Helper()
	testPool.Exec(context.Background(), "TRUNCATE llm_policies CASCADE")
}

func newStore(t *testing.T) *llmpolicy.PGStore {
	t.Helper()
	truncate(t)
	return llmpolicy.NewPGStore(testPool)
}

func TestCreate_StoresAllFields(t *testing.T) {
	s := newStore(t)

	p, err := s.Create("my policy", "Allow read-only access", "bedrock-anthropic", "claude-3", "", "", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if p.ID == "" {
		t.Error("expected non-empty ID")
	}
	if p.Name != "my policy" {
		t.Errorf("Name: want %q, got %q", "my policy", p.Name)
	}
	if p.Prompt != "Allow read-only access" {
		t.Errorf("Prompt: want %q, got %q", "Allow read-only access", p.Prompt)
	}
	if p.Provider != "bedrock-anthropic" {
		t.Errorf("Provider: want %q, got %q", "bedrock-anthropic", p.Provider)
	}
	if p.Model != "claude-3" {
		t.Errorf("Model: want %q, got %q", "claude-3", p.Model)
	}
	if p.ForkedFrom != "" {
		t.Errorf("ForkedFrom: want empty, got %q", p.ForkedFrom)
	}
	if p.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestCreate_EmptyProviderAndModel(t *testing.T) {
	s := newStore(t)

	p, err := s.Create("minimal", "some prompt", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.Provider != "" {
		t.Errorf("expected empty Provider, got %q", p.Provider)
	}
	if p.Model != "" {
		t.Errorf("expected empty Model, got %q", p.Model)
	}
}

func TestCreate_WithForkedFrom(t *testing.T) {
	s := newStore(t)

	parent, err := s.Create("parent", "original prompt", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("Create parent: %v", err)
	}

	child, err := s.Create("child", "updated prompt", "", "", parent.ID, "", nil)
	if err != nil {
		t.Fatalf("Create child: %v", err)
	}

	if child.ForkedFrom != parent.ID {
		t.Errorf("ForkedFrom: want %q, got %q", parent.ID, child.ForkedFrom)
	}
}

func TestCreate_InvalidForkedFrom(t *testing.T) {
	s := newStore(t)

	_, err := s.Create("bad fork", "prompt", "", "", "llmpol_nonexistent", "", nil)
	if err == nil {
		t.Error("expected error for non-existent forked_from, got nil")
	}
}

func TestGet_ReturnsCreatedPolicy(t *testing.T) {
	s := newStore(t)

	created, _ := s.Create("test", "prompt text", "bedrock-anthropic", "claude-3", "", "", nil)

	got, err := s.Get(created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID: want %q, got %q", created.ID, got.ID)
	}
	if got.Prompt != "prompt text" {
		t.Errorf("Prompt: want %q, got %q", "prompt text", got.Prompt)
	}
}

func TestGet_NotFound(t *testing.T) {
	s := newStore(t)

	_, err := s.Get("llmpol_doesnotexist")
	if err == nil {
		t.Error("expected error for missing ID, got nil")
	}
}

func TestList_ReturnsAllPolicies(t *testing.T) {
	s := newStore(t)

	s.Create("policy-a", "prompt a", "", "", "", "", nil)
	s.Create("policy-b", "prompt b", "", "", "", "", nil)
	s.Create("policy-c", "prompt c", "", "", "", "", nil)

	policies, err := s.List(50, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 3 {
		t.Errorf("expected 3 policies, got %d", len(policies))
	}
}

func TestList_OrderedByCreatedAtDesc(t *testing.T) {
	s := newStore(t)

	s.Create("first", "p1", "", "", "", "", nil)
	s.Create("second", "p2", "", "", "", "", nil)
	s.Create("third", "p3", "", "", "", "", nil)

	policies, _ := s.List(50, 0)
	// Most recently created should be first.
	if policies[0].Name != "third" {
		t.Errorf("expected most recent first, got %q", policies[0].Name)
	}
}

func TestList_Pagination(t *testing.T) {
	s := newStore(t)

	for i := 0; i < 5; i++ {
		s.Create("policy", "prompt", "", "", "", "", nil)
	}

	page1, _ := s.List(3, 0)
	page2, _ := s.List(3, 3)

	if len(page1) != 3 {
		t.Errorf("page1: expected 3, got %d", len(page1))
	}
	if len(page2) != 2 {
		t.Errorf("page2: expected 2, got %d", len(page2))
	}

	// No overlap.
	seen := make(map[string]bool)
	for _, p := range append(page1, page2...) {
		if seen[p.ID] {
			t.Errorf("duplicate policy ID %q across pages", p.ID)
		}
		seen[p.ID] = true
	}
}

func TestDelete_SoftDeletesPolicy(t *testing.T) {
	s := newStore(t)

	p, _ := s.Create("to-delete", "prompt", "", "", "", "", nil)

	if err := s.Delete(p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// List should not include it
	policies, _ := s.List(50, 0)
	for _, pol := range policies {
		if pol.ID == p.ID {
			t.Error("deleted policy should not appear in List")
		}
	}

	// Get should still return it (with DeletedAt set)
	got, err := s.Get(p.ID)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if got.DeletedAt == nil {
		t.Error("expected DeletedAt to be set after soft-delete")
	}
}

func TestDelete_AlreadyDeleted_ReturnsError(t *testing.T) {
	s := newStore(t)

	p, _ := s.Create("double-delete", "prompt", "", "", "", "", nil)
	s.Delete(p.ID)

	if err := s.Delete(p.ID); err == nil {
		t.Error("expected error when deleting already-deleted policy")
	}
}

func TestDelete_NonExistent_ReturnsError(t *testing.T) {
	s := newStore(t)

	if err := s.Delete("llmpol_doesnotexist"); err == nil {
		t.Error("expected error for non-existent policy")
	}
}

func TestDelete_BlockedWhenUsersAssigned(t *testing.T) {
	s := newStore(t)

	p, _ := s.Create("in-use", "prompt", "", "", "", "", nil)

	// Assign a user to the policy
	_, err := testPool.Exec(context.Background(), `
		INSERT INTO users(id, is_admin, llm_policy_id) VALUES('user-1', false, $1)
	`, p.ID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	if err := s.Delete(p.ID); err == nil {
		t.Error("expected error when users are assigned to policy")
	}
}

func TestList_ExcludesDeleted(t *testing.T) {
	s := newStore(t)

	a, _ := s.Create("keep", "p", "", "", "", "", nil)
	b, _ := s.Create("delete-me", "p", "", "", "", "", nil)
	s.Delete(b.ID)

	policies, _ := s.List(50, 0)
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].ID != a.ID {
		t.Errorf("expected surviving policy %q, got %q", a.ID, policies[0].ID)
	}
}

func TestList_EmptyReturnsEmptySlice(t *testing.T) {
	s := newStore(t)

	policies, err := s.List(50, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected empty result, got %v", policies)
	}
}

func TestGet_ForkedFromPopulated(t *testing.T) {
	s := newStore(t)

	parent, _ := s.Create("parent", "prompt", "", "", "", "", nil)
	child, _ := s.Create("child", "updated", "", "", parent.ID, "", nil)

	got, err := s.Get(child.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ForkedFrom != parent.ID {
		t.Errorf("ForkedFrom: want %q, got %q", parent.ID, got.ForkedFrom)
	}
}

// ---- UpdateDraft ----

func TestUpdateDraft_UpdatesFields(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("original", "old prompt", "", "", "", "draft", nil)
	updated, err := s.UpdateDraft(draft.ID, "renamed", "new prompt", "anthropic", "claude", nil)
	if err != nil {
		t.Fatalf("UpdateDraft: %v", err)
	}
	if updated.Name != "renamed" {
		t.Errorf("Name: want renamed, got %q", updated.Name)
	}
	if updated.Prompt != "new prompt" {
		t.Errorf("Prompt: want new prompt, got %q", updated.Prompt)
	}
	if updated.Provider != "anthropic" {
		t.Errorf("Provider: want anthropic, got %q", updated.Provider)
	}
}

func TestUpdateDraft_RejectsPublished(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	published, _ := s.Create("pub", "prompt", "", "", "", "published", nil)
	_, err := s.UpdateDraft(published.ID, "renamed", "new", "", "", nil)
	if !errors.Is(err, llmpolicy.ErrPolicyNotDraft) {
		t.Errorf("expected ErrPolicyNotDraft, got %v", err)
	}
}

func TestUpdateDraft_MetadataIndependentOfPolicyFields(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)

	// Write metadata separately via UpsertMetadata.
	meta := &types.PolicyMetadata{Source: "suggest", AnalyzedUserID: "alice@example.com"}
	if err := s.UpsertMetadata(draft.ID, meta); err != nil {
		t.Fatalf("UpsertMetadata: %v", err)
	}

	// Updating policy fields does NOT touch metadata.
	if _, err := s.UpdateDraft(draft.ID, "renamed", "new prompt", "", "", nil); err != nil {
		t.Fatalf("UpdateDraft: %v", err)
	}

	loaded, _ := s.GetMetadata(draft.ID)
	if loaded == nil {
		t.Fatal("expected metadata to still be set after UpdateDraft")
	}
	if loaded.AnalyzedUserID != "alice@example.com" {
		t.Errorf("AnalyzedUserID: want alice@example.com, got %q", loaded.AnalyzedUserID)
	}
}

// ---- Publish ----

func TestPublish_TransitionsToDraftPublished(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "prompt", "", "", "", "draft", nil)
	if draft.Status != "draft" {
		t.Fatalf("expected draft status, got %q", draft.Status)
	}

	pub, err := s.Publish(draft.ID)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if pub.Status != "published" {
		t.Errorf("Status: want published, got %q", pub.Status)
	}
}

func TestPublish_RejectsAlreadyPublished(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	published, _ := s.Create("p", "prompt", "", "", "", "published", nil)
	_, err := s.Publish(published.ID)
	if !errors.Is(err, llmpolicy.ErrPolicyNotDraft) {
		t.Errorf("expected ErrPolicyNotDraft, got %v", err)
	}
}

func TestCreate_DraftStatus(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, err := s.Create("draft policy", "prompt", "", "", "", "draft", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if draft.Status != "draft" {
		t.Errorf("Status: want draft, got %q", draft.Status)
	}
}

func TestCreate_DefaultsToPublished(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	policy, err := s.Create("pub policy", "prompt", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if policy.Status != "published" {
		t.Errorf("Status: want published (default), got %q", policy.Status)
	}
}

// ---- SetChatHistory ----

func TestSetChatHistory_PersistsAndLoads(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)

	history := []types.ChatMessage{
		{Role: "user", Content: "analyze my traffic"},
		{Role: "assistant", Content: "I found 12 endpoint patterns."},
	}
	if err := s.SetChatHistory(draft.ID, history); err != nil {
		t.Fatalf("SetChatHistory: %v", err)
	}

	loaded, err := s.GetMetadata(draft.ID)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected metadata to be set")
	}
	if len(loaded.ChatHistory) != 2 {
		t.Fatalf("expected 2 chat turns, got %d", len(loaded.ChatHistory))
	}
	if loaded.ChatHistory[0].Role != "user" {
		t.Errorf("turn[0].Role = %q, want user", loaded.ChatHistory[0].Role)
	}
	if loaded.ChatHistory[1].Content != "I found 12 endpoint patterns." {
		t.Errorf("turn[1].Content = %q", loaded.ChatHistory[1].Content)
	}
}

func TestSetChatHistory_AppendsTurnsAcrossCalls(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)

	// First turn.
	if err := s.SetChatHistory(draft.ID, []types.ChatMessage{
		{Role: "user", Content: "first"},
		{Role: "assistant", Content: "reply one"},
	}); err != nil {
		t.Fatalf("SetChatHistory (1): %v", err)
	}

	// Second turn appends by passing the full updated slice.
	if err := s.SetChatHistory(draft.ID, []types.ChatMessage{
		{Role: "user", Content: "first"},
		{Role: "assistant", Content: "reply one"},
		{Role: "user", Content: "second"},
		{Role: "assistant", Content: "reply two"},
	}); err != nil {
		t.Fatalf("SetChatHistory (2): %v", err)
	}

	loaded, _ := s.GetMetadata(draft.ID)
	if len(loaded.ChatHistory) != 4 {
		t.Errorf("expected 4 turns, got %d", len(loaded.ChatHistory))
	}
}

func TestSetChatHistory_PreservesExistingMetadata(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)
	// Set initial metadata so we can verify SetChatHistory preserves it.
	s.UpsertMetadata(draft.ID, &types.PolicyMetadata{Source: "suggest", AnalyzedUserID: "alice@example.com"}) //nolint:errcheck

	if err := s.SetChatHistory(draft.ID, []types.ChatMessage{
		{Role: "user", Content: "hello"},
	}); err != nil {
		t.Fatalf("SetChatHistory: %v", err)
	}

	loaded, _ := s.GetMetadata(draft.ID)
	if len(loaded.ChatHistory) != 1 {
		t.Errorf("expected 1 chat turn, got %d", len(loaded.ChatHistory))
	}
	if loaded.AnalyzedUserID != "alice@example.com" {
		t.Errorf("AnalyzedUserID clobbered, got %q", loaded.AnalyzedUserID)
	}
	if loaded.Source != "suggest" {
		t.Errorf("Source clobbered, got %q", loaded.Source)
	}
}

func TestSetChatHistory_WorksWithNoPreexistingMetadata(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	// Create draft with no metadata at all.
	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)

	if err := s.SetChatHistory(draft.ID, []types.ChatMessage{
		{Role: "user", Content: "hello"},
	}); err != nil {
		t.Fatalf("SetChatHistory on nil metadata: %v", err)
	}

	loaded, _ := s.GetMetadata(draft.ID)
	if loaded == nil || len(loaded.ChatHistory) != 1 {
		t.Error("expected chat history to be created even with no prior metadata")
	}
}

// ---- SetEndpointSummaries ----

func TestSetEndpointSummaries_PersistsAndLoads(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)

	summaries := []types.PolicyEndpointSummary{
		{Method: "GET", PathPattern: "/v1/applications/{id}", Count: 120, Description: "Fetches an application."},
		{Method: "POST", PathPattern: "/v1/jobs/{id}/move", Count: 15, Description: "Moves a candidate."},
	}
	if err := s.SetEndpointSummaries(draft.ID, summaries); err != nil {
		t.Fatalf("SetEndpointSummaries: %v", err)
	}

	loaded, err := s.GetMetadata(draft.ID)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected metadata to be set")
	}
	if len(loaded.EndpointSummaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(loaded.EndpointSummaries))
	}
	if loaded.EndpointSummaries[0].PathPattern != "/v1/applications/{id}" {
		t.Errorf("summary[0].PathPattern = %q", loaded.EndpointSummaries[0].PathPattern)
	}
	if loaded.EndpointSummaries[1].Count != 15 {
		t.Errorf("summary[1].Count = %d, want 15", loaded.EndpointSummaries[1].Count)
	}
}

func TestSetEndpointSummaries_PreservesOtherMetadata(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)
	s.UpsertMetadata(draft.ID, &types.PolicyMetadata{Source: "agent", AnalyzedUserID: "alice@example.com"}) //nolint:errcheck

	if err := s.SetEndpointSummaries(draft.ID, []types.PolicyEndpointSummary{
		{Method: "GET", PathPattern: "/v1/items", Count: 5, Description: "Lists items."},
	}); err != nil {
		t.Fatalf("SetEndpointSummaries: %v", err)
	}

	loaded, _ := s.GetMetadata(draft.ID)
	if loaded.Source != "agent" {
		t.Errorf("Source clobbered, got %q", loaded.Source)
	}
	if loaded.AnalyzedUserID != "alice@example.com" {
		t.Errorf("AnalyzedUserID clobbered, got %q", loaded.AnalyzedUserID)
	}
	if len(loaded.EndpointSummaries) != 1 {
		t.Errorf("expected 1 summary, got %d", len(loaded.EndpointSummaries))
	}
}

func TestSetEndpointSummaries_WorksWithNoPreexistingMetadata(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)

	if err := s.SetEndpointSummaries(draft.ID, []types.PolicyEndpointSummary{
		{Method: "GET", PathPattern: "/v1/items", Count: 5, Description: "Lists items."},
	}); err != nil {
		t.Fatalf("SetEndpointSummaries on nil metadata: %v", err)
	}

	loaded, _ := s.GetMetadata(draft.ID)
	if loaded == nil || len(loaded.EndpointSummaries) != 1 {
		t.Error("expected summaries to be created even with no prior metadata")
	}
}

func TestSetEndpointSummaries_EmptySliceClearsExisting(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	s := newStore(t)

	draft, _ := s.Create("d", "p", "", "", "", "draft", nil)
	// Set initial summaries.
	s.UpsertMetadata(draft.ID, &types.PolicyMetadata{ //nolint:errcheck
		Source:            "agent",
		EndpointSummaries: []types.PolicyEndpointSummary{{Method: "GET", PathPattern: "/v1/items", Count: 5, Description: "Lists items."}},
	})

	// Overwrite with empty slice (e.g. all endpoints removed).
	if err := s.SetEndpointSummaries(draft.ID, []types.PolicyEndpointSummary{}); err != nil {
		t.Fatalf("SetEndpointSummaries: %v", err)
	}

	loaded, _ := s.GetMetadata(draft.ID)
	if len(loaded.EndpointSummaries) != 0 {
		t.Errorf("expected 0 summaries after clear, got %d", len(loaded.EndpointSummaries))
	}
}
