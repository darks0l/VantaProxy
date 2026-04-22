package eval

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/darksol/Vanta/internal/judge"
	"github.com/darksol/Vanta/internal/llm"
	"github.com/darksol/Vanta/pkg/types"
)

// --- in-memory Store stub ---

type memStore struct {
	mu      sync.Mutex
	runs    map[string]*EvalRun
	results []*EvalResult
}

func newMemStore() *memStore {
	return &memStore{runs: make(map[string]*EvalRun)}
}

func (s *memStore) CreateRun(policyID string) (*EvalRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := &EvalRun{ID: "run_1", PolicyID: policyID, Status: "pending"}
	s.runs[run.ID] = run
	return run, nil
}

func (s *memStore) UpdateRunStatus(id, status, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run, ok := s.runs[id]; ok {
		run.Status = status
		run.Error = errMsg
	}
	return nil
}

func (s *memStore) GetRun(id string) (*EvalRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return run, nil
}

func (s *memStore) ListRuns(policyID string, limit, offset int) ([]*EvalRun, error) {
	return []*EvalRun{}, nil
}

func (s *memStore) AddResult(result EvalResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := result
	s.results = append(s.results, &r)
	return nil
}

func (s *memStore) GetRunStats(_ string) (*EvalRunStats, error) { return &EvalRunStats{}, nil }
func (s *memStore) SetTotalEntries(id string, n int) error    { return nil }
func (s *memStore) ListResults(runID string, _ ResultFilter, limit, offset int) ([]*EvalResult, int, error) {
	return []*EvalResult{}, 0, nil
}

func (s *memStore) CreateLLMResponse(r types.LLMResponse) (string, error) { return "llmr_test", nil }
func (s *memStore) GetLLMResponse(id string) (*types.LLMResponse, error)  { return nil, nil }
func (s *memStore) UpsertLabel(label AuditLabel) error                    { return nil }
func (s *memStore) GetLabel(entryID string) (*AuditLabel, error)          { return nil, nil }
func (s *memStore) DeleteLabel(entryID string) error                      { return nil }

// --- helpers ---

func makeStore(runID string) *memStore {
	s := newMemStore()
	s.runs[runID] = &EvalRun{ID: runID, PolicyID: "pol_1", Status: "pending"}
	return s
}

func newAllowJudge() *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: `{"decision":"ALLOW","reason":"ok"}`}, nil
	}})
}

func newDenyJudge() *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: `{"decision":"DENY","reason":"blocked"}`}, nil
	}})
}

func newErrorJudge(err error) *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{}, err
	}})
}

// --- tests ---

func TestRunEval_AllAllow(t *testing.T) {
	store := makeStore("run_1")
	entries := []types.AuditEntry{
		{ID: "audit_1", Method: "GET", URL: "/api/foo"},
		{ID: "audit_2", Method: "POST", URL: "/api/bar"},
	}

	RunEvalFromSlice(context.Background(), newAllowJudge(), entries, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "completed" {
		t.Errorf("status = %q, want completed", store.runs["run_1"].Status)
	}
	if len(store.results) != 2 {
		t.Fatalf("results count = %d, want 2", len(store.results))
	}
	for _, r := range store.results {
		if r.ReplayDecision != "ALLOW" {
			t.Errorf("ReplayDecision = %q, want ALLOW", r.ReplayDecision)
		}
	}
}

func TestRunEval_AllDeny(t *testing.T) {
	store := makeStore("run_1")
	entries := []types.AuditEntry{{ID: "audit_1", Method: "DELETE", URL: "/api/x"}}

	RunEvalFromSlice(context.Background(), newDenyJudge(), entries, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "completed" {
		t.Errorf("status = %q, want completed", store.runs["run_1"].Status)
	}
	if len(store.results) != 1 || store.results[0].ReplayDecision != "DENY" {
		t.Errorf("expected 1 DENY result, got %+v", store.results)
	}
}

func TestRunEval_JudgeError_RunStillCompletes(t *testing.T) {
	store := makeStore("run_1")
	entries := []types.AuditEntry{{ID: "audit_1", Method: "GET", URL: "/api/x"}}

	RunEvalFromSlice(context.Background(), newErrorJudge(errors.New("model unavailable")), entries, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "completed" {
		t.Errorf("status = %q, want completed (judge errors don't fail the run)", store.runs["run_1"].Status)
	}
	if len(store.results) != 1 || store.results[0].ReplayDecision != "ERROR" {
		t.Errorf("expected 1 ERROR result, got %+v", store.results)
	}
}

func TestRunEval_EmptyEntries(t *testing.T) {
	store := makeStore("run_1")

	RunEvalFromSlice(context.Background(), newAllowJudge(), nil, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "completed" {
		t.Errorf("status = %q, want completed", store.runs["run_1"].Status)
	}
	if len(store.results) != 0 {
		t.Errorf("expected 0 results, got %d", len(store.results))
	}
}

func TestRunEval_LLMDecisions_ApprovedByLLM(t *testing.T) {
	store := makeStore("run_1")
	entries := []types.AuditEntry{
		{ID: "audit_1", Method: "POST", URL: "https://api.example.com/write"},
	}

	RunEvalFromSlice(context.Background(), newAllowJudge(), entries, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(store.results))
	}
	if store.results[0].ApprovedBy != "llm" {
		t.Errorf("ApprovedBy = %q, want llm", store.results[0].ApprovedBy)
	}
}

func TestRunEval_StaticAllowRule_SkipsLLM(t *testing.T) {
	// Judge always denies — but static allow rule should prevent it from being called.
	judgeCallCount := 0
	denyAndCount := judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		judgeCallCount++
		return llm.Response{Text: `{"decision":"DENY","reason":"blocked"}`}, nil
	}})

	store := makeStore("run_1")
	policy := types.LLMPolicy{
		ID: "pol_1",
		StaticRules: []types.StaticRule{
			{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "allow"},
		},
	}
	entries := []types.AuditEntry{
		{ID: "audit_1", Method: "GET", URL: "https://api.example.com/v1/items"},
		{ID: "audit_2", Method: "POST", URL: "https://api.example.com/v1/items"}, // no static rule match (POST)
	}

	RunEvalFromSlice(context.Background(), denyAndCount, entries, policy, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()

	if judgeCallCount != 1 {
		t.Errorf("LLM judge called %d times, want 1 (only POST should reach it)", judgeCallCount)
	}

	byEntry := map[string]*EvalResult{}
	for _, r := range store.results {
		byEntry[r.EntryID] = r
	}

	get := byEntry["audit_1"]
	if get == nil {
		t.Fatal("no result for GET entry")
	}
	if get.ReplayDecision != "ALLOW" {
		t.Errorf("GET static-allow ReplayDecision = %q, want ALLOW", get.ReplayDecision)
	}
	if get.ApprovedBy != "llm-static-rule" {
		t.Errorf("GET static-allow ApprovedBy = %q, want llm-static-rule", get.ApprovedBy)
	}
	if get.LLMResponseID != "" {
		t.Error("GET static-allow should have no LLMResponseID")
	}

	post := byEntry["audit_2"]
	if post == nil {
		t.Fatal("no result for POST entry")
	}
	if post.ReplayDecision != "DENY" {
		t.Errorf("POST LLM ReplayDecision = %q, want DENY", post.ReplayDecision)
	}
	if post.ApprovedBy != "llm" {
		t.Errorf("POST LLM ApprovedBy = %q, want llm", post.ApprovedBy)
	}
}

func TestRunEval_StaticDenyRule_BlocksWithoutLLM(t *testing.T) {
	judgeCallCount := 0
	allowAndCount := judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		judgeCallCount++
		return llm.Response{Text: `{"decision":"ALLOW","reason":"ok"}`}, nil
	}})

	store := makeStore("run_1")
	policy := types.LLMPolicy{
		ID: "pol_1",
		StaticRules: []types.StaticRule{
			{Methods: []string{"DELETE"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "deny"},
		},
	}
	entries := []types.AuditEntry{
		{ID: "audit_1", Method: "DELETE", URL: "https://api.example.com/v1/items/1"},
	}

	RunEvalFromSlice(context.Background(), allowAndCount, entries, policy, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()

	if judgeCallCount != 0 {
		t.Errorf("LLM judge called %d times, want 0 (static deny must skip judge)", judgeCallCount)
	}
	if len(store.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(store.results))
	}
	r := store.results[0]
	if r.ReplayDecision != "DENY" {
		t.Errorf("ReplayDecision = %q, want DENY", r.ReplayDecision)
	}
	if r.ApprovedBy != "llm-static-rule" {
		t.Errorf("ApprovedBy = %q, want llm-static-rule", r.ApprovedBy)
	}
}

func TestRunEval_StaticRule_MethodNotMatched_GoesToLLM(t *testing.T) {
	// Rule is GET-only; DELETE should go to the judge.
	store := makeStore("run_1")
	policy := types.LLMPolicy{
		ID: "pol_1",
		StaticRules: []types.StaticRule{
			{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix"},
		},
	}
	entries := []types.AuditEntry{
		{ID: "audit_1", Method: "DELETE", URL: "https://api.example.com/v1/items/1"},
	}

	RunEvalFromSlice(context.Background(), newDenyJudge(), entries, policy, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(store.results))
	}
	r := store.results[0]
	if r.ApprovedBy != "llm" {
		t.Errorf("ApprovedBy = %q, want llm (DELETE not in static rules)", r.ApprovedBy)
	}
	if r.ReplayDecision != "DENY" {
		t.Errorf("ReplayDecision = %q, want DENY", r.ReplayDecision)
	}
}

func TestRunEval_ContextCancelled_RunFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before RunEval is called

	store := makeStore("run_1")
	entries := []types.AuditEntry{
		{ID: "audit_1", Method: "GET", URL: "/api/1"},
		{ID: "audit_2", Method: "GET", URL: "/api/2"},
	}

	RunEvalFromSlice(ctx, newAllowJudge(), entries, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "failed" {
		t.Errorf("status = %q, want failed", store.runs["run_1"].Status)
	}
}

func TestRunEval_Channel_StreamsEntries(t *testing.T) {
	store := makeStore("run_1")
	ch := make(chan types.AuditEntry, 5)
	for i := 1; i <= 5; i++ {
		ch <- types.AuditEntry{ID: fmt.Sprintf("audit_%d", i), Method: "GET", URL: "/api/x"}
	}
	close(ch)

	RunEval(context.Background(), newAllowJudge(), ch, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "completed" {
		t.Errorf("status = %q, want completed", store.runs["run_1"].Status)
	}
	if len(store.results) != 5 {
		t.Errorf("results count = %d, want 5", len(store.results))
	}
}

func TestRunEval_Channel_EmptyChannel(t *testing.T) {
	store := makeStore("run_1")
	ch := make(chan types.AuditEntry)
	close(ch)

	RunEval(context.Background(), newAllowJudge(), ch, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "completed" {
		t.Errorf("status = %q, want completed", store.runs["run_1"].Status)
	}
	if len(store.results) != 0 {
		t.Errorf("expected 0 results, got %d", len(store.results))
	}
}

func TestRunEval_Channel_ContextCancel_MidStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the run fails on the first entry check

	store := makeStore("run_1")
	ch := make(chan types.AuditEntry, 5)
	ch <- types.AuditEntry{ID: "audit_1", Method: "GET", URL: "/api/1"}
	ch <- types.AuditEntry{ID: "audit_2", Method: "GET", URL: "/api/2"}
	// channel intentionally left open — RunEval must handle cancellation without draining

	RunEval(ctx, newAllowJudge(), ch, types.LLMPolicy{ID: "pol_1"}, store, "run_1")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runs["run_1"].Status != "failed" {
		t.Errorf("status = %q, want failed", store.runs["run_1"].Status)
	}
}
