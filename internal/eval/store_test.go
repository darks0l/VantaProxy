package eval

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/darksol/Vanta/internal/db"
	"github.com/darksol/Vanta/pkg/types"
)

// --- seed helpers ---

func seedPolicy(t *testing.T) string {
	t.Helper()
	id := db.NewID("llmpol")
	_, err := testPool.Exec(context.Background(), `
		INSERT INTO llm_policies(id, name, prompt, provider, model)
		VALUES($1, 'test-policy', '', '', '')
	`, id)
	if err != nil {
		t.Fatalf("seedPolicy: %v", err)
	}
	return id
}

func seedAuditEntry(t *testing.T, id, method, urlStr, decision string) {
	t.Helper()
	_, err := testPool.Exec(context.Background(), `
		INSERT INTO audit_log(
			id, timestamp, request_id, method, url, operation, decision,
			cache_hit, response_status, duration_ms, error,
			request_headers, request_body, response_headers, response_body
		) VALUES($1, NOW(), '', $2, $3, 'READ', $4, false, 200, 0, '', '{}', '', '{}', '')
	`, id, method, urlStr, decision)
	if err != nil {
		t.Fatalf("seedAuditEntry(%s): %v", id, err)
	}
}

func newStore(t *testing.T) *PGStore {
	t.Helper()
	return NewPGStore(testPool)
}

// --- tests ---

func TestCreateRun_GetRun_NoResults(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	run, err := s.CreateRun(policyID)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if run.ID == "" {
		t.Error("expected non-empty ID")
	}
	if run.Status != "pending" {
		t.Errorf("Status = %q, want pending", run.Status)
	}

	got, err := s.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Total != 0 || got.Agreed != 0 || got.Errored != 0 || got.Labeled != 0 {
		t.Errorf("expected all counts = 0, got total=%d agreed=%d errored=%d labeled=%d",
			got.Total, got.Agreed, got.Errored, got.Labeled)
	}
}

func TestAddResult_GetRun_ComputesStats(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	// Seed audit entries with original decisions
	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved") // ALLOW → should agree with ALLOW replay
	seedAuditEntry(t, "ae2", "GET", "/api/2", "denied")   // DENY  → should agree with DENY replay
	seedAuditEntry(t, "ae3", "GET", "/api/3", "approved") // ALLOW → DENY replay = disagree
	seedAuditEntry(t, "ae4", "GET", "/api/4", "approved") // ALLOW → ERROR replay = errored

	run, err := s.CreateRun(policyID)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	now := time.Now()
	cases := []struct {
		entryID  string
		decision string
	}{
		{"ae1", "ALLOW"},
		{"ae2", "DENY"},
		{"ae3", "DENY"},  // disagrees with "approved"
		{"ae4", "ERROR"},
	}
	for _, c := range cases {
		if err := s.AddResult(EvalResult{
			RunID: run.ID, EntryID: c.entryID,
			ReplayDecision: c.decision, ReplayedAt: now,
		}); err != nil {
			t.Fatalf("AddResult(%s): %v", c.entryID, err)
		}
	}

	got, err := s.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Total != 4 {
		t.Errorf("Total = %d, want 4", got.Total)
	}
	if got.Agreed != 2 {
		t.Errorf("Agreed = %d, want 2 (ae1 ALLOW matches approved, ae2 DENY matches denied)", got.Agreed)
	}
	if got.Disagreed != 1 {
		t.Errorf("Disagreed = %d, want 1 (ae3 DENY vs approved)", got.Disagreed)
	}
	if got.Errored != 1 {
		t.Errorf("Errored = %d, want 1 (ae4 ERROR)", got.Errored)
	}
	if got.Labeled != 0 {
		t.Errorf("Labeled = %d, want 0", got.Labeled)
	}
}

func TestUpsertLabel_AffectsAgreedCount(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	// ae1: original=approved, replay=DENY → disagrees without label
	// With label decision=DENY → agrees with label
	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")

	run, err := s.CreateRun(policyID)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := s.AddResult(EvalResult{
		RunID: run.ID, EntryID: "ae1",
		ReplayDecision: "DENY", ReplayedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddResult: %v", err)
	}

	// Without label: disagrees (DENY vs approved→ALLOW)
	got, err := s.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun (before label): %v", err)
	}
	if got.Agreed != 0 || got.Disagreed != 1 || got.Labeled != 0 {
		t.Errorf("before label: agreed=%d disagreed=%d labeled=%d, want 0,1,0",
			got.Agreed, got.Disagreed, got.Labeled)
	}

	// Add label: DENY is what should happen
	if err := s.UpsertLabel(AuditLabel{
		EntryID: "ae1", Decision: "DENY", LabeledBy: "admin@x.com",
	}); err != nil {
		t.Fatalf("UpsertLabel: %v", err)
	}

	got, err = s.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun (after label): %v", err)
	}
	if got.Agreed != 1 || got.Disagreed != 0 || got.Labeled != 1 {
		t.Errorf("after label: agreed=%d disagreed=%d labeled=%d, want 1,0,1",
			got.Agreed, got.Disagreed, got.Labeled)
	}
}

func TestListResults_WithAndWithoutLabels(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	seedAuditEntry(t, "ae2", "POST", "/api/2", "denied")

	run, err := s.CreateRun(policyID)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	now := time.Now()
	for _, id := range []string{"ae1", "ae2"} {
		if err := s.AddResult(EvalResult{
			RunID: run.ID, EntryID: id, ReplayDecision: "ALLOW", ReplayedAt: now,
		}); err != nil {
			t.Fatalf("AddResult(%s): %v", id, err)
		}
	}

	// Without labels: LabelDecision should be empty for all
	results, _, err := s.ListResults(run.ID, ResultFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, r := range results {
		if r.LabelDecision != "" {
			t.Errorf("entry %s: LabelDecision = %q, want empty", r.EntryID, r.LabelDecision)
		}
	}

	// Label ae1
	if err := s.UpsertLabel(AuditLabel{EntryID: "ae1", Decision: "ALLOW"}); err != nil {
		t.Fatalf("UpsertLabel: %v", err)
	}

	results, _, err = s.ListResults(run.ID, ResultFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults after label: %v", err)
	}
	byEntry := map[string]*EvalResult{}
	for _, r := range results {
		byEntry[r.EntryID] = r
	}
	if byEntry["ae1"].LabelDecision != "ALLOW" {
		t.Errorf("ae1 LabelDecision = %q, want ALLOW", byEntry["ae1"].LabelDecision)
	}
	if byEntry["ae2"].LabelDecision != "" {
		t.Errorf("ae2 LabelDecision = %q, want empty", byEntry["ae2"].LabelDecision)
	}
}

func TestDeleteLabel(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	run, err := s.CreateRun(policyID)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := s.AddResult(EvalResult{
		RunID: run.ID, EntryID: "ae1", ReplayDecision: "ALLOW", ReplayedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddResult: %v", err)
	}

	// Add then delete label
	if err := s.UpsertLabel(AuditLabel{EntryID: "ae1", Decision: "ALLOW"}); err != nil {
		t.Fatalf("UpsertLabel: %v", err)
	}
	if err := s.DeleteLabel("ae1"); err != nil {
		t.Fatalf("DeleteLabel: %v", err)
	}

	results, _, err := s.ListResults(run.ID, ResultFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults: %v", err)
	}
	if len(results) != 1 || results[0].LabelDecision != "" {
		t.Errorf("after delete: LabelDecision = %q, want empty", results[0].LabelDecision)
	}
}

func TestCreateLLMResponse_RoundTrip(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)

	id, err := s.CreateLLMResponse(types.LLMResponse{
		Model: "claude-haiku-4-5", DurationMs: 312,
		InputTokens: 800, OutputTokens: 38,
		Result: "success", Decision: "ALLOW", Reason: "looks fine",
		RawOutput: `{"decision":"ALLOW","reason":"looks fine"}`,
	})
	if err != nil {
		t.Fatalf("CreateLLMResponse: %v", err)
	}
	if id == "" {
		t.Error("expected non-empty ID")
	}

	got, err := s.GetLLMResponse(id)
	if err != nil {
		t.Fatalf("GetLLMResponse: %v", err)
	}
	if got.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q, want claude-haiku-4-5", got.Model)
	}
	if got.DurationMs != 312 {
		t.Errorf("DurationMs = %d, want 312", got.DurationMs)
	}
	if got.InputTokens != 800 {
		t.Errorf("InputTokens = %d, want 800", got.InputTokens)
	}
	if got.Result != "success" {
		t.Errorf("Result = %q, want success", got.Result)
	}
	if got.Decision != "ALLOW" {
		t.Errorf("Decision = %q, want ALLOW", got.Decision)
	}
}

func TestCreateLLMResponse_ErrorResult(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)

	id, err := s.CreateLLMResponse(types.LLMResponse{
		Model: "claude-haiku-4-5", DurationMs: 5001,
		Result: "error", RawOutput: "bedrock invoke failed: context deadline exceeded",
	})
	if err != nil {
		t.Fatalf("CreateLLMResponse: %v", err)
	}

	got, _ := s.GetLLMResponse(id)
	if got.Result != "error" {
		t.Errorf("Result = %q, want error", got.Result)
	}
	if got.Decision != "" {
		t.Errorf("Decision should be empty on error, got %q", got.Decision)
	}
}

func TestAddResult_WithLLMResponseID(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)

	policyID := seedPolicy(t)
	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	run, _ := s.CreateRun(policyID)

	llmID, _ := s.CreateLLMResponse(types.LLMResponse{
		Model: "claude-sonnet-4-6", DurationMs: 890, Result: "success",
		Decision: "ALLOW", Reason: "read-only is fine",
	})

	if err := s.AddResult(EvalResult{
		RunID: run.ID, EntryID: "ae1",
		ReplayDecision: "ALLOW", LLMResponseID: llmID, ReplayedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddResult: %v", err)
	}

	results, _, err := s.ListResults(run.ID, ResultFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].LLMResponseID != llmID {
		t.Errorf("LLMResponseID = %q, want %q", results[0].LLMResponseID, llmID)
	}
	if results[0].ReplayReason != "read-only is fine" {
		t.Errorf("ReplayReason = %q, want 'read-only is fine' (from JOIN)", results[0].ReplayReason)
	}
}

func TestListRuns_IncludesStats(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved") // ALLOW replay → agreed
	seedAuditEntry(t, "ae2", "GET", "/api/2", "denied")   // DENY replay  → agreed
	seedAuditEntry(t, "ae3", "GET", "/api/3", "approved") // DENY replay  → disagreed
	seedAuditEntry(t, "ae4", "GET", "/api/4", "approved") // ERROR replay → errored

	run, err := s.CreateRun(policyID)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	now := time.Now()
	for _, c := range []struct{ id, dec string }{
		{"ae1", "ALLOW"}, {"ae2", "DENY"}, {"ae3", "DENY"}, {"ae4", "ERROR"},
	} {
		if err := s.AddResult(EvalResult{
			RunID: run.ID, EntryID: c.id, ReplayDecision: c.dec, ReplayedAt: now,
		}); err != nil {
			t.Fatalf("AddResult(%s): %v", c.id, err)
		}
	}

	runs, err := s.ListRuns(policyID, 10, 0)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	got := runs[0]
	if got.Total != 4 {
		t.Errorf("Total = %d, want 4", got.Total)
	}
	if got.Agreed != 2 {
		t.Errorf("Agreed = %d, want 2", got.Agreed)
	}
	if got.Disagreed != 1 {
		t.Errorf("Disagreed = %d, want 1", got.Disagreed)
	}
	if got.Errored != 1 {
		t.Errorf("Errored = %d, want 1", got.Errored)
	}
	if got.Labeled != 0 {
		t.Errorf("Labeled = %d, want 0", got.Labeled)
	}
}

func TestListRuns_FilterByPolicy(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	pol1 := seedPolicy(t)
	pol2 := seedPolicy(t)

	run1, _ := s.CreateRun(pol1)
	run2, _ := s.CreateRun(pol2)
	_, _ = run1, run2

	all, err := s.ListRuns("", 10, 0)
	if err != nil {
		t.Fatalf("ListRuns(all): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("len(all) = %d, want 2", len(all))
	}

	filtered, err := s.ListRuns(pol1, 10, 0)
	if err != nil {
		t.Fatalf("ListRuns(pol1): %v", err)
	}
	if len(filtered) != 1 {
		t.Errorf("len(filtered) = %d, want 1", len(filtered))
	}
	if filtered[0].PolicyID != pol1 {
		t.Errorf("PolicyID = %q, want %q", filtered[0].PolicyID, pol1)
	}
}

func TestGetLabel_UnknownEntry_ReturnsNil(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)

	lbl, err := s.GetLabel("nonexistent")
	if err != nil {
		t.Fatalf("GetLabel: unexpected error: %v", err)
	}
	if lbl != nil {
		t.Errorf("GetLabel(nonexistent) = %+v, want nil", lbl)
	}
}

func TestListResults_FilterApprovedBy(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	seedAuditEntry(t, "ae2", "GET", "/api/2", "approved")

	run, _ := s.CreateRun(policyID)
	now := time.Now()
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae1", ReplayDecision: "ALLOW", ApprovedBy: "llm", ReplayedAt: now})
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae2", ReplayDecision: "ALLOW", ApprovedBy: "llm-passthrough", ReplayedAt: now})

	res, total, err := s.ListResults(run.ID, ResultFilter{ApprovedBy: "llm"}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(approved_by=llm): %v", err)
	}
	if len(res) != 1 || total != 1 {
		t.Errorf("approved_by=llm: got %d results (total %d), want 1", len(res), total)
	}
	if res[0].EntryID != "ae1" {
		t.Errorf("expected ae1, got %s", res[0].EntryID)
	}

	res, total, err = s.ListResults(run.ID, ResultFilter{ApprovedBy: "llm-passthrough"}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(approved_by=llm-passthrough): %v", err)
	}
	if len(res) != 1 || total != 1 {
		t.Errorf("approved_by=llm-passthrough: got %d results (total %d), want 1", len(res), total)
	}
}

func TestListResults_FilterReplayDecision(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	seedAuditEntry(t, "ae2", "GET", "/api/2", "denied")
	seedAuditEntry(t, "ae3", "GET", "/api/3", "approved")

	run, _ := s.CreateRun(policyID)
	now := time.Now()
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae1", ReplayDecision: "ALLOW", ReplayedAt: now})
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae2", ReplayDecision: "DENY", ReplayedAt: now})
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae3", ReplayDecision: "ERROR", ReplayedAt: now})

	for _, tc := range []struct {
		decision string
		want     int
	}{
		{"ALLOW", 1},
		{"DENY", 1},
		{"ERROR", 1},
	} {
		res, total, err := s.ListResults(run.ID, ResultFilter{ReplayDecision: tc.decision}, 10, 0)
		if err != nil {
			t.Fatalf("ListResults(replay_decision=%s): %v", tc.decision, err)
		}
		if len(res) != tc.want || total != tc.want {
			t.Errorf("replay_decision=%s: got %d results (total %d), want %d", tc.decision, len(res), total, tc.want)
		}
	}
}

func TestListResults_FilterHasLabel(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	seedAuditEntry(t, "ae2", "GET", "/api/2", "approved")

	run, _ := s.CreateRun(policyID)
	now := time.Now()
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae1", ReplayDecision: "ALLOW", ReplayedAt: now})
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae2", ReplayDecision: "ALLOW", ReplayedAt: now})
	s.UpsertLabel(AuditLabel{EntryID: "ae1", Decision: "ALLOW"})

	tru := true
	fls := false

	res, total, err := s.ListResults(run.ID, ResultFilter{HasLabel: &tru}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(has_label=true): %v", err)
	}
	if len(res) != 1 || total != 1 {
		t.Errorf("has_label=true: got %d results (total %d), want 1", len(res), total)
	}

	res, total, err = s.ListResults(run.ID, ResultFilter{HasLabel: &fls}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(has_label=false): %v", err)
	}
	if len(res) != 1 || total != 1 {
		t.Errorf("has_label=false: got %d results (total %d), want 1", len(res), total)
	}
	_ = res
}

func TestListResults_FilterMatched(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	// ae1: original=approved, replay=ALLOW → agreed
	// ae2: original=approved, replay=DENY  → disagreed
	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	seedAuditEntry(t, "ae2", "GET", "/api/2", "approved")

	run, _ := s.CreateRun(policyID)
	now := time.Now()
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae1", ReplayDecision: "ALLOW", ReplayedAt: now})
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae2", ReplayDecision: "DENY", ReplayedAt: now})

	tru := true
	fls := false

	res, total, err := s.ListResults(run.ID, ResultFilter{Matched: &tru}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(matched=true): %v", err)
	}
	if len(res) != 1 || total != 1 || res[0].EntryID != "ae1" {
		t.Errorf("matched=true: got %d results (total %d), want 1 (ae1)", len(res), total)
	}

	res, total, err = s.ListResults(run.ID, ResultFilter{Matched: &fls}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(matched=false): %v", err)
	}
	if len(res) != 1 || total != 1 || res[0].EntryID != "ae2" {
		t.Errorf("matched=false: got %d results (total %d), want 1 (ae2)", len(res), total)
	}
}

func TestListResults_FilterCombination(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/1", "approved")
	seedAuditEntry(t, "ae2", "GET", "/api/2", "approved")
	seedAuditEntry(t, "ae3", "GET", "/api/3", "approved")

	run, _ := s.CreateRun(policyID)
	now := time.Now()
	// ae1: llm, disagreed (DENY vs approved)
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae1", ReplayDecision: "DENY", ApprovedBy: "llm", ReplayedAt: now})
	// ae2: llm-passthrough, agreed (ALLOW)
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae2", ReplayDecision: "ALLOW", ApprovedBy: "llm-passthrough", ReplayedAt: now})
	// ae3: llm, agreed (ALLOW)
	s.AddResult(EvalResult{RunID: run.ID, EntryID: "ae3", ReplayDecision: "ALLOW", ApprovedBy: "llm", ReplayedAt: now})

	fls := false
	res, total, err := s.ListResults(run.ID, ResultFilter{ApprovedBy: "llm", Matched: &fls}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(approved_by=llm, matched=false): %v", err)
	}
	if len(res) != 1 || total != 1 || res[0].EntryID != "ae1" {
		t.Errorf("combination filter: got %d results (total %d), want 1 (ae1)", len(res), total)
	}
}

func TestListResults_FilterReturnsTotal(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("ae%d", i)
		seedAuditEntry(t, id, "GET", fmt.Sprintf("/api/%d", i), "approved")
	}

	run, _ := s.CreateRun(policyID)
	now := time.Now()
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("ae%d", i)
		dec := "ALLOW"
		if i > 3 {
			dec = "DENY"
		}
		s.AddResult(EvalResult{RunID: run.ID, EntryID: id, ReplayDecision: dec, ReplayedAt: now})
	}

	// Fetch page of 2 with ALLOW filter — total should be 3, page returns 2
	res, total, err := s.ListResults(run.ID, ResultFilter{ReplayDecision: "ALLOW"}, 2, 0)
	if err != nil {
		t.Fatalf("ListResults: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3 (all ALLOW entries even though page size is 2)", total)
	}
	if len(res) != 2 {
		t.Errorf("len(res) = %d, want 2 (page size)", len(res))
	}
}

func TestListResults_FilterURL(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	seedAuditEntry(t, "ae1", "GET", "/api/users/123", "approved")
	seedAuditEntry(t, "ae2", "GET", "/api/orders/456", "approved")
	seedAuditEntry(t, "ae3", "GET", "/api/users/789", "approved")

	run, _ := s.CreateRun(policyID)
	now := time.Now()
	for _, id := range []string{"ae1", "ae2", "ae3"} {
		s.AddResult(EvalResult{RunID: run.ID, EntryID: id, ReplayDecision: "ALLOW", ReplayedAt: now})
	}

	// Substring match on "users" should return ae1 and ae3
	res, total, err := s.ListResults(run.ID, ResultFilter{URL: "users"}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(url=users): %v", err)
	}
	if total != 2 || len(res) != 2 {
		t.Errorf("url=users: got %d results (total %d), want 2", len(res), total)
	}
	for _, r := range res {
		if r.URL != "/api/users/123" && r.URL != "/api/users/789" {
			t.Errorf("unexpected URL %q", r.URL)
		}
	}

	// Exact-ish match on "orders" should return ae2 only
	res, total, err = s.ListResults(run.ID, ResultFilter{URL: "orders"}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(url=orders): %v", err)
	}
	if total != 1 || len(res) != 1 {
		t.Errorf("url=orders: got %d results (total %d), want 1", len(res), total)
	}

	// Case-insensitive
	_, total, err = s.ListResults(run.ID, ResultFilter{URL: "USERS"}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(url=USERS): %v", err)
	}
	if total != 2 {
		t.Errorf("url=USERS (case-insensitive): got total=%d, want 2", total)
	}

	// No match
	res, total, err = s.ListResults(run.ID, ResultFilter{URL: "nonexistent"}, 10, 0)
	if err != nil {
		t.Fatalf("ListResults(url=nonexistent): %v", err)
	}
	if total != 0 || len(res) != 0 {
		t.Errorf("url=nonexistent: got %d results, want 0", total)
	}
}

func TestUpdateRunStatus_CompletedSetsCompletedAt(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTestTables(t)
	s := newStore(t)
	policyID := seedPolicy(t)

	run, err := s.CreateRun(policyID)
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := s.UpdateRunStatus(run.ID, "completed", ""); err != nil {
		t.Fatalf("UpdateRunStatus: %v", err)
	}

	got, err := s.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Status != "completed" {
		t.Errorf("Status = %q, want completed", got.Status)
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt should be set after status=completed")
	}
}
