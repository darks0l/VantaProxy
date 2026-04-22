package eval

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/darksol/Vanta/internal/db"
	"github.com/darksol/Vanta/pkg/types"
)

// EvalRun represents an async re-evaluation run of audit entries against a policy.
// Aggregate stats (Total, Agreed, etc.) are computed via SQL on read, not stored.
type EvalRun struct {
	ID          string     `json:"id"`
	PolicyID    string     `json:"policy_id"`
	PolicyName  string     `json:"policy_name,omitempty"` // from llm_policies JOIN; present even if deleted
	Status      string     `json:"status"` // "pending" | "running" | "completed" | "failed"
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	// Populated by GetRun/ListRuns via SQL aggregation — not stored columns:
	TotalEntries int `json:"total_entries"` // set at run creation; 0 = unknown
	Total        int `json:"total"`
	Agreed       int `json:"agreed"`
	Disagreed    int `json:"disagreed"`
	Errored      int `json:"errored"`
	Labeled      int `json:"labeled"`
}

// EvalResult stores the outcome of re-evaluating one audit entry.
// Method, URL, OriginalDecision come from audit_log JOIN on read;
// LabelDecision/LabelNote from audit_labels JOIN; ReplayReason from llm_responses JOIN.
type EvalResult struct {
	ID              string    `json:"id"`
	RunID           string    `json:"run_id"`
	EntryID         string    `json:"entry_id"`
	ReplayDecision  string    `json:"replay_decision"`
	ApprovedBy      string    `json:"approved_by"`           // "llm" | "llm-static-rule"
	LLMResponseID   string    `json:"llm_response_id,omitempty"`
	ReplayedAt      time.Time `json:"replayed_at"`
	// Populated on read only (not stored directly):
	ReplayReason     string `json:"replay_reason,omitempty"`  // from llm_responses JOIN
	Method           string `json:"method,omitempty"`
	URL              string `json:"url,omitempty"`
	OriginalDecision string `json:"original_decision,omitempty"`
	LabelDecision    string `json:"label_decision,omitempty"`
	LabelNote        string `json:"label_note,omitempty"`
}

// AuditLabel is a global ground-truth label for an audit entry, independent of
// any eval run. One label per entry (upsert). Created by admins after review.
type AuditLabel struct {
	ID        string    `json:"id"`
	EntryID   string    `json:"entry_id"`
	Decision  string    `json:"decision"` // "ALLOW" | "DENY"
	Note      string    `json:"note,omitempty"`
	LabeledBy string    `json:"labeled_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ResultFilter filters eval results returned by ListResults.
type ResultFilter struct {
	ApprovedBy     string // "llm" | "llm-passthrough" | "" (all)
	ReplayDecision string // "ALLOW" | "DENY" | "ERROR" | "" (all)
	HasLabel       *bool  // nil=all, true=labeled, false=unlabeled
	Matched        *bool  // nil=all, true=agreed, false=disagreed
	URL            string // substring match against alog.url (case-insensitive)
}

// EvalApproverStats holds per-approver (or overall) counts and latency percentiles.
type EvalApproverStats struct {
	ApprovedBy string `json:"approved_by"`
	Total      int    `json:"total"`
	Agreed     int    `json:"agreed"`
	Disagreed  int    `json:"disagreed"`
	Errored    int    `json:"errored"`
	P50Ms      *int   `json:"p50_ms,omitempty"`
	P95Ms      *int   `json:"p95_ms,omitempty"`
	P99Ms      *int   `json:"p99_ms,omitempty"`
}

// EvalLabeledStats holds counts and latency for labeled entries per approver (or overall).
type EvalLabeledStats struct {
	ApprovedBy       string `json:"approved_by"`
	Labeled          int    `json:"labeled"`
	LabeledAgreed    int    `json:"labeled_agreed"`
	LabeledDisagreed int    `json:"labeled_disagreed"`
	P50Ms            *int   `json:"p50_ms,omitempty"`
	P95Ms            *int   `json:"p95_ms,omitempty"`
	P99Ms            *int   `json:"p99_ms,omitempty"`
}

// EvalRunStats is the response shape for GET /admin/evals/{id}/stats.
type EvalRunStats struct {
	ByApprovedBy        []EvalApproverStats `json:"by_approved_by"`
	Overall             EvalApproverStats   `json:"overall"`
	LabeledByApprovedBy []EvalLabeledStats  `json:"labeled_by_approved_by"`
	LabeledOverall      EvalLabeledStats    `json:"labeled_overall"`
}

// Store manages eval runs, results, audit labels, and LLM response records.
type Store interface {
	// LLM responses
	CreateLLMResponse(r types.LLMResponse) (string, error) // returns generated ID
	GetLLMResponse(id string) (*types.LLMResponse, error)

	// Eval runs
	CreateRun(policyID string) (*EvalRun, error)
	UpdateRunStatus(id, status, errMsg string) error
	GetRun(id string) (*EvalRun, error) // computes aggregate stats via SQL
	GetRunStats(id string) (*EvalRunStats, error)
	ListRuns(policyID string, limit, offset int) ([]*EvalRun, error)

	// Eval run mutation
	SetTotalEntries(id string, n int) error

	// Eval results
	AddResult(result EvalResult) error
	ListResults(runID string, filter ResultFilter, limit, offset int) ([]*EvalResult, int, error)

	// Labels (global ground truth)
	UpsertLabel(label AuditLabel) error
	GetLabel(entryID string) (*AuditLabel, error)
	DeleteLabel(entryID string) error
}

// PGStore implements Store using PostgreSQL.
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore creates a new PGStore.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// CreateLLMResponse inserts an llm_responses row and returns the generated ID.
func (s *PGStore) CreateLLMResponse(r types.LLMResponse) (string, error) {
	id := db.NewID("llmr")
	ctx := context.Background()
	var inputTokens, outputTokens *int
	if r.InputTokens > 0 {
		inputTokens = &r.InputTokens
	}
	if r.OutputTokens > 0 {
		outputTokens = &r.OutputTokens
	}
	var decision, reason, rawOutput *string
	if r.Decision != "" {
		decision = &r.Decision
	}
	if r.Reason != "" {
		reason = &r.Reason
	}
	if r.RawOutput != "" {
		rawOutput = &r.RawOutput
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO llm_responses(id, model, duration_ms, input_tokens, output_tokens, result, decision, reason, raw_output)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, id, r.Model, r.DurationMs, inputTokens, outputTokens, r.Result, decision, reason, rawOutput)
	if err != nil {
		return "", fmt.Errorf("CreateLLMResponse: %w", err)
	}
	return id, nil
}

// GetLLMResponse fetches a single llm_responses row by ID.
func (s *PGStore) GetLLMResponse(id string) (*types.LLMResponse, error) {
	ctx := context.Background()
	var r types.LLMResponse
	var inputTokens, outputTokens *int
	var decision, reason, rawOutput *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, model, duration_ms, input_tokens, output_tokens, result, decision, reason, raw_output, created_at
		FROM llm_responses WHERE id = $1
	`, id).Scan(&r.ID, &r.Model, &r.DurationMs, &inputTokens, &outputTokens, &r.Result, &decision, &reason, &rawOutput, &r.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("llm_response not found: %s", id)
		}
		return nil, fmt.Errorf("GetLLMResponse: %w", err)
	}
	if inputTokens != nil {
		r.InputTokens = *inputTokens
	}
	if outputTokens != nil {
		r.OutputTokens = *outputTokens
	}
	if decision != nil {
		r.Decision = *decision
	}
	if reason != nil {
		r.Reason = *reason
	}
	if rawOutput != nil {
		r.RawOutput = *rawOutput
	}
	return &r, nil
}

// CreateRun inserts a new eval run with status "pending" and returns it.
func (s *PGStore) CreateRun(policyID string) (*EvalRun, error) {
	id := db.NewID("evalrun")
	ctx := context.Background()
	var run EvalRun
	err := s.pool.QueryRow(ctx, `
		INSERT INTO eval_runs(id, policy_id, status)
		VALUES($1, $2, 'pending')
		RETURNING id, policy_id, status, error, created_at, completed_at, COALESCE(total_entries, 0)
	`, id, policyID).Scan(
		&run.ID, &run.PolicyID, &run.Status, &run.Error, &run.CreatedAt, &run.CompletedAt, &run.TotalEntries,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateRun: %w", err)
	}
	return &run, nil
}

// UpdateRunStatus updates the status and optional error message of a run.
// Sets completed_at when status is "completed" or "failed".
func (s *PGStore) UpdateRunStatus(id, status, errMsg string) error {
	ctx := context.Background()
	var err error
	if status == "completed" || status == "failed" || status == "canceled" {
		_, err = s.pool.Exec(ctx, `
			UPDATE eval_runs SET status=$2, error=$3, completed_at=NOW()
			WHERE id=$1
		`, id, status, errMsg)
	} else {
		_, err = s.pool.Exec(ctx, `
			UPDATE eval_runs SET status=$2, error=$3
			WHERE id=$1
		`, id, status, errMsg)
	}
	if err != nil {
		return fmt.Errorf("UpdateRunStatus: %w", err)
	}
	return nil
}

// GetRun fetches a run by ID and computes aggregate stats via SQL aggregation.
//
// Agreement logic:
//   - If a label exists for the entry: agreed = replay_decision matches label.decision
//   - If no label: agreed = replay_decision matches normalized original_decision
//     ("approved" → "ALLOW", "denied" → "DENY")
func (s *PGStore) GetRun(id string) (*EvalRun, error) {
	ctx := context.Background()
	var run EvalRun
	err := s.pool.QueryRow(ctx, `
		SELECT r.id, r.policy_id, COALESCE(p.name, ''), r.status, r.error, r.created_at, r.completed_at, COALESCE(r.total_entries, 0)
		FROM eval_runs r
		LEFT JOIN llm_policies p ON p.id = r.policy_id
		WHERE r.id=$1
	`, id).Scan(&run.ID, &run.PolicyID, &run.PolicyName, &run.Status, &run.Error, &run.CreatedAt, &run.CompletedAt, &run.TotalEntries)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("eval_run not found: %s", id)
		}
		return nil, fmt.Errorf("GetRun: %w", err)
	}

	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*)                                                 AS total,
			COUNT(lbl.id)                                           AS labeled,
			COUNT(*) FILTER (WHERE er.replay_decision = 'ERROR')    AS errored,
			COUNT(*) FILTER (WHERE
				er.replay_decision != 'ERROR'
				AND (
					(lbl.decision IS NOT NULL AND er.replay_decision = lbl.decision)
					OR (lbl.decision IS NULL AND er.replay_decision = CASE alog.decision
						WHEN 'approved' THEN 'ALLOW'
						WHEN 'denied'   THEN 'DENY'
						ELSE alog.decision END)
				)
			) AS agreed,
			COUNT(*) FILTER (WHERE
				er.replay_decision != 'ERROR'
				AND NOT (
					(lbl.decision IS NOT NULL AND er.replay_decision = lbl.decision)
					OR (lbl.decision IS NULL AND er.replay_decision = CASE alog.decision
						WHEN 'approved' THEN 'ALLOW'
						WHEN 'denied'   THEN 'DENY'
						ELSE alog.decision END)
				)
			) AS disagreed
		FROM eval_results er
		LEFT JOIN audit_log alog ON alog.id = er.entry_id
		LEFT JOIN audit_labels lbl ON lbl.entry_id = er.entry_id
		WHERE er.run_id = $1
	`, id).Scan(&run.Total, &run.Labeled, &run.Errored, &run.Agreed, &run.Disagreed)
	if err != nil {
		return nil, fmt.Errorf("GetRun stats: %w", err)
	}
	return &run, nil
}

// ListRuns returns runs filtered by policyID (empty = all) with pagination,
// ordered by creation time descending. Stats are computed inline via aggregation.
func (s *PGStore) ListRuns(policyID string, limit, offset int) ([]*EvalRun, error) {
	if limit <= 0 {
		limit = 50
	}
	ctx := context.Background()

	const statsSubquery = `
		SELECT
			r.id, r.policy_id, COALESCE(p.name, ''), r.status, r.error, r.created_at, r.completed_at, COALESCE(r.total_entries, 0),
			COUNT(er.id)                                              AS total,
			COUNT(lbl.id)                                             AS labeled,
			COUNT(er.id) FILTER (WHERE er.replay_decision = 'ERROR')  AS errored,
			COUNT(er.id) FILTER (WHERE
				er.replay_decision != 'ERROR'
				AND (
					(lbl.decision IS NOT NULL AND er.replay_decision = lbl.decision)
					OR (lbl.decision IS NULL AND er.replay_decision = CASE alog.decision
						WHEN 'approved' THEN 'ALLOW'
						WHEN 'denied'   THEN 'DENY'
						ELSE alog.decision END)
				)
			) AS agreed,
			COUNT(er.id) FILTER (WHERE
				er.replay_decision != 'ERROR'
				AND NOT (
					(lbl.decision IS NOT NULL AND er.replay_decision = lbl.decision)
					OR (lbl.decision IS NULL AND er.replay_decision = CASE alog.decision
						WHEN 'approved' THEN 'ALLOW'
						WHEN 'denied'   THEN 'DENY'
						ELSE alog.decision END)
				)
			) AS disagreed
		FROM eval_runs r
		LEFT JOIN llm_policies p ON p.id = r.policy_id
		LEFT JOIN eval_results er ON er.run_id = r.id
		LEFT JOIN audit_log alog ON alog.id = er.entry_id
		LEFT JOIN audit_labels lbl ON lbl.entry_id = er.entry_id
	`

	var (
		rows pgx.Rows
		err  error
	)
	if policyID != "" {
		rows, err = s.pool.Query(ctx, statsSubquery+`
			WHERE r.policy_id=$1
			GROUP BY r.id, p.name
			ORDER BY r.created_at DESC LIMIT $2 OFFSET $3
		`, policyID, limit, offset)
	} else {
		rows, err = s.pool.Query(ctx, statsSubquery+`
			GROUP BY r.id, p.name
			ORDER BY r.created_at DESC LIMIT $1 OFFSET $2
		`, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("ListRuns: %w", err)
	}
	defer rows.Close()

	var runs []*EvalRun
	for rows.Next() {
		var run EvalRun
		if err := rows.Scan(
			&run.ID, &run.PolicyID, &run.PolicyName, &run.Status, &run.Error, &run.CreatedAt, &run.CompletedAt, &run.TotalEntries,
			&run.Total, &run.Labeled, &run.Errored, &run.Agreed, &run.Disagreed,
		); err != nil {
			return nil, fmt.Errorf("ListRuns scan: %w", err)
		}
		runs = append(runs, &run)
	}
	if runs == nil {
		runs = []*EvalRun{}
	}
	return runs, rows.Err()
}

// SetTotalEntries stores the number of entries queued for evaluation on a run.
func (s *PGStore) SetTotalEntries(id string, n int) error {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `UPDATE eval_runs SET total_entries=$2 WHERE id=$1`, id, n)
	if err != nil {
		return fmt.Errorf("SetTotalEntries: %w", err)
	}
	return nil
}

// AddResult inserts an eval result. The ID is generated internally.
func (s *PGStore) AddResult(result EvalResult) error {
	id := db.NewID("evalres")
	ctx := context.Background()
	var llmResponseID *string
	if result.LLMResponseID != "" {
		llmResponseID = &result.LLMResponseID
	}
	approvedBy := result.ApprovedBy
	if approvedBy == "" {
		approvedBy = "llm"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO eval_results(id, run_id, entry_id, replay_decision, approved_by, llm_response_id, replayed_at)
		VALUES($1, $2, $3, $4, $5, $6, $7)
	`, id, result.RunID, result.EntryID, result.ReplayDecision, approvedBy, llmResponseID, result.ReplayedAt)
	if err != nil {
		return fmt.Errorf("AddResult: %w", err)
	}
	return nil
}

// agreeInnerSQL is the agreement condition (without the ERROR guard) used in
// both GetRun aggregation and ListResults filtering.
const agreeInnerSQL = `(
			(lbl.decision IS NOT NULL AND er.replay_decision = lbl.decision)
			OR (lbl.decision IS NULL AND er.replay_decision = CASE alog.decision
				WHEN 'approved' THEN 'ALLOW'
				WHEN 'denied'   THEN 'DENY'
				ELSE alog.decision END)
		)`

// ListResults returns eval results for a run filtered by filter, joined with
// audit_log, audit_labels, and llm_responses. Returns the total filtered count
// (via window function) alongside the page of results.
func (s *PGStore) ListResults(runID string, filter ResultFilter, limit, offset int) ([]*EvalResult, int, error) {
	if limit <= 0 {
		limit = 100
	}
	ctx := context.Background()

	var conds []string
	var args []interface{}
	idx := 1

	add := func(cond string, val interface{}) {
		conds = append(conds, fmt.Sprintf(cond, idx))
		args = append(args, val)
		idx++
	}

	conds = append(conds, fmt.Sprintf("er.run_id = $%d", idx))
	args = append(args, runID)
	idx++

	if filter.ApprovedBy != "" {
		add("er.approved_by = $%d", filter.ApprovedBy)
	}
	if filter.ReplayDecision != "" {
		add("er.replay_decision = $%d", filter.ReplayDecision)
	}
	if filter.HasLabel != nil {
		if *filter.HasLabel {
			conds = append(conds, "lbl.decision IS NOT NULL")
		} else {
			conds = append(conds, "lbl.decision IS NULL")
		}
	}
	if filter.Matched != nil {
		if *filter.Matched {
			conds = append(conds, "er.replay_decision != 'ERROR' AND "+agreeInnerSQL)
		} else {
			conds = append(conds, "er.replay_decision != 'ERROR' AND NOT "+agreeInnerSQL)
		}
	}
	if filter.URL != "" {
		add("alog.url ILIKE $%d", "%"+filter.URL+"%")
	}

	where := "WHERE " + strings.Join(conds, " AND ")

	q := fmt.Sprintf(`
		SELECT
			er.id, er.run_id, er.entry_id,
			er.replay_decision, er.approved_by, COALESCE(er.llm_response_id, ''), er.replayed_at,
			COALESCE(lr.reason, '')     AS replay_reason,
			COALESCE(alog.method, '')   AS method,
			COALESCE(alog.url, '')      AS url,
			COALESCE(alog.decision, '') AS original_decision,
			COALESCE(lbl.decision, '')  AS label_decision,
			COALESCE(lbl.note, '')      AS label_note,
			COUNT(*) OVER()             AS total_count
		FROM eval_results er
		LEFT JOIN llm_responses lr   ON lr.id = er.llm_response_id
		LEFT JOIN audit_log alog     ON alog.id = er.entry_id
		LEFT JOIN audit_labels lbl   ON lbl.entry_id = er.entry_id
		%s
		ORDER BY er.replayed_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListResults: %w", err)
	}
	defer rows.Close()

	var results []*EvalResult
	totalCount := 0
	for rows.Next() {
		var r EvalResult
		if err := rows.Scan(
			&r.ID, &r.RunID, &r.EntryID,
			&r.ReplayDecision, &r.ApprovedBy, &r.LLMResponseID, &r.ReplayedAt,
			&r.ReplayReason,
			&r.Method, &r.URL, &r.OriginalDecision,
			&r.LabelDecision, &r.LabelNote,
			&totalCount,
		); err != nil {
			return nil, 0, fmt.Errorf("ListResults scan: %w", err)
		}
		results = append(results, &r)
	}
	if results == nil {
		results = []*EvalResult{}
	}
	return results, totalCount, rows.Err()
}

// GetRunStats returns per-approver counts, latency percentiles, and labeled
// entry breakdown for an eval run. Latency is only meaningful for "llm" entries
// (those with an llm_response_id); static-rule entries show nil latency.
//
// Three queries:
//  1. Counts (total/agreed/disagreed/errored) per approved_by + overall via GROUPING SETS
//  2. Latency percentiles per approved_by + overall (LLM entries only, via JOIN llm_responses)
//  3. Labeled counts + latency per approved_by + overall
func (s *PGStore) GetRunStats(id string) (*EvalRunStats, error) {
	ctx := context.Background()
	stats := &EvalRunStats{
		ByApprovedBy:        []EvalApproverStats{},
		LabeledByApprovedBy: []EvalLabeledStats{},
	}

	// ── Query 1: counts per approved_by + overall ──────────────────────────
	rows, err := s.pool.Query(ctx, `
		SELECT
			er.approved_by,
			COUNT(*)                                                              AS total,
			COUNT(*) FILTER (WHERE er.replay_decision = 'ERROR')                 AS errored,
			COUNT(*) FILTER (WHERE er.replay_decision != 'ERROR' AND `+agreeInnerSQL+`)     AS agreed,
			COUNT(*) FILTER (WHERE er.replay_decision != 'ERROR' AND NOT `+agreeInnerSQL+`) AS disagreed
		FROM eval_results er
		LEFT JOIN audit_log alog   ON alog.id       = er.entry_id
		LEFT JOIN audit_labels lbl ON lbl.entry_id  = er.entry_id
		WHERE er.run_id = $1
		GROUP BY GROUPING SETS ((er.approved_by), ())
	`, id)
	if err != nil {
		return nil, fmt.Errorf("GetRunStats counts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var approvedBy *string
		var row EvalApproverStats
		if err := rows.Scan(&approvedBy, &row.Total, &row.Errored, &row.Agreed, &row.Disagreed); err != nil {
			return nil, fmt.Errorf("GetRunStats counts scan: %w", err)
		}
		if approvedBy == nil {
			stats.Overall = row
		} else {
			row.ApprovedBy = *approvedBy
			stats.ByApprovedBy = append(stats.ByApprovedBy, row)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRunStats counts rows: %w", err)
	}

	// ── Query 2: LLM latency percentiles per approved_by + overall ─────────
	// Only entries with an llm_response_id are included (static-rule entries
	// have no LLM call and therefore no meaningful eval latency).
	latRows, err := s.pool.Query(ctx, `
		SELECT
			er.approved_by,
			ROUND(percentile_cont(0.50) WITHIN GROUP (ORDER BY lr.duration_ms))::int AS p50,
			ROUND(percentile_cont(0.95) WITHIN GROUP (ORDER BY lr.duration_ms))::int AS p95,
			ROUND(percentile_cont(0.99) WITHIN GROUP (ORDER BY lr.duration_ms))::int AS p99
		FROM eval_results er
		JOIN llm_responses lr ON lr.id = er.llm_response_id
		WHERE er.run_id = $1
		GROUP BY GROUPING SETS ((er.approved_by), ())
	`, id)
	if err != nil {
		return nil, fmt.Errorf("GetRunStats latency: %w", err)
	}
	defer latRows.Close()

	latByApprover := map[string][3]*int{}
	var overallLat [3]*int
	for latRows.Next() {
		var approvedBy *string
		var p50, p95, p99 *int
		if err := latRows.Scan(&approvedBy, &p50, &p95, &p99); err != nil {
			return nil, fmt.Errorf("GetRunStats latency scan: %w", err)
		}
		if approvedBy == nil {
			overallLat = [3]*int{p50, p95, p99}
		} else {
			latByApprover[*approvedBy] = [3]*int{p50, p95, p99}
		}
	}
	if err := latRows.Err(); err != nil {
		return nil, fmt.Errorf("GetRunStats latency rows: %w", err)
	}

	for i := range stats.ByApprovedBy {
		if lat, ok := latByApprover[stats.ByApprovedBy[i].ApprovedBy]; ok {
			stats.ByApprovedBy[i].P50Ms = lat[0]
			stats.ByApprovedBy[i].P95Ms = lat[1]
			stats.ByApprovedBy[i].P99Ms = lat[2]
		}
	}
	stats.Overall.P50Ms = overallLat[0]
	stats.Overall.P95Ms = overallLat[1]
	stats.Overall.P99Ms = overallLat[2]

	// ── Query 3: labeled counts + latency per approved_by + overall ─────────
	lblRows, err := s.pool.Query(ctx, `
		SELECT
			er.approved_by,
			COUNT(*)                                                                            AS labeled,
			COUNT(*) FILTER (WHERE er.replay_decision != 'ERROR' AND er.replay_decision = lbl.decision)  AS labeled_agreed,
			COUNT(*) FILTER (WHERE er.replay_decision != 'ERROR' AND er.replay_decision != lbl.decision) AS labeled_disagreed,
			ROUND(percentile_cont(0.50) WITHIN GROUP (ORDER BY lr.duration_ms))::int           AS p50,
			ROUND(percentile_cont(0.95) WITHIN GROUP (ORDER BY lr.duration_ms))::int           AS p95,
			ROUND(percentile_cont(0.99) WITHIN GROUP (ORDER BY lr.duration_ms))::int           AS p99
		FROM eval_results er
		JOIN audit_labels lbl      ON lbl.entry_id  = er.entry_id
		LEFT JOIN llm_responses lr ON lr.id         = er.llm_response_id
		WHERE er.run_id = $1
		GROUP BY GROUPING SETS ((er.approved_by), ())
	`, id)
	if err != nil {
		return nil, fmt.Errorf("GetRunStats labeled: %w", err)
	}
	defer lblRows.Close()

	for lblRows.Next() {
		var approvedBy *string
		var ls EvalLabeledStats
		var p50, p95, p99 *int
		if err := lblRows.Scan(&approvedBy, &ls.Labeled, &ls.LabeledAgreed, &ls.LabeledDisagreed, &p50, &p95, &p99); err != nil {
			return nil, fmt.Errorf("GetRunStats labeled scan: %w", err)
		}
		ls.P50Ms, ls.P95Ms, ls.P99Ms = p50, p95, p99
		if approvedBy == nil {
			stats.LabeledOverall = ls
		} else {
			ls.ApprovedBy = *approvedBy
			stats.LabeledByApprovedBy = append(stats.LabeledByApprovedBy, ls)
		}
	}
	if err := lblRows.Err(); err != nil {
		return nil, fmt.Errorf("GetRunStats labeled rows: %w", err)
	}

	return stats, nil
}

// UpsertLabel inserts or updates the ground-truth label for an audit entry.
// One label per entry_id; subsequent calls update decision/note/labeled_by.
func (s *PGStore) UpsertLabel(label AuditLabel) error {
	id := db.NewID("evallbl")
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_labels(id, entry_id, decision, note, labeled_by, created_at)
		VALUES($1, $2, $3, $4, $5, NOW())
		ON CONFLICT(entry_id) DO UPDATE
			SET decision   = EXCLUDED.decision,
			    note       = EXCLUDED.note,
			    labeled_by = EXCLUDED.labeled_by
	`, id, label.EntryID, label.Decision, label.Note, label.LabeledBy)
	if err != nil {
		return fmt.Errorf("UpsertLabel: %w", err)
	}
	return nil
}

// GetLabel returns the label for an audit entry, or nil, nil if not found.
func (s *PGStore) GetLabel(entryID string) (*AuditLabel, error) {
	ctx := context.Background()
	var l AuditLabel
	err := s.pool.QueryRow(ctx, `
		SELECT id, entry_id, decision, note, labeled_by, created_at
		FROM audit_labels WHERE entry_id=$1
	`, entryID).Scan(&l.ID, &l.EntryID, &l.Decision, &l.Note, &l.LabeledBy, &l.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("GetLabel: %w", err)
	}
	return &l, nil
}

// DeleteLabel removes the label for an audit entry.
func (s *PGStore) DeleteLabel(entryID string) error {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `DELETE FROM audit_labels WHERE entry_id=$1`, entryID)
	if err != nil {
		return fmt.Errorf("DeleteLabel: %w", err)
	}
	return nil
}
