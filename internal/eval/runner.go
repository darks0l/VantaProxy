package eval

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/darksol/Vanta/internal/approval"
	"github.com/darksol/Vanta/internal/judge"
	"github.com/darksol/Vanta/pkg/types"
)

// judgeResultToLLMResponse converts a JudgeResult (and optional error) to a
// types.LLMResponse ready to be persisted.
func judgeResultToLLMResponse(r judge.JudgeResult, err error) types.LLMResponse {
	lr := types.LLMResponse{
		Model:        r.Model,
		DurationMs:   r.DurationMs,
		InputTokens:  r.InputTokens,
		OutputTokens: r.OutputTokens,
		RawOutput:    r.RawOutput,
	}
	if err != nil {
		lr.Result = "error"
		if lr.RawOutput == "" {
			lr.RawOutput = err.Error()
		}
	} else {
		lr.Result = "success"
		lr.Decision = string(r.Decision)
		lr.Reason = r.Reason
	}
	return lr
}

// ErrUserCanceled is set as the context cause when a run is stopped via the
// cancel API, allowing RunEval to distinguish user-initiated stops from failures.
var ErrUserCanceled = errors.New("canceled by user")

// evalConcurrency is the number of judge calls that run in parallel per eval run.
const evalConcurrency = 25

// RunEval re-evaluates entries from entryCh against policy, writing results to
// store as it goes. Runs synchronously — caller is responsible for launching in
// a goroutine.
//
// Status transitions:
//   - pending → running (immediately on entry)
//   - running → completed (after channel is drained without cancellation)
//   - running → failed (on context cancellation or panic)
//
// Individual judge errors produce results with ReplayDecision="ERROR" but do not
// fail the run — only context cancellation or panics set status to "failed".
func RunEval(ctx context.Context, j *judge.LLMJudge, entryCh <-chan types.AuditEntry, policy types.LLMPolicy, store Store, runID string) {
	defer func() {
		if r := recover(); r != nil {
			errMsg := fmt.Sprintf("panic: %v", r)
			slog.Error("eval.RunEval: panic", "run_id", runID, "error", errMsg)
			store.UpdateRunStatus(runID, "failed", errMsg) //nolint:errcheck — panic is never user-initiated
		}
	}()

	if err := store.UpdateRunStatus(runID, "running", ""); err != nil {
		slog.Error("eval.RunEval: set running failed", "run_id", runID, "error", err)
	}

	sem := make(chan struct{}, evalConcurrency)
	var wg sync.WaitGroup

loop:
	for {
		// Check cancellation deterministically before reading the next entry.
		// A bare select{ctx.Done, entryCh} is non-deterministic when both
		// cases are ready (already-cancelled context + entry available), which
		// causes flaky test failures.
		if err := ctx.Err(); err != nil {
			wg.Wait()
			if updateErr := store.UpdateRunStatus(runID, canceledOrFailed(ctx), err.Error()); updateErr != nil {
				slog.Error("eval.RunEval: set failed", "run_id", runID, "error", updateErr)
			}
			return
		}

		var entry types.AuditEntry
		select {
		case <-ctx.Done():
			wg.Wait()
			if err := store.UpdateRunStatus(runID, canceledOrFailed(ctx), ctx.Err().Error()); err != nil {
				slog.Error("eval.RunEval: set failed", "run_id", runID, "error", err)
			}
			return
		case e, ok := <-entryCh:
			if !ok {
				break loop
			}
			entry = e
		}

		// Check cancellation deterministically before attempting to acquire the
		// semaphore. A bare select{ctx.Done, sem<-} is non-deterministic when
		// both cases are ready (already-cancelled context + available semaphore
		// slot), which causes flaky test failures.
		if err := ctx.Err(); err != nil {
			wg.Wait()
			if updateErr := store.UpdateRunStatus(runID, canceledOrFailed(ctx), err.Error()); updateErr != nil {
				slog.Error("eval.RunEval: set failed", "run_id", runID, "error", updateErr)
			}
			return
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			if err := store.UpdateRunStatus(runID, canceledOrFailed(ctx), ctx.Err().Error()); err != nil {
				slog.Error("eval.RunEval: set failed", "run_id", runID, "error", err)
			}
			return
		case sem <- struct{}{}:
		}

		wg.Add(1)
		e := entry
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			var replayDecision, approvedBy, llmResponseID string

			// Check static rules before calling the LLM judge,
			// mirroring production behaviour.
			if matched, action := approval.MatchesStaticRules(e.Method, e.URL, policy.StaticRules); matched {
				if action == "deny" {
					replayDecision = "DENY"
				} else {
					replayDecision = "ALLOW"
				}
				approvedBy = "llm-static-rule"
			} else {
				approvedBy = "llm"
				judgeResult, judgeErr := j.Evaluate(ctx, e.Method, e.URL, e.RequestHeaders, e.RequestBody, policy)

				replayDecision = "ERROR"
				if judgeErr == nil {
					replayDecision = string(judgeResult.Decision)
				}

				// Persist the LLM response row (even on error, if we have model metadata).
				if judgeResult.Model != "" {
					llmResp := judgeResultToLLMResponse(judgeResult, judgeErr)
					if id, createErr := store.CreateLLMResponse(llmResp); createErr != nil {
						slog.Error("eval.RunEval: CreateLLMResponse failed", "run_id", runID, "entry_id", e.ID, "error", createErr)
					} else {
						llmResponseID = id
					}
				}
			}

			if addErr := store.AddResult(EvalResult{
				RunID:          runID,
				EntryID:        e.ID,
				ReplayDecision: replayDecision,
				ApprovedBy:     approvedBy,
				LLMResponseID:  llmResponseID,
				ReplayedAt:     time.Now(),
			}); addErr != nil {
				slog.Error("eval.RunEval: AddResult failed", "run_id", runID, "entry_id", e.ID, "error", addErr)
			}
		}()
	}

	wg.Wait()

	if err := store.UpdateRunStatus(runID, "completed", ""); err != nil {
		slog.Error("eval.RunEval: set completed failed", "run_id", runID, "error", err)
	}
}

// canceledOrFailed returns "canceled" if the context was stopped via
// ErrUserCanceled, otherwise "failed".
func canceledOrFailed(ctx context.Context) string {
	if context.Cause(ctx) == ErrUserCanceled {
		return "canceled"
	}
	return "failed"
}

// RunEvalFromSlice is a convenience wrapper that feeds entries into a channel
// and calls RunEval. Used by tests and any caller with an in-memory slice.
func RunEvalFromSlice(ctx context.Context, j *judge.LLMJudge, entries []types.AuditEntry, policy types.LLMPolicy, store Store, runID string) {
	ch := make(chan types.AuditEntry, len(entries))
	for _, e := range entries {
		ch <- e
	}
	close(ch)
	RunEval(ctx, j, ch, policy, store, runID)
}
