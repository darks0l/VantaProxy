package eval

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/darksol/Vanta/internal/dbtest"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup, err := dbtest.Setup()
	if err != nil {
		slog.Error("eval TestMain", "error", err)
		os.Exit(1)
	}
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// truncateTestTables wipes all tables relevant to eval tests.
// TRUNCATE llm_policies CASCADE covers: audit_log (via llm_policy_id FK),
// eval_runs (via policy_id FK), and transitively eval_results and audit_labels.
func truncateTestTables(t *testing.T) {
	t.Helper()
	testPool.Exec(context.Background(), "TRUNCATE llm_policies CASCADE")
	// Also truncate audit_log rows that have no llm_policy_id (NULL FK rows are
	// not covered by the llm_policies cascade).
	testPool.Exec(context.Background(), "TRUNCATE audit_log CASCADE")
}
