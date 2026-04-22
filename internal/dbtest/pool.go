// Package dbtest provides test helpers for spinning up a real PostgreSQL instance.
// Only test files import this package; production code never does.
//
// If TEST_DATABASE_URL is set, both Setup and NewPool connect to that existing
// instance instead of starting a container. This is used in CI where Postgres
// runs as a service sidecar.
package dbtest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/darksol/Vanta/internal/db"
)

// NewPool connects to Postgres and returns a pool for the test.
// Uses TEST_DATABASE_URL if set; otherwise starts a container.
func NewPool(tb testing.TB) *pgxpool.Pool {
	tb.Helper()
	pool, cleanup, err := Setup()
	if err != nil {
		tb.Fatalf("dbtest.NewPool: %v", err)
	}
	tb.Cleanup(cleanup)
	return pool
}

// EnsureUser upserts a row into the users table so that FK references do not fail in tests.
func EnsureUser(ctx context.Context, pool *pgxpool.Pool, userID string) error {
	if userID == "" {
		return nil
	}
	_, err := pool.Exec(ctx,
		`INSERT INTO users(id) VALUES($1) ON CONFLICT(id) DO NOTHING`, userID)
	return err
}

// Setup returns a pool backed by either TEST_DATABASE_URL (CI) or a fresh
// testcontainers postgres instance (local dev). Caller must call cleanup().
func Setup() (pool *pgxpool.Pool, cleanup func(), err error) {
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		return setupExternal(dsn)
	}
	return setupContainer()
}

// setupExternal connects to an already-running Postgres instance.
func setupExternal(dsn string) (*pgxpool.Pool, func(), error) {
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn, 5, 1)
	if err != nil {
		return nil, nil, fmt.Errorf("dbtest: connect to %s: %w", dsn, err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("dbtest: migrate: %w", err)
	}
	slog.Info("dbtest: using external postgres", "dsn", dsn)
	return pool, pool.Close, nil
}

// setupContainer starts a postgres:17-alpine container via testcontainers-go.
func setupContainer() (*pgxpool.Pool, func(), error) {
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("vantaproxy_test"),
		tcpostgres.WithUsername("vantaproxy",
		tcpostgres.WithPassword("secret"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, nil, err
	}

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		ctr.Terminate(ctx)
		return nil, nil, err
	}

	pool, err := db.Open(ctx, dsn, 5, 1)
	if err != nil {
		ctr.Terminate(ctx)
		return nil, nil, err
	}

	if err = db.Migrate(ctx, pool); err != nil {
		pool.Close()
		ctr.Terminate(ctx)
		return nil, nil, err
	}

	cleanup := func() {
		pool.Close()
		if err := ctr.Terminate(context.Background()); err != nil {
			slog.Error("dbtest: terminate container", "error", err)
		}
	}
	return pool, cleanup, nil
}
