package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a new pgxpool.Pool with sensible defaults.
// maxConns and minConns are optional overrides; pass 0 to use defaults (10/2).
func Open(ctx context.Context, dsn string, maxConns, minConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db.Open: parse config: %w", err)
	}

	configurePoolConfig(cfg, maxConns, minConns)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db.Open: connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db.Open: ping: %w", err)
	}

	return pool, nil
}

func configurePoolConfig(cfg *pgxpool.Config, maxConns, minConns int32) {
	// Avoid server-side prepared statements so PgBouncer / pooled Postgres
	// endpoints do not break on deterministic stmtcache names while keeping
	// pgx's type inference for parameters like JSON payloads.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	if maxConns > 0 {
		cfg.MaxConns = maxConns
	} else {
		cfg.MaxConns = 10
	}
	if minConns > 0 {
		cfg.MinConns = minConns
	} else {
		cfg.MinConns = 2
	}
}
