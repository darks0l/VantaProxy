package db

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestConfigurePoolConfigUsesCacheDescribeQueryMode(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://crabtrap:secret@localhost:5432/crabtrap?sslmode=disable")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	configurePoolConfig(cfg, 5, 1)

	if got := cfg.ConnConfig.DefaultQueryExecMode; got != pgx.QueryExecModeCacheDescribe {
		t.Fatalf("DefaultQueryExecMode = %v, want %v", got, pgx.QueryExecModeCacheDescribe)
	}
	if got := cfg.MaxConns; got != 5 {
		t.Fatalf("MaxConns = %d, want 5", got)
	}
	if got := cfg.MinConns; got != 1 {
		t.Fatalf("MinConns = %d, want 1", got)
	}
}

func TestConfigurePoolConfigUsesDefaultPoolSizes(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://crabtrap:secret@localhost:5432/crabtrap?sslmode=disable")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	configurePoolConfig(cfg, 0, 0)

	if got := cfg.ConnConfig.DefaultQueryExecMode; got != pgx.QueryExecModeCacheDescribe {
		t.Fatalf("DefaultQueryExecMode = %v, want %v", got, pgx.QueryExecModeCacheDescribe)
	}
	if got := cfg.MaxConns; got != 10 {
		t.Fatalf("MaxConns = %d, want 10", got)
	}
	if got := cfg.MinConns; got != 2 {
		t.Fatalf("MinConns = %d, want 2", got)
	}
}
