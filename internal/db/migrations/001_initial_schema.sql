-- Collapsed migration: represents the final schema state.
-- All statements are idempotent (IF NOT EXISTS / IF EXISTS) so this migration
-- is safe to run against both fresh databases and existing databases that
-- already have the schema in place from prior incremental migrations.

--------------------------------------------------------------------------------
-- llm_policies (must precede users, audit_log, eval_runs)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS llm_policies (
    id           TEXT PRIMARY KEY,  -- "llmpol_xxx"
    name         TEXT NOT NULL,
    prompt       TEXT NOT NULL DEFAULT '',
    provider     TEXT NOT NULL DEFAULT '',  -- "" = use gateway default
    model        TEXT NOT NULL DEFAULT '',  -- "" = use gateway default
    forked_from  TEXT REFERENCES llm_policies(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ,
    static_rules JSONB NOT NULL DEFAULT '[]',
    status       VARCHAR(20) NOT NULL DEFAULT 'published'
);

CREATE INDEX IF NOT EXISTS idx_llm_policies_created ON llm_policies(created_at DESC);

--------------------------------------------------------------------------------
-- llm_policy_builder_metadata
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS llm_policy_builder_metadata (
    policy_id  TEXT        NOT NULL PRIMARY KEY REFERENCES llm_policies(id) ON DELETE CASCADE,
    metadata   JSONB       NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

--------------------------------------------------------------------------------
-- users
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,  -- email, e.g. john@company.com
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    llm_policy_id TEXT REFERENCES llm_policies(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

--------------------------------------------------------------------------------
-- user_channels
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_channels (
    id           TEXT PRIMARY KEY,  -- "chan_xxx"
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_type TEXT NOT NULL,     -- "slack" | "web" | "gateway_auth"
    payload      JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, channel_type)
);

-- Used by GetUserByWebToken (called on every proxied request)
CREATE INDEX IF NOT EXISTS idx_user_channels_web_token
    ON user_channels((payload->>'web_token')) WHERE channel_type = 'web';

-- Used by GetUserByGatewayAuthToken (called on every proxied request)
CREATE INDEX IF NOT EXISTS idx_user_channels_gateway_auth_token
    ON user_channels((payload->>'gateway_auth_token')) WHERE channel_type = 'gateway_auth';

--------------------------------------------------------------------------------
-- llm_responses (must precede audit_log, eval_results)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS llm_responses (
    id            TEXT PRIMARY KEY,
    model         TEXT        NOT NULL,
    duration_ms   INT         NOT NULL,
    input_tokens  INT,
    output_tokens INT,
    result        TEXT        NOT NULL, -- 'success' | 'error'
    decision      TEXT,                 -- 'ALLOW' | 'DENY' | NULL on error
    reason        TEXT,                 -- parsed reason | NULL on error
    raw_output    TEXT,                 -- model text on success, error message on error
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

--------------------------------------------------------------------------------
-- audit_log
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id               TEXT        PRIMARY KEY,  -- "audit_xxx"
    user_id          TEXT        REFERENCES users(id),  -- nullable: ADMIN ops have no user
    timestamp        TIMESTAMPTZ NOT NULL,
    request_id       TEXT        NOT NULL,
    method           TEXT        NOT NULL DEFAULT '',
    url              TEXT        NOT NULL DEFAULT '',
    operation        TEXT        NOT NULL DEFAULT '',  -- "READ"|"WRITE"|"ADMIN"
    decision         TEXT        NOT NULL DEFAULT '',  -- "ALLOW"|"DENY"|"TIMEOUT"
    cache_hit        BOOLEAN     NOT NULL DEFAULT FALSE,
    approved_by      TEXT        NOT NULL DEFAULT '',
    approved_at      TEXT        NOT NULL DEFAULT '',
    channel          TEXT        NOT NULL DEFAULT '',
    response_status  INT         NOT NULL DEFAULT 0,
    duration_ms      BIGINT      NOT NULL DEFAULT 0,
    error            TEXT        NOT NULL DEFAULT '',
    request_headers  JSONB       NOT NULL DEFAULT '{}',
    request_body     TEXT        NOT NULL DEFAULT '',
    response_headers JSONB       NOT NULL DEFAULT '{}',
    response_body    TEXT        NOT NULL DEFAULT '',
    api_info         JSONB,
    llm_policy_id    TEXT        REFERENCES llm_policies(id),
    llm_response_id  TEXT        REFERENCES llm_responses(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id         ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp        ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_decision         ON audit_log(decision);
CREATE INDEX IF NOT EXISTS idx_audit_log_channel          ON audit_log(channel);
CREATE INDEX IF NOT EXISTS idx_audit_log_request_id       ON audit_log(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_cache_hit        ON audit_log(cache_hit);
CREATE INDEX IF NOT EXISTS idx_audit_log_llm_policy_id    ON audit_log(llm_policy_id) WHERE llm_policy_id IS NOT NULL;

--------------------------------------------------------------------------------
-- eval_runs
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eval_runs (
    id            TEXT PRIMARY KEY,
    policy_id     TEXT NOT NULL REFERENCES llm_policies(id),
    status        TEXT NOT NULL DEFAULT 'pending',
    error         TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ,
    total_entries INT
);

CREATE INDEX IF NOT EXISTS idx_eval_runs_policy_id  ON eval_runs(policy_id);
CREATE INDEX IF NOT EXISTS idx_eval_runs_created_at ON eval_runs(created_at DESC);

--------------------------------------------------------------------------------
-- eval_results
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eval_results (
    id              TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL REFERENCES eval_runs(id),
    entry_id        TEXT NOT NULL REFERENCES audit_log(id),
    replay_decision TEXT NOT NULL DEFAULT '',
    llm_response_id TEXT REFERENCES llm_responses(id),
    replayed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by     TEXT NOT NULL DEFAULT 'llm'
);

CREATE INDEX IF NOT EXISTS idx_eval_results_run_id              ON eval_results(run_id);
CREATE INDEX IF NOT EXISTS idx_eval_results_entry_id            ON eval_results(entry_id);
CREATE INDEX IF NOT EXISTS idx_eval_results_run_approved_by     ON eval_results(run_id, approved_by);
CREATE INDEX IF NOT EXISTS idx_eval_results_run_replay_decision ON eval_results(run_id, replay_decision);

--------------------------------------------------------------------------------
-- audit_labels
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_labels (
    id          TEXT PRIMARY KEY,
    entry_id    TEXT NOT NULL UNIQUE REFERENCES audit_log(id),
    decision    TEXT NOT NULL,          -- "ALLOW" | "DENY"
    note        TEXT NOT NULL DEFAULT '',
    labeled_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
