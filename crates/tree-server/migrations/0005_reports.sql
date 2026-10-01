-- Reports and account suspension (docs/PROTOCOL.md 8.5).
-- A server secret for franking tags; generated once.
CREATE TABLE server_secrets (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- What a user's device submitted: the reported message(s) in plaintext, by
-- the reporter's choice. Kept for operator review only.
CREATE TABLE reports (
    id               TEXT PRIMARY KEY,
    reported_account TEXT NOT NULL,
    reporter_account TEXT NOT NULL,
    reason           TEXT NOT NULL,
    messages         TEXT NOT NULL,      -- JSON array of {payload, verified}
    verified         INTEGER NOT NULL,   -- every message's franking tag checked out
    created_day      INTEGER NOT NULL,
    resolved         INTEGER NOT NULL DEFAULT 0,
    resolution       TEXT,
    resolved_day     INTEGER             -- deleted RESOLVED_KEEP_DAYS later
);
CREATE INDEX reports_reporter ON reports(reporter_account, created_day);
CREATE INDEX reports_reported ON reports(reported_account, created_day);

-- Suspended accounts may not send, commit, claim or upload.
CREATE TABLE suspensions (
    account_id TEXT PRIMARY KEY,
    since_day  INTEGER NOT NULL,
    reason     TEXT
);
