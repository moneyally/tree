-- Group invite links (docs/PROTOCOL.md 8.7). The server keeps the hash of
-- the link's secret, who made it, and the limits; never the group.
CREATE TABLE invites (
    token_hash    BLOB PRIMARY KEY,           -- SHA-256("tree/invite/v1" || token)
    owner_account TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    owner_device  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at    INTEGER NOT NULL,
    max_uses      INTEGER NOT NULL,
    uses          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX invites_owner ON invites(owner_device);

-- Someone used a link; waits until the owner's device handles it.
CREATE TABLE invite_requests (
    id         TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL REFERENCES invites(token_hash) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    UNIQUE (token_hash, account_id)
);
