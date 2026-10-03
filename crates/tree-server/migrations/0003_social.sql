-- Stage-1 identity/social state.
-- Usernames are stored only as a deterministic 32-byte hash computed by the
-- client. Message requests and blocks are account-to-account state; they do
-- not contain message content.

CREATE TABLE usernames (
    account_id    TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    username_hash BLOB NOT NULL UNIQUE
);

CREATE TABLE blocks (
    blocker_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    blocked_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (blocker_account_id, blocked_account_id),
    CHECK (blocker_account_id <> blocked_account_id)
);
CREATE INDEX blocks_blocked ON blocks(blocked_account_id);

CREATE TABLE message_requests (
    requester_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    target_account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('pending', 'accepted', 'rejected')),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (requester_account_id, target_account_id),
    CHECK (requester_account_id <> target_account_id)
);
CREATE INDEX message_requests_target_state
    ON message_requests(target_account_id, state);

-- Reports intentionally store opaque MLS/Tree evidence only. The server
-- cannot decrypt the envelope. category is a small moderation label, not
-- message content.
CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    reporter_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    group_id BLOB,
    ciphertext BLOB NOT NULL,
    ciphertext_sha256 BLOB NOT NULL,
    category TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX reports_created_at ON reports(created_at);
