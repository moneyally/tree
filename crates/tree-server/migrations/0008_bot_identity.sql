-- Every bot owns a separate Tree account identity so its E2E device keys
-- are isolated from the human owner account.

CREATE TABLE bot_identities (
    bot_id            TEXT PRIMARY KEY REFERENCES bots(id) ON DELETE CASCADE,
    account_id        TEXT NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
    gateway_device_id TEXT UNIQUE REFERENCES devices(id) ON DELETE SET NULL,
    created_at        INTEGER NOT NULL
);
