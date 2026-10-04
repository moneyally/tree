-- Username links (docs/PROTOCOL.md 8.4, `user.username_link`): the hash of
-- a random link token per account, never the token. Resetting replaces the
-- row, so the old link stops working. Lookups answer only while the
-- account's @username is registered and discoverable.
CREATE TABLE username_links (
    account_id  TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    hash        BLOB NOT NULL UNIQUE,         -- SHA-256("tree/ulink/v1" || token)
    created_day INTEGER NOT NULL
);
