-- External-developer bot registry.
-- Token plaintext never persists. token_hmac is HMAC-SHA256(server secret, token).

CREATE TABLE bots (
    id                  TEXT PRIMARY KEY,
    owner_account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    token_hmac          BLOB UNIQUE,
    token_issued_at     INTEGER,
    token_revoked_at    INTEGER,
    privacy_mode        INTEGER NOT NULL DEFAULT 1 CHECK (privacy_mode IN (0,1)),
    join_groups         INTEGER NOT NULL DEFAULT 1 CHECK (join_groups IN (0,1)),
    inline_mode         INTEGER NOT NULL DEFAULT 0 CHECK (inline_mode IN (0,1)),
    directory_listed    INTEGER NOT NULL DEFAULT 0 CHECK (directory_listed IN (0,1)),
    created_at          INTEGER NOT NULL
);
CREATE INDEX bots_owner ON bots(owner_account_id);

CREATE TABLE bot_commands (
    bot_id       TEXT PRIMARY KEY REFERENCES bots(id) ON DELETE CASCADE,
    commands_json TEXT NOT NULL
);

CREATE TABLE bot_menu_button (
    bot_id       TEXT PRIMARY KEY REFERENCES bots(id) ON DELETE CASCADE,
    text         TEXT NOT NULL,
    url          TEXT NOT NULL
);
