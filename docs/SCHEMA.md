# Data schemas

Every place Tree stores data, what is in it, and who can read it. Byte formats
on the wire are in [PROTOCOL.md](PROTOCOL.md); the HTTP API is in
[SERVER_API.md](SERVER_API.md).

| Store | Where | Encrypted at rest | Readable by |
| --- | --- | --- | --- |
| Device database | one file per device identity, `<name>.db` + `<name>.db.hdr` | yes: SQLCipher 4, key from Argon2id (or another `KeySource`) | the device after unlock |
| Server database | `DATABASE_URL` (SQLite file today) | no (holds only ciphertext and routing data) | the server operator |

## 1. Device database (`crates/tree-core/src/storage`)

SQLCipher 4 with a raw 256-bit key (`PRAGMA cipher_version` must answer,
otherwise opening fails). `secure_delete = ON`, `temp_store = MEMORY`. Every
group operation runs in one transaction (`TreeProvider::atomically`).
Schema version: `PRAGMA user_version`.

| Version | Change |
| --- | --- |
| 1 | `tree_meta`, `tree_groups` + OpenMLS tables |
| 2 | `tree_group_state` (HANDOFF 3.1) |
| 3 | `tree_app` (app data), `tree_messages` (history). Versions 1 and 2 are upgraded on open (all later tables are created idempotently); newer versions are refused |
| 4 | `tree_messages.franking` (report records), `tree_messages.seq` (arrival order). Version 3 gets the columns added on open |

### 1.1 Key header `<db>.hdr` (not secret)

Salt and Argon2id parameters for rebuilding the database key; format in
`storage/key.rs` (`KeyHeader`). Default parameters: 64 MiB, 3 passes,
1 lane. Without the passphrase it reveals nothing.

### 1.2 Tree tables

```sql
CREATE TABLE tree_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE tree_groups (
    seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id BLOB NOT NULL UNIQUE
);
CREATE TABLE tree_group_state (group_id BLOB PRIMARY KEY, state BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE tree_app (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE tree_messages (
    group_id    BLOB NOT NULL,
    id          TEXT NOT NULL,       -- sender-chosen random id (hex)
    sender      TEXT NOT NULL,       -- member id (hex)
    received_at INTEGER NOT NULL,    -- this device's clock
    kind        TEXT NOT NULL,       -- text | file
    text        TEXT,                -- NULL once deleted for everyone
    data        BLOB,                -- e.g. the file reference; NULL after a view-once download
    edited_at   INTEGER,
    deleted     INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER,             -- disappearing messages
    reactions   TEXT NOT NULL DEFAULT '{}',  -- JSON emoji -> member ids
    franking    BLOB,                -- JSON {payload, key, tag, minute} to report it (v4); NULL when deleted
    seq         INTEGER NOT NULL DEFAULT 0,  -- arrival order within the same second (v4)
    PRIMARY KEY (group_id, id)
) WITHOUT ROWID;
CREATE TABLE tree_outbox (                     -- messages being sent (v5, PROTOCOL.md 6.13)
    seq        INTEGER PRIMARY KEY AUTOINCREMENT, -- send order
    local_id   TEXT NOT NULL UNIQUE,  -- random 16 bytes (hex); enqueue is idempotent by it
    group_id   BLOB NOT NULL,
    message_id TEXT,                  -- the tree_messages row it carries (text, file), if any
    payload    BLOB,                  -- encoded app payload while not sealed yet; NULL once sealed
    body       BLOB,                  -- the sealed MLS message, made once; NULL once sent
    recipients TEXT NOT NULL DEFAULT '[]',  -- JSON device ids, fixed when sealed
    idem_key   BLOB,                  -- 32-byte idempotency key, fixed when sealed
    state      TEXT NOT NULL CHECK (state IN ('queued', 'sending', 'sent', 'retry', 'failed')),
    attempts   INTEGER NOT NULL DEFAULT 0,  -- counted failed attempts (8 -> failed)
    next_at    INTEGER NOT NULL DEFAULT 0,  -- next attempt due (retry); time sent (sent)
    created_at INTEGER NOT NULL,
    last_error TEXT                   -- error text of the last attempt, no content
);
```

`tree_outbox`: a `sent` row keeps only ids, key and state (for the
history's "sent" mark and idempotent enqueue) and is deleted 30 days after
sending, on the next open. A cancelled `failed` row is deleted with its
history entry. Version 4 profiles get the table on open.

History is plaintext under the database encryption: forward secrecy does not
cover it (PROTOCOL.md 6.3 item 6). Deleted and expired rows are overwritten
(`secure_delete`).

`tree_app`: app data under the same encryption (`Client::app_data`,
`set_app_data`, `app_data_keys`). Keys used by `tree-client` are listed in
[APP_PROTOCOL.md](APP_PROTOCOL.md) section 4.

`tree_meta` rows (the device identity):

| key | value |
| --- | --- |
| `name` | display name, UTF-8 (never leaves the device except inside groups, F-009) |
| `ciphersuite` | MLS ciphersuite, 2 bytes big-endian (`0x004E`) |
| `signature_public_key` | Ed25519 public key (32 bytes); the private key is in `openmls_signature_keys` |
| `credential` | TLS-serialised MLS `Credential` (identity = the signature public key) |

`tree_groups`: every group this device created or joined, oldest first
(including groups it was later removed from).

`tree_group_state.state`: Tree's own state per group (`group_state.rs`),
binary, version byte `0x01`:

```text
u8  version = 1
u8  has_pending;  if 1: u64 epoch, bytes commit, u8 has_welcome, [bytes welcome]
u8  should_refresh
u8  n_past;       n_past x (u64 epoch, [32] envelope_key, u32 n, n x (u32 leaf, [32] member_id))
u16 n_sent;       n_sent x (u64 epoch, [32] sha256 of own merged commit envelope)
bytes = u32 length (big-endian) + data
```

| Field | Secret? | Kept until |
| --- | --- | --- |
| pending commit + welcome | the welcome carries group secrets for the added devices | confirmed or discarded |
| `envelope_key` of epochs `N-1`, `N-2` | yes (integrity key of that epoch) | the epoch leaves the 2-epoch window |
| leaf -> member id of `N-1`, `N-2` | no (public within the group) | same |
| own commit hashes | no | same |

### 1.3 OpenMLS tables (library `openmls_sqlite_storage` 0.3, JSON values)

Created by the library's own migrations. The ones Tree uses:

| Table | Content | Secret |
| --- | --- | --- |
| `openmls_signature_keys` | the device's MLS signature key pair | yes |
| `openmls_key_packages` | private parts of unused one-time key packages, and of the current and previous last-resort key package | yes |
| `openmls_encryption_keys`, `openmls_epoch_keys_pairs` | HPKE private keys of the leaf and path | yes |
| `openmls_group_data` | group context, ratchet tree, epoch secrets, secret tree (message keys) incl. retained past epochs, pending commit, join config | yes |
| `openmls_own_leaf_nodes` | own leaf nodes | no |
| `openmls_proposals` | queued proposals (always empty in Tree, F-007) | — |
| `openmls_psks` | pre-shared keys (unused) | — |

The library's `vc_*` tables (virtual clients, a draft feature) exist but are
not used. Values are JSON (the format the library is tested with). A binary
encoding would be ~3.7x smaller ([BENCHMARKS.md](BENCHMARKS.md) rec. 7) but
needs a codec for every stored type and a migration; not done.

### 1.4 Not stored yet

Contacts, pinned devices and the user's settings are app data (`tree_app`,
keys in APP_PROTOCOL.md section 6). When they are
added they belong in new `tree_*` tables of the same encrypted file, listed
here.

## 2. Server database (`crates/tree-server/migrations`)

SQLite through `sqlx` today (the design targets PostgreSQL at scale; the SQL
is kept portable). The server stores only what it needs to forward
ciphertext: no sender, no IP address, no plaintext. Creation dates at day
granularity, message arrival at minute granularity.

```sql
CREATE TABLE accounts (id TEXT PRIMARY KEY, created_day INTEGER NOT NULL);

CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    auth_pub    BLOB NOT NULL UNIQUE,            -- Ed25519 request-signing key
    created_day INTEGER NOT NULL
);

CREATE TABLE key_packages (                      -- one-time MLS key packages, opaque
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    data      BLOB NOT NULL
);

CREATE TABLE last_resort_key_packages (          -- one per device, never deleted by a claim
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data      BLOB NOT NULL
);

CREATE TABLE blobs (                             -- ciphertext, stored once per send
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    body        BLOB NOT NULL,
    received_at INTEGER NOT NULL                 -- unix time rounded to the minute
);

CREATE TABLE deliveries (                        -- one mailbox entry per recipient device
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    id        TEXT NOT NULL UNIQUE,              -- random public message id
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    blob_id   INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE
);

CREATE TABLE features (                          -- operator flags (server scope)
    key        TEXT PRIMARY KEY,
    state      TEXT NOT NULL CHECK (state IN ('applied', 'released')),
    changed_at INTEGER NOT NULL
);

CREATE TABLE feature_audit (                     -- operator actions, not user data
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, state TEXT NOT NULL,
    at INTEGER NOT NULL, reason TEXT
);
```

Indexes: `devices(account_id)`, `key_packages(device_id, id)`,
`blobs(received_at)`, `deliveries(device_id, seq)`, `deliveries(blob_id)`.

Retention: deliveries until acknowledged, at most `MESSAGE_TTL_SECS`
(30 days); blobs when no delivery refers to them; key packages until
claimed; accounts and devices until deleted.

What a seized server database reveals is listed in PROTOCOL.md section 11.

### 2.1 Commit ordering (migration `0002_commits.sql`)

```sql
CREATE TABLE groups (group_id BLOB PRIMARY KEY, last_epoch INTEGER NOT NULL);
CREATE TABLE group_devices (                     -- may take the next commit slot
    group_id  BLOB NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, device_id)
);
CREATE TABLE group_winners (                     -- last 64 accepted commits
    group_id BLOB NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL, sha256 BLOB NOT NULL, id TEXT NOT NULL,
    PRIMARY KEY (group_id, epoch)
);
```

This makes group membership (as device ids) visible in the database; the
server already sees it through recipient lists (PROTOCOL.md 11). A group's
rows are deleted by the purge task once none of its devices exists.

### 2.8 Idempotent sends (migration `0011_idempotency.sql`, PROTOCOL.md 8.10)

```sql
CREATE TABLE idempotency_keys (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,      -- age order for the per-device cap
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,  -- sending device
    key          BLOB NOT NULL,                          -- 16..64 bytes chosen by the device
    request_hash BLOB NOT NULL,                          -- SHA-256 over body and sorted recipients
    delivered    INTEGER NOT NULL,                       -- the first answer's count
    created_day  INTEGER NOT NULL,                       -- day only
    UNIQUE (device_id, key)
);
CREATE INDEX idempotency_keys_device ON idempotency_keys(device_id, seq);
CREATE INDEX idempotency_keys_day ON idempotency_keys(created_day);
```

No recipients, body, message id or time of day. Deleted by the purge task
once the whole day is older than `MESSAGE_TTL_SECS`, with the device, and
beyond `MAX_IDEMPOTENCY_KEYS` per device (oldest first). Migration number
`0010` is left free on purpose.

### 2.2 Usernames (migration `0003_usernames.sql`)

```sql
CREATE TABLE usernames (
    hash         BLOB PRIMARY KEY,           -- SHA-256("tree/username/v1" || name)
    account_id   TEXT NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
    discoverable INTEGER NOT NULL DEFAULT 1,
    created_day  INTEGER NOT NULL
);
```

### 2.3 Attachments (migration `0004_attachments.sql`)

```sql
CREATE TABLE attachments (id TEXT PRIMARY KEY, size INTEGER NOT NULL, created_at INTEGER NOT NULL);
```

The ciphertext itself is a file named by the id in `ATTACHMENT_DIR`. Deleted
with the row after the mailbox TTL.

### 2.4 Reports (migration `0005_reports.sql`, PROTOCOL.md 8.5)

```sql
CREATE TABLE server_secrets (name TEXT PRIMARY KEY, value BLOB NOT NULL);  -- 'franking': 32 random bytes
CREATE TABLE reports (
    id TEXT PRIMARY KEY, reported_account TEXT NOT NULL, reporter_account TEXT NOT NULL,
    reason TEXT NOT NULL,
    messages TEXT NOT NULL,          -- JSON [{payload, verified}]: plaintext the reporter chose to send
    verified INTEGER NOT NULL, created_day INTEGER NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0, resolution TEXT,
    resolved_day INTEGER               -- deleted 30 days later
);
CREATE TABLE suspensions (account_id TEXT PRIMARY KEY, since_day INTEGER NOT NULL, reason TEXT);
```

`server_secrets` is a secret: back it up with the database, never log it.

### 2.7 Push (migration `0008_push.sql`, PROTOCOL.md 8.8)

```sql
CREATE TABLE push_endpoints (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    endpoint  TEXT NOT NULL,     -- URL at an allowed gateway host
    set_day   INTEGER NOT NULL
);
```

### 2.6 Invite links (migration `0007_invites.sql`, PROTOCOL.md 8.7)

```sql
CREATE TABLE invites (
    token_hash BLOB PRIMARY KEY,            -- SHA-256("tree/invite/v1" || secret)
    owner_account TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    owner_device  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL, max_uses INTEGER NOT NULL, uses INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE invite_requests (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL REFERENCES invites(token_hash) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    UNIQUE (token_hash, account_id)
);
```

### 2.5 Recovery (migration `0006_recovery.sql`, PROTOCOL.md 8.6)

```sql
CREATE TABLE account_recovery (
    account_id   TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    recovery_pub   BLOB UNIQUE,          -- Ed25519 public key from the phrase; NULL = none
    set_day        INTEGER NOT NULL,
    pending_action TEXT,                 -- 'replace' | 'release': unsigned change waiting 7 days
    pending_pub    BLOB,
    pending_since  INTEGER
);
```
