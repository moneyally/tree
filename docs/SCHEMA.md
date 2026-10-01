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
| 2 | `tree_group_state` (HANDOFF 3.1), `tree_app` (HANDOFF 3.3). Version-1 files are upgraded on open; other versions are refused |

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
```

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
| `openmls_key_packages` | private parts of unused one-time key packages | yes |
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

Message history, contacts, pinned safety numbers and feature-registry state
are not stored yet. When they are
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
