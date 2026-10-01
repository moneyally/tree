# Tree server API (v1, stage 1)

The server stores and forwards ciphertext. Message bodies and key packages are
opaque bytes; the server never sees plaintext or MLS keys.

## Conventions

- JSON over HTTPS. Binary values are **standard base64 with padding** (RFC 4648 §4).
- Identifiers (account, device, message) are 16 random bytes, **base64url without
  padding** (22 characters, canonical encoding).
- Times are unix seconds. Message arrival is rounded down to the minute.
- Every response carries a `Date` header (useful to correct clock skew).

## Errors

Every error is `{"code": "...", "message": "..."}`. `message` is for humans; match on `code`.
Some errors add fields (named with the endpoint).

| Code | HTTP | Meaning |
| --- | --- | --- |
| `BAD_REQUEST` | 400 | malformed JSON, base64, identifier or field |
| `POW_INVALID` | 400 | signup proof-of-work does not meet `POW_BITS` |
| `UNAUTHORIZED` | 401 | missing/bad signature, unknown device, replayed request, bad operator token |
| `TIMESTAMP_SKEW` | 401 | `X-Tree-Timestamp` more than 300 s away from server time |
| `LOCKED_BY_SERVER` | 403 | the feature is released by the operator (e.g. signups) |
| `NOT_ELIGIBLE` | 403 | commit from a device the server does not know as a member of the group |
| `SUSPENDED` | 403 | the account is suspended by the operator (every signed request) |
| `LIMITED` | 403 | a message or commit to more devices than the account may reach for now (new account, or recent verified reports; PROTOCOL.md 8.9) |
| `RECOVERY_REFUSED` | 403 | no account holds this recovery key, or the recovery signature is wrong |
| `NOT_FOUND` | 404 | no such endpoint, account or device |
| `UNKNOWN_FEATURE` | 404 | unknown feature key |
| `METHOD_NOT_ALLOWED` | 405 | wrong HTTP method |
| `ALREADY_EXISTS` | 409 | this authentication key is already registered |
| `LIMIT_EXCEEDED` | 409 | a stored quota is full (devices per account, key packages per device) |
| `COMMIT_CONFLICT` | 409 | another commit already won this epoch; field `winner_sha256` |
| `USERNAME_TAKEN` | 409 | another account holds this username |
| `EPOCH_MISMATCH` | 409 | commit for an epoch beyond the next one; field `last_epoch` |
| `TOO_LARGE` | 413 | body, message, commit, welcome, key package, or a list (recipients, key packages, ack ids) too large |
| `RATE_LIMITED` | 429 | slow down; see `Retry-After` (seconds) |
| `INTERNAL` | 500 | server error |

## Authentication

Each device has an Ed25519 **authentication key** (separate from its MLS keys).
Authenticated requests carry four headers:

| Header | Value |
| --- | --- |
| `X-Tree-Device` | device id |
| `X-Tree-Timestamp` | unix seconds, decimal digits only |
| `X-Tree-Nonce` | 16–64 characters of `[A-Za-z0-9_-]`, fresh for every request |
| `X-Tree-Signature` | base64 Ed25519 signature over the signing string |

Signing string (UTF-8, fields joined by `\n`, no trailing newline):

```
tree-auth-v1
<METHOD>
<path and query exactly as sent, e.g. /v1/messages?wait=25>
<X-Tree-Timestamp>
<X-Tree-Nonce>
<X-Tree-Device, or empty for signup>
<lowercase hex SHA-256 of the raw body; body may be empty>
```

The server rejects a timestamp more than 300 s from its clock, and accepts each
signature only once while it is inside that window. Signatures are verified
strictly (no malleable or small-order keys). The rate limit is applied only
after the signature verifies, so forged requests cannot drain a device's budget.

## Accounts and devices

### `POST /v1/accounts` — sign up

No phone number or email. Signed with the headers above, using the new key and
an **empty** device field; `X-Tree-Device` must be absent.

```json
{ "auth_pub": "<32-byte Ed25519 public key>", "pow_nonce": 123456 }
```

Proof-of-work: `SHA-256("tree-signup-v1" || auth_pub (32 bytes) || pow_nonce as
8-byte big-endian)` must start with `POW_BITS` zero bits (default 20).
`pow_nonce` is an integer in `0 ..= 2^53-1`.

`201` → `{ "account_id": "...", "device_id": "..." }`

Errors: `LOCKED_BY_SERVER` (flag `server.signups` released), `RATE_LIMITED`
(per client address, memory only), `POW_INVALID`, `UNAUTHORIZED`, `ALREADY_EXISTS`.

### `DELETE /v1/accounts` — delete my account

Signed by any device of the account. Deletes the account and every device
with its mailbox and key packages, its username, recovery key, push
endpoints and invite links. `200 { "deleted": true, "devices": n }`. A
suspended account cannot do this (`403 SUSPENDED`; whether it should:
변호사 확인 필요). Reports others filed about the account are kept.

### `POST /v1/devices` — add a device to my account

```json
{ "auth_pub": "<new device key>", "proof": "<signature by the new key>" }
```

`proof` signs `"tree-add-device-v1\n" + account_id + "\n"` followed by the 32
raw key bytes, proving the new device holds its key.
`201` → `{ "device_id": "..." }`. Errors: `LIMIT_EXCEEDED` (default 10 devices), `ALREADY_EXISTS`.

### `GET /v1/devices` — my devices

`200` → `{ "account_id": "...", "devices": ["<device_id>", ...] }`

### `DELETE /v1/devices/{device_id}` — remove one of my devices

Deletes the device, its key packages and its mailbox. Removing the last device
removes the account. `200` → `{ "removed": "<device_id>" }`; `NOT_FOUND` if it is
not on my account.

## Key packages (one-time, MLS)

### `POST /v1/keypackages` — upload

```json
{ "key_packages": ["<base64>", ...] }
```

At most 100 per upload, 16 KiB each, 200 stored per device.
`200` → `{ "stored": 3, "count": 42 }`. Errors: `TOO_LARGE`, `LIMIT_EXCEEDED`.

### `POST /v1/keypackages/claim` — take one per device of an account

```json
{ "account_id": "..." }
```

`200` →

```json
{
  "key_packages": [{ "device_id": "...", "key_package": "<base64>" }],
  "exhausted": ["<device_id with none left>"]
}
```

Each package is selected and deleted in one statement, so it is never handed
out twice, even under concurrent claims. Oldest first. A claim costs extra
rate-limit tokens. `NOT_FOUND` for an unknown account.

### `GET /v1/keypackages/count` — my remaining count

`200` → `{ "count": 42 }`

## Mailbox

### `POST /v1/messages` — send

```json
{ "recipients": ["<device_id>", ...], "body": "<base64 ciphertext>" }
```

One mailbox entry per recipient device (duplicates collapse); the body is
stored once. At most 2048 recipients and 256 KiB body. The sender is **not**
stored.

The body must be a Tree envelope holding an MLS application message
(PROTOCOL.md 4.1; the server reads only the cleartext header). Refused with
`BAD_REQUEST`: commits (use `/v1/commits`), proposals (not allowed in v1),
welcomes (they travel only with their commit), anything else.

`200` →

```json
{ "delivered": 2, "unknown_devices": ["..."], "full_devices": ["..."] }
```

`full_devices`: mailboxes holding 10 000 pending messages already.



### `GET /v1/messages?wait=N` — fetch my pending messages

`wait` (seconds, optional, capped at 25): if the mailbox is empty, wait up to
`N` seconds for a message (long-poll). Up to 100 messages, oldest first.

```json
{
  "messages": [{ "id": "...", "body": "<base64>", "received_at": 1790834880 }],
  "more": false
}
```

### `POST /v1/messages/ack` — delete my messages

```json
{ "ids": ["...", ...] }
```

At most 1000 ids. Only messages in the caller's own mailbox are deleted; other
ids are ignored. `200` → `{ "deleted": 2 }`. A body is erased when its last
recipient acknowledges it. Unacknowledged messages are purged after 30 days.

## Commits

### `POST /v1/commits` — submit a commit (first per group and epoch wins)

```json
{
  "group_id": "<base64 MLS group id>",
  "epoch": 17,
  "recipients": ["<device_id>", ...],
  "body": "<base64 envelope with an MLS commit>",
  "added": ["<device_id>", ...],
  "welcome": "<base64 MLS welcome, present iff added is non-empty>",
  "removed": ["<device_id>", ...]
}
```

`recipients`: all other devices of the group in this epoch, including devices
being removed. `added`, `welcome`, `removed` may be left out. Limits:
`recipients` + `added` at most 2048 devices, commit and welcome 4 MiB each
(`MAX_COMMIT_BYTES`, `MAX_WELCOME_BYTES`).

The server checks that `body` is an envelope whose MLS header is a commit for
`group_id` and `epoch`, and that `welcome` starts like an MLS welcome, then in
one transaction (PROTOCOL.md 7.4):

1. no record for the group: accept;
2. `epoch` at or below the last accepted one: if `SHA-256(body)` equals the
   winner of that epoch, `200` again with the same `id` and `delivered: 0`
   (a retry after a lost answer); otherwise `409 COMMIT_CONFLICT` with
   `winner_sha256` (lowercase hex, or `null` if the epoch is older than the
   last 64 accepted);
3. the caller is not a device of the group: `403 NOT_ELIGIBLE`;
4. `epoch` is the next one: accept; further ahead: `409 EPOCH_MISMATCH` with
   `last_epoch`.

On accept the group's device set becomes `({caller} ∪ recipients ∪ added) \
removed` (registered devices only), the commit goes into every recipient's
mailbox and the welcome into every added device's mailbox, before the
transaction ends.

`200` →

```json
{ "accepted": true, "id": "...", "epoch": 17, "delivered": 3,
  "unknown_devices": [], "full_devices": [] }
```

`full_devices` missed the commit (mailbox full) and must be removed from the
group and added again.

## Attachments

### `POST /v1/attachments` — upload ciphertext

Body: the raw encrypted file (`Content-Type: application/octet-stream`),
signed like every request (the body hash covers the raw bytes). At most
`MAX_ATTACHMENT_BYTES` (default 100 MiB); one extra rate-limit token per MiB.
`201` → `{ "id": "...", "size": 1234 }`. Empty body: `BAD_REQUEST`.

### `GET /v1/attachments/{id}` — download

Any registered device that knows the id. `200` with the raw bytes, or
`404 NOT_FOUND`. Blobs are deleted after `MESSAGE_TTL_SECS`.

## Usernames

The client sends `hash` = standard base64 of `SHA-256("tree/username/v1" ||
normalised name)` (PROTOCOL.md 8.4); the server never sees the name.

### `POST /v1/usernames/apply` — register or change my name

`{ "hash": "<32 bytes>", "discoverable": true }` (`discoverable` optional,
default `true`). One name per account; applying again replaces it.
`200` → `{ "state": "applied", "discoverable": true }`. `409 USERNAME_TAKEN` if
another account holds it (also when that account hid it).

### `POST /v1/usernames/release` — drop my name

`200` → `{ "state": "released" }`, also when there was none.

### `POST /v1/usernames/lookup` — find an account

`{ "hash": "<32 bytes>" }` → `200 { "account_id": "..." }`, or `404 NOT_FOUND`
if no account holds it or it is hidden. Costs 10 rate-limit tokens.

## Push wake-ups (PROTOCOL.md 8.8)

### `POST /v1/push` — set this device's endpoint

`{ "endpoint": "https://<allowed gateway host>/..." }` → `200 { "state": "applied" }`.
`400` if push is off, the host (with port: an entry `host` allows the default
port only, `host:port` that port) is not in `PUSH_ALLOWED_HOSTS`, the URL is not
https, carries credentials or is longer than 1024 characters.

### `DELETE /v1/push` — no wake-ups

`200 { "state": "released" }`.

When anything arrives in the device's mailbox (message, commit, welcome,
invite request), the server POSTs the body `wake` (`text/plain`) to the
endpoint, at most once per `PUSH_INTERVAL_SECS`, without following
redirects. A `404` or `410` from the gateway deletes the endpoint.

## Invite links (PROTOCOL.md 8.7)

### `POST /v1/invites` — register a link

`{ "token_hash": "<32 bytes: SHA-256(\"tree/invite/v1\" || secret)>", "lifetime": 86400, "max_uses": 10 }`
→ `201 { "expires_at": ... }`. Lifetime 60 s .. 30 days, uses 1 .. 10,000, at
most 100 open links per device (`LIMIT_EXCEEDED`). `409 ALREADY_EXISTS` for a
known hash.

### `DELETE /v1/invites/{token_hash}` — revoke (base64url, no padding)

Only the device that made it; idempotent. `200 { "state": "released" }`.

### `POST /v1/invites/join` — use a link

`{ "token": "<16 bytes>" }` → `202 { "owner_account": "..." }`. `404` if
unknown, expired or used up; `400` for the owner's own account. A repeated
request by the same account counts once. Costs 5 rate tokens.

### `GET /v1/invites/requests` — requests for my links

`200 { "requests": [{ "id", "token_hash", "account_id" }] }`, oldest first,
at most 100.

### `POST /v1/invites/requests/ack` — handled

`{ "ids": [...] }` (at most 100) → `200 { "deleted": n }`; only the owner
device's requests.

## Recovery (PROTOCOL.md 8.6)

### `POST /v1/recovery/apply` — set my account's recovery key

```json
{ "recovery_pub": "<Ed25519 public key>",
  "proof": "<new key over \"tree-recovery-set-v1\" || u32 len || account || recovery_pub>",
  "current_signature": "<optional: current key over \"tree-recovery-change-v1\" || u32 len || account || recovery_pub>" }
```

`200 { "state": "applied", "pending": null }` when set (first key, or a
replacement signed by the current key), or
`{ "state": "applied", "pending": { "action": "replace", "effective_at": ... } }`
when the replacement waits 7 days. `400` bad proof, `403 RECOVERY_REFUSED`
wrong current signature, `409 ALREADY_EXISTS` key held elsewhere.

### `POST /v1/recovery/release` — no recovery for my account

`{ "current_signature": "<optional: current key over the change message with 32 zero bytes>" }`
→ `200` with `state: released` (signed, or no key) or a pending `release`.

### `GET /v1/recovery` — state and pending change

`200 { "state": "applied" | "released", "pending": null | { "action", "effective_at" } }`.

### `POST /v1/recovery/recover` — a new device joins my account

Like signup: no `X-Tree-Device`, signed with the new key, per-IP limit.

```json
{ "recovery_pub": "...", "auth_pub": "<new device key>", "pow_nonce": 123,
  "signature": "<64 bytes: recovery key over \"tree-recover-v1\" || auth_pub || revoke_others || i64 ts>",
  "ts": 1790834880, "revoke_others": false }
```

`201 { "account_id", "device_id", "revoked": 0 }`; cancels a pending change.
Errors: `TIMESTAMP_SKEW` (`ts` outside the window), `POW_INVALID`,
`RECOVERY_REFUSED`, `ALREADY_EXISTS` (key already registered; nothing is
revoked), `LIMIT_EXCEEDED` (device limit; use `revoke_others`).

## Reports (PROTOCOL.md 8.5)

### `POST /v1/franking` — tag for a message commitment

`{ "com": "<32 bytes>" }` → `200 { "tag": "<32 bytes>", "minute": 1790834880 }`.
The tag binds `com` to the caller's account and the minute. Nothing is stored.

### `POST /v1/reports` — report messages of one account

```json
{ "reported_account": "...", "reason": "harassment",
  "messages": [{ "payload": "{\"t\":\"text\",...}", "key": "<32 bytes>", "tag": "<32 bytes>",
                 "minute": 1790834880, "group_id": "<base64>" }] }
```

1 to 20 messages, payload ≤ 16 KiB each, reason ≤ 500 characters, at most
20 reports per account per day (`LIMIT_EXCEEDED`), `404` for an unknown
account. Resolved reports are deleted 30 days after resolution. `201` →
`{ "id": "...", "verified": true }`; `verified` is true only if every message's
tag checks out against `reported_account`. Costs 10 rate-limit tokens.

### `GET /v1/reports` — operator: open reports

Header `X-Tree-Admin`. `200` → `{ "reports": [{ "id", "reported_account",
"reporter_account", "reason", "messages": [{ "payload", "verified" }],
"verified", "created_day" }] }`, oldest first, at most 100.

### `POST /v1/reports/{id}/resolve` — operator: close a report

Header `X-Tree-Admin`; optional body `{ "resolution": "..." }`. `200`, or `404`.

### `POST /v1/accounts/{id}/suspend/apply`, `.../suspend/release` — operator

Header `X-Tree-Admin`; optional body `{ "resolution": "reason" }`. Idempotent.
`200` → `{ "account_id": "...", "state": "applied" }`. While applied, every
signed request of the account gets `403 SUSPENDED`.

## Operator feature flags

Every flag has apply and release. Both are idempotent and return the current state.

### `GET /v1/features` — public

`200` → `{ "features": [{ "key": "server.signups", "state": "applied", "changed_at": 1790834908 }, ...] }`

Flags: `server.signups`, `server.bot_platform`, `server.calls`, `server.public_spaces`,
`server.new_account_limits`, `server.report_limits` (anti-spam, PROTOCOL.md 8.9).

### `POST /v1/features/{key}/apply`, `POST /v1/features/{key}/release`

Header `X-Tree-Admin: <operator token>`; the server stores only its SHA-256
(`ADMIN_TOKEN_SHA256`) and compares in constant time. Optional body
`{ "reason": "..." }` (≤ 500 characters) goes to the operator audit trail.

`200` → `{ "key": "...", "state": "released", "changed_at": 1790834910 }`.
Errors: `UNAUTHORIZED`, `UNKNOWN_FEATURE`.

## Health

`GET /healthz` → `200 {"status": "ok"}` when the database answers.

## What the server stores

| Data | Stored |
| --- | --- |
| account id, device ids, device authentication public keys | yes |
| account/device creation date | day only |
| key packages | until claimed |
| attachment ciphertext (file named by a random id), its size and upload minute; not the uploader | until the mailbox TTL (30 days) |
| username hash per account (if registered), discoverable flag, day registered | until released or the account is deleted |
| per group: last accepted epoch, the device ids that may commit next, SHA-256 and id of the last 64 accepted commits | while one of its devices exists |
| message ciphertext + recipient device + arrival minute | until acknowledged, at most 30 days |
| message sender | **no** |
| IP addresses | **no** (signup rate limit keeps them in memory only) |
| operator flag changes | key, state, time, optional reason |
| franking | the server key only; nothing per message |
| reports | reported and reporting account, reason, the reported messages' plaintext as the reporter sent it, verified flags, day; until the operator deletes them |
| suspensions | account id, day, optional reason; until released |
| recovery | the Ed25519 public key derived from the phrase, day set; never the phrase |
| push | one endpoint URL per device, day set; wake-ups are not logged |
| invite links | hash of the secret, owner account and device, expiry, use limit and count; until 7 days after expiry. Join requests: link hash, requesting account, time; until the owner's device handles them. Never the group |

Logs contain method, route template, status and latency only.

## Configuration (environment)

| Variable | Default |
| --- | --- |
| `DATABASE_URL` | `sqlite://tree-server.db` |
| `BIND_ADDR` | `127.0.0.1:8080` |
| `ADMIN_TOKEN_SHA256` | unset (operator endpoints disabled) |
| `POW_BITS` | `20` |
| `MESSAGE_TTL_SECS` / `PURGE_INTERVAL_SECS` | `2592000` / `3600` |
| `CLOCK_SKEW_SECS` / `LONG_POLL_MAX_SECS` | `300` / `25` |
| `MAX_DEVICES_PER_ACCOUNT` | `10` |
| `MAX_KEY_PACKAGES_PER_DEVICE` / `_PER_UPLOAD` / `MAX_KEY_PACKAGE_BYTES` | `200` / `100` / `16384` |
| `MAX_MESSAGE_BYTES` / `MAX_RECIPIENTS` / `MAX_MAILBOX_MESSAGES` / `FETCH_LIMIT` | `262144` / `2048` / `10000` / `100` |
| `MAX_COMMIT_BYTES` / `MAX_WELCOME_BYTES` | `4194304` / `4194304` |
| `ATTACHMENT_DIR` / `MAX_ATTACHMENT_BYTES` | `attachments` / `104857600` |
| `RATE_PER_SEC` / `RATE_BURST` (per device) | `20` / `200` |
| `SIGNUP_PER_HOUR` / `SIGNUP_BURST` (per address, IPv6 per /64) | `20` / `10` |
| `TRUST_FORWARDED_FOR` | `false` (set `true` only behind a proxy that overwrites `X-Forwarded-For`) |
| `PUSH_ALLOWED_HOSTS` | empty = push off; comma-separated gateway host names (e.g. a self-hosted UnifiedPush server) |
| `PUSH_INTERVAL_SECS` | `5` (at most one wake-up per device this often) |
| `PUSH_ALLOW_HTTP` | `false` (tests only) |
| `RUST_LOG` | `info` |
