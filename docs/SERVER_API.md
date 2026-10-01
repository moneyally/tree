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

| Code | HTTP | Meaning |
| --- | --- | --- |
| `BAD_REQUEST` | 400 | malformed JSON, base64, identifier or field |
| `POW_INVALID` | 400 | signup proof-of-work does not meet `POW_BITS` |
| `UNAUTHORIZED` | 401 | missing/bad signature, unknown device, replayed request, bad operator token |
| `TIMESTAMP_SKEW` | 401 | `X-Tree-Timestamp` more than 300 s away from server time |
| `LOCKED_BY_SERVER` | 403 | the feature is released by the operator (e.g. signups) |
| `NOT_FOUND` | 404 | no such endpoint, account or device |
| `UNKNOWN_FEATURE` | 404 | unknown feature key |
| `METHOD_NOT_ALLOWED` | 405 | wrong HTTP method |
| `ALREADY_EXISTS` | 409 | this authentication key is already registered |
| `LIMIT_EXCEEDED` | 409 | a stored quota is full (devices per account, key packages per device) |
| `TOO_LARGE` | 413 | body, message, key package, or a list (recipients, key packages, ack ids) too large |
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
stored once. At most 1000 recipients and 256 KiB body. The sender is **not**
stored.

`200` →

```json
{ "delivered": 2, "unknown_devices": ["..."], "full_devices": ["..."] }
```

`full_devices`: mailboxes holding 10 000 pending messages already.

Planned (not implemented): commits and welcomes will go through a separate
`POST /v1/commits` endpoint that accepts only the first commit per (group,
epoch), and this endpoint will refuse commits, proposals and welcomes. See
[PROTOCOL.md](PROTOCOL.md), section 7.4.

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

## Operator feature flags

Every flag has apply and release. Both are idempotent and return the current state.

### `GET /v1/features` — public

`200` → `{ "features": [{ "key": "server.signups", "state": "applied", "changed_at": 1790834908 }, ...] }`

Flags: `server.signups`, `server.bot_platform`, `server.calls`, `server.public_spaces`.

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
| message ciphertext + recipient device + arrival minute | until acknowledged, at most 30 days |
| message sender | **no** |
| IP addresses | **no** (signup rate limit keeps them in memory only) |
| operator flag changes | key, state, time, optional reason |

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
| `MAX_MESSAGE_BYTES` / `MAX_RECIPIENTS` / `MAX_MAILBOX_MESSAGES` / `FETCH_LIMIT` | `262144` / `1000` / `10000` / `100` |
| `RATE_PER_SEC` / `RATE_BURST` (per device) | `20` / `200` |
| `SIGNUP_PER_HOUR` / `SIGNUP_BURST` (per address, IPv6 per /64) | `20` / `10` |
| `TRUST_FORWARDED_FOR` | `false` (set `true` only behind a proxy that overwrites `X-Forwarded-For`) |
| `RUST_LOG` | `info` |
