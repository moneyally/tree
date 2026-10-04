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
| `TRANSCRIPT_MISMATCH` | 403 | device link: the hash differs from the one the new device confirmed |
| `LINK_SIGNATURE` | 403 | device link: a confirmation or authorisation signature does not verify |
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
| `IDEMPOTENCY_KEY_REUSE` | 409 | this device already used the idempotency key for another send (PROTOCOL.md 8.10) |
| `LINK_STATE` | 409 | device link: not the step the session is at |
| `LINK_GONE` | 410 | device link expired, cancelled or already used |
| `LINK_REQUIRED` | 410 | `POST /v1/devices` is gone: link devices with a confirmed device link |
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

### `POST /v1/devices` — gone

`410 LINK_REQUIRED`. Devices join an account only through a confirmed device
link (below) or the recovery phrase (`user.device_link_code` is
permanently applied).

### `GET /v1/devices` — my devices

`200` → `{ "account_id": "...", "devices": ["<device_id>", ...] }`

### `DELETE /v1/devices/{device_id}` — remove one of my devices

Deletes the device, its key packages and its mailbox. Removing the last device
removes the account. `200` → `{ "removed": "<device_id>" }`; `NOT_FOUND` if it is
not on my account.

## Device links (PROTOCOL.md 8.11)

The new device (N) has no device id yet: its requests carry no
`X-Tree-Device` and are signed with the request key named in the session
(otherwise exactly as in Authentication). The relayed `offer`, `reveal` and
`sealed` are opaque to the server (base64 in JSON). A session expires 10
minutes after it was opened and is used once.

### `POST /v1/links` — open a session (existing device E)

```json
{ "link_id": "<22-char base64url from the invitation>", "new_auth_pub": "<N's key>", "offer": "<base64>" }
```

`201` → `{ "expires_at": 1790000600 }`. Errors: `ALREADY_EXISTS` (the link id
was used, or the key is already a device), `RATE_LIMITED` (2 open sessions
per account, 10 per hour), `TOO_LARGE` (offer over 1 KiB).

### `GET /v1/links/{link_id}` — E polls

`200` → `{ "state": "offered|revealed|confirmed|linked|cancelled|expired",
"expires_at", "reveal", "transcript_hash", "new_signature", "device_id" }`
(absent fields are `null`). `NOT_FOUND` unless E opened it.

### `POST /v1/links/{link_id}/complete` — E authorises N

```json
{ "transcript_hash": "<32 bytes>", "signature": "<E's key over lp(\"tree/link/authorise/v1\", link_id, account_id, new_auth_pub, hash)>", "sealed": "<base64, at most 256 KiB>" }
```

Only in state `confirmed`. `201` → `{ "device_id": "..." }`: N is now a
device of E's account. Errors: `410 LINK_GONE` (expired, cancelled or
used), `LINK_STATE` (409: N has not confirmed), `TRANSCRIPT_MISMATCH` (403:
not the hash N confirmed), `LINK_SIGNATURE` (403), `LIMIT_EXCEEDED`.

### `POST /v1/links/{link_id}/cancel` — E refuses

`200` → `{ "state": "cancelled" }`; relayed data is deleted. `LINK_STATE` if
already linked.

### `GET /v1/links/{link_id}/new` — N polls (signed by N's key)

`200` → `{ "state", "expires_at", "offer", "sealed", "device_id" }`.
`NOT_FOUND` until E opened the session (N keeps polling), `410 LINK_GONE`
once expired.

### `POST /v1/links/{link_id}/new` — N's steps (signed by N's key)

`{ "action": "reveal", "reveal": "<base64, at most 64 KiB>" }` (state
`offered` → `revealed`); `{ "action": "confirm", "transcript_hash": "...",
"signature": "<N's key over lp(\"tree/link/confirm/v1\", link_id, hash)>" }`
(`revealed` → `confirmed`, `403 LINK_SIGNATURE` if it does not verify);
`{ "action": "cancel" }`; `{ "action": "done" }` (after `linked`: deletes
the sealed data). `200` → `{ "state": "..." }`. Errors: `LINK_GONE`,
`LINK_STATE`.

## Key packages (MLS)

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
  "key_packages": [{ "device_id": "...", "key_package": "<base64>", "last_resort": false }],
  "exhausted": ["<device_id with none left, not even a last-resort one>"]
}
```

Each package is selected and deleted in one statement, so it is never handed
out twice, even under concurrent claims. Oldest first. A device with no
one-time package left gets its last-resort package instead
(`"last_resort": true`), which is not deleted. A claim costs extra
rate-limit tokens. `NOT_FOUND` for an unknown account.

### `GET /v1/keypackages/count` — my remaining count

`200` → `{ "count": 42, "last_resort": true }` (one-time packages left;
whether a last-resort package is stored).

### `PUT /v1/keypackages/last-resort` — set my last-resort key package

```json
{ "key_package": "<base64>" }
```

One per device; a new one replaces the old. Same size limit as uploads.
`200` → `{ "ok": true }`. Errors: `TOO_LARGE`, `BAD_REQUEST`.

## Mailbox

### `POST /v1/messages` — send

```json
{ "recipients": ["<device_id>", ...], "body": "<base64 ciphertext>", "idempotency_key": "<base64, optional>" }
```

One mailbox entry per recipient device (duplicates collapse); the body is
stored once. At most 2048 recipients and 256 KiB body. The sender is **not**
stored with the message.

`idempotency_key` (16 to 64 bytes, PROTOCOL.md 8.10): a retry of the same
request (same body, same set of recipients) with the same key from the same
device is answered `200` with the first `delivered` count and
`"replayed": true`, and delivers nothing again. The same key with another
body or other recipients: `409 IDEMPOTENCY_KEY_REUSE`. Keys are per sending
device and kept one to two days (until the day after the send has passed);
at most `MAX_IDEMPOTENCY_KEYS` per device are kept (the oldest go first).
After a server restart a retry of a key from before is answered as a
replay (it can no longer be compared). Malformed key: `400`.

The body must be a Tree envelope holding an MLS application message
(PROTOCOL.md 4.1; the server reads only the cleartext header). Refused with
`BAD_REQUEST`: commits (use `/v1/commits`), proposals (not allowed in v1),
welcomes (they travel only with their commit), anything else.

`200` →

```json
{ "delivered": 2, "unknown_devices": ["..."], "full_devices": ["..."], "replayed": false }
```

`full_devices`: mailboxes holding 10 000 pending messages already. A replayed
answer has empty `unknown_devices` and `full_devices` (they are not stored).



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

Commits take no idempotency key: they are idempotent by their hash (rule 2).
A client that lost the answer resubmits the same bytes and gets `200` with
the same `id` and nothing delivered again.

`200` →

```json
{ "accepted": true, "id": "...", "epoch": 17, "delivered": 3,
  "unknown_devices": [], "full_devices": [] }
```

`full_devices` missed the commit (mailbox full) and must be removed from the
group and added again.

## Attachments

Ciphertext only, already padded by the client (PROTOCOL.md 6.12). Uploads go
in parts and resume; downloads go by ranges.

### `POST /v1/uploads` — start an upload

`{ "size": N }`: the blob size in bytes. At most `MAX_ATTACHMENT_BYTES`
(default 2 GiB + 64 KiB, a 2 GiB file with its encryption overhead), else
`413 TOO_LARGE` with `max_bytes`; `0` is `BAD_REQUEST`. The size counts
against the account's `UPLOAD_QUOTA_BYTES_PER_DAY` (UTC day, all devices of
the account; not given back when an upload is cancelled or dropped): over
it, `403 QUOTA_EXCEEDED`.

`201` →

```json
{ "id": "...", "size": N, "chunk_size": 1048576, "chunks": 3,
  "received": 0, "complete": false }
```

### `PUT /v1/uploads/{id}/{index}` — one part

Body: raw bytes of part `index` (`0 <= index < chunks`), exactly
`chunk_size` long except the last. Only the device that started the upload
(others: `404`). Parts go in order: `index > received` is `409 OUT_OF_ORDER`
with `received`; `index < received` (a retry after a lost answer) changes
nothing. One extra rate-limit token per whole MiB. `200` → the status as
above; after the last part `complete: true` and the blob is downloadable as
attachment `id`. Wrong length: `BAD_REQUEST`; a body over `chunk_size`:
`413`.

### `GET /v1/uploads/{id}` — where to resume

The uploader gets the status (`received` parts); once complete, any device
gets `complete: true`. Unknown or dropped (unfinished for 24 hours): `404`,
start again.

### `DELETE /v1/uploads/{id}` — give up

The uploader only; the partial file is deleted. `204`.

### `GET /v1/attachments/{id}?offset=N` — download a range

Any registered device that knows the id. `200` with at most
`UPLOAD_CHUNK_BYTES` from byte `N` (default 0) and header `X-Tree-Total`
(the blob size); `offset` beyond the size: `BAD_REQUEST`; unknown: `404`.
Blobs are deleted after `MESSAGE_TTL_SECS`.

## Usernames

The client sends `hash` = standard base64 of `SHA-256("tree/username/v1" ||
normalised name)` (PROTOCOL.md 8.4); the server never sees the name.

### `POST /v1/usernames/apply` — register or change my name

`{ "hash": "<32 bytes>", "discoverable": true }` (`discoverable` optional,
default `true`). One name per account; applying again replaces it.
`200` → `{ "state": "applied", "discoverable": true }`. `409 USERNAME_TAKEN` if
another account holds it (also when that account hid it).

### `POST /v1/usernames/release` — drop my name

`200` → `{ "state": "released" }`, also when there was none. The name's
link (below) is deleted with it.

### `POST /v1/usernames/lookup` — find an account

`{ "hash": "<32 bytes>" }` → `200 { "account_id": "..." }`, or `404 NOT_FOUND`
if no account holds it or it is hidden. Costs 10 rate-limit tokens.

### Username links (`user.username_link`)

The client makes a random 16-byte token, shares `tree://u/<token>` and sends
only `hash` = standard base64 of `SHA-256("tree/ulink/v1" || token)`.

- `POST /v1/usernames/link/apply` `{ "hash": "<32 bytes>" }` — set my link,
  replacing the one before (reset: the old link stops working). Needs a
  registered name: `409 NO_USERNAME` otherwise; `409 ALREADY_EXISTS` if
  another account holds that hash. `200` → `{ "state": "applied" }`.
- `POST /v1/usernames/link/release` — delete my link. `200` →
  `{ "state": "released" }`, also when there was none.
- `POST /v1/usernames/link/lookup` `{ "hash": "<32 bytes>" }` → `200
  { "account_id": "..." }` while the link is current and the account's name
  is registered and discoverable; otherwise `404 NOT_FOUND` (the same answer
  as for a link nobody has). Costs 10 rate-limit tokens.

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

## Relays: GIF search and map tiles (PROTOCOL.md 8.12)

Off unless the operator applies `server.gif_relay` / `server.map_relay`
(released by default) **and** sets `GIF_PROVIDER_URL` / `MAP_TILE_URL`.
Otherwise every endpoint below except the status answers `503
RELAY_UNAVAILABLE`. The upstream request is built fresh: no client address,
forwarding header, device id or Tree header; user agent `tree-relay/1`.
Nothing is stored or logged beyond the route template.

### `GET /v1/relay` — which relays exist (public)

`200` → `{ "gif": true, "map": false }`.

### `POST /v1/relay/gif/search` — search (signed)

`{ "q": "1 to 100 characters", "limit": 20 }` (1 to 50) → `200
{ "results": [{ "media": "<opaque id>", "preview": "<opaque id>" | null,
"title": "…", "width": 320, "height": 240 }] }`. The server asks
`GET <GIF_PROVIDER_URL>?q=…&limit=…` (`Authorization: Bearer
<GIF_PROVIDER_KEY>` if set) and expects `{ "results": [{ "title", "url",
"preview"?, "width"?, "height"? }] }`; results whose URL is not https (or
has credentials, an IP literal or localhost) are left out. `400` for a bad
query, `502 RELAY_UPSTREAM` if the provider fails. Costs 1 rate token.

### `GET /v1/relay/gif/media/{id}` — a GIF or preview from a search (signed)

`200` with the bytes and their type (`image/*` or `video/*` only, at most
`RELAY_MAX_BYTES`), `Cache-Control: no-store`. `404` for an unknown or
expired id (ids live one hour, in memory), `502 RELAY_UPSTREAM` for
anything else the upstream answers. Costs 1 rate token.

### `GET /v1/relay/map/{z}/{x}/{y}` — a map tile (signed)

Zoom 0 to 19, `x` and `y` below 2^z (else `400`). `200` with the image
(`image/*` only). Costs 0.25 rate tokens.

## Invite links (PROTOCOL.md 8.7)

### `POST /v1/invites` — register a link

`{ "token_hash": "<32 bytes: SHA-256(\"tree/invite/v1\" || secret)>", "lifetime": 86400, "max_uses": 10 }`
→ `201 { "expires_at": ... }`. Lifetime 60 s .. 30 days, uses 1 .. 10,000, at
most 100 open links per device (`LIMIT_EXCEEDED`). `409 ALREADY_EXISTS` for a
known hash.

### `DELETE /v1/invites/{token_hash}` — revoke (base64url, no padding)

Only the device that made it; idempotent. `200 { "state": "released" }`.

### `POST /v1/invites/join` — use a link

`{ "token": "<16 bytes>", "nonce": "<16 bytes>" }` → `202 { "owner_account":
"..." }`. `nonce` (optional, random from the joining device) is handed only
to the owner's device with the request (PROTOCOL.md 8.7). `404` if unknown,
expired or used up; `400` for the owner's own account or a nonce that is not
16 bytes. A repeated request by the same account counts once and replaces
the nonce. Costs 5 rate tokens.

### `GET /v1/invites/requests` — requests for my links

`200 { "requests": [{ "id", "token_hash", "account_id", "nonce" }] }`
(`nonce` null if the joiner sent none), oldest first, at most 100.

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
`server.new_account_limits`, `server.report_limits` (anti-spam, PROTOCOL.md 8.9),
`server.gif_relay`, `server.map_relay` (relays, PROTOCOL.md 8.12; these two
start released).

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
| attachment ciphertext (file named by a random id, padded by the client), its size and upload minute; not the uploader | until the mailbox TTL (30 days) |
| unfinished uploads: id, uploading device, declared size, parts received, minute started, the partial file | until complete (then only the attachment row), cancelled, or 24 hours |
| upload quota: bytes declared per account per day | the current day only |
| username hash per account (if registered), discoverable flag, day registered | until released or the account is deleted |
| username link: hash of the link token per account, day set | until reset, released, the name is released, or the account is deleted |
| per group: last accepted epoch, the device ids that may commit next, SHA-256 and id of the last 64 accepted commits | while one of its devices exists |
| message ciphertext + recipient device + arrival minute | until acknowledged, at most 30 days |
| message sender | **no** (not with the message) |
| idempotency records (`POST /v1/messages` with a key) | sending device, key, a tag of the request (HMAC under a key held only in memory, forgotten after a day, PROTOCOL.md 8.10), delivered count, day; one to two days, at most `MAX_IDEMPOTENCY_KEYS` per device, deleted with the device. Not stored: the body, the recipients, the message id. A database copy cannot match a record to a stored message; the running server can, for the record's lifetime, by recomputing tags of stored bodies with the key in its memory |
| IP addresses | **no** (signup rate limit keeps them in memory only) |
| relays | **no**: search words and tile coordinates are passed on and forgotten; media ids (opaque id -> provider URL) in memory for one hour |
| operator flag changes | key, state, time, optional reason |
| franking | the server key only; nothing per message |
| reports | reported and reporting account, reason, the reported messages' plaintext as the reporter sent it, verified flags, day; until the operator deletes them |
| suspensions | account id, day, optional reason; until released |
| recovery | the Ed25519 public key derived from the phrase, day set; never the phrase |
| push | one endpoint URL per device, day set; wake-ups are not logged |
| device links | link id, account, opening device, new device's request key, state, times; offer, reveal and sealed account data (opaque) until acknowledged, cancelled or expired; the confirmed transcript hash and both signatures; rows purged 1 hour after expiry |
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
| `MAX_IDEMPOTENCY_KEYS` (per sending device) | `10000` |
| `ATTACHMENT_DIR` / `MAX_ATTACHMENT_BYTES` | `attachments` / `2147549184` (2 GiB + 64 KiB) |
| `UPLOAD_CHUNK_BYTES` (part and download range size, 4096 to 16777216) | `1048576` |
| `UPLOAD_QUOTA_BYTES_PER_DAY` (per account) | `21474836480` (20 GiB) |
| `RATE_PER_SEC` / `RATE_BURST` (per device) | `20` / `200` |
| `SIGNUP_PER_HOUR` / `SIGNUP_BURST` (per address, IPv6 per /64) | `20` / `10` |
| `TRUST_FORWARDED_FOR` | `false` (set `true` only behind a proxy that overwrites `X-Forwarded-For`) |
| `PUSH_ALLOWED_HOSTS` | empty = push off; comma-separated gateway host names (e.g. a self-hosted UnifiedPush server) |
| `PUSH_INTERVAL_SECS` | `5` (at most one wake-up per device this often) |
| `PUSH_ALLOW_HTTP` | `false` (tests only) |
| `GIF_PROVIDER_URL` | unset = no GIF relay (no default provider) |
| `GIF_PROVIDER_KEY` | unset; sent to the provider as a bearer token; environment only, never in git |
| `MAP_TILE_URL` | unset = no map relay; a template with `{z}`, `{x}`, `{y}` |
| `RELAY_MAX_BYTES` | `8388608` (largest answer passed on) |
| `RELAY_ALLOW_HTTP` | `false` (tests only: http and local upstreams) |
| `RUST_LOG` | `info` |
