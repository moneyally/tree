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
| `STORAGE_LIMIT` | 403 | the account holds as many attachment bytes as `MAX_LIVE_BYTES_PER_ACCOUNT` allows (F-026) |
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
| `INSUFFICIENT_STORAGE` | 507 | the server is short of disk space for attachments (F-026) |

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
`413 TOO_LARGE` with `max_bytes`. Only sizes the attachment format produces
are accepted (`32 + padded + 16 · ceil(padded / 1 MiB)` with `padded` a
bucket of PROTOCOL.md 6.12; the smallest is 1072): any other, `0`
included, is `BAD_REQUEST` (F-026). The size counts against the account's
`UPLOAD_QUOTA_BYTES_PER_DAY` (UTC day, all devices of the account; not
given back when an upload is cancelled or dropped): over it, `403
QUOTA_EXCEEDED`; and against `MAX_LIVE_BYTES_PER_ACCOUNT`, all bytes the
account started uploading within the attachment lifetime (an upper bound on
what it holds): over it, `403 STORAGE_LIMIT` with `max_bytes`. If the file
system of `ATTACHMENT_DIR` would keep less than `MIN_FREE_DISK_BYTES` free
after this and the unfinished uploads (or, where free space cannot be read,
`MAX_TOTAL_ATTACHMENT_BYTES` would be passed), `507
INSUFFICIENT_STORAGE`.

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

`{ "token": "<16 or 32 bytes>", "nonce": "<16 or 44 bytes>" }` → `202 {
"owner_account": "..." }`. `token`: the proof derived from a version 2
link's secret (32 bytes; the server never sees the secret) or a version 1
secret (16 bytes). The server looks up `SHA-256("tree/invite/v1" || token)`.
`nonce` (optional) is opaque to the server and handed only to the owner's
device with the request (PROTOCOL.md 8.7): sealed to the link's owner for
version 2 links (44 bytes), 16 bytes in the clear only from older clients.
`404` if unknown, expired or used up; `400` for the owner's own account or
other lengths. A repeated request by the same account counts once and
replaces the nonce. Costs 5 rate tokens. Version 2 joiners compare
`owner_account` with the owner named in the link and stop if they differ.

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

## Public spaces (PROTOCOL.md 8.15) — NOT end-to-end encrypted

Public groups and channels: plaintext on the server, readable by anyone
signed in. A separate data path (own tables, no mailboxes, no MLS). Every
endpoint is signed and refused with `403 LOCKED_BY_SERVER` while the
operator flag `server.public_spaces` is released. Every space and post in
an answer carries `"is_public": true`.

A space as answered:

```json
{ "id": "...", "is_public": true, "kind": "channel", "handle": "tree_news", "name": "Tree news",
  "description": "", "avatar": null, "members": 2,
  "features": { "chat.public_listing": false, "channel.comments": true, "channel.signatures": false, "chat.slow_mode": null },
  "role": "member", "notify": false, "banned": false, "last_rev": 41,
  "admins": ["..."], "bans": ["..."] }
```

`role` is the caller's (`owner`, `admin`, `member` or null); `admins` and
`bans` only for admins. A post:

```json
{ "id": "...", "space": "...", "is_public": true, "seq": 17, "rev": 40, "reply_to": null,
  "text": "...", "attachment": null, "created_at": 1790834880, "edited_at": null,
  "deleted": false, "mine": false, "author": "<account>", "author_name": "Alice", "comments": 3 }
```

In a channel `author` and `author_name` of a post (not of a comment) are
null unless `channel.signatures` is applied or the caller is an admin;
`comments` only on channel posts; a deleted post has no `text`.

| Endpoint | Who | Body / query → answer |
| --- | --- | --- |
| `POST /v1/public/spaces` | any account not under anti-spam limits (`LIMITED`) | `{ kind: "group"\|"channel", name (1-64), handle, description? (≤ 1000), avatar? (≤ 512 bytes, opaque) }`, unknown fields refused → `201` space. `HANDLE_TAKEN`, `LIMIT_EXCEEDED` (10 owned). 21 rate tokens |
| `GET /v1/public/spaces/{id}` | anyone | → space |
| `DELETE /v1/public/spaces/{id}` | owner (`NOT_OWNER`) | → `{ id, deleted: true }`; posts, members and bans go with it |
| `GET /v1/public/handles/{handle}` | anyone | → space, listed or not; `404` |
| `GET /v1/public/directory?q=&limit=` | anyone | → `{ spaces }`: listed spaces whose handle starts with or name contains `q`, largest first (≤ 200). 5 rate tokens |
| `GET /v1/public/subscriptions` | anyone | → `{ spaces }` the caller's account is in |
| `POST /v1/public/spaces/{id}/profile` | admins | `{ name?, description?, avatar? ("" removes) }` → space |
| `POST /v1/public/spaces/{id}/features/{key}/apply\|release` | admins (`NOT_ADMIN`) | optional `{ option }` (only `chat.slow_mode`: `10`-`3600` s, `30s`, `5m`, `1h`; default 30 s) → space. Keys `chat.public_listing`, `channel.comments`, `channel.signatures` (channels only), `chat.slow_mode`. `INVALID_OPTION`, `UNKNOWN_FEATURE` |
| `POST /v1/public/spaces/{id}/join` | not banned (`BANNED`) | → space; idempotent; at most 1,000 per account. 2 rate tokens |
| `POST /v1/public/spaces/{id}/leave` | members; not the owner (`OWNER_CANNOT_LEAVE`) | → space |
| `POST /v1/public/spaces/{id}/notify/apply\|release` | members (`NOT_MEMBER`) | → space: content-free wake-ups for new posts, at most once per `PUBLIC_PUSH_INTERVAL_SECS` per space |
| `POST /v1/public/spaces/{id}/admins/{account}/apply\|release` | admins | → space. Only subscribers (`NOT_MEMBER`); the owner's role never changes (`OWNER`); at most 50 admins |
| `POST /v1/public/spaces/{id}/bans/{account}/apply\|release` | admins | → space. A ban unsubscribes; admins cannot be banned (`ADMIN`) |
| `POST /v1/public/spaces/{id}/posts` | members; in a channel admins, members comment while `channel.comments` is applied | `{ id (16 bytes base64url, chosen by the client), text (1-4096 characters), reply_to?, attachment?, author_name? (≤ 64) }` → `201` post; a retry with the same id and content → `200` with `"replayed": true`; other content → `409 IDEMPOTENCY_KEY_REUSE`. `NOT_MEMBER`, `NOT_ADMIN`, `BANNED`, `LOCKED_BY_CHAT` (comments released), `429 SLOW_MODE` (`Retry-After`). 3 rate tokens |
| `GET /v1/public/spaces/{id}/posts?before=&limit=&reply_to=` | anyone | → `{ posts }` newest first by `seq`, not deleted; in a channel posts only unless `reply_to` names one (then its comments) |
| `GET /v1/public/spaces/{id}/posts?after_rev=&limit=` | anyone | → `{ posts }` changed after `rev`, oldest change first, including deleted ones (tombstones) and comments |
| `PUT /v1/public/posts/{post}` | the author (`NOT_AUTHOR`), not banned | `{ text }` → post |
| `DELETE /v1/public/posts/{post}` | the author or an admin of the space | → `{ id, deleted: true, rev }`; text, attachment and name are erased at once |
| `POST /v1/public/reports` | anyone but the author | `{ post, reason (≤ 500) }` → `201 { id, verified: true }`; into the report queue with the stored text, `public_post` and `public_space`; 20 per account per day, 10 rate tokens |

## Bots (PROTOCOL.md 8.16)

All of these answer `403 LOCKED_BY_SERVER` while `server.bot_platform` is
released (the default), and so do every request of a bot's device and
every claim of a bot's key packages. Bots' objects (`bot`):

```json
{ "account": "…", "username": "quiz_bot", "is_bot": true, "description": "…",
  "commands": [{ "command": "start", "description": "…" }],
  "privacy_mode": true, "join_groups": true, "inline": false, "directory": false }
```

The owner's view adds `owner`, `token_active`, `gateway_devices` (0 or 1),
`contacts`, `reports_open`, `features` (`[{key, state, locked}]`, the money
features with their lock reason) and `created_day`. The owner is never
shown to anyone else.

### `POST /v1/bots` — create a bot (signed, a person's device)

`{ "username": "quiz_bot", "pow_key": "<32 random bytes, base64>", "pow_nonce": 123 }`,
where `SHA-256("tree-bot-signup-v1" || pow_key || nonce as 8 bytes
big-endian)` has `POW_BITS` leading zero bits; each `pow_key` works once.
Charges the per-address signup budget. `201 { "bot": {owner's view},
"token": "<bot id>:<secret>" }` — **the only time the token is shown.**
Errors: `NOT_FOR_BOTS`, `LOCKED_BY_SERVER` (bot platform or signups
released), `LIMITED` (anti-spam limits), `RATE_LIMITED`, `POW_INVALID`
(wrong or reused), `BAD_REQUEST` (username: 5 to 32 of `a-z 0-9 _`, starts
with a letter, ends with `bot`), `USERNAME_TAKEN` (a bot's or a person's),
`LIMIT_EXCEEDED` (`MAX_BOTS_PER_OWNER`).

### `GET /v1/bots` — my bots (signed) · `GET /v1/bots/{id}` — one bot

`{ "bots": [owner's view] }`. `GET /v1/bots/{id}`: the owner's view for
the owner, the public view for anyone else.

### `PUT /v1/bots/{id}/profile` — description and commands (owner)

`{ "description": "…" (≤ 512), "commands": [{ "command": "/start", "description": "…" }] }`
(either may be left out; ≤ 100 commands of 1 to 32 `a-z 0-9 _`, the
leading `/` dropped). `200` owner's view.

### `POST /v1/bots/{id}/features/{key}/apply|release` (owner)

Keys `bot.privacy_mode`, `bot.join_groups`, `bot.inline`, `bot.directory`.
`bot.payments`, `bot.tips`, `bot.pay_out_points`: apply → `403
RELEASED_ALWAYS` (release is a no-op). Unknown → `404 UNKNOWN_FEATURE`.
`200` owner's view. Someone else's bot → `404`.

### `POST /v1/bots/{id}/token/rotate` · `POST /v1/bots/{id}/token/revoke` (owner)

Rotate: `200 { "bot": …, "token": "<new>" }` (shown once). Revoke: `200
{ "bot": … }`, no token works until a rotation. Either way, at once: the
old token stops, every gateway device registered with it answers `401
BOT_DEVICE_DISABLED` (an open long-poll too), its key packages are deleted.

### `DELETE /v1/bots/{id}` (owner)

Deletes the bot account with its device, mailbox and contacts.
`200 { "deleted": "<id>" }`. An owner's bots also go when the owner's
account is deleted.

### `POST /v1/bots/{id}/stop` — stop a bot (signed, anyone)

The caller's contact with the bot ends: it can no longer claim the
caller's key packages (start chats) or reach the caller outside shared
groups. `200 { "stopped": true|false }`.

### `POST /v1/bots/lookup` — which are bots (signed)

`{ "accounts": [≤ 256 ids], "devices": [≤ MAX_RECIPIENTS ids] }` →
`{ "bots": [public view], "devices": { "<device id>": "<bot account>" } }`.
Only bots are named; nothing is said about people's accounts or devices.

### `GET /v1/bots/directory?q=` (signed) · `GET /v1/bots/by-username/{name}` (signed)

The directory lists bots with `bot.directory` applied and a working token,
by username prefix or a word of the description (≤ 50). An exact username
finds any bot (`404` otherwise).

### Gateway (header `Authorization: Bearer <bot token>`)

- `POST /v1/bots/gateway/challenge` → `{ "challenge": "<32 bytes, base64>", "expires_at": …, "account_id": "<bot id>" }`;
  good once, for 2 minutes, for this bot only.
- `POST /v1/bots/gateway/register` `{ "auth_pub": "<Ed25519 key, base64>",
  "challenge": "…", "signature": "<signature over lp('tree/bot-gateway/v1', bot id, challenge, auth_pub)>" }`
  → `201 { "account_id", "device_id", "username" }`. The same key as before
  keeps its device id; every other device of the bot is deleted. Errors:
  `BAD_TOKEN`, `CHALLENGE_INVALID`, `PROOF_INVALID`, `ALREADY_EXISTS` (the
  key belongs to another account), `RATE_LIMITED`.
- `GET /v1/bots/gateway/me` → the public view.

### Bots and the other endpoints

- `POST /v1/keypackages/claim`: the answer has `"bot": true|false`. A
  person claiming a bot's key packages contacts it. A bot's device may
  claim only people who contacted it: `403 BOT_NO_CONTACT`.
- `POST /v1/messages` from a bot's device: recipients it may not reach (not
  its own, no contact, no shared group) are left out and listed in
  `refused_devices`. While the bot platform is released, bots' devices are
  left out of every send the same way.
- `POST /v1/commits` from a bot's device: `403 BOT_NO_CONTACT` (with
  `refused_devices`) if any recipient or added device is out of its reach.
- `GET /v1/messages`: a message a bot's device sent carries `"bot": "<bot
  account>"`. People's messages carry no sender.
- `NOT_FOR_BOTS` (403) for bots' devices: `POST /v1/links`, `/v1/recovery*`,
  `/v1/usernames/apply`, `/v1/usernames/link/apply`, `DELETE /v1/accounts`,
  `DELETE /v1/devices/{id}`, `POST /v1/public/spaces`, `/v1/bots` (owning).
- `GET /v1/reports` (operator): `reported_bot_owner` for a report about a bot.
- `POST /v1/usernames/apply`: a bot's username is taken (`USERNAME_TAKEN`).

## Operator feature flags

Every flag has apply and release. Both are idempotent and return the current state.

### `GET /v1/features` — public

`200` → `{ "features": [{ "key": "server.signups", "state": "applied", "changed_at": 1790834908 }, ...] }`

Flags: `server.signups`, `server.bot_platform`, `server.calls`, `server.public_spaces`,
`server.new_account_limits`, `server.report_limits` (anti-spam, PROTOCOL.md 8.9),
`server.gif_relay`, `server.map_relay` (relays, PROTOCOL.md 8.12) and
`server.bot_platform` (PROTOCOL.md 8.16); these three start released.

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
| message sender | **no** (not with the message); except a bot's device: its bot's account id with each message it sent (PROTOCOL.md 8.16) |
| bots: account, owner, username (plaintext) and its hash, description, commands, switches, HMAC of the token, token generation, the gateway device and its generation, who contacted the bot (account pairs, day), used bot proof-of-work keys | until the bot is deleted (pairs: until the person stops the bot); proof-of-work keys kept |
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
| **public spaces (not end-to-end)** | in **plaintext**: kind, @handle, name, description, avatar reference, owner, settings, creation day; subscribers (account, role, notifications wanted, time of the last post); bans; posts and comments (text, attachment reference, author account, the name the author published, reply target, creation and edit times). Until deleted by the author, an admin or the owner, or the account is deleted; a deleted post's text is erased at once, its tombstone purged after the mailbox TTL |

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
| `MAX_LIVE_BYTES_PER_ACCOUNT` (bytes started within the attachment lifetime) | `5368709120` (5 GiB) |
| `MIN_FREE_DISK_BYTES` (free space kept on the attachment file system; `0` = no check) | `1073741824` (1 GiB) |
| `MAX_TOTAL_ATTACHMENT_BYTES` (all attachments and unfinished uploads; `0` = no limit) | `0` |
| `RATE_PER_SEC` / `RATE_BURST` (per device) | `20` / `200` |
| `SIGNUP_PER_HOUR` / `SIGNUP_BURST` (per address, IPv6 per /64) | `20` / `10` |
| `TRUST_FORWARDED_FOR` | `false` (set `true` only behind a proxy that overwrites `X-Forwarded-For`) |
| `PUSH_ALLOWED_HOSTS` | empty = push off; comma-separated gateway host names (e.g. a self-hosted UnifiedPush server) |
| `PUSH_INTERVAL_SECS` | `5` (at most one wake-up per device this often) |
| `PUBLIC_PUSH_INTERVAL_SECS` | `60` (subscribers of a public space are woken at most once per space this often) |
| `PUSH_ALLOW_HTTP` | `false` (tests only) |
| `GIF_PROVIDER_URL` | unset = no GIF relay (no default provider) |
| `GIF_PROVIDER_KEY` | unset; sent to the provider as a bearer token; environment only, never in git |
| `MAP_TILE_URL` | unset = no map relay; a template with `{z}`, `{x}`, `{y}` |
| `RELAY_MAX_BYTES` | `8388608` (largest answer passed on) |
| `RELAY_ALLOW_HTTP` | `false` (tests only: http and local upstreams) |
| `MAX_BOTS_PER_OWNER` | `20` (bots one account may own) |
| `BOT_TOKEN_KEY` | unset = a random key kept in the database; 64 hex characters: the key of the bot token HMACs, environment only, never in git (then a copy of the database alone cannot check tokens) |
| `BOT_RATE_PER_SEC` / `BOT_RATE_BURST` | `10` / `200` (one bucket per bot over all its requests, on top of the per-device bucket) |
| `RUST_LOG` | `info` |
