# Tree P0 Messenger Core Contract

## Goal
Turn the existing MLS/server vertical slice into a crash-safe, offline-first messenger core without moving plaintext to the server.

## Invariants
1. Server stores ciphertext only.
2. Local plaintext history lives only inside the encrypted SQLCipher profile.
3. Outbox state is durable before a network send is attempted.
4. ACK is sent only after the ciphertext has been durably processed locally.
5. Message and mutation identifiers are client-generated and idempotent.
6. Sync is cursor-based and resumable.
7. ViewOnce is consumed only after successful authenticated media open.
8. UI is not the authority for message state; the Rust core is.

## Local data model
### message_records
group_id, message_id, sender_member_id, sequence, created_at, edited_at, expires_at, view_once, deleted, body, reply_to, media_manifest.
Primary key: (group_id, message_id).

### message_mutations
group_id, mutation_id, target_message_id, sender_member_id, sequence, kind, payload, received_at.
Unique: (group_id, mutation_id).

### outbox
local_id, group_id, message_id, kind, envelope, state, attempts, next_retry_at, created_at, last_error_code, server_id.
Unique local_id. Retries reuse the same envelope/message id.

### inbox_cursor
device_id, cursor, updated_at.

## Flows
Outbox: create event -> persist outbox -> encrypt -> network send -> server response -> mark sent.
Inbox: fetch cursor -> authenticate/decrypt -> transactionally persist -> ACK only after durable handling.

## Sync contract
Keep GET /v1/messages backward compatible. Add:
- POST /v1/sync/pull
- POST /v1/sync/ack
- POST /v1/sync/repair

The server still stores only opaque mailbox data.

## Message lifecycle
DRAFT -> QUEUED -> ENCRYPTING -> SENDING -> SENT -> DELIVERED -> READ
Error/terminal states: FAILED, CANCELLED, EXPIRED, DELETED.

## Retry
Bounded exponential backoff with jitter. Never create a second message because of a transient network failure.

## P0 tests
- crash after outbox insert
- crash after server acceptance
- duplicate mailbox delivery
- duplicate ACK
- reconnect/cursor recovery
- cursor gap repair
- local DB transaction failure
- mutation before target
- edit/delete after restart
- timer expiry after restart
- ViewOnce success/failure/replay

## Implementation order
1. SQLCipher message store + migration
2. Message lifecycle repository
3. Durable outbox
4. Inbox transaction + ACK gating
5. Cursor sync API
6. Retry worker interface
7. Public Rust Messenger API
8. Tests + CI
