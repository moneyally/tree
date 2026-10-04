# Status against the design

What the design (internal design document v5, not in this repository) asks
for, what exists in this repository, and in which order the rest is built.
Updated with every merged step. Last update: 2026-10-04 (chat list basics, username links; rich chats part A).

Legend: **done** = implemented and tested here; **partial** = some of it,
named; **missing** = not started; **decided otherwise** = deliberately
different from the design, see section 4.

## 1. Where Tree is

The design has six stages (0 preparation, 1 core MVP, 2 bot platform,
3 community / calls / revenue, 4 next-generation security + audit,
5 scale to 10 million).

- **Stage 0: technically done.** Threat model, feature key table, repository,
  post-quantum MLS checked, own core chosen. The non-technical items (company
  country, lawyer, trademark, security reviewer, developer accounts) are the
  owner's (변호사 확인 필요 where legal).
- **Stage 1: started.** The cryptographic core and a first server exist and
  are tested. **There is no app yet**, no client that talks to the server,
  and nothing is deployed. Stage 1 is finished when (design): Android and iOS
  apps pass store review, the crypto code had one external review, and 1,000
  beta users use it.

Nothing here proves that "Tree as designed" is secure. What exists is listed
in section 5.

## 2. Stage 1, item by item

### 2.1 Cryptographic core (`crates/tree-core`)

| Requirement | Status | Where / note |
| --- | --- | --- |
| MLS (RFC 9420) for 1:1 and groups, OpenMLS 0.9 | done | `group.rs` |
| Hybrid key exchange ML-KEM-768 + X25519 | done | suite `0x004E`, PROTOCOL.md 2 |
| Three-way hybrid with HQC for first key agreement and daily reset | decided otherwise | section 4.1 |
| SLH-DSA root identity, ML-DSA device keys | decided otherwise (stage 4+) | section 4.2; Ed25519 in v1 |
| 256-bit symmetric keys | done | AES-256-GCM in the suite, SQLCipher AES-256 |
| Outer envelope (reject non-member input before MLS) | done | F-001 |
| Commit ordering, no forks | done | client (F-003) and server (`POST /v1/commits`, HANDOFF 3.2); no app uses it yet |
| Messages in flight during a commit | done | 2 past epochs (F-002) |
| Members identified by key, not name | done | member ids (F-008) |
| Server never sees display names | done | names only inside groups (F-009) |
| Proposals from others not trusted | done | F-007 |
| Message size padding | done | 256-byte buckets |
| Forward secrecy / post-compromise security by key refresh | done | PROTOCOL.md 6.9: every 24 h with traffic, 1-10 min after joining, all groups on demand (`refresh_all`, CLI `refresh-all`) |
| Encrypted device storage (SQLCipher, hardware-wrapped key) | partial | SQLCipher + Argon2id done; hardware key (Secure Enclave / Keystore) needs the apps (`KeySource` is the hook) |
| Feature registry: apply/release for every feature, permanent locks, layers | done | `features.rs`; server, chat, user, bot layers; `LOCKED_BY_CHAT`; one option table with `INVALID_OPTION` (durations such as `1d`, word options; PROTOCOL.md 6.11); locked chat keys rejected in commits and ignored on read |
| All 34 stage-1 feature keys in the registry | done | all 34, plus `user.recovery_phrase`, `user.drafts`, `user.unarchive_on_message` and `user.username_link` (behaviour behind most of them: see next row) |
| Behaviour behind the keys (disappearing timer, edit window, view once, ...) | partial | enforced on every device: chat.media, chat.edit (window), chat.delete_for_all (window), chat.reactions, chat.view_once, chat.disappearing, chat.invite_link, chat.voice, chat.formatting, chat.mention_all, chat.screenshot_block (the apps do the blocking), user.search_index, user.message_requests, user.stranger_block, user.group_add (a contact's account claimed by an unconfirmed device does not count, F-018), user.key_change_warning (APP_PROTOCOL.md 3). user.discoverable (server registration of the @username follows it, PROTOCOL.md 8.4). Also: user.read_receipts (both ways; stored receipts hidden after a release) and user.typing (both ways), user.peek (apps preview without a receipt), user.note_to_self, user.stranger_labels, user.group_safety_notice, user.folders, user.default_folders, user.quiet_folder, user.drafts (released: none kept, stored ones deleted), user.unarchive_on_message (`crates/tree-client/src/organize.rs`), user.username_link (server link hash follows it, `links.rs`). user.link_preview (made by the sender's app; receivers never fetch) and user.last_seen (both ways, receiver's clock). user.auto_download (network and size option, contacts only; PROTOCOL.md 6.12). Not yet: the remaining device-level settings |
| Message history and on-device search | done | `tree_messages` in the encrypted database; `history`, `search` |
| Recovery phrase (12-24 words) | done | PROTOCOL.md 8.6: BIP-39 (English, Korean), HKDF → Ed25519 recovery key; `/v1/recovery/*`; new device with optional revoke of the others; `user.recovery_phrase` follows the server ("release pending until <date>" while a release without the phrase waits 7 days); CLI `recovery-phrase`, `recover`. Not yet: notify other devices and a waiting period |
| Safety number / QR comparison, key change warning | done | PROTOCOL.md 5.4 (Q4 decided); pinning on first use, warning on any new device key; CLI `safety`, `verify` |
| Device link with confirmation code on both devices | done (branch `claude/device-link`) | PROTOCOL.md 8.11: commit-then-reveal six-digit code over the whole transcript, confirmed on both devices; the server adds a device only with the new device's confirmation and the existing device's signature over the same hash (`POST /v1/devices` without a link is gone); account data HPKE-sealed to the new device; the existing device adds the new one to its groups by commit; removing a device removes it from groups. `user.device_link_code` stays permanently applied. Client, FFI, desktop UI (paste link, compare code); Android shares the model, no screen yet |
| Per-file encryption for attachments | done | PROTOCOL.md 6.12 (format v2): per-file secret, HKDF-SHA256 labels for the AES-256-GCM key, the STREAM nonce prefix and the commitment key; 1 MiB STREAM chunks; HMAC key commitment in the blob; padding to size buckets (powers of two to 1 MiB, Padmé above); `chat.media` enforced; CLI `send-file` (streams from disk), `download` |
| Message franking for reports | done | PROTOCOL.md 8.5: HMAC commitment per message, server tag bound to the account; every text, edit and file is franked; CLI `report` |
| Admin roles inside the group (admins, kick) | done | PROTOCOL.md 6.11: admins, name and chat settings in the MLS group context; non-admin settings changes and removals rejected by every device; CLI `make-admin`, `name`, `group-apply` |
| Invite links with expiry / use count | done | PROTOCOL.md 8.7: secret in the link, only its hash on the server, expiry and use limit enforced by the server, the owner's admin device adds the requester; a join answers only the nonce the joiner sent (F-018); `chat.invite_link`; CLI `invite-link`, `join`, `revoke-links` |
| Official test vectors before merging crypto | partial | the libraries carry their own; Tree has no vector file of its own yet |

### 2.2 Server (`crates/tree-server`, `deploy/`)

| Requirement | Status | Where / note |
| --- | --- | --- |
| Sign-up without phone or e-mail: random id + device key | done | `POST /v1/accounts`, proof of work |
| Device attestation or paid signup as alternatives to proof of work | missing | |
| Anonymous credentials for signup | decided otherwise (stage 4) | |
| One-time key package store | done | |
| Mailboxes, 30-day purge, delete on acknowledge | done | |
| Reliable sending: idempotent sends | built (branch `claude/outbox`) | PROTOCOL.md 8.10: optional `idempotency_key` on `POST /v1/messages`, per device, same request answered from the record, other request `409 IDEMPOTENCY_KEY_REUSE`; records expire with the message TTL, capped per device (migration `0011`); commits idempotent by hash |
| Commit ordering endpoint | done | HANDOFF 3.2; eligibility set, idempotent retry, welcome only with a winning commit |
| Size limits for large hybrid groups | done | commits / welcomes 4 MiB, 2048 devices (BENCHMARKS.md rec. 6) |
| Minimal logs (no IP, no sender, day / minute granularity) | done | SERVER_API.md "What the server stores" |
| Operator feature flags + audit trail | done | own implementation; section 4.4 |
| `@username` (hash only, rate-limited search) | done | PROTOCOL.md 8.4; `/v1/usernames/*`; CLI `username`, `find`, `invite <group> @name`. Username links and QR text (`user.username_link`: `tree://u/<token>`, only the token's hash on the server, reset gives a new link while the name stays, found only while the name is discoverable; add a contact by link) |
| Chat list basics (device only) | done | APP_PROTOCOL.md 6.1: mute for 1 h / 8 h / 1 w / until unmuted (no notification), archive (an unmuted chat comes back with a new message, `user.unarchive_on_message`), pins (at most 5, ordered), drafts (`user.drafts`), mark unread / read, silent send (flag inside the encrypted message), quiet leave (no "left" line; the member list still changes), stranger labels in the desktop header and request list. Not synced to the user's other devices yet |
| Message request inbox for strangers, blocking | done (on the device) | APP_PROTOCOL.md 5: requests, decline, block, `user.message_requests` / `stranger_block` / `group_add`; the server still delivers (it cannot know contacts) |
| Report service (reporter's device submits) | done | `/v1/franking`, `/v1/reports`, operator review and resolve, account suspension (apply/release, `403 SUSPENDED`) |
| Spam limits for new accounts | done | PROTOCOL.md 8.9: new accounts and accounts with verified reports from 3+ people pay more per outreach and reach fewer devices; operator flags with apply/release |
| File service (encrypted blobs only) | done | resumable uploads in parts (`/v1/uploads`, migration `0014`), ranged downloads, 2 GiB per file, daily quota per account, unfinished uploads purged after 24 h, files after 30 days |
| Media: large files, thumbnails, auto-download | built (branch `claude/media`) | Wave 1 item 5: files through the outbox (offline queue, resumed and paused uploads, failed with retry / cancel), metadata and sender-made previews inside the message, resumable downloads, progress without holding the session, `user.auto_download`; view-once and voice on chunked media; FFI `send_media`, `send_file_path`, `download_to`, `transfers`, `pause_transfer`, `resume_transfer`, `set_network`; tests `crates/tree-client/tests/media.rs`, `crates/tree-server/tests/attachments.rs` |
| Media editor | built (branch `claude/media`) | Wave 1 item 6: crop, rotate, draw, text, blur on the device (`apps/shared/.../media`, platform-neutral operations on pixels), JPEG export without metadata, desktop editor screen; the original never leaves the device; tests `MediaEditTest` |
| Push relay without content | done (server) | PROTOCOL.md 8.8: `wake` only, coalesced, allowed gateway hosts only; CLI `push`. Platform push gateways (vendor credentials) come with deployment |
| Docker Compose + Caddy TLS, one region | partial | files in `deploy/`; manual steps and a manual-only GitHub Actions deploy (`.github/workflows/deploy.yml`, needs the owner's secrets) ready; never deployed (HANDOFF 3.5) |
| Stateless, partitionable by user-id hash | partial | the server keeps a replay cache and rate limits in memory (Q7) |

### 2.3 Clients

| Requirement | Status | Note |
| --- | --- | --- |
| Client logic library shared by all apps | done | `crates/tree-client`: server API, sync, two-phase commits, rosters, names, held messages (APP_PROTOCOL.md) |
| Reliable sending: durable outbox | built (branch `claude/outbox`) | PROTOCOL.md 6.13: `tree_outbox` in the encrypted profile, sealed once, same key on every retry, backoff 5 s to 1 h, failed after 8 attempts, crash recovery, retry / cancel; sync drives it; FFI `outbox`, `retry_send`, `cancel_send`, `Message.status`; desktop and Android show pending / failed with retry and cancel; tests `crates/tree-client/tests/outbox.rs`, `crates/tree-server/tests/idempotency.rs` |
| Command-line client through the server | done | `crates/tree-cli`, `scripts/cli_demo.sh`; end-to-end test with a real server (HANDOFF 3.3) |
| UniFFI bindings | done | `crates/tree-ffi` (`TreeSession`); Kotlin bindings run on the JVM against a real server (`scripts/ffi_kotlin_demo.sh`), Python likewise (`scripts/ffi_demo.sh`); Swift generated. Android/iOS library builds need the NDK / Xcode |
| Android app (Kotlin + Compose Multiplatform) | partial | `apps/android`: the Rust client cross-compiled with the NDK (`scripts/android_lib.sh`, arm64-v8a, x86_64), the desktop app's model and texts shared (`apps/shared`), Compose screens (sign-up, chats, requests, chat with files and report, invite links incl. `tree://join` links, safety numbers, settings, recovery phrase); `FLAG_SECURE` for `chat.screenshot_block` / `user.app_switcher_blur`; profile excluded from backups. `gradle assembleDebug` builds the APK; **not yet run on a device or emulator** (no KVM here). Not yet: push (UnifiedPush distributor), notifications, release signing |
| Desktop app (same code) | partial | `apps/desktop` (Compose for desktop on the JVM, Korean and English): sign-up / open, chats, request inbox (accept, decline, block), invite by @username or account, invite links, messages with report, files (send, check, save as; previews, progress, pause / resume, auto-download), the media editor, safety numbers with "mark verified", group chat settings for admins, settings from the registry with apply/release, option choices (e.g. disappearing time, `user.group_add` = nobody), lock reasons and pending releases, recovery phrase, chat list menu (pin, mute with duration, archive section, mark unread, leave or leave quietly), drafts restored, silent send, stranger labels, username link with reset and add-by-link (the link text; no QR image yet: no QR library in the build), tray notifications that respect mutes and silent messages. Model tested against a real server and screens rendered off-screen (`scripts/desktop_test.sh`). Not yet: edit/delete/reactions UI, voice, packaging and signing |
| iOS app (Swift + SwiftUI) | missing | the Swift bindings are verified against a real server (`scripts/ffi_swift_demo.sh`, Swift 6 on Linux); the app needs macOS (a hosted macOS runner) and the owner's developer account |
| Settings screens generated from the registry, apply/release buttons | done (desktop, Android) | user settings from `features()`, group chat settings from `chat_features()`; locked switches show the reason |
| Korean and English UI | done (desktop, Android) | `apps/shared/.../Strings.kt`; every key in both languages (tested) |
| Terms, privacy policy screens | missing | 변호사 확인 필요 for the texts |
| App-level protections (app lock, screenshot block, notification content, incognito keyboard, app-switcher blur, PC screen security) | partial | Android: screenshot block and app-switcher blur (`FLAG_SECURE`), profile excluded from backups. Both apps: app lock (`user.app_lock`: leaving the app on Android, 5 minutes unfocused on desktop, closes the profile and its key). Not yet: notification content (no notifications yet), incognito keyboard, desktop screen security |
| Store submission checklist (report, block, content filter, contact) | partial | [STORE_CHECKLIST.md](STORE_CHECKLIST.md); in-app account deletion done; legal texts and forms: 변호사 확인 필요 |

### 2.4 Verification

| Requirement | Status | Note |
| --- | --- | --- |
| Attack-scenario tests on the core | done | 111 core tests, proptest; TESTING.md |
| Mutation testing | done for the core | 3.1: 277 mutants of the changed files; TESTING.md |
| Formal models of Tree's own additions | done | ProVerif models (envelope, commit ordering, removal, PCS, FS, franking, device link) with negative controls, abstract; formal/README.md |
| Design's "tests not run yet" for stage 1: removed member cannot read (real OpenMLS code) | done | `removed_member_cannot_decrypt_even_if_ignoring_removal` |
| Same: key-committing file encryption | done | `attachment::tests::key_commitment`, `attachment::tests::truncation_reorder_and_bit_flips_detected`, `files_end_to_end`, `media::chunked_file_end_to_end_with_metadata_and_padding` |
| Same: device link code commitment | done | `crates/tree-client/tests/link.rs` (swapped key: different codes, nothing linked; swapped nonce: refused), `tree-core` `link::tests`, `formal/device_link.pv` with negative control |
| Load test | missing | |
| External review of the crypto code (stage-1 exit criterion) | missing | owner to engage a reviewer |
| Reproducible builds | missing (stage 4) | |

## 3. Later stages

Feature keys in the design per stage: stage 1: 34, stage 2: 1 (+ the bot
platform section), stage 3: 68, stage 4: 14, stage 5: 14, unstaged: 14. None
of stages 2 to 5 is started, except that the registry already holds the
permanent locks those stages rely on (points never move between people, bots
never pay out points, private groups never become public).

Stage 3, rich chats (wave 2 part A, branch `claude/rich-chats-a`): **built**.
Pinned messages with expiry (`chat.pins`), polls (`chat.polls`; anonymous
means the apps hide names, votes stay MLS-authenticated to members'
devices), scheduled messages (device only, sent when due by the running
app or the next sync), forwarding (`chat.forwarding`; honest apps only),
reminders (device only), chat export (`chat.export`) and storage clean-up
(`user.storage_clean`): APP_PROTOCOL.md 3 and 6.2, client, FFI, desktop UI
and model tests (`crates/tree-client/tests/rich_chats.rs`, `AppModelTest`).
The Android app shares the model; its screens for these are not built yet.

Big blocks per stage: bots (gateway, bot lane, factory, tokens) in 2;
1,000-member groups, public groups and channels, admin roles, multi-device,
calls, backup, plans, points ledger, duress PIN, hidden profiles in 3;
sealed sender, anonymous credentials, group mailboxes, key transparency,
social / PIN / passkey recovery, reproducible builds, formal work, external
audit in 4; three regions, group calls, verifiable server, payouts in 5.

## 4. Where the implementation is deliberately different

Each needs the owner's confirmation; the reasons are in PROTOCOL.md.

1. **Three-way hybrid (ML-KEM + HQC + X25519).** Not in v1 (PROTOCOL.md 3.1):
   no standard way to put a third KEM into MLS, so it would be a home-made
   construction (hard rule 1); no audited implementation; ~10x larger
   commits. Re-evaluated when a standard MLS ciphersuite with it exists.
2. **SLH-DSA root identity / ML-DSA device keys.** Not in v1 (PROTOCOL.md
   3.2): needs a non-basic MLS credential and its own specification. The
   simpler path is an MLS suite with ML-DSA signatures (Tree v2).
3. **Crypto provider.** The design names the formally verified libcrux
   provider; `0x004E` is only available on the RustCrypto provider in the
   library version used, so v1 runs on RustCrypto. libcrux with `0x004D`
   is tested as an alternative (open question Q1).
4. **Feature flags.** The design names an external flag server; stage 1 uses
   a table in the server database with an audit trail. Swappable later.
5. **Databases.** The design names PostgreSQL (accounts, keys) and a
   wide-column store (mailboxes) at scale; stage 1 runs on SQLite with
   portable SQL. Changed before the first load test.
6. **Adds without an update path.** Not in the design; chosen from
   measurements (BENCHMARKS.md rec. 4) and specified in PROTOCOL.md 6.4.

## 5. What counts as evidence here

- Done: unit, integration and property tests; mutation testing; symbolic
  formal models of Tree's own additions; measured benchmarks; demos that run;
  an end-to-end test with a real server over HTTP that also searches the
  server's database for plaintext and names (none found).
- Not done: external review, real apps, a deployed server, load tests,
  reproducible builds. Until the external review, no security claim is final.

## 6. Order of work to finish stage 1

1. HANDOFF 3.1 core fixes — done.
2. HANDOFF 3.2 server commit ordering + size limits — done.
3. HANDOFF 3.3 command-line client: two devices chat through a local server — done.
4. Identity and safety basics in core + server: recovery phrase, safety
   numbers and key-change warning, usernames (hash) with QR, message
   requests and blocking, reporting with message franking.
5. Group administration in the MLS group context: admins, kick, invite
   links, chat settings that devices enforce (disappearing, edit window,
   media, ...), the four missing stage-1 keys.
6. Files: per-file key-committing encryption + encrypted blob service.
7. HANDOFF 3.5 deploy to the owner's server; push relay.
8. UniFFI bindings, then Android, desktop, iOS apps with registry-driven
   settings, Korean and English, terms screens.
9. Load test, store checklist, external crypto review, beta.

Each step: main code first, run it, tests, review, the checks of HANDOFF 3.4,
then merge and update this file.
