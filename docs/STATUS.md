# Status against the design

What the design (internal design document v5, not in this repository) asks
for, what exists in this repository, and in which order the rest is built.
Updated with every merged step. Last update: 2026-10-01, HANDOFF 3.1.

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
| Forward secrecy / post-compromise security by key refresh | partial | refresh exists; no scheduler that triggers it (PROTOCOL.md 6.9) |
| Encrypted device storage (SQLCipher, hardware-wrapped key) | partial | SQLCipher + Argon2id done; hardware key (Secure Enclave / Keystore) needs the apps (`KeySource` is the hook) |
| Feature registry: apply/release for every feature, permanent locks, layers | done | `features.rs`; server, chat, user, bot layers; `LOCKED_BY_CHAT` |
| All 34 stage-1 feature keys in the registry | partial | 30 of 34; missing `user.username`, `user.note_to_self`, `user.folders`, `user.default_folders` |
| Behaviour behind the keys (disappearing timer, edit window, view once, ...) | missing | the registry stores the setting; nothing acts on it yet. Chat settings must live in the MLS group context (design: the server never knows them) |
| Recovery phrase (12-24 words) | missing | threat model in RECOVERY_THREAT_MODEL.md |
| Safety number / QR comparison, key change warning | done | PROTOCOL.md 5.4 (Q4 decided); pinning on first use, warning on any new device key; CLI `safety`, `verify` |
| Device link with confirmation code on both devices | missing | permanent lock in the registry, no code (multi-device is stage 3) |
| Per-file encryption for attachments | missing | |
| Message franking for reports | missing | |
| Admin roles inside the group (admins, kick) | missing | today any member may add or remove (PROTOCOL.md 6.4) |
| Invite links with expiry / use count | missing | |
| Official test vectors before merging crypto | partial | the libraries carry their own; Tree has no vector file of its own yet |

### 2.2 Server (`crates/tree-server`, `deploy/`)

| Requirement | Status | Where / note |
| --- | --- | --- |
| Sign-up without phone or e-mail: random id + device key | done | `POST /v1/accounts`, proof of work |
| Device attestation or paid signup as alternatives to proof of work | missing | |
| Anonymous credentials for signup | decided otherwise (stage 4) | |
| One-time key package store | done | |
| Mailboxes, 30-day purge, delete on acknowledge | done | |
| Commit ordering endpoint | done | HANDOFF 3.2; eligibility set, idempotent retry, welcome only with a winning commit |
| Size limits for large hybrid groups | done | commits / welcomes 4 MiB, 2048 devices (BENCHMARKS.md rec. 6) |
| Minimal logs (no IP, no sender, day / minute granularity) | done | SERVER_API.md "What the server stores" |
| Operator feature flags + audit trail | done | own implementation; section 4.4 |
| `@username` (hash only, rate-limited search) | missing | |
| Message request inbox for strangers, blocking | missing | needs server support (who may write to whom) and client UI |
| Report service (reporter's device submits) | missing | |
| Spam limits for new accounts | partial | per-device rate limits and signup limits exist; no new-account sending limit |
| File service (encrypted blobs only) | missing | |
| Push relay without content | missing | |
| Docker Compose + Caddy TLS, one region | partial | files in `deploy/`; never deployed (HANDOFF 3.5) |
| Stateless, partitionable by user-id hash | partial | the server keeps a replay cache and rate limits in memory (Q7) |

### 2.3 Clients

| Requirement | Status | Note |
| --- | --- | --- |
| Client logic library shared by all apps | done | `crates/tree-client`: server API, sync, two-phase commits, rosters, names, held messages (APP_PROTOCOL.md) |
| Command-line client through the server | done | `crates/tree-cli`, `scripts/cli_demo.sh`; end-to-end test with a real server (HANDOFF 3.3) |
| UniFFI bindings | missing | |
| Android app (Kotlin + Compose Multiplatform) | missing | |
| Desktop app (same code) | missing | |
| iOS app (Swift + SwiftUI) | missing | needs macOS (GitHub Actions runner) and an Apple developer account |
| Settings screens generated from the registry, apply/release buttons | missing | |
| Korean and English UI | missing | |
| Terms, privacy policy screens | missing | 변호사 확인 필요 for the texts |
| App-level protections (app lock, screenshot block, notification content, incognito keyboard, app-switcher blur, PC screen security) | missing | registry keys exist; behaviour is per platform |
| Store submission checklist (report, block, content filter, contact) | missing | |

### 2.4 Verification

| Requirement | Status | Note |
| --- | --- | --- |
| Attack-scenario tests on the core | done | 111 core tests, proptest; TESTING.md |
| Mutation testing | done for the core | 3.1: 277 mutants of the changed files; TESTING.md |
| Formal models of Tree's own additions | done | 9 ProVerif models (envelope, commit ordering, removal, PCS, FS), abstract; formal/README.md |
| Design's "tests not run yet" for stage 1: removed member cannot read (real OpenMLS code) | done | `removed_member_cannot_decrypt_even_if_ignoring_removal` |
| Same: device link code commitment, key-committing file encryption | missing | features not built |
| Load test | missing | |
| External review of the crypto code (stage-1 exit criterion) | missing | owner to engage a reviewer |
| Reproducible builds | missing (stage 4) | |

## 3. Later stages

Feature keys in the design per stage: stage 1: 34, stage 2: 1 (+ the bot
platform section), stage 3: 68, stage 4: 14, stage 5: 14, unstaged: 14. None
of stages 2 to 5 is started, except that the registry already holds the
permanent locks those stages rely on (points never move between people, bots
never pay out points, private groups never become public).

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
