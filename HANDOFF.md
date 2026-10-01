# HANDOFF — continue here in a new session

> 한국어 요약: 0단계(핵심·서버·저장소 암호화·검증·명세·형식 검증·실측)와 ① 핵심 버그 수정(3.1)은 main에 들어가 있어.
> 다음은 ② 서버 커밋 순서 + 크기 제한 ③ 명령줄 앱으로 서버 경유 대화 ④ 전체 재검증 ⑤ 헤츠너 배포 순서야.
> 보고는 한국어 반말, 결론 먼저. 직접 돌려본 것만 "됐다".

Read `CLAUDE.md` first (hard rules), then this file, then `docs/STATUS.md` (design vs. code, work order),
then `docs/PROTOCOL.md`. Data layouts: `docs/SCHEMA.md`.

## 1. GitHub access (no keys from the owner, ever)

- Repo: `moneyally/tree`. If it is not visible in the session, attach it with the `add_repo`
  tool (owner `moneyally`, repo `tree`, access `push`), clone with
  `git clone --depth 1 https://github.com/moneyally/tree <dir>` (long timeout), then
  `register_repo_root`.
- Push: plain `git push -u origin <branch>`; the session proxy authenticates.
- PRs: `python3 .claude/skills/tree-deploy/scripts/pr.py create|status|merge|list`
  (uses the session's `GH_TOKEN` placeholder). Steps: `.claude/skills/tree-deploy/SKILL.md`.
- Always work on `claude/<topic>` branches; merge to `main` only after the checks in section 4 pass.
- Shallow clone cannot see a pushed branch: `git config --add remote.origin.fetch '+refs/heads/<b>:refs/remotes/origin/<b>' && git fetch origin`.
- The internal design document (Korean, v1–v5) is pasted by the owner into the chat. It names
  other companies: **never commit it or quote it in the repo.**

## 2. What is on `main` (PR #1–#4, plus HANDOFF 3.1)

| Area | Where | State |
| --- | --- | --- |
| E2E groups | `crates/tree-core` | MLS on OpenMLS 0.9, hybrid suite `0x004E` (ML-KEM-768 + X25519, AES-256), outer envelope seal (F-001), welcome key-package restore (F-006), two-phase commits (F-003 client side), member ids (F-008), proposals rejected (F-007), 2 past epochs (F-002), own-commit echoes (F-004), adds without update path |
| Feature registry | `crates/tree-core/src/features.rs` | apply/release for every feature, permanent locks, internal kinds, chat lock of user preferences (`LOCKED_BY_CHAT`), bot owner check |
| Encrypted local storage | `crates/tree-core/src/storage` | SQLCipher + Argon2id (64 MiB, 3 passes), restart-safe, `Client::create/open`, `load_group` |
| Server | `crates/tree-server`, `docs/SERVER_API.md`, `deploy/` | accounts (PoW), signed requests, one-time key packages, mailboxes (30-day purge), operator flags, rate limits, no IP/body logs, Docker + Caddy |
| Spec | `docs/PROTOCOL.md` | Tree v1 = MLS + hybrid suite (no own ratchet; HQC not in v1), byte formats, claims C1–C11, metadata table, open questions Q1–Q10 |
| Formal | `formal/` | ProVerif 2.05 models: seal, commit ordering, removal secrecy, PCS, FS + 4 negative controls. `PROVERIF=/opt/opam/default/bin/proverif sh formal/run.sh` (install ProVerif via opam if missing) |
| Tests | `docs/TESTING.md` | 100 tests pass; core mutation score 100% (102 mutants) at PR #3 |
| Benchmarks | `docs/BENCHMARKS.md`, `examples/bench_groups.rs` | groups up to 2,000 leaves |
| Recovery | `docs/RECOVERY_THREAT_MODEL.md` | phrase, passphrase, future PIN realms, passkey |

## 3. Next work, in order

### 3.1 Core fixes (`crates/tree-core`, branch `claude/core-fixes`) — DONE
Merged. What was left out on purpose: binary storage encoding (item 6, not contained enough: needs a codec for
every OpenMLS stored type plus a migration; see `docs/BENCHMARKS.md` rec. 7). Core API for the app / CLI:
`Group::add(&[key packages]) / remove(&[MemberId]) / refresh_keys -> PendingCommit`, then
`confirm_commit` (server said 200) or `discard_commit` (409); `pending_commit()` after a restart;
`Incoming::{Message{from,name,body}, GroupChanged{.., own_commit_discarded}, OwnCommitMerged, RemovedFromGroup, OwnEcho}`;
`Group::should_refresh_keys()` after joining. Original task list, for reference:
1. **F-003 two-phase commits.** add/remove/refresh return a pending commit (sealed bytes, optional welcome,
   group id, epoch) and do not merge. `confirm_commit()` after server accept, `discard_commit()` on reject.
   While pending: no new commit, receiving works; a winning commit for that epoch arriving while ours is
   pending discards ours automatically and says so. Welcome only delivered if our commit wins.
   Survives restart. Keep a confirm-immediately helper for tests/demo only.
2. **F-007** reject member proposals and external join proposals (never stored); own commits never include
   others' proposals; commit referencing an unknown proposal fails cleanly. Provide or document "leave group".
3. **F-008** members identified by member id; `members()` returns id + display name + duplicate flag;
   `remove` takes member ids (several in one commit, e.g. all devices of a user).
4. **F-002** application messages from up to 2 past epochs decryptable (`max_past_epochs`); past-epoch commits rejected; document FS cost.
5. **F-004** echo of our own confirmed commit returns `Incoming::OwnEcho`.
6. **Benchmarks:** adds without update path by default; "send one key update soon after joining" hint;
   smaller stored state (binary vs JSON) only if safe and contained.
7. **Registry:** internal kinds SecurityPolicy / ChatPolicy / UserPreference / ModerationPolicy /
   BillingCapability (public API unchanged); bot-scope owner permission check; Chat-level release locks
   the same key for users (LOCKED_BY_CHAT).
8. Envelope compare via the `subtle` crate.

### 3.2 Server (`crates/tree-server`, after 3.1)
1. **Commit ordering endpoint** per `docs/PROTOCOL.md`: first commit per (group, epoch) wins, idempotent
   retry, conflict response; device eligibility set so non-members/removed members cannot grab the slot;
   welcome travels in the same request and is delivered only if the commit wins.
2. **Size limits** from `docs/BENCHMARKS.md`: hybrid welcomes exceed 256 KiB from ~150 leaves; raise
   limits for commits/welcomes (or deliver the tree separately) and handle >1000 recipients.
3. Update `docs/SERVER_API.md` and server tests (incl. concurrent commits for the same epoch).

### 3.3 CLI client (`crates/tree-cli`, new)
Encrypted profile (`Client::create/open`), signup with PoW, key package upload, create group,
invite by account id (claim key packages), send/receive via long-poll, confirm/discard pending commits.
Demonstrate two CLIs chatting end to end through a locally running server (and later the Hetzner one).

### 3.4 Full re-verification before merging each step
`cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets` (0 warnings),
`cargo mutants -p tree-core` and `-p tree-server` (kill or justify every missed mutant),
`formal/run.sh` ("all results as expected"), `check_public_text.py`, demos run.
Record new findings in `docs/SECURITY_FINDINGS.md`.

### 3.5 Deploy to the owner's Hetzner server
Owner already has a server. Do not ask for passwords or keys in chat. Options to offer:
(a) owner runs `deploy/README.md` steps himself; (b) a GitHub Actions deploy workflow using an SSH key the
owner stores as a repository secret. Mark the access-log retention question "변호사 확인 필요".

### 3.6 After that (stage 1 apps)
Android + desktop: Kotlin + Compose Multiplatform with UniFFI bindings to tree-core; iOS: Swift + SwiftUI
(needs macOS: GitHub Actions macOS runner + TestFlight). Check toolchains are installable first.

## 4. Open decisions for the owner
- License: Apache-2.0 (current) or AGPL-3.0.
- `docs/PROTOCOL.md` §12 open questions Q1–Q10 (provider choice, commit-slot freeze rule, leaving a group, inactive devices, …).
- Mac availability for iOS builds.

## 5. Notes
- Building from scratch takes ~15 min (SQLCipher + OpenSSL compiled in). `cargo-mutants` is slow on 2 vCPUs.
- Sub-agents need the owner's approval in the app; if launching them is rejected, work directly instead.
