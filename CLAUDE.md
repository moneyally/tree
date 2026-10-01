# Tree — handoff for coding sessions

Owner: 정원. Not a developer, does not read English. Report in Korean 반말, short,
conclusion first. Say "됐다" only for things actually run and checked.

## Hard rules
1. No home-made cryptography. Only standards (MLS RFC 9420, FIPS 203/204/205,
   HPKE, etc.) and independent audited libraries.
2. Clean room: never use or read the source of other messengers' apps,
   servers or protocol libraries.
3. README and any public text never name other companies or messengers.
   The internal design document stays out of this repository.
4. Every feature has apply and release (`crates/tree-core/src/features.rs`).
   Permanent exceptions are `Lock::AlwaysOn` / `Lock::AlwaysOff` with a reason.
5. Points never move between people; bots never pay out points.
6. Secrets (keys, tokens) never go into git.
7. Work style: write the main code fully first, run it, check the output,
   then review. Crypto changes must still pass `cargo test -p tree-core`.
8. Anything legal or app-store related: mark "변호사 확인 필요", do not guess.

## GitHub access
- Access comes from this session itself. Never ask the owner for keys or tokens.
- clone/pull/push: plain git (the session proxy authenticates). Work on `claude/<topic>` branches, never directly on `main`.
- PRs: `python3 .claude/skills/tree-deploy/scripts/pr.py` (uses `GH_TOKEN`, a placeholder the proxy replaces). Steps in `.claude/skills/tree-deploy/SKILL.md`.
- Repo not visible or push rejected: attach `moneyally/tree` with the `add_repo` tool (push access), retry once.
- Merging to `main` deploys nothing yet (no server). Deploy steps go into the skill once the server exists.

## Stack
Rust core + server + bot gateway; Android/desktop: Kotlin + Compose
Multiplatform; iOS: Swift + SwiftUI; bindings via UniFFI; web console:
TypeScript. Server host: Hetzner (owner already has a server).

## Current state (stage 0)
- `crates/tree-core`: MLS groups on OpenMLS 0.9, default ciphersuite
  `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519` (IETF draft, provisional
  code point), X-Wing on libcrux also tested. Outer envelope seal (F-001).
  Feature registry with stage-1 features and permanent locks.
- `cargo run -p tree-core --example demo`, `cargo test -p tree-core`.

## Next
1. Persistent storage (SQLCipher) instead of in-memory OpenMLS storage.
2. Server: mailbox + one-time key package store (Rust, axum), Docker, Hetzner.
3. CLI client talking through the server.
4. Android shell + UniFFI bindings.

See `docs/THREAT_MODEL.md` and `docs/SECURITY_FINDINGS.md`.
