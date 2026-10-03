# Tree backend completion status

v5 design baseline: 2026-10-03
App/UI is intentionally out of scope until the backend contract is stable.

## Verification rule

Every backend feature must have:
1. implementation;
2. malformed-input and authorization tests;
3. regression coverage against existing E2E flows;
4. CI fmt + workspace test + clippy;
5. documentation of any deliberate limitation.

## Stage 1

- E2E 1:1/group messaging: implemented in Tree Core + server transport.
- Group membership changes: implemented with server epoch ordering and OpenMLS.
- Replay/future-epoch handling: implemented with persisted ciphertext hashes and bounded future queue.
- Recovery phrase: implemented as 24-word BIP-39 + HKDF/Ed25519 recovery key.
- Username hash lookup: implemented.
- Message requests / blocks: implemented.
- Opaque report transport: implemented; message franking is still required before release.
- Verified device linking: implemented; encrypted multi-device state sync remains.
- Structured message events: implemented for new/edit/delete/reaction/read/typing; policy/storage still needs expansion.
- Encrypted media: implemented with per-file AES-256-GCM and capability-protected server storage.
- User feature persistence: implemented in SQLCipher.
- Group settings/admin controls: implemented as E2E control messages.
- WebSocket mailbox transport: implemented.
- Bot registry/token lifecycle: implemented.
- Privacy-mode bot-lane protocol: implemented.

## Stage 2+

Remaining backend work:
- bot gateway methods and bot-lane membership/key lifecycle;
- multi-device encrypted state synchronization;
- safety-number trust state and key-change persistence;
- chat feature apply/release semantics for all v5 Stage 1 keys;
- message history/index/search and disappearing/view-once enforcement;
- public groups/channels, join approvals and moderation;
- encrypted backups, friend recovery, PIN recovery;
- sealed sender, key transparency, group mailbox metadata reduction;
- calls signaling/media keying;
- payments, subscriptions, points ledger and business messaging;
- load tests, multi-region deployment, operational security controls.

## Release gates outside pure code

External security audit, reproducible release verification, penetration testing,
app-store review, legal/privacy review, and production-scale load validation
are release gates rather than claims that can be proven by this repository alone.
