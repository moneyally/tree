# Tree status against the v5 design

Status baseline: **2026-10-04**  
Branch under verification: `claude/backend-complete-v1`  
Target: `main`

> This file describes repository state, not a security certification. A feature is only treated as
> verified after its targeted tests, full regression, fmt/test/clippy CI, and the relevant protocol/design
> review have passed.

## 1. Current gate

The backend is in the **pre-merge verification gate**.

Required before merge:

```text
implementation
   ↓
targeted tests
   ↓
workspace regression
   ↓
rustfmt + clippy
   ↓
design/protocol audit
   ↓
PR check
   ↓
merge to main
```

The application/UI remains intentionally out of scope until this gate is complete.

## 2. What is implemented in the backend branch

| Area | State | Evidence / scope |
|---|---|---|
| MLS 1:1 and group E2E | implemented | `tree-core/group.rs`, server transport, E2E tests |
| ML-KEM-768 + X25519 hybrid | implemented | Tree v1 suite selection and downgrade checks |
| Outer envelope seal | implemented | epoch-bound member seal; checked before MLS |
| Commit ordering | implemented | server first-wins sequencing, idempotent retry, eligibility, epoch checks |
| Replay / past epochs | implemented | persisted hashes, two retained past epochs, bounded future queue |
| Encrypted local storage | implemented | SQLCipher + Argon2id, persisted client/group state |
| Recovery primitive + server flow | implemented | BIP-39 phrase, HKDF-derived recovery key, recovery endpoint |
| Username hash / social basics | implemented | canonical username hash, lookup/claim/delete |
| Message requests / blocking | implemented | server APIs and authorization tests |
| Opaque reports | implemented | encrypted evidence transport; message franking remains a release requirement |
| Encrypted file primitive | implemented | per-file AES-256-GCM, capability-protected blob service |
| Group settings/admin control framework | implemented | E2E control state; policy enforcement still expanding |
| Structured message events | implemented | new/edit/delete/reaction/read/typing ledger primitives |
| Mailbox + WebSocket transport | implemented | long-poll and WebSocket delivery paths |
| Device-link flow | implemented | challenge/code/proof flow; encrypted state sync still separate |
| Bot registry + token lifecycle | implemented | creation, token rotation/revoke, commands, gateway identity |
| Privacy-mode bot lane | implemented | explicit lane descriptor/events and allowlist protocol |
| Safety-key persistence | implemented | encrypted fingerprint state + key-change observation |

## 3. Design gaps still requiring backend work

### Stage-1 completion gaps

These are not declared complete merely because adjacent infrastructure exists:

- **All behavior behind feature keys**: settings such as disappearing messages, edit windows,
  view-once and client privacy controls need enforcement in the message/group state machine.
- **Remaining Stage-1 feature keys**: reconcile the registry against the v5 list and add any missing
  user preference keys.
- **Group administration semantics**: enforce admin-only membership changes where required by the
  design; define initial-admin and role-transfer rules in the authenticated MLS control plane.
- **Invite links**: expiring / use-count-limited invite capability.
- **Message franking**: verifiable report evidence construction.
- **Push relay**: content-free push wake-up path.
- **Official Tree test vectors**: fixed protocol vectors for independent implementations.

### Multi-device and recovery

- Encrypted multi-device state synchronization.
- Safety-number/person-level identity model and QR flow.
- Recovery hardening beyond the current primitive: backup/state restoration semantics, retry/abuse
  boundaries, and app-level protections.
- Key-refresh scheduling after join, restore, recovery and suspected compromise.

### Search/history and lifecycle

- Encrypted message history/index strategy.
- Server-independent search semantics.
- Disappearing-message enforcement and view-once consumption semantics.
- Reliable cleanup/expiry across client and server copies.

### Community, calls and business layers

- Public groups/channels with join approvals and moderation.
- Calls signaling and media-keying.
- Sealed sender / key transparency / metadata reduction.
- Payments, subscriptions, points ledger and business messaging.
- Load testing, multi-region architecture and operational hardening.

## 4. Deliberate v1 deviations from the original design

These are architectural decisions, not accidental omissions:

1. **No three-way HQC + ML-KEM + X25519 layer.** Tree v1 stays inside the MLS/X-Wing construction
   rather than defining a custom three-KEM combiner.
2. **Ed25519 authentication in v1.** ML-DSA / SLH-DSA identity work is deferred to a later protocol
   version with its own credential specification.
3. **RustCrypto provider for the v1 hybrid suite.** The alternative libcrux path is tested where the
   library exposes a compatible suite.
4. **SQLite at the current stage.** The design can move to PostgreSQL / larger mailbox infrastructure
   before production-scale load validation.
5. **Tree server implements commit sequencing.** The client does not merge a new epoch until its commit
   is accepted by the server.

The protocol specification remains the authority for v1 wire behavior.

## 5. Verification inventory

Already present in the repository:

- unit tests
- malformed-input tests
- property-based robustness tests
- real HTTP integration tests with real Ed25519 signatures
- end-to-end Core → Server → Core message flow
- mutation/adversarial testing for the core
- selected ProVerif models for Tree-specific protocol additions
- group-size benchmarks

Still required before a production/security claim:

- full green workspace CI on the release candidate
- production-scale load validation
- external cryptographic/security review
- penetration testing
- reproducible release verification
- platform-store/privacy/legal review

## 6. Merge and app sequence

The execution order is intentionally strict:

```text
backend compile/CI green
        ↓
backend design audit
        ↓
PR to main + checks
        ↓
merge
        ↓
continue remaining backend blocks
        ↓
backend contract freeze
        ↓
app architecture/bindings
        ↓
UI design together
```

The app design is **not being chosen unilaterally**. When the backend contract is stable, the UI work
will start with concrete questions about navigation, chat layout, onboarding/recovery, security
verification, notifications and visual direction.
Verification note: the latest cycle also normalized strict rustfmt/clippy findings and backend integration-test fixtures.
