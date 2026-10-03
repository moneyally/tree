# Tree

<p align="center">
  <strong>A privacy-first end-to-end encrypted messenger built around MLS.</strong><br/>
  The server transports encrypted state; conversation plaintext stays with the clients.
</p>

> **Development status:** backend completion work is in progress. The current branch is being
> regression-tested against the protocol/design. **Not externally audited and not ready for
> sensitive real-world communication.**

## Architecture

Tree is split into a small trusted client core and a deliberately limited transport/service layer.

```text
┌──────────────────────────────────────────────────────────────────────┐
│                            Tree Client                               │
│                                                                      │
│  UI / Platform                                                      │
│  Android · iOS · Desktop                                             │
│          │                                                           │
│          ▼                                                           │
│  Rust client core                                                   │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ MLS / TreeKEM / Secret Tree                                     │ │
│  │ ML-KEM-768 + X25519 hybrid                                      │ │
│  │ Ed25519 authentication                                           │ │
│  │ Message / group state · feature registry · encrypted storage    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│          │ TLS 1.3 + signed API requests                             │
└──────────┼───────────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         Tree Server                                 │
│                                                                      │
│  API / Auth  ──  Mailboxes  ──  Commit sequencer  ──  Key packages │
│      │              │                  │                    │        │
│      └──────────────┴──────────────────┴────────────────────┘        │
│                         ciphertext / minimal metadata                │
│                                                                      │
│  The server does NOT receive ordinary chat plaintext or media keys. │
└──────────────────────────────────────────────────────────────────────┘
```

### Trust boundaries

| Layer | Responsibility | What it should learn |
|---|---|---|
| Client core | MLS state, encryption/decryption, group membership, local encrypted state | Plaintext for the user's device |
| Tree server | Delivery, commit ordering, rate limiting, one-time key packages, bot registry | Ciphertext + minimal service metadata |
| Reverse proxy | TLS termination / routing when deployed | Network-level transport data |
| Bot gateway | Developer-controlled bot execution | Only bot-lane data explicitly authorized by the client/group |

The design intentionally avoids a server-side message decryption path. Tree's message confidentiality
and sender authentication come from MLS; Tree's additional protocol handles transport hardening,
ordering, replay boundaries and service controls.

## Cryptographic model

```text
Application message / media key / receipt
                │
                ▼
        MLS PrivateMessage
                │
      ┌─────────┴─────────┐
      │                   │
  Secret Tree          TreeKEM
      │                   │
      └─────────┬─────────┘
                ▼
   ML-KEM-768 + X25519 (X-Wing)
                │
                ▼
     AES-256-GCM / SHA-384
```

Tree does not add a second home-made ratchet or key hierarchy beside MLS.

For transport hardening, Tree adds an outer envelope seal so malformed or outsider input can be rejected
before the MLS state machine consumes a message-generation key. The server can parse the envelope
header for routing/validation, but cannot verify the member-only seal.

## Backend components

```text
crates/
├── tree-core/
│   ├── group.rs          MLS groups, membership, commits, receives
│   ├── provider.rs       persistent OpenMLS provider integration
│   ├── storage/          SQLCipher local encrypted storage
│   ├── message.rs        structured E2E message events
│   ├── message_state.rs  bounded authenticated message metadata
│   ├── safety.rs         persistent safety-key observations
│   ├── bot_lane.rs       privacy-mode bot lane protocol
│   └── features.rs       typed feature / policy registry
│
├── tree-server/
│   ├── lib.rs            HTTP API + server lifecycle
│   ├── auth.rs           signed request authentication
│   ├── commits.rs        server-side epoch/commit ordering
│   ├── bots.rs           bot registry + token lifecycle
│   ├── recovery.rs       account recovery primitive
│   ├── device_links.rs   verified device-link flow
│   └── wire.rs            minimal MLS wire inspection
│
└── tree-cli/             reference CLI for exercising the backend
```

## Security properties we are building toward

**Confidentiality.** Private messages are protected by MLS E2E encryption.

**Forward secrecy / post-compromise recovery.** MLS epoch updates and key-refresh commits are used
instead of a parallel custom ratchet.

**Server minimization.** The service stores/forwards ciphertext and intentionally avoids sender/message
plaintext logging.

**Commit consistency.** The server accepts the first valid commit for a group epoch and makes the same
winning history available to recipients.

**Local protection.** The client can keep identity/group state in SQLCipher-encrypted storage with
Argon2id-based key derivation.

These are implementation goals and test targets, not a claim of completed independent security assurance.

## Current backend verification

```text
Unit tests
   │
Property / malformed-input tests
   │
Integration tests (real HTTP + real Ed25519)
   │
Core mutation / adversarial testing
   │
Formal models for selected Tree protocol additions
   │
GitHub Actions: fmt + test + clippy
   │
External security review + penetration testing  ← release gate
```

GitHub's Rust CI documentation recommends ordinary Cargo build/test commands inside workflow automation
for continuous verification. See the repository workflow and [GitHub's Rust guide](https://docs.github.com/en/actions/tutorials/build-and-test-code/rust).

## Current backend scope

The backend branch contains work for:

- MLS 1:1/group messaging and membership changes
- encrypted local storage
- epoch/replay handling and commit ordering
- recovery primitives
- username-hash lookup and message-request/block flows
- structured message events
- encrypted media primitives
- mailbox/WebSocket transport work
- bot registry, token rotation/revocation and privacy-mode bot lane
- persistent safety-key fingerprint detection
- backend completion tracking and regression-test infrastructure

**Important:** the repository is still being brought to a green full-CI state. A feature appearing in code
does not by itself mean the whole backend is verified.

## Repository map

| Path | Purpose |
|---|---|
| `crates/tree-core` | Client cryptographic/state core |
| `crates/tree-server` | Minimal server / mailbox / registry APIs |
| `crates/tree-cli` | Reference backend client |
| `docs/PROTOCOL.md` | Protocol and security model |
| `docs/STATUS.md` | Design-vs-code coverage |
| `docs/BACKEND_COMPLETION.md` | Backend completion checklist |
| `docs/SERVER_API.md` | HTTP API contract |
| `docs/RECOVERY_THREAT_MODEL.md` | Recovery threat model |
| `formal/` | ProVerif models |
| `deploy/` | Container / reverse-proxy deployment |

## Development workflow

Every backend feature follows this gate:

```text
Design requirement
      ↓
Implement
      ↓
Targeted tests
      ↓
Full regression
      ↓
fmt + test + clippy
      ↓
Design/protocol audit
      ↓
Merge to main
```

A failed regression blocks the next feature. This keeps the backend contract stable before the app UI is designed.

## Local verification

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

For the formal models:

```sh
formal/run.sh
```

## Application roadmap

The app layer is intentionally kept behind the backend contract.

```text
Backend contract
     │
     ├── Android
     ├── iOS
     └── Desktop
            │
            ▼
   shared Rust crypto core
            │
            ▼
   registry-driven settings / privacy controls
```

The visual system, navigation, chat layout, onboarding, recovery UX and security-verification screens
will be designed together after the backend API and state-machine contracts stop changing.

## Documentation

- [Tree Protocol v1](docs/PROTOCOL.md)
- [Backend completion](docs/BACKEND_COMPLETION.md)
- [Status against the design](docs/STATUS.md)
- [Server API](docs/SERVER_API.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Recovery threat model](docs/RECOVERY_THREAT_MODEL.md)
- [Security findings](docs/SECURITY_FINDINGS.md)
- [Testing notes](docs/TESTING.md)

## Security reporting

Please report security vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Third-party notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).