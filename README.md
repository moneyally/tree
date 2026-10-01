# Tree

An end-to-end encrypted messenger where the server knows as little as possible.

- **Every private chat is end-to-end encrypted**: one-to-one and groups alike. The server only stores and forwards ciphertext.
- **Post-quantum by default**: key exchange combines ML-KEM-768 (FIPS 203) with X25519, so it stays secure as long as either one holds. All symmetric keys are 256-bit.
- **No phone number or email** to sign up.
- **Bots are end-to-end encrypted too**: they decrypt only on their owner's server, never on Tree's.
- **Every feature can be applied and released**, through the API and with a button in the app. The few that cannot (like encryption itself) say why.
- **Open source**, built only on published standards (MLS, RFC 9420) and independent, audited libraries. No home-made cryptography.

> **Status: early development (stage 1 started).** Not audited. Do not rely on Tree for sensitive communication yet.
> What exists and what does not: [docs/STATUS.md](docs/STATUS.md).

## What works today

The Rust core (`crates/tree-core`) can:

- create device identities and one-time key packages
- create groups, add and remove members, refresh keys
- encrypt, decrypt and authenticate messages
- reject tampered, replayed, cross-group and outsider messages
- manage features through the apply/release registry

The server (`crates/tree-server`) orders commits and stores ciphertext only;
the client library (`crates/tree-client`) and the `tree` command line
(`crates/tree-cli`) chat through it. On top of that:

- @usernames (the server keeps only a hash), message requests and blocking
- safety numbers (60 digits or a QR code) and key-change warnings
- group admins, chat settings every device enforces (disappearing
  messages, edit and delete windows, media, voice, reactions, mentions,
  screenshot blocking), invite links with expiry and a use limit
- encrypted attachments, message history and search on the device
- reports with message franking (the server can check a reported message
  is genuine without storing anything per message), account suspension
- a recovery phrase (12 to 24 words, English or Korean)
- push wake-ups that carry no content
- app bindings (`crates/tree-ffi`), a desktop app and an Android app

Try it:

```sh
cargo build -p tree-server -p tree-cli && sh scripts/cli_demo.sh   # two people chat through a real server
sh scripts/ffi_demo.sh                  # the app bindings, through a real server
sh scripts/desktop_test.sh              # the desktop app's model and screens (needs a JDK and Gradle)
cargo run -p tree-core --example demo   # three people chatting end to end (no server)
cargo test -p tree-core                 # attack-scenario tests on the reference implementation
formal/run.sh                           # formal models (needs ProVerif)
```

Tests find bugs; they do not prove security. What Tree claims, under which
assumptions, and which parts are machine-checked is in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Layout

```
crates/tree-core   end-to-end encryption, groups, feature registry
crates/tree-server server: mailboxes, one-time key packages, commit ordering (ciphertext only)
crates/tree-client client logic for all apps: server API, sync, commits, rosters
crates/tree-cli    `tree` command-line client
crates/tree-ffi    bindings for the apps (Kotlin, Swift)
apps/              desktop and Android apps (shared model in apps/shared)
bindings/          binding demos (Python, Kotlin on the JVM)
scripts/           demos
deploy/            Docker image and compose file for running the server
docs/              protocol specification, threat models, server API, security findings
formal/            ProVerif models of the parts Tree adds on top of MLS
```

The server API is described in [docs/SERVER_API.md](docs/SERVER_API.md).

Coming next: the iOS app, running the server, notifications through a
push gateway, an external security review.

## Security

Found a vulnerability? Please report it privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Third-party notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
