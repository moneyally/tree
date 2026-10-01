# Tree

An end-to-end encrypted messenger where the server knows as little as possible.

- **Every private chat is end-to-end encrypted**: one-to-one and groups alike. The server only stores and forwards ciphertext.
- **Post-quantum by default**: key exchange combines ML-KEM-768 (FIPS 203) with X25519, so it stays secure as long as either one holds. All symmetric keys are 256-bit.
- **No phone number or email** to sign up.
- **Bots are end-to-end encrypted too**: they decrypt only on their owner's server, never on Tree's.
- **Every feature can be applied and released**, through the API and with a button in the app. The few that cannot (like encryption itself) say why.
- **Open source**, built only on published standards (MLS, RFC 9420) and independent, audited libraries. No home-made cryptography.

> **Status: early development (stage 0).** Not audited. Do not rely on Tree for sensitive communication yet.

## What works today

The Rust core (`crates/tree-core`) can:

- create device identities and one-time key packages
- create groups, add and remove members, refresh keys
- encrypt, decrypt and authenticate messages
- reject tampered, replayed, cross-group and outsider messages
- manage features through the apply/release registry

Try it:

```sh
cargo run -p tree-core --example demo   # three people chatting end to end
cargo test -p tree-core                 # attack-scenario tests on the reference implementation
formal/run.sh                           # formal models (needs ProVerif)
```

Tests find bugs; they do not prove security. What Tree claims, under which
assumptions, and which parts are machine-checked is in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Layout

```
crates/tree-core   end-to-end encryption, groups, feature registry
crates/tree-server server: mailboxes and one-time key packages (ciphertext only)
deploy/            Docker image and compose file for running the server
docs/              protocol specification, threat models, server API, security findings
formal/            ProVerif models of the parts Tree adds on top of MLS
```

The server API is described in [docs/SERVER_API.md](docs/SERVER_API.md).

Coming next: Android app, desktop app, iOS app.

## Security

Found a vulnerability? Please report it privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Third-party notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
