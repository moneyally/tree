# Testing

## Run the tests

```sh
cargo test -p tree-core                        # everything (about 1 minute in debug)
cargo test -p tree-core --test robustness      # property-based tests only
PROPTEST_CASES=3000 cargo test -p tree-core --test robustness   # longer fuzzing run
cargo clippy -p tree-core --all-targets
python3 .claude/skills/tree-deploy/scripts/check_public_text.py
```

Post-quantum crypto is slow in debug builds. Proptest case counts are kept
moderate by default (256 to 512 per property) and can be raised with
`PROPTEST_CASES`.

## Test files (`crates/tree-core/tests/`)

| File | What it covers |
| --- | --- |
| `security.rs` | attacker scenarios against the core (removed member, tampering, replay, cross-group, forged group id, downgrade, X-Wing) |
| `key_burn.rs` | F-001 regression: a tampered copy must not burn the genuine message key |
| `envelope.rs` | outer seal: layout, version byte, boundary lengths, every tag byte, compensating tag changes, truncation/extension, per-group and per-epoch keys, padding |
| `membership.rs` | add / remove / refresh reporting, removed device locked out, one-time welcomes, duplicate key packages, tampered commits, proposals from members (F-007), duplicate names (F-008) |
| `delivery.rs` | out-of-order window, forward distance, epoch changes in flight (F-002), early next-epoch messages, removed member's old messages, commit replay, own echoes (F-004), concurrent commits (F-003) |
| `registry.rs` | feature registry: error codes, standard table, defaults, list per scope, permanent locks, admin rules, options, server flags, plan gating, `define` (F-005) |
| `welcome_burn.rs` | F-006 regression: a damaged welcome must not destroy the key package |
| `robustness.rs` | proptest, see below |
| `common/mod.rs` | fixtures, including `Insider`: a member built directly on the MLS library that can seal arbitrary bytes, used to reach the code behind the outer seal |

Tests marked **KNOWN LIMITATION** / **KNOWN ISSUE** pin the current behaviour of
an open finding. When the finding is fixed, the test must be changed to assert
the fixed behaviour.

## Robustness tests (proptest)

Every property checks: no panic, never accepted, and the genuine input still
works afterwards (a failed input does not damage state).

| Property | Input |
| --- | --- |
| `receive_random_bytes_never_accepted` | random bytes, random bytes behind a version byte, random bytes behind a zero tag |
| `receive_mutated_message_never_accepted` | 1 to 3 mutations (bit flip, truncate, extend, insert, delete, overwrite) of a genuine message |
| `receive_mutated_commit_never_accepted` | mutations of a genuine commit; epoch must not change |
| `insider_sealed_random_bytes_never_accepted` | random bytes in a VALID envelope (reaches the MLS parser) |
| `insider_sealed_mutated_mls_never_accepted` | mutated genuine MLS message, re-sealed by a member |
| `join_random_bytes_never_accepted` | random bytes into `Client::join` |
| `join_mutated_welcome_never_accepted` | mutated genuine welcome; the genuine welcome must still join (F-006) |
| `add_random_or_mutated_key_package_never_accepted` | random or mutated key packages into `Group::add`; epoch and members unchanged |
| `feature_registry_random_sequences` | up to 60 random apply / release / server-flag calls by four caller types, checked against an independent model of the rules, plus invariants: AlwaysOn never released, AlwaysOff never applied, idempotency, a failed call changes nothing, a call changes no other key, non-admins never change Chat/Server features |

A 3000-case run of every property passed on 2026-10-01.

## Mutation testing

```sh
cargo install cargo-mutants --locked
cargo mutants -p tree-core --timeout 300 \
  -C '--config=profile.dev.package."*".opt-level=2'
```

The `--config` flag optimizes dependencies only, which makes the crypto in each
test run fast; the code under test is still built in debug mode.

Results (cargo-mutants 27.1.0, 102 mutants):

| | caught | missed | unviable | timeout | score (caught / viable) |
| --- | --- | --- | --- | --- | --- |
| before this pass | 41 | 42 | 19 | 0 | 49% |
| after this pass | 82 | 0 | 20 | 0 | 100% |

The mutant set is the same except that `Registry::define` now returns a
`Result`, so its "replace body with `()`" mutant became "replace with `Ok(())`".

The 42 mutants missed before were all test gaps; there were no equivalent
mutants. Grouped:

- envelope check: `||`/`&&` and `<`/`==`/`<=` in the length check, `1 + TAG_LEN`
  to `1 * TAG_LEN` (would panic on a 32-byte input), and `|` to `^` in the
  constant-time fold (would accept a tag with two compensating changes);
- `sender_ratchet` replaced by the default window of 5;
- `receive`: removed-from-group check, proposal and external-join-proposal arms;
- `refresh_keys` returning a fake commit; `id`, `epoch`, `is_member`, `members`,
  `verification_code`, `Client::name`, `Client::signature_public_key`;
- feature registry: `code`, `define`, `server_lock`, the server-lock guard in
  `status`, scope filter in `list`, plan check in `apply`, `set_server_flag`.

Unviable mutants do not compile (mostly "return `Default::default()`" for types
without a default) and are not counted.

### Equivalent mutants

None. Every viable mutant changes behaviour that a test can observe.

## Findings from this pass

See `SECURITY_FINDINGS.md`: F-005 and F-006 fixed with regression tests;
F-002, F-003, F-004, F-007 and F-008 open, each pinned by a test. Other notes:

- The out-of-order window "32" keeps 32 generations behind the ratchet head,
  which is one past the newest message, so in practice the 31 messages before
  the newest one can still arrive late.
- `Scope::Bot` features are not permission checked (`Caller` has no bot-owner
  flag). Today the only bot feature is permanently locked.
- `LockReason::Chat`, `LockReason::Plan` and `FeatureError::LockedByChat` are
  never produced: a chat-level setting does not lock the same key for users.
