# Testing

These are attack-scenario tests on the reference implementation. They find
bugs and pin known limitations; they do not prove that Tree is secure. Security
claims and their assumptions are in [PROTOCOL.md](PROTOCOL.md) (section 9);
the formal models in [`formal/`](../formal/README.md) check parts of them
under stated abstractions.

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
| `membership.rs` | member ids, add / remove / refresh reporting (several devices per commit), removed device locked out, one-time welcomes, duplicate key packages, tampered commits, adds without update path, proposals and disallowed commits rejected (F-007), duplicate names told apart by member id (F-008) |
| `delivery.rs` | out-of-order window, forward distance, past-epoch window and its boundary (F-002), early next-epoch messages, removed member's old-epoch messages, commit replay, past-epoch commits, own echoes (F-004), two-phase commits: pending, confirm, discard, automatic discard, own commit arriving, retry with the same key package, joiner refresh hint (F-003) |
| `registry.rs` | feature registry: error codes, standard table, defaults, list per scope, permanent locks, admin rules, options, server flags, plan gating, `define` (F-005), security never plan-gated, bot owner, chat lock of user preferences (`LOCKED_BY_CHAT`) |
| `storage.rs` | encrypted storage: restarts, wrong keys, isolation, pending commit / past epochs / refresh hint across restarts |
| `welcome_burn.rs` | F-006 regression: a damaged welcome must not destroy the key package |
| `robustness.rs` | proptest, see below |
| `common/mod.rs` | fixtures, including `Insider`: a member built directly on the MLS library that can seal arbitrary bytes, used to reach the code behind the outer seal |

Tests marked **KNOWN LIMITATION** / **KNOWN ISSUE** pin the current behaviour of
an open finding. When the finding is fixed, the test must be changed to assert
the fixed behaviour. (None are open in the core after HANDOFF 3.1.)

Tests that need a commit to be merged at once use the confirm-immediately
helpers in `tests/common/mod.rs` (`add_now`, `remove_now`, `refresh_now`). They
stand in for the server's acceptance and exist only in tests; real clients
call `confirm_commit` after the server accepted.

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
| `feature_registry_random_sequences` | up to 60 random apply / release / server-flag / chat-lock calls by four caller types, checked against an independent model of the rules, plus invariants: AlwaysOn never released, AlwaysOff never applied, idempotency, a failed call changes nothing, a call changes no other key, non-admins never change Chat/Server/Bot features or lock anything for a chat |

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

None at PR #3. Every viable mutant changed behaviour that a test could observe.

### HANDOFF 3.1 (core fixes)

Pass 1 on the files 3.1 changed (`group.rs`, `group_state.rs`, `features.rs`,
`client.rs`, `provider.rs`, `storage/mod.rs`, `error.rs`): 277 mutants, 211
caught, 13 missed, 53 unviable. Of the 13:

- fixed by a new test: the header epoch must equal the epoch of the matching
  envelope key (`header_epoch_must_match_envelope_key`);
- fixed by removing redundant code: a second pending-commit check in
  `begin_commit`, and the trait default `load_group_state` (now only on the
  stored provider);
- equivalent (no observable difference):
  - `check_commit`: committer-removes-itself guard set to `false`: OpenMLS
    rejects such a commit first (RFC 9420 §12.2);
  - `check_commit`: `&&` -> `||` in the add-only rule: MLS already requires
    an UpdatePath for any commit with a Remove or with no proposals, so the
    differing cases never reach the check;
  - `StoredProvider::crypto` / `rand` -> `Default::default()`: the RustCrypto
    provider is stateless;
  - schema upgrade `version < 2` -> `<= 2`: re-runs an idempotent
    `CREATE TABLE IF NOT EXISTS` and sets the same version;
  - open flags `|` -> `^`: the two flag bits are disjoint;
- accepted test gaps (documented, not reachable without fault injection):
  - `Client::join` "already active" guard -> `false`: needs a second welcome
    for a device that is already a member; an honest adder cannot create one
    (MLS forbids two leaves with one signature key);
  - `open_connection`: `NotADatabase` guard -> `true`: would report an I/O
    error while reading page 1 as a wrong key.

Pass 2 (after the fixes) on `group.rs`: only the two equivalent
`check_commit` mutants above remain.

### HANDOFF 3.2 (server commit ordering)

`cargo mutants -p tree-server --in-diff` on the lines 3.2 changed
(`commits.rs`, `messages.rs`, `wire.rs`, `config.rs`, `error.rs`): 142
mutants, 50 caught, 6 missed, 86 unviable. Of the 6:

- fixed by new tests: the limit on `removed` devices (`> max_recipients`, two
  mutants), `Config::validate` (every limit), the error message for each kind
  of body `/v1/messages` refuses (a commit and a proposal were told apart only
  by the message), and the rate cost of a small commit (`/ 100` -> `* 100`);
- equivalent for every reachable input of the tests: rate cost
  `(recipients + added) / 100` -> `(recipients * added) / 100` differs only
  above 100 devices, where both cost more than one token.

## Findings from this pass

See `SECURITY_FINDINGS.md`. At PR #3: F-005 and F-006 fixed with regression
tests; F-002, F-003, F-004, F-007 and F-008 open. HANDOFF 3.1 fixed F-002,
F-003 (client side), F-004, F-007 and F-008. Other notes from PR #3:

- The out-of-order window "32" keeps 32 generations behind the ratchet head,
  which is one past the newest message, so in practice the 31 messages before
  the newest one can still arrive late.
- `Scope::Bot` features were not permission checked. Fixed in 3.1: they need
  the bot owner (`Caller::is_admin`).
- `LockReason::Chat` and `FeatureError::LockedByChat` were never produced.
  Fixed in 3.1 (`Registry::release_for_chat`). `LockReason::Plan` is still
  never produced: a plan-gated feature is shown as released, not locked.
