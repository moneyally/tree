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

### Media (PROTOCOL.md 6.12)

| Test | What it proves |
| --- | --- |
| `tree-core` `attachment::tests::padding_buckets` | the bucket table (1 KiB, powers of two to 1 MiB, Padmé), never smaller than the file, overhead under 4 % above 1 MiB, a bucket pads to itself, few distinct sizes |
| `attachment::tests::round_trip_sizes_and_streaming` | round trip at chunk boundaries (0, 1, 1 KiB +- 1, 1 MiB +- 1, 2 MiB + 17), streaming reader in small pieces, size must match the input |
| `attachment::tests::truncation_reorder_and_bit_flips_detected` | truncation, extension, dropped, swapped and repeated chunks, a cut on a chunk boundary (last-chunk flag), changed commitment and bit flips are all refused |
| `attachment::tests::key_commitment` | another secret fails at the commitment; other content or size claims and non-zero padding are refused |
| `attachment::tests::fresh_secret_and_separate_keys` | one secret per file; the three HKDF outputs differ from each other and from the secret; the key is never printed |
| `tree-server` `tests/attachments.rs` | uploads in order, by the uploader only, a lost answer, resume status, ranged download, no uploader stored; size limit and daily quota per account (shared by its devices, reset per day); unfinished uploads purged after 24 h with partial files (also of deleted devices); cost per MiB |
| `tree-client` `tests/media.rs` | multi-chunk file from disk with metadata and preview, padded size on the server, no plaintext or name there, download into a file, tampering refused; view-once and voice with chunked media; upload resumed after the app stops (slice limit) and after the network goes away (proxy cuts after N parts), nothing sent twice, restart after the server dropped the upload; offline queue in order; refused upload (quota) failed, retried, cancelled; pause / resume / cancel; auto-download rules (contact vs stranger, size, network, view-once, option, release) |
| desktop `MediaEditTest` | crop, rotate, stroke, blur (detail gone, outside unchanged), text, order of operations, thumbnail size, a JPEG with GPS EXIF exported without it, safe file names |
| desktop `MediaModelTest` | an edited picture with its preview, auto-download on Wi-Fi only, upload progress in slices, save as, through the model against a real server |

### Groups and communities (Wave 3, APP_PROTOCOL.md 9)

Every chat key is toggled both ways through a real server, and for every
permission a member whose own checks are bypassed (`send_unchecked`, or a
raw MLS commit from the `Insider` fixture) is refused by the honest devices.

| Test | What it proves |
| --- | --- |
| `tree-core` `group_settings::tests::roles_restrictions_community` | role, assignment, restriction and community limits; permissions through roles only while `chat.roles` is applied; `chat.member_adds`; entries of departed members dropped on read; older encodings unchanged |
| `tree-core` `membership.rs` `member_adds_follow_settings_and_roles` | with `chat.member_adds` released an honest member's add is refused and a raw MLS add commit by a member without `add` is rejected by every device; a role with `add` allows it; `GroupChanged.by` is the committer |
| `membership.rs` `successor_is_the_same_everywhere` | every member computes the same successor; restricted members are skipped |
| `tree-client` `groups.rs` `topics_hold_threads_with_unread_counts_and_follow_chat_topics` | `chat.topics` both ways, option `admins` / `all`, forged topic dropped, per-topic history and unread, closed topic (sender refuses, forged message dropped), role with `topics`, topic list for new members, released: topic ignored |
| `groups.rs` `roles_grant_permissions_that_every_receiver_enforces` | `pin` and `delete` through a role, forged pin and delete dropped, `chat.roles` both ways, `chat.member_adds` both ways with an `add` role, role deletion |
| `groups.rs` `admin_log_records_what_admins_did_with_the_authenticated_actor` | settings, adds and pins logged with the authenticated actor, own commits too, dropped actions not logged, admins only, `chat.admin_log` both ways |
| `groups.rs` `welcome_text_is_shown_to_new_members_only` | `chat.welcome` both ways, option limit, only the joiner sees it |
| `groups.rs` `history_is_shared_with_new_members_by_their_adder_only` | `chat.history_share` both ways and its option range, N newest with "shared by" and the claimed authors, a second bundle and one from another member dropped, released: none sent and a forged one dropped |
| `groups.rs` `the_last_admin_names_the_next_one_before_leaving` | `chat.owner_succession` both ways |
| `groups.rs` `join_approval_holds_link_joins_for_an_admin` | `chat.join_approval` both ways, approve (joiner accepts) and decline, admins only |
| `groups.rs` `slow_mode_spaces_messages_of_members_on_both_sides` | `chat.slow_mode` both ways, sender refusal, admins exempt, forged fast message hidden by receivers, admins told |
| `groups.rs` `restricted_members_read_but_cannot_send` | `chat.restrict` both ways, sender refusal, forged message dropped, still reads, lifted and expired restrictions |
| `groups.rs` `communities_list_chats_and_members_join_them` | community list, join through the admin device, a request naming another account refused, unlisted chat refused, chat removed from the list |
| `tree-client` `groups::tests::slow_mode_rule` | an honest sender at exactly the interval always passes for every option and start second |
| desktop `AppModelTest.groupsThroughTheModel` | topics, role tags, moderator delete, notices, admin log, join approval with welcome and shared history, restriction, slow mode, a community join, through the model |

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

### Stage-1 stack, part 1 (`claude/cli` … `claude/reports`)

`cargo mutants --in-diff` over everything the stack changed in `tree-core`,
`tree-server` and `tree-client` up to the reports branch: 758 mutants, 544
caught, 163 unviable, 51 missed (runs on 2026-10-01; a disk-full moment
spoiled 8 results, which were run again). The 51 were re-run on the code
after the new tests: 53 of 64 matching mutants caught, and the rest are
handled below.

- fixed by new tests (most): group-context commits holding anything but
  Tree's settings (`group_context_holds_only_tree_settings`, an insider
  admin with raw MLS; verified to fail when the check is disabled),
  `wire::peek` in the core (`peek_classifies_real_messages`), MemberId hex
  parsing, settings size and name limits, attachment constants and redacted
  `Debug`, proof-of-work bit counting, per-group storage keys, safety-number
  format, verification code per group, group ids, settings surviving a
  restart, exact report limits, random 32-byte franking keys, lookup and
  upload rate costs, `Config::from_env`, `forget_messages` and purge counts;
- equivalent:
  - `safety::digits` `|` -> `^`: the low byte is zero after the shift;
  - `wire::peek` `> 33` -> `>= 33`: 33 bytes leave no MLS bytes, which fail
    to parse either way;
  - `Session::own_changeable` `>` -> `>=`: differs only in the exact second
    the edit window ends;
  - `Session::change` `==` -> `!=` in "keep user-scope settings": the
    device's own caller cannot apply any other scope (refused earlier), so
    the branch is never reached with another scope;
  - `purge_expired`: `+` -> `-`/`*` at the orphan-blob term, which is 0
    whenever messages are deleted with their last delivery (always now).

### Stage-1 stack, part 2 (`claude/push` … `claude/organize`, core and server)

`cargo mutants --in-diff` over what the later branches changed in
`tree-core` and `tree-server`: 493 mutants, 166 caught, 299 unviable, 28
missed (2026-10-02). All 28 are handled:

- fixed by new tests: `Words::language` (Korean phrases), invite lifetime
  and use limits at the edge and the week-long keep after expiry, the cost
  of commits reaching 100+ devices, the exact commit fan-out limit, ack of
  up to 100 invite requests, push endpoint edge cases (exact length limit,
  user name or password only, a bare IPv6 host, ports 0 and 1), push
  gateways answering 404/410 versus 500, the 7-day change delay, the
  recovery time window edge, and a wrong `current_signature` on release
  (403, nothing released, the key still recovers);
- unique-violation branches (unreachable in normal use: every write follows
  a check in the same `BEGIN IMMEDIATE` transaction): tests inject a
  concurrent insert (must give 409) or a database failure (must give 500,
  not 409) with database triggers;
- real bug found: `POST /v1/recovery/apply` checked "this key is active or
  pending on another account" only for delayed changes. A key set
  immediately could collide with another account's pending change, which
  then failed on the unique index forever and blocked that account's
  recovery. Fixed (the check runs on every path) with
  `a_key_pending_elsewhere_cannot_be_applied`;
- equivalent:
  - `push::check_endpoint` line 50 `||` -> `&&`, and `default_port`
    returning `None` or losing its arms: for http/https the URL parser
    leaves the port empty exactly when it is the default, so both sides of
    that comparison are always equal;
  - `push::send` "2xx" guard -> false: falls into the catch-all arm, which
    only logs;
  - `DeviceCtx::charge_outreach` `>` -> `>=`: a cost of exactly 0 charges
    nothing either way;
  - `purge_expired` orphan term: as in part 1.

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
