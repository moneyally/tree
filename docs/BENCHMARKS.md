# Group benchmarks

What joins, removals, key updates and messages cost in groups of 2 to 2,000
leaves (2,000 = 1,000 users x 2 devices, each device its own leaf).

```sh
cargo run --release -p tree-core --example bench_groups              # everything, ~15 min
cargo run --release -p tree-core --example bench_groups -- --sizes 100,1000 --suites hybrid
```

The benchmark (`crates/tree-core/examples/bench_groups.rs`) runs directly on
OpenMLS 0.9 with the core's group configuration: ratchet tree extension on,
padding 256, ciphertext wire format, same sender ratchet window. Suites:

- **hybrid** (default): `MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`, RustCrypto provider
- **X-Wing**: `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`, libcrux provider
- **classical**: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, RustCrypto provider

## Machine and method

- Intel Xeon @ 2.80 GHz cloud VM, **2 vCPUs**, 7.7 GB RAM, Linux. Far slower
  per thread than a current server, and not comparable to phones (different
  CPUs, thermal limits, storage). Phone numbers must be measured on phones.
- The box was shared with other jobs, so all times are **process CPU time**
  (all threads), not wall-clock. The reported run had a load average of about
  1.1 to 1.3 (only this benchmark). An earlier run under load 4 to 5 gave
  times within about +-30 % of these; treat times as rough, sizes as exact.
- Median of 5 repetitions per operation. The committer is the group creator
  (leaf 0). "process" is measured on 3 receivers spread over the tree (leaf 1,
  n/2, n-1; never the committer); "apply" (merging the commit into the state,
  including writing it to the store) is the median over all ~20 members that
  hold real state. Other leaves are real key packages whose private keys are
  never used.
- **cold tree**: right after the creator built the group by adding everyone
  in batches of 100. Only the creator's path holds keys, so a commit with an
  update path encrypts to almost every leaf.
- **warm tree**: after the members covering the committer's (and the removed
  member's) copath refreshed their keys once. Every copath node then holds a
  key, which is what a group where members refresh regularly looks like; a
  commit encrypts to about log2(n) nodes. Real groups sit between the two.
- In-memory store with the same JSON encoding the core uses for SQLCipher.
  SQLCipher encryption and disk I/O are **not** included. The core's outer
  envelope (+33 bytes and one HMAC per message) is not included.

## Results: hybrid suite (default)

Key package: **2.6 KB**. Application message with 100 bytes of text:
**318 B** ciphertext, encrypt 0.06 to 0.15 ms, decrypt 0.08 to 0.2 ms at every
group size. Normal messages do not get more expensive in big groups.

Per group size:

| leaves | ratchet tree | stored state, 1 member (JSON) | welcome for 1 new device | join (process welcome) | build: creator CPU, batches of 100 |
|---:|---:|---:|---:|---:|---:|
| 2 | 4.0 KB | 29 KB | 8.1 KB | 1.5 ms | 3 ms |
| 10 | 19 KB | 87 KB | 28 KB | 3.4 ms | 7 ms |
| 100 | 145 KB | 561 KB | 191 KB | 20 ms | 0.11 s |
| 500 | 695 KB | 2.55 MB | 778 KB | 87 ms | 1.4 s |
| 1000 | 1.35 MB | 5.05 MB | 1.45 MB | 177 ms | 5.9 s |
| 2000 | 2.68 MB | 10.0 MB | 2.81 MB | 416 ms | 21 s |

Commit size, warm tree (cold tree in brackets):

| leaves | update (key refresh) | remove 1 | add 1 (with path) | add 1, no path |
|---:|---:|---:|---:|---:|
| 2 | 4.1 KB | 6.3 KB ¹ | 7.8 KB | 3.1 KB |
| 10 | 11 KB (17 KB) | 16 KB (18 KB) | 14 KB (20 KB) | 3.1 KB |
| 100 | 18 KB (125 KB) | 26 KB (126 KB) | 21 KB (128 KB) | 3.1 KB |
| 500 | 23 KB (591 KB) | 33 KB (593 KB) | 26 KB (594 KB) | 3.1 KB |
| 1000 | 25 KB (1.15 MB) | 37 KB (1.15 MB) | 28 KB (1.15 MB) | 3.1 KB |
| 2000 | 28 KB (2.28 MB) | 40 KB (2.28 MB) | 30 KB (2.28 MB) | 3.1 KB |

¹ at 2 leaves the removed device is one added earlier in the run (4 leaves at that point).

CPU time per commit, warm tree (ms). "create" is the committer, "process" and
"apply" are each other member:

| leaves | update create | update process | apply | remove create | remove process | add create | add process |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 1.4 | 1.0 | 0.3 | 2.4 | 1.4 | 2.6 | 1.6 |
| 10 | 4.1 | 2.1 | 0.7 | 6.0 | 1.9 | 5.0 | 2.1 |
| 100 | 12 | 4.2 | 3.2 | 15 | 4.5 | 17 | 4.6 |
| 500 | 48 | 18 | 18 | 43 | 13 | 58 | 18 |
| 1000 | 100 | 35 | 25 | 83 | 27 | 99 | 51 |
| 2000 | 174 | 72 | 51 | 174 | 54 | 249 | 60 |

Cold tree at 2000 leaves: update create 657 ms, process 78 ms, apply 47 ms;
add without path: create 209 ms, process 33 ms. "apply" is about the same for
every kind of commit at a given size.

## Suite comparison at 2000 leaves

| | hybrid (RustCrypto) | X-Wing (libcrux) | classical |
|---|---:|---:|---:|
| key package | 2.6 KB | 2.6 KB | 0.3 KB |
| ratchet tree / welcome | 2.68 / 2.81 MB | 2.68 / 2.81 MB | 421 / 429 KB |
| stored state, 1 member (JSON) | 10.0 MB | 10.0 MB | 2.0 MB |
| update commit, warm (cold) | 28 KB (2.28 MB) | 27 KB (2.25 MB) | 1.8 KB (161 KB) |
| remove commit, warm | 40 KB | 40 KB | 2.6 KB |
| update create, warm (cold) | 174 ms (657 ms) | 184 ms (687 ms) | 75 ms (350 ms) |
| receiver process + apply, warm update | 123 ms | 132 ms | 37 ms |
| join | 416 ms | 505 ms | 195 ms |
| build, creator CPU | 21 s | 30 s | 7 s |

At 1000 leaves the ratios are the same (hybrid update 25 KB vs classical
1.6 KB; receiver 60 ms vs 15 ms). X-Wing and the default hybrid have the same
sizes (both ML-KEM-768 + X25519) and similar per-commit CPU cost (within the
noise either way); building the group was slower on libcrux (30 s vs 21 s).

## Fan-out: one commit delivered to every other device

Commit size x (leaves - 1), i.e. server egress for one commit:

| leaves | hybrid update, warm | hybrid remove, warm | hybrid update, cold | classical remove, warm | classical update, cold |
|---:|---:|---:|---:|---:|---:|
| 100 | 1.75 MB | 2.54 MB | 12.1 MB | 179 KB | 872 KB |
| 500 | 11.1 MB | 16.2 MB | 288 MB | 1.13 MB | 19.9 MB |
| 1000 | 24.7 MB | 35.9 MB | 1.14 GB | 2.50 MB | 78.8 MB |
| 2000 | 53.8 MB | 78.7 MB | 4.56 GB | 5.00 MB | 314 MB |

One **refresh round** (every device commits one key update) in a warm
2000-leaf hybrid group: about 2,000 commits, so each device downloads about
54 MB and spends about 4 minutes of CPU (on this box) processing them, and the
server sends about 108 GB. At 1000 leaves: 25 MB, about 1 minute, 25 GB.
Classical at 2000 leaves: 3.5 MB, about 75 s, 7 GB.

## What dominates at 1,000 to 2,000 leaves

1. **Bandwidth is set by the tree's state, not by the operation.** In a warm
   tree a commit carries ~log2(n) = 11 path nodes, each a 1.2 KB hybrid public
   key plus a 1.1 KB KEM ciphertext, so 25 to 40 KB. In a cold tree it carries
   one ~1.14 KB ciphertext per leaf (2.3 MB at 2000, 4.6 GB fanned out). The
   post-quantum KEM sizes make every per-node cost ~15x the classical one.
2. **CPU is dominated by work linear in the group size, not by crypto.** Every
   member pays ~100 to 130 ms per commit at 2000 leaves whatever the commit
   is: an add without a path (no encryption at all) still costs receivers
   33 ms to process and ~50 ms to apply. Encoding the ratchet tree as JSON
   alone takes 40 ms at 2000 leaves, close to the whole "apply" time; the rest
   is tree hashing and validation. The classical suite is ~3x cheaper per
   commit only because its tree is ~6x smaller.
3. **Joins are tree-sized.** The welcome carries the whole ratchet tree
   (2.8 MB at 2000 leaves) and takes ~0.4 s to process.
4. **Stored state is tree-sized and rewritten every epoch**: 10 MB of JSON per
   2000-leaf group per device (3.7x the binary size of the tree), rewritten on
   every commit. With SQLCipher this becomes a 10 MB encrypted write per
   commit (not measured here).
5. **A cold tree is a transient, but an expensive one.** A model of the tree
   (not a measurement; RFC 9420 resolution rules, members doing their first
   update in random order after a batched build) gives, at 2000 leaves: the
   first update encrypts to ~980 leaves, after 10 % of members updated ~22,
   after 25 % ~11; only ~5 commits encrypt to more than n/4 leaves. So one
   refresh round warms the tree for roughly the cost of a normal round plus a
   few ~1 MB commits.

## Recommendations

1. **1,000-member private groups with 2 devices each (2,000 leaves) are
   practical for messaging and for occasional membership changes, with the
   hybrid suite,** provided the points below are handled. Messages cost the
   same as in a 1:1 chat. A membership change costs every device ~30 to 40 KB
   and ~0.1 s CPU here (more on a slow phone); 20 changes a day is under 1 MB
   and a few seconds per device. What does not scale is every device
   committing often.
2. **Budget commits per group, not per device.** Every commit costs every
   other device a download and a full-tree apply. A fixed "refresh daily" rule
   means 2,000 commits a day in a 2000-leaf group: ~54 MB and ~4 min CPU per
   device per day here, ~108 GB/day of server egress for that one group.
   Make the refresh interval grow with group size, e.g. aim for a group total
   of ~50 to 100 refresh commits a day (2000 leaves: each device every 20 to
   40 days; 100 leaves: about daily), plus an immediate refresh after a
   suspected compromise. Any commit a device makes (add, remove) refreshes its
   own path, so it resets that device's timer. Trade-off: a longer interval is
   a longer window before post-compromise security recovers.
3. **Batch membership changes.** The linear per-commit cost is paid once per
   commit, not per member. Adding or removing a user should add or remove all
   of their devices in one commit; queue admin changes for a few seconds and
   commit them together.
4. **Use add-only commits without an update path** (RFC 9420 allows it) for
   adds: 3.1 KB instead of 30 KB warm or 2.3 MB cold at 2000 leaves, and 3.5x
   less committer CPU in a cold tree. Building a group from batches of 100
   then sends ~100 key packages (~260 KB, estimate) per batch instead of up to
   2.4 MB. The committer's own key is then refreshed by its next update.
   (Done: the core's `Group::add` sends no path since HANDOFF 3.1.)
5. **Warm new and freshly built groups.** A newly joined device should send
   one update commit soon after joining, flagged by the core as
   `Group::should_refresh_keys` (this also replaces the key from its
   one-time key package, which sat on the server). In a freshly built large
   group stagger these first updates; the first few are ~1 MB each.
6. **Server limits must match.** The server defaults (`MAX_MESSAGE_BYTES`
   256 KiB, `MAX_RECIPIENTS` 1000) are below what large hybrid groups need:
   a hybrid welcome exceeds 256 KiB from about 140 to 180 leaves, a cold hybrid
   commit from about 220 leaves, and a classical welcome from about 1,200
   leaves; a 2000-leaf group needs two sends per commit. Either raise the
   limits for welcomes (about 3 MB at 2000 leaves) or deliver the ratchet tree
   outside the welcome (a separate, chunked download), and keep commits small
   by keeping trees warm. (Done for commits: `/v1/commits` takes commits and
   welcomes up to 4 MiB and 2048 devices; HANDOFF 3.2.)
7. **Store state in a binary encoding**, not JSON: 3.7x less to encrypt and
   write per commit, and most of the 50 ms "apply" at 2000 leaves is JSON
   encoding. This is a storage-format change, so it needs a migration.
   (Not done yet: the OpenMLS storage crate is tested with JSON, and the
   values it stores have no stable binary format of their own; switching
   needs a codec that round-trips every stored type plus a migration of
   existing databases, which is not contained enough for HANDOFF 3.1.
   Tree's own new table `tree_group_state` is binary already.)
8. **Keep the hybrid suite as the default.** The 1,000 x 2 target is reachable
   with it once commits are budgeted and batched. The classical suite would
   cut bandwidth ~15x and receiver CPU ~3x, but gives up post-quantum
   protection of group keys; the numbers here do not justify that for the
   target size. Reconsider only for groups well beyond 2,000 leaves, and only
   after measuring on phones. X-Wing showed no performance gain over the
   current default.

## Limits of these measurements

- One 2-vCPU VM, shared; CPU time, not wall-clock. OpenMLS encrypts update
  paths on a thread pool, so wall time on an idle multi-core device can be
  lower than the CPU time shown; on phones everything is likely slower per
  core. Nothing was measured on a phone.
- Warm and cold are two constructed tree states; real trees depend on the
  history of updates, adds and removals (each removal blanks a path until
  those members update again). The warm-up numbers are a model, not a run.
- Only the creator commits; only 3 receivers' processing is timed per
  operation; 5 repetitions. Sub-millisecond numbers are noisy.
- Not measured: SQLCipher encryption and disk writes, the core's outer
  envelope, the server, network transfer, concurrent commits racing for the
  same epoch, external joins, devices that are members of many large groups.
