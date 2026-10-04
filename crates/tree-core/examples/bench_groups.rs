//! Group load benchmark: what joins, removals, key updates and messages cost
//! in large groups, measured directly on the OpenMLS APIs with the same group
//! configuration the core uses (ratchet tree extension on, padding 256,
//! ciphertext wire format).
//!
//! Run (release build, takes several minutes for all sizes):
//!   cargo run --release -p tree-core --example bench_groups
//! Options:
//!   --sizes 2,10,100        group sizes (leaves) to measure
//!   --suites hybrid,classical,xwing
//!   --reps 5                repetitions per timed operation
//!   --batch 100             members added per commit while building
//!
//! Every group size is measured twice:
//! * cold: right after the group was built by batched adds. Only the
//!   creator's path in the ratchet tree holds keys, so every commit with a
//!   path has to encrypt to (almost) every leaf.
//! * warm: after the members on the committer's and the removed member's
//!   copath have refreshed their keys. Every copath node then holds a key, as
//!   in a group where all members refresh their keys regularly, so a commit
//!   encrypts to about log2(n) nodes.
//!
//! Only a few members hold real state (the committer, three measured
//! receivers spread over the tree, and the members that warm the tree); all
//! other leaves are real key packages whose private keys are never used.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use openmls::prelude::{tls_codec::Deserialize, tls_codec::Serialize as _, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::MemoryStorage;
use openmls_traits::OpenMlsProvider;

/// Same values as the core (`Group::PADDING`, `Group::sender_ratchet`).
const PADDING: usize = 256;
const MESSAGE: &[u8] = &[b'x'; 100];

fn sender_ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(32, 1000)
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING)
        .sender_ratchet_configuration(sender_ratchet())
        .build()
}

trait Provider: OpenMlsProvider<StorageProvider = MemoryStorage> + Default {}
impl<P: OpenMlsProvider<StorageProvider = MemoryStorage> + Default> Provider for P {}

/// A member that holds real group state.
struct Live<P: Provider> {
    leaf: u32,
    provider: P,
    signer: SignatureKeyPair,
    cred: CredentialWithKey,
    group: Option<MlsGroup>,
}

impl<P: Provider> Live<P> {
    fn new(cs: Ciphersuite, leaf: u32) -> Self {
        let provider = P::default();
        let (signer, cred) = identity(cs, leaf);
        Self {
            leaf,
            provider,
            signer,
            cred,
            group: None,
        }
    }

    fn g(&mut self) -> &mut MlsGroup {
        self.group.as_mut().expect("joined")
    }

    fn key_package(&self, cs: Ciphersuite) -> KeyPackage {
        KeyPackage::builder()
            .build(cs, &self.provider, &self.signer, self.cred.clone())
            .expect("key package")
            .key_package()
            .clone()
    }

    fn storage_bytes(&self) -> usize {
        let values = self.provider.storage().values.read().expect("lock");
        values.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
}

fn identity(cs: Ciphersuite, leaf: u32) -> (SignatureKeyPair, CredentialWithKey) {
    let signer = SignatureKeyPair::new(cs.signature_algorithm()).expect("signer");
    // Realistic length for "<user id>/<device id>".
    let name = format!("user-{leaf:010}/device-1");
    let cred = CredentialWithKey {
        credential: BasicCredential::new(name.into_bytes()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    (signer, cred)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// CPU time used by this process (all threads), in milliseconds.
///
/// Timings use CPU time rather than wall-clock time: the benchmark box is
/// shared, and other jobs inflate wall-clock time but not our CPU time.
/// OpenMLS encrypts update paths on a thread pool, so wall time on an idle
/// multi-core machine can be lower than this.
fn cpu_ms() -> f64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    extern "C" {
        fn clock_gettime(clock: i32, tp: *mut Timespec) -> i32;
    }
    const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a correctly laid out timespec (64-bit Linux).
    let rc = unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime");
    ts.tv_sec as f64 * 1000.0 + ts.tv_nsec as f64 / 1e6
}

struct Timer(f64);

impl Timer {
    fn start() -> Self {
        Self(cpu_ms())
    }
    fn ms(&self) -> f64 {
        cpu_ms() - self.0
    }
}

fn median(v: &mut [f64]) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn protocol(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("decode")
        .try_into_protocol_message()
        .expect("protocol message")
}

/// Cost of one commit, as seen by the committer and by the other members.
#[derive(Default, Clone)]
struct CommitCost {
    commit_bytes: usize,
    welcome_bytes: usize,
    create_ms: f64,
    commit_merge_ms: f64,
    /// Decrypt + verify + stage, on the measured receivers.
    process_ms: f64,
    /// Apply the staged commit (includes writing the new state to storage).
    merge_ms: f64,
    join_ms: f64,
}

#[derive(Default, Clone)]
struct PhaseResult {
    update: CommitCost,
    add: CommitCost,
    add_no_path: CommitCost,
    remove: CommitCost,
    msg_bytes: usize,
    enc_us: f64,
    dec_us: f64,
}

struct SizeResult {
    leaves: usize,
    build_ms: f64,
    build_cpu_ms: f64,
    build_commit_max: usize,
    build_welcome_max: usize,
    kp_bytes: usize,
    tree_bytes: usize,
    json_tree_bytes: usize,
    json_tree_ms: f64,
    storage_bytes: usize,
    warmers: usize,
    cold: PhaseResult,
    warm: Option<PhaseResult>,
}

struct Bench<P: Provider> {
    cs: Ciphersuite,
    reps: usize,
    /// lives[0] is the committer (group creator, leaf 0).
    lives: Vec<Live<P>>,
    receivers: Vec<usize>,
}

/// What a measured commit does; the closure gets the committer and the
/// repetition index and returns (commit, welcome, joiner provider).
type MakeCommit<'a, P> =
    dyn FnMut(&mut Live<P>, usize) -> (MlsMessageOut, Option<MlsMessageOut>, Option<P>) + 'a;

impl<P: Provider> Bench<P> {
    /// Delivers a commit to every live member except `skip`, merging it.
    /// Returns the merge times.
    fn deliver(&mut self, skip: usize, commit: &[u8]) -> Vec<f64> {
        let mut merges = Vec::new();
        for (i, live) in self.lives.iter_mut().enumerate() {
            if i == skip {
                continue;
            }
            let provider = &live.provider;
            let g = live.group.as_mut().expect("joined");
            let processed = g
                .process_message(provider, protocol(commit))
                .expect("process");
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    let t = Timer::start();
                    g.merge_staged_commit(provider, *staged).expect("merge");
                    merges.push(t.ms());
                }
                _ => panic!("expected a commit"),
            }
        }
        merges
    }

    /// Times `reps` versions of a commit made by lives[0]. All but the last are
    /// discarded by the committer; the measured receivers process every
    /// version (each is a distinct message), and everyone merges the last.
    fn measure(&mut self, make: &mut MakeCommit<'_, P>) -> CommitCost {
        let mut create = Vec::new();
        let mut joins = Vec::new();
        let mut commits = Vec::new();
        let mut welcome_bytes = 0;
        for r in 0..self.reps {
            let c = &mut self.lives[0];
            let t = Timer::start();
            let (commit, welcome, joiner) = make(c, r);
            let commit = commit.to_bytes().expect("encode");
            create.push(t.ms());
            commits.push(commit);
            if let (Some(w), Some(joiner)) = (welcome, joiner) {
                let w = w.to_bytes().expect("encode");
                welcome_bytes = w.len();
                let t = Timer::start();
                let welcome = match MlsMessageIn::tls_deserialize_exact(&w)
                    .expect("decode")
                    .extract()
                {
                    MlsMessageBodyIn::Welcome(w) => w,
                    _ => panic!("not a welcome"),
                };
                let staged =
                    StagedWelcome::new_from_welcome(&joiner, &join_config(), welcome, None)
                        .expect("welcome");
                let _group = staged.into_group(&joiner).expect("join");
                joins.push(t.ms());
            }
            if r + 1 < self.reps {
                let p = &c.provider;
                c.group
                    .as_mut()
                    .expect("joined")
                    .clear_pending_commit(p.storage())
                    .expect("clear");
            }
        }

        // Measured receivers process every version without applying it.
        let mut process = Vec::new();
        for &ri in &self.receivers.clone() {
            let live = &mut self.lives[ri];
            let provider = &live.provider;
            let g = live.group.as_mut().expect("joined");
            for commit in &commits[..commits.len() - 1] {
                let t = Timer::start();
                let p = g
                    .process_message(provider, protocol(commit))
                    .expect("process");
                process.push(t.ms());
                drop(p);
            }
        }
        // Everyone applies the last version; receivers' processing is timed.
        let last = commits.last().expect("one commit").clone();
        let mut merges = Vec::new();
        let receivers = self.receivers.clone();
        for (i, live) in self.lives.iter_mut().enumerate().skip(1) {
            let provider = &live.provider;
            let g = live.group.as_mut().expect("joined");
            let t = Timer::start();
            let processed = g
                .process_message(provider, protocol(&last))
                .expect("process");
            if receivers.contains(&i) {
                process.push(t.ms());
            }
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    let t = Timer::start();
                    g.merge_staged_commit(provider, *staged).expect("merge");
                    merges.push(t.ms());
                }
                _ => panic!("expected a commit"),
            }
        }
        let c = &mut self.lives[0];
        let t = Timer::start();
        let p = &c.provider;
        c.group
            .as_mut()
            .expect("joined")
            .merge_pending_commit(p)
            .expect("merge own");
        let commit_merge_ms = t.ms();

        CommitCost {
            commit_bytes: last.len(),
            welcome_bytes,
            create_ms: median(&mut create),
            commit_merge_ms,
            process_ms: median(&mut process),
            merge_ms: median(&mut merges),
            join_ms: median(&mut joins),
        }
    }

    fn messages(&mut self, count: usize) -> (usize, f64, f64) {
        let mut enc = Vec::new();
        let mut msgs = Vec::new();
        for _ in 0..count {
            let c = &mut self.lives[0];
            let t = Timer::start();
            let p = &c.provider;
            let m = c
                .group
                .as_mut()
                .expect("joined")
                .create_message(p, &c.signer, MESSAGE)
                .expect("encrypt");
            let m = m.to_bytes().expect("encode");
            enc.push(t.ms() * 1000.0);
            msgs.push(m);
        }
        let mut dec = Vec::new();
        for &ri in &self.receivers.clone() {
            let live = &mut self.lives[ri];
            let provider = &live.provider;
            let g = live.group.as_mut().expect("joined");
            for m in &msgs {
                let t = Timer::start();
                let p = g.process_message(provider, protocol(m)).expect("decrypt");
                assert!(matches!(
                    p.into_content(),
                    ProcessedMessageContent::ApplicationMessage(_)
                ));
                dec.push(t.ms() * 1000.0);
            }
        }
        (msgs[0].len(), median(&mut enc), median(&mut dec))
    }

    /// Fresh devices to add, prepared outside the timed region.
    fn joiners(&self, first_id: u32) -> Vec<Option<(P, KeyPackage)>> {
        (0..self.reps)
            .map(|r| {
                let j = Live::<P>::new(self.cs, first_id + r as u32);
                let kp = j.key_package(self.cs);
                Some((j.provider, kp))
            })
            .collect()
    }

    fn phase(&mut self, remove_leaf: u32) -> PhaseResult {
        let (msg_bytes, enc_us, dec_us) = self.messages(self.reps * 4);

        let update = self.measure(&mut |c: &mut Live<P>, _r| {
            let p = &c.provider;
            let b = c
                .group
                .as_mut()
                .expect("joined")
                .self_update(p, &c.signer, LeafNodeParameters::default())
                .expect("update");
            (b.into_commit(), None, None)
        });

        let mut joiners = self.joiners(1_000_000);
        let add = self.measure(&mut |c: &mut Live<P>, r| {
            let (joiner, kp) = joiners[r].take().expect("joiner");
            let p = &c.provider;
            let (commit, welcome, _) = c
                .group
                .as_mut()
                .expect("joined")
                .add_members(p, &c.signer, &[kp])
                .expect("add");
            (commit, Some(welcome), Some(joiner))
        });

        // RFC 9420 allows an add-only commit without an update path: no
        // encryption to the tree, but also no key refresh for the committer.
        let mut joiners = self.joiners(2_000_000);
        let add_no_path = self.measure(&mut |c: &mut Live<P>, r| {
            let (joiner, kp) = joiners[r].take().expect("joiner");
            let p = &c.provider;
            let (commit, welcome, _) = c
                .group
                .as_mut()
                .expect("joined")
                .add_members_without_update(p, &c.signer, &[kp])
                .expect("add");
            (commit, Some(welcome), Some(joiner))
        });

        let remove = self.measure(&mut |c: &mut Live<P>, _r| {
            let p = &c.provider;
            let (commit, _, _) = c
                .group
                .as_mut()
                .expect("joined")
                .remove_members(p, &c.signer, &[LeafNodeIndex::new(remove_leaf)])
                .expect("remove");
            (commit, None, None)
        });

        PhaseResult {
            update,
            add,
            add_no_path,
            remove,
            msg_bytes,
            enc_us,
            dec_us,
        }
    }
}

/// One leaf in each subtree on `leaf`'s copath (levels >= 1; a sibling leaf
/// needs nothing), avoiding `avoid`. Subtrees containing leaf 0 are skipped:
/// the committer refreshes its own path.
fn copath_warmers(leaf: u32, n: u32, avoid: &BTreeSet<u32>) -> Vec<u32> {
    let mut out = Vec::new();
    let mut m = 1;
    while (1u32 << m) < 2 * n {
        let start = ((leaf >> m) ^ 1) << m;
        let end = (start + (1 << m)).min(n);
        if start < n && start != 0 {
            if let Some(w) = (start..end).find(|x| !avoid.contains(x)) {
                out.push(w);
            }
        }
        m += 1;
    }
    out
}

fn run_size<P: Provider>(cs: Ciphersuite, n: usize, reps: usize, batch: usize) -> SizeResult {
    assert!(n >= 2);
    let n32 = n as u32;
    let receiver_leaves: Vec<u32> = [1, n32 / 2, n32 - 1]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let warm_phase = n >= 10;
    let (l_cold, l_warm) = if warm_phase {
        (n32 / 4 + 1, 3 * n32 / 4 + 1)
    } else {
        (n32, n32)
    };
    let removed: BTreeSet<u32> = [l_cold, l_warm].into_iter().collect();
    let mut warmers: BTreeSet<u32> = BTreeSet::new();
    if warm_phase {
        warmers.extend(copath_warmers(0, n32, &removed));
        warmers.extend(copath_warmers(l_warm, n32, &removed));
    }
    let mut live_leaves: BTreeSet<u32> = receiver_leaves.iter().copied().collect();
    live_leaves.extend(warmers.iter().copied());
    live_leaves.insert(0);
    let live_leaves: Vec<u32> = live_leaves.into_iter().collect();

    let mut lives: Vec<Live<P>> = live_leaves.iter().map(|&l| Live::new(cs, l)).collect();
    let receivers: Vec<usize> = receiver_leaves
        .iter()
        .map(|r| live_leaves.iter().position(|l| l == r).expect("live"))
        .collect();

    // Key packages for leaves 1..n (real ones; dummy members share a store).
    let dummy = P::default();
    let mut kps = Vec::with_capacity(n);
    let mut kp_bytes = 0;
    for leaf in 1..n32 {
        let kp = if let Some(i) = live_leaves.iter().position(|&l| l == leaf) {
            lives[i].key_package(cs)
        } else {
            let (signer, cred) = identity(cs, leaf);
            KeyPackage::builder()
                .build(cs, &dummy, &signer, cred)
                .expect("kp")
                .key_package()
                .clone()
        };
        kp_bytes = kp.tls_serialize_detached().expect("encode").len();
        kps.push(kp);
    }

    // Build: the creator adds everyone in batches.
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(cs)
        .use_ratchet_tree_extension(true)
        .padding_size(PADDING)
        .sender_ratchet_configuration(sender_ratchet())
        .build();
    {
        let c = &mut lives[0];
        c.group =
            Some(MlsGroup::new(&c.provider, &c.signer, &config, c.cred.clone()).expect("create"));
    }
    let mut bench = Bench {
        cs,
        reps,
        lives,
        receivers,
    };
    let mut build = Duration::ZERO;
    let mut build_cpu = 0.0;
    let (mut build_commit_max, mut build_welcome_max) = (0, 0);
    let mut next = 1u32;
    for chunk in kps.chunks(batch) {
        let c = &mut bench.lives[0];
        let wall = Instant::now();
        let t = Timer::start();
        let p = &c.provider;
        let g = c.group.as_mut().expect("joined");
        let (commit, welcome, _) = g.add_members(p, &c.signer, chunk).expect("add batch");
        let commit = commit.to_bytes().expect("encode");
        let welcome = welcome.to_bytes().expect("encode");
        g.merge_pending_commit(p).expect("merge");
        build_cpu += t.ms();
        build += wall.elapsed();
        build_commit_max = build_commit_max.max(commit.len());
        build_welcome_max = build_welcome_max.max(welcome.len());

        let range = next..next + chunk.len() as u32;
        next = range.end;
        // Existing live members apply the commit; new ones join.
        for live in bench.lives.iter_mut().skip(1) {
            if live.leaf < range.start {
                let provider = &live.provider;
                let g = live.group.as_mut().expect("joined");
                let processed = g
                    .process_message(provider, protocol(&commit))
                    .expect("process");
                if let ProcessedMessageContent::StagedCommitMessage(s) = processed.into_content() {
                    g.merge_staged_commit(provider, *s).expect("merge");
                }
            } else if range.contains(&live.leaf) {
                let w = match MlsMessageIn::tls_deserialize_exact(&welcome)
                    .expect("decode")
                    .extract()
                {
                    MlsMessageBodyIn::Welcome(w) => w,
                    _ => panic!("not a welcome"),
                };
                let staged =
                    StagedWelcome::new_from_welcome(&live.provider, &join_config(), w, None)
                        .expect("welcome");
                let g = staged.into_group(&live.provider).expect("join");
                assert_eq!(g.own_leaf_index().u32(), live.leaf, "leaf position");
                live.group = Some(g);
            }
        }
    }
    drop(dummy);
    drop(kps);
    assert_eq!(bench.lives[0].g().members().count(), n);

    let tree = bench.lives[0].g().export_ratchet_tree();
    let tree_bytes = tree.tls_serialize_detached().expect("encode").len();
    // The core stores state as JSON; time encoding the tree once that way.
    let t = Timer::start();
    let json_tree_bytes = serde_json::to_vec(&tree).expect("json").len();
    let json_tree_ms = t.ms();
    drop(tree);
    let storage_bytes = bench.lives[bench.receivers[bench.receivers.len() / 2]].storage_bytes();

    let cold = bench.phase(if warm_phase { l_cold } else { n32 });

    let warm = if warm_phase {
        // Warm the tree: each warmer refreshes its keys once.
        for w in &warmers {
            let wi = bench.lives.iter().position(|l| l.leaf == *w).expect("live");
            let live = &mut bench.lives[wi];
            let p = &live.provider;
            let g = live.group.as_mut().expect("joined");
            let b = g
                .self_update(p, &live.signer, LeafNodeParameters::default())
                .expect("update");
            let commit = b.into_commit().to_bytes().expect("encode");
            g.merge_pending_commit(p).expect("merge");
            bench.deliver(wi, &commit);
        }
        Some(bench.phase(l_warm))
    } else {
        None
    };

    SizeResult {
        leaves: n,
        build_ms: ms(build),
        build_cpu_ms: build_cpu,
        build_commit_max,
        build_welcome_max,
        kp_bytes,
        tree_bytes,
        json_tree_bytes,
        json_tree_ms,
        storage_bytes,
        warmers: warmers.len(),
        cold,
        warm,
    }
}

fn kb(b: usize) -> String {
    if b < 10 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else if b < 1024 * 1024 {
        format!("{:.0} KB", b as f64 / 1024.0)
    } else {
        format!("{:.2} MB", b as f64 / (1024.0 * 1024.0))
    }
}

fn t(v: f64) -> String {
    if v.is_nan() {
        "-".into()
    } else if v < 10.0 {
        format!("{v:.2}")
    } else if v < 100.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

fn print_tables(label: &str, results: &[SizeResult]) {
    println!("\n### {label}\n");
    println!("| leaves | build: creator CPU ms (wall ms) | max batch commit | max batch welcome | key package | ratchet tree | tree as JSON (encode ms) | stored state (1 member) |");
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|");
    for r in results {
        println!(
            "| {} | {} ({}) | {} | {} | {} | {} | {} ({}) | {} |",
            r.leaves,
            t(r.build_cpu_ms),
            t(r.build_ms),
            kb(r.build_commit_max),
            kb(r.build_welcome_max),
            kb(r.kp_bytes),
            kb(r.tree_bytes),
            kb(r.json_tree_bytes),
            t(r.json_tree_ms),
            kb(r.storage_bytes)
        );
    }
    println!("\n| leaves | tree | op | commit | welcome | create ms | process ms | apply ms | join ms | fan-out (commit x members) |");
    println!("|---:|---|---|---:|---:|---:|---:|---:|---:|---:|");
    for r in results {
        let phases: Vec<(&str, &PhaseResult)> = std::iter::once(("cold", &r.cold))
            .chain(r.warm.as_ref().map(|w| ("warm", w)))
            .collect();
        for (name, p) in phases {
            for (op, c) in [
                ("update", &p.update),
                ("add 1", &p.add),
                ("add 1, no path", &p.add_no_path),
                ("remove 1", &p.remove),
            ] {
                let fan = c.commit_bytes * (r.leaves - 1);
                println!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                    r.leaves,
                    name,
                    op,
                    kb(c.commit_bytes),
                    if c.welcome_bytes > 0 {
                        kb(c.welcome_bytes)
                    } else {
                        "-".into()
                    },
                    t(c.create_ms + c.commit_merge_ms),
                    t(c.process_ms),
                    t(c.merge_ms),
                    t(c.join_ms),
                    kb(fan)
                );
            }
        }
    }
    println!("\n| leaves | message ciphertext (100 B text) | encrypt us | decrypt us |");
    println!("|---:|---:|---:|---:|");
    for r in results {
        let p = r.warm.as_ref().unwrap_or(&r.cold);
        println!(
            "| {} | {} B | {} | {} |",
            r.leaves,
            p.msg_bytes,
            t(p.enc_us),
            t(p.dec_us)
        );
    }
    println!(
        "\n(warmers per size: {})",
        results
            .iter()
            .map(|r| format!("{}={}", r.leaves, r.warmers))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn run_suite<P: Provider>(
    label: &str,
    cs: Ciphersuite,
    sizes: &[usize],
    reps: usize,
    batch: usize,
) {
    let mut results = Vec::new();
    for &n in sizes {
        let t0 = Instant::now();
        let load0 = loadavg();
        let r = run_size::<P>(cs, n, reps, batch);
        eprintln!(
            "[{label}] n={n} done in {:.1}s, loadavg before {load0} after {} (cold update {} / warm update {})",
            t0.elapsed().as_secs_f64(),
            loadavg(),
            kb(r.cold.update.commit_bytes),
            r.warm.as_ref().map(|w| kb(w.update.commit_bytes)).unwrap_or_else(|| "-".into())
        );
        results.push(r);
        print_tables(label, &results[results.len() - 1..]);
    }
    print_tables(&format!("{label} (all sizes)"), &results);
}

/// 1-minute load average; anything well above 1 means another process
/// competed for the CPU during the run.
fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .unwrap_or_else(|| "?".into())
}

fn main() {
    let mut sizes = vec![2, 10, 100, 500, 1000, 2000];
    let mut suites = vec![
        "hybrid".to_string(),
        "classical".to_string(),
        "xwing".to_string(),
    ];
    let mut reps = 5;
    let mut batch = 100;
    let args: Vec<String> = std::env::args().skip(1).collect();
    for pair in args.chunks(2) {
        let v = pair.get(1).expect("option value");
        match pair[0].as_str() {
            "--sizes" => sizes = v.split(',').map(|s| s.parse().expect("size")).collect(),
            "--suites" => suites = v.split(',').map(str::to_string).collect(),
            "--reps" => reps = v.parse().expect("reps"),
            "--batch" => batch = v.parse().expect("batch"),
            other => panic!("unknown option {other}"),
        }
    }
    assert!(reps >= 2, "need at least 2 repetitions");

    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("machine: {cpu}, {threads} hardware threads; reps={reps}, batch={batch}");

    for s in &suites {
        match s.as_str() {
            "hybrid" => run_suite::<openmls_rust_crypto::OpenMlsRustCrypto>(
                "hybrid: MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519 (RustCrypto, default)",
                Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
                &sizes,
                reps,
                batch,
            ),
            "classical" => run_suite::<openmls_rust_crypto::OpenMlsRustCrypto>(
                "classical: MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (RustCrypto)",
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                &sizes,
                reps,
                batch,
            ),
            "xwing" => run_suite::<openmls_libcrux_crypto::Provider>(
                "x-wing: MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 (libcrux)",
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
                &sizes,
                reps,
                batch,
            ),
            other => panic!("unknown suite {other}"),
        }
    }
}
