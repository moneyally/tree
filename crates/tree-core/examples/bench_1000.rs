//! A 1,000-member group through the core's own API (Wave 3, groups up to
//! 1,000): `Client` and `Group` with the outer envelope, the group
//! settings checks and the two-phase commits, all in memory (no SQLCipher,
//! no server, no network). Measures what a group of this size costs:
//! building it, commit sizes and times (add, remove, key refresh, a settings
//! change that fills the Wave 3 fields to their limits), joining, a message,
//! and the settings lookups the client makes for every message.
//!
//! cargo run --release -p tree-core --example bench_1000 [-- --members 1000]
//!
//! Results: docs/BENCHMARKS.md, "Groups of 1,000 through the core API".

use std::time::{Duration, Instant};

use tree_core::group_settings::{perm, ChatSetting, Community, CommunityChat, Role, MAX_ASSIGNMENTS, MAX_COMMUNITY_CHATS, MAX_RESTRICTED, MAX_ROLES};
use tree_core::{Client, Group, Incoming, MemberId, PendingCommit};

fn kb(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MB", n as f64 / (1 << 20) as f64)
    } else {
        format!("{:.1} KB", n as f64 / 1024.0)
    }
}

fn ms(d: Duration) -> String {
    format!("{:.1} ms", d.as_secs_f64() * 1000.0)
}

/// Commits `p` on the committer and lets every receiver process it.
fn deliver(g: &mut Group, me: &Client, p: &PendingCommit, receivers: &mut [(Client, Group)]) -> (Duration, Duration) {
    let t = Instant::now();
    g.confirm_commit(me).unwrap();
    let confirm = t.elapsed();
    let mut worst = Duration::ZERO;
    for (c, rg) in receivers.iter_mut() {
        let t = Instant::now();
        match rg.receive(c, &p.commit).unwrap() {
            Incoming::GroupChanged { .. } => {}
            other => panic!("{other:?}"),
        }
        worst = worst.max(t.elapsed());
    }
    (confirm, worst)
}

fn main() {
    let n: usize = std::env::args()
        .skip_while(|a| a != "--members")
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    println!("members: {n} (one device each), batches of 100, in memory\n");

    let alice = Client::new("alice").unwrap();
    let mut g = alice.create_group().unwrap();
    let t = Instant::now();
    let people: Vec<Client> = (1..n).map(|i| Client::new(&format!("m{i}")).unwrap()).collect();
    let kps: Vec<Vec<u8>> = people.iter().map(|c| c.key_package().unwrap()).collect();
    println!("identities and key packages for {} devices: {}", n - 1, ms(t.elapsed()));

    // Build: the creator adds everyone in batches of 100. The first member
    // of the first batch and the last member join and follow every commit.
    let mut receivers: Vec<(Client, Group)> = Vec::new();
    let mut people = people.into_iter();
    let mut build = Duration::ZERO;
    let mut largest_add = 0;
    let mut last_welcome = 0;
    let mut join_time = Duration::ZERO;
    for batch in kps.chunks(100) {
        let joining: Vec<Client> = (0..batch.len()).map(|_| people.next().unwrap()).collect();
        let t = Instant::now();
        let p = g.add(&alice, batch).unwrap();
        build += t.elapsed();
        largest_add = largest_add.max(p.commit.len());
        let (confirm, _) = deliver(&mut g, &alice, &p, &mut receivers);
        build += confirm;
        let w = p.welcome.clone().unwrap();
        last_welcome = w.len();
        let first = receivers.is_empty();
        for (i, c) in joining.into_iter().enumerate() {
            let last = g.members().len() == n && i == batch.len() - 1;
            if (first && i == 0) || last {
                let t = Instant::now();
                let jg = c.join(&w).unwrap();
                join_time = t.elapsed();
                receivers.push((c, jg));
            }
        }
    }
    assert_eq!(g.members().len(), n);
    println!("build (creator CPU, add commits + merges): {}", ms(build));
    println!("largest add commit (100 devices, no path): {}", kb(largest_add));
    println!("welcome for the last batch: {}; join (process welcome): {}", kb(last_welcome), ms(join_time));

    // One add, one remove, one key refresh by the creator.
    let extra = Client::new("late").unwrap();
    let t = Instant::now();
    let p = g.add(&alice, &[extra.key_package().unwrap()]).unwrap();
    let create = t.elapsed();
    let (_, recv) = deliver(&mut g, &alice, &p, &mut receivers);
    println!("add 1: commit {}, create {}, receiver {}", kb(p.commit.len()), ms(create), ms(recv));
    let victim = extra.member_id();
    let t = Instant::now();
    let p = g.remove(&alice, &[victim]).unwrap();
    let create = t.elapsed();
    let (_, recv) = deliver(&mut g, &alice, &p, &mut receivers);
    println!("remove 1 (cold tree): commit {}, create {}, receiver {}", kb(p.commit.len()), ms(create), ms(recv));
    let t = Instant::now();
    let p = g.refresh_keys(&alice).unwrap();
    let create = t.elapsed();
    let (_, recv) = deliver(&mut g, &alice, &p, &mut receivers);
    println!("key refresh (creator path warm now): commit {}, create {}, receiver {}", kb(p.commit.len()), ms(create), ms(recv));

    // A settings change with every Wave 3 field at its limit.
    let members = g.members();
    let mut s = g.settings();
    s.name = Some("천 명의 모임".into());
    for i in 0..MAX_ROLES {
        s.roles.insert(format!("r{i:02}"), Role { name: format!("역할 {i}"), color: "#3366ff".into(), perms: [perm::PIN.to_string()].into() });
    }
    for m in members.iter().skip(1).take(MAX_ASSIGNMENTS) {
        s.member_roles.insert(*m, ["r00".to_string()].into());
    }
    let mut full = s.clone();
    for m in members.iter().skip(1 + MAX_ASSIGNMENTS).take(MAX_RESTRICTED) {
        full.restricted.insert(*m, i64::MAX);
    }
    full.community = Some(Community { chats: (0..MAX_COMMUNITY_CHATS).map(|i| CommunityChat { id: format!("{i:032x}"), name: format!("chat {i}") }).collect() });
    println!(
        "settings with 16 roles + 150 assignments: {}; with 50 restrictions and 50 community chats too: {} (limit 16 KiB: {})",
        kb(s.encode().unwrap().len()),
        kb(serde_json::to_vec(&full).unwrap().len()),
        if full.encode().is_ok() { "fits" } else { "too large, refused" }
    );
    s.features.insert("chat.slow_mode".into(), ChatSetting { applied: true, option: Some("1m".into()) });
    let t = Instant::now();
    let p = g.change_settings(&alice, &s).unwrap();
    let create = t.elapsed();
    let (_, recv) = deliver(&mut g, &alice, &p, &mut receivers);
    println!("settings change: commit {}, create {}, receiver {}", kb(p.commit.len()), ms(create), ms(recv));

    // Messages (median of 21) and the lookups the client makes for each one.
    let (c, rg) = &mut receivers[0];
    let (mut enc, mut dec, mut size) = (vec![], vec![], 0);
    for _ in 0..21 {
        let t = Instant::now();
        let msg = g.send(&alice, &[b'x'; 100]).unwrap();
        enc.push(t.elapsed());
        size = msg.len();
        let t = Instant::now();
        rg.receive(c, &msg).unwrap();
        dec.push(t.elapsed());
    }
    enc.sort();
    dec.sort();
    println!("message, 100 bytes: {size} sealed, encrypt {}, decrypt {} (median of 21)", ms(enc[10]), ms(dec[10]));
    let t = Instant::now();
    for _ in 0..100 {
        std::hint::black_box(rg.settings());
    }
    println!("settings lookup (decode + effective + members of the epoch, cached): {} each", ms(t.elapsed() / 100));
    let t = Instant::now();
    let me = MemberId::of(&c.signature_public_key());
    for _ in 0..100 {
        std::hint::black_box(rg.settings().may(&me, perm::PIN));
    }
    println!("permission check: {} each", ms(t.elapsed() / 100));
    let t = Instant::now();
    std::hint::black_box(rg.successor(&[members[0]], 0));
    println!("successor rule: {}", ms(t.elapsed()));
}
