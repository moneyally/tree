//! Identities and conversations that survive a restart.
//!
//! Alice and Bob each keep their device state in an encrypted database file.
//! They chat, the "app" closes (everything in memory is dropped), both reopen
//! with their passphrase and keep chatting, add and remove a member, and
//! restart again.
//!
//! Run: cargo run -p tree-core --example persist_demo

use std::{path::Path, time::Instant};

use tree_core::{Client, Group, Incoming, StoredProvider, TreeError};

type Stored = Client<StoredProvider>;

fn show(who: &str, ev: &Incoming) {
    match ev {
        Incoming::Message { name, body, .. } => {
            println!("  {who:<8} <- {name}: {}", String::from_utf8_lossy(body))
        }
        other => println!("  {who:<8} <- {other:?}"),
    }
}

fn open(path: &Path, pass: &str) -> Result<(Stored, Vec<Group>), TreeError> {
    let t = Instant::now();
    let client = Client::open(path, pass)?;
    let groups = client
        .group_ids()?
        .iter()
        .map(|id| client.load_group(id))
        .collect::<Result<Vec<_>, _>>()?;
    println!(
        "  reopened {:<8} {} group(s), epoch {:?}  ({} ms incl. Argon2id)",
        client.name(),
        groups.len(),
        groups.iter().map(|g| g.epoch()).collect::<Vec<_>>(),
        t.elapsed().as_millis()
    );
    Ok((client, groups))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("tree-persist-demo-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (pa, pb, pc) = (
        dir.join("alice.db"),
        dir.join("bob.db"),
        dir.join("charlie.db"),
    );

    println!("1) create two identities in encrypted databases");
    let t = Instant::now();
    let alice = Client::create(&pa, "alice: correct horse battery", "alice")?;
    println!(
        "  created alice ({} ms incl. Argon2id)",
        t.elapsed().as_millis()
    );
    let bob = Client::create(&pb, "bob: staple purple tiger", "bob")?;

    let mut a = alice.create_group()?;
    let add = a.add(&alice, &[bob.key_package()?])?;
    a.confirm_commit(&alice)?; // (the server accepted it)
    let mut b = bob.join(add.welcome.as_ref().unwrap())?;
    let m = a.send(&alice, "재시작 전 첫 메시지".as_bytes())?;
    show("bob", &b.receive(&bob, &m)?);
    let m = b.send(&bob, "응, 받았어".as_bytes())?;
    show("alice", &a.receive(&alice, &m)?);
    let in_flight = a.send(&alice, "보내는 중에 밥 앱이 꺼짐".as_bytes())?;

    println!("\n2) close both apps (all memory dropped)");
    drop((a, b, alice, bob));

    println!("\n3) wrong passphrase");
    match Client::open(&pb, "bob: wrong guess") {
        Err(e) => println!("  refused: {e}"),
        Ok(_) => println!("  !!! opened with a wrong passphrase"),
    }

    println!("\n4) reopen and keep chatting");
    let (alice, mut ga) = open(&pa, "alice: correct horse battery")?;
    let (bob, mut gb) = open(&pb, "bob: staple purple tiger")?;
    let (mut a, mut b) = (ga.remove(0), gb.remove(0));
    show("bob", &b.receive(&bob, &in_flight)?);
    match b.receive(&bob, &in_flight) {
        Err(_) => println!("  bob      <- replay of the same message refused"),
        Ok(ev) => println!("  bob      <- !!! replay accepted: {ev:?}"),
    }
    let m = b.send(&bob, "재시작 후에도 그대로네".as_bytes())?;
    show("alice", &a.receive(&alice, &m)?);
    assert_eq!(a.verification_code(), b.verification_code());
    println!("  verification codes still match");

    println!("\n5) add charlie (his key package survives his own restart), then remove bob");
    let charlie = Client::create(&pc, "charlie: river stone lamp", "charlie")?;
    let kp = charlie.key_package()?;
    drop(charlie);
    let charlie = Client::open(&pc, "charlie: river stone lamp")?;
    let add = a.add(&alice, &[kp])?;
    a.confirm_commit(&alice)?;
    show("bob", &b.receive(&bob, &add.commit)?);
    let mut c = charlie.join(add.welcome.as_ref().unwrap())?;
    let m = c.send(&charlie, "나도 왔어".as_bytes())?;
    show("alice", &a.receive(&alice, &m)?);
    show("bob", &b.receive(&bob, &m)?);
    let bob_id = bob.member_id();
    let rm = a.remove(&alice, &[bob_id])?;
    println!("  alice's removal of bob is pending (epoch {}); alice's app closes before the server answers", a.epoch());
    drop((a, alice));
    let (alice, mut ga) = open(&pa, "alice: correct horse battery")?;
    let mut a = ga.remove(0);
    let again = a
        .pending_commit()
        .expect("pending commit survives the restart");
    println!(
        "  pending commit still there after restart: same bytes = {}",
        again.commit == rm.commit
    );
    // The server accepted it meanwhile; its echo merges it.
    show("alice", &a.receive(&alice, &again.commit)?);
    show("charlie", &c.receive(&charlie, &rm.commit)?);
    show("bob", &b.receive(&bob, &rm.commit)?);

    println!("\n6) everyone restarts again");
    drop((a, b, c, alice, bob, charlie));
    let (alice, mut ga) = open(&pa, "alice: correct horse battery")?;
    let (bob, gb) = open(&pb, "bob: staple purple tiger")?;
    let (charlie, mut gc) = open(&pc, "charlie: river stone lamp")?;
    let (mut a, mut c) = (ga.remove(0), gc.remove(0));
    let names: Vec<String> = a.members().into_iter().map(|m| m.name).collect();
    println!(
        "  members: {names:?}; bob still a member: {}",
        gb[0].is_member()
    );
    let m = a.send(&alice, "밥 없는 비밀 이야기".as_bytes())?;
    show("charlie", &c.receive(&charlie, &m)?);
    let mut b = gb.into_iter().next().unwrap();
    match b.receive(&bob, &m) {
        Ok(ev) => println!("  bob      <- !!! {ev:?}"),
        Err(e) => println!("  bob      <- blocked: {e}"),
    }

    println!("\n7) what is on disk");
    drop((a, b, c, alice, bob, charlie));
    let raw = std::fs::read(&pa)?;
    let found = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
    println!(
        "  alice.db: {} bytes, first 16: {}",
        raw.len(),
        hex(&raw[..16])
    );
    println!(
        "  contains \"SQLite format 3\": {}",
        found(b"SQLite format 3")
    );
    println!("  contains the name \"alice\":   {}", found(b"alice"));
    println!(
        "  key header alice.db.hdr: {} bytes (salt + Argon2id parameters, no secret)",
        std::fs::metadata(dir.join("alice.db.hdr"))?.len()
    );

    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
