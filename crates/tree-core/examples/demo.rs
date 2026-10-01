//! Three devices chatting end-to-end, with no server: bytes are handed over
//! directly, exactly as a mailbox would deliver them. A few lines stand in
//! for the server's commit ordering (first commit per group and epoch wins,
//! docs/PROTOCOL.md section 7).
//!
//! Run: cargo run -p tree-core --example demo

use std::collections::HashMap;

use tree_core::{Client, Group, Incoming, PendingCommit, TREE_CIPHERSUITE};

fn recv(who: &str, g: &mut Group, me: &Client, bytes: &[u8]) -> Result<(), tree_core::TreeError> {
    let ev = g.receive(me, bytes)?;
    match &ev {
        Incoming::Message { from, name, body } => {
            let dup = if g.members().iter().any(|m| m.id == *from && m.duplicate_name) { " (same name as another member!)" } else { "" };
            println!("  {who:<8} <- {name} [{}]{dup}: {}", &from.to_hex()[..8], String::from_utf8_lossy(body))
        }
        other => println!("  {who:<8} <- {other:?}"),
    }
    Ok(())
}

/// Stand-in for the server's commit ordering: accepts the first commit per
/// (group, epoch) and answers the same way to an identical retry.
#[derive(Default)]
struct Sequencer(HashMap<(Vec<u8>, u64), Vec<u8>>);

impl Sequencer {
    fn submit(&mut self, p: &PendingCommit) -> bool {
        let winner = self.0.entry((p.group_id.clone(), p.epoch)).or_insert_with(|| p.commit.clone());
        *winner == p.commit
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ciphersuite: {TREE_CIPHERSUITE:?}\n");
    let mut server = Sequencer::default();

    let alice = Client::new("alice")?;
    let bob = Client::new("bob")?;
    let charlie = Client::new("charlie")?;

    // Bob and Charlie publish key packages (normally uploaded to the server).
    let bob_kp = bob.key_package()?;
    let charlie_kp = charlie.key_package()?;
    println!("key package size: {} bytes", bob_kp.len());

    // Alice starts a chat and adds Bob: commit is pending until the server accepts.
    let mut a = alice.create_group()?;
    let add_bob = a.add(&alice, &[&bob_kp])?;
    println!("alice's add is pending: epoch still {}", a.epoch());
    assert!(server.submit(&add_bob));
    a.confirm_commit(&alice)?;
    let mut b = bob.join(add_bob.welcome.as_ref().unwrap())?;
    println!("server accepted; alice + bob in group, epoch {}", a.epoch());
    println!("bob should refresh his keys soon: {}", b.should_refresh_keys());

    // 1:1 messages.
    let m = a.send(&alice, "안녕 밥, 트리 첫 메시지야".as_bytes())?;
    println!("ciphertext size: {} bytes (padded)", m.len());
    recv("bob", &mut b, &bob, &m)?;
    let m = b.send(&bob, "잘 왔어! E2E 맞지?".as_bytes())?;
    recv("alice", &mut a, &alice, &m)?;

    // Safety check: both sides compare this code out of band.
    assert_eq!(a.verification_code(), b.verification_code());
    println!("verification codes match: {}", hex(&a.verification_code()[..8]));

    // Race: alice adds charlie while bob refreshes his keys, in the same epoch.
    println!("\nrace: alice adds charlie, bob refreshes keys, both in epoch {}", a.epoch());
    let add_charlie = a.add(&alice, &[&charlie_kp])?;
    let refresh = b.refresh_keys(&bob)?;
    // Bob can still send while his commit is pending.
    let while_pending = b.send(&bob, "커밋 기다리는 중에도 보낼 수 있어".as_bytes())?;
    println!("  server: bob's refresh {}", if server.submit(&refresh) { "accepted" } else { "rejected" });
    println!("  server: alice's add   {}", if server.submit(&add_charlie) { "accepted" } else { "rejected (bob was first)" });
    // Alice could call discard_commit() on the rejection; here she simply
    // receives the winner, which discards her pending commit automatically.
    // Mailbox order: bob's message, then his commit (bob gets his own echo).
    recv("alice", &mut a, &alice, &while_pending)?;
    recv("alice", &mut a, &alice, &refresh.commit)?;
    recv("bob", &mut b, &bob, &refresh.commit)?;
    println!("  bob should refresh his keys soon: {}", b.should_refresh_keys());

    // Alice decides again in the new epoch. The discarded welcome was never
    // delivered, so charlie's key package can be used again.
    let add_charlie = a.add(&alice, &[&charlie_kp])?;
    assert!(server.submit(&add_charlie));
    a.confirm_commit(&alice)?;
    recv("bob", &mut b, &bob, &add_charlie.commit)?;
    let mut c = charlie.join(add_charlie.welcome.as_ref().unwrap())?;
    let names: Vec<String> = a.members().into_iter().map(|m| m.name).collect();
    println!("members: {names:?}, epoch {}", a.epoch());

    let m = c.send(&charlie, "나도 들어왔다".as_bytes())?;
    recv("alice", &mut a, &alice, &m)?;
    recv("bob", &mut b, &bob, &m)?;

    // A message sent just before a commit still arrives after it (past-epoch window).
    let late = b.send(&bob, "커밋 직전에 보낸 메시지".as_bytes())?;

    // Alice removes Charlie by member id (names are not identities).
    let rm = a.remove(&alice, &[charlie.member_id()])?;
    assert!(server.submit(&rm));
    // The server echoes alice's own commit back to her: merged on arrival.
    recv("alice", &mut a, &alice, &rm.commit)?;
    recv("alice", &mut a, &alice, &rm.commit)?;
    recv("bob", &mut b, &bob, &rm.commit)?;
    recv("charlie", &mut c, &charlie, &rm.commit)?;
    recv("alice", &mut a, &alice, &late)?;

    let m = a.send(&alice, "찰리 없는 비밀 이야기".as_bytes())?;
    recv("bob", &mut b, &bob, &m)?;
    match c.receive(&charlie, &m) {
        Ok(ev) => println!("  charlie  <- !!! {ev:?}"),
        Err(e) => println!("  charlie  <- blocked: {e}"),
    }

    let names: Vec<String> = a.members().into_iter().map(|m| m.name).collect();
    println!("\nfinal members: {names:?}, epoch {}", a.epoch());
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
