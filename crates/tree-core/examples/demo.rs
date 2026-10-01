//! Three devices chatting end-to-end, with no server: bytes are handed over
//! directly, exactly as a mailbox would deliver them.
//!
//! Run: cargo run -p tree-core --example demo

use tree_core::{Client, Incoming, TREE_CIPHERSUITE};

fn show(who: &str, ev: &Incoming) {
    match ev {
        Incoming::Message { from, body } => {
            println!("  {who:<8} <- {from}: {}", String::from_utf8_lossy(body))
        }
        other => println!("  {who:<8} <- {other:?}"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ciphersuite: {TREE_CIPHERSUITE:?}\n");

    let alice = Client::new("alice")?;
    let bob = Client::new("bob")?;
    let charlie = Client::new("charlie")?;

    // Bob and Charlie publish key packages (normally uploaded to the server).
    let bob_kp = bob.key_package()?;
    let charlie_kp = charlie.key_package()?;
    println!("key package size: {} bytes", bob_kp.len());

    // Alice starts a chat and adds Bob.
    let mut a = alice.create_group()?;
    let add_bob = a.add(&alice, &bob_kp)?;
    let mut b = bob.join(&add_bob.welcome)?;
    println!("alice + bob in group, epoch {}", a.epoch());

    // 1:1 messages.
    let m = a.send(&alice, "안녕 밥, 트리 첫 메시지야".as_bytes())?;
    println!("ciphertext size: {} bytes (padded)", m.len());
    show("bob", &b.receive(&bob, &m)?);
    let m = b.send(&bob, "잘 왔어! E2E 맞지?".as_bytes())?;
    show("alice", &a.receive(&alice, &m)?);

    // Safety check: both sides compare this code out of band.
    assert_eq!(a.verification_code(), b.verification_code());
    println!("verification codes match: {}", hex(&a.verification_code()[..8]));

    // Alice adds Charlie.
    let add_charlie = a.add(&alice, &charlie_kp)?;
    show("bob", &b.receive(&bob, &add_charlie.commit)?);
    let mut c = charlie.join(&add_charlie.welcome)?;
    println!("members: {:?}, epoch {}", a.members(), a.epoch());

    let m = c.send(&charlie, "나도 들어왔다".as_bytes())?;
    show("alice", &a.receive(&alice, &m)?);
    show("bob", &b.receive(&bob, &m)?);

    // Bob refreshes his keys (post-compromise security).
    let r = b.refresh_keys(&bob)?;
    show("alice", &a.receive(&alice, &r)?);
    show("charlie", &c.receive(&charlie, &r)?);

    // Alice removes Charlie.
    let rm = a.remove(&alice, "charlie")?;
    show("bob", &b.receive(&bob, &rm)?);
    show("charlie", &c.receive(&charlie, &rm)?);

    let m = a.send(&alice, "찰리 없는 비밀 이야기".as_bytes())?;
    show("bob", &b.receive(&bob, &m)?);
    match c.receive(&charlie, &m) {
        Ok(ev) => println!("  charlie  <- !!! {ev:?}"),
        Err(e) => println!("  charlie  <- blocked: {e}"),
    }

    println!("\nfinal members: {:?}, epoch {}", a.members(), a.epoch());
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
