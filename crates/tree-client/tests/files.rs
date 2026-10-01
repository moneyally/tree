//! Encrypted attachments through a real server.

mod common;

use common::Env;
use tree_client::Event;

#[test]
fn files_end_to_end() {
    let env = Env::new("files");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    bob.add_contact(alice.account_id()).unwrap();
    let g = alice.create_group().unwrap();
    alice.invite(&g, bob.account_id()).unwrap();
    bob.sync(0).unwrap();

    let photo: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).chain(b"PLAINTEXT-MARKER-91c2".iter().copied()).collect();
    let sent = alice.send_file(&g, &photo, "산.jpg", "image/jpeg", false).unwrap();
    let ev = bob.sync(0).unwrap();
    let file = ev
        .iter()
        .find_map(|e| match e {
            Event::File { file, name, request: false, .. } => {
                assert_eq!(name.as_deref(), Some("alice"));
                Some(file.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{ev:?}"));
    assert_eq!(file, sent);
    assert_eq!(bob.download(&file).unwrap(), photo);
    assert_eq!(bob.received_file(&file.id).unwrap(), Some(file.clone()));

    // The server holds only ciphertext: no marker, no name.
    let stored = std::fs::read(env.dir.join("attachments").join(&file.id)).unwrap();
    assert!(!stored.windows(21).any(|w| w == b"PLAINTEXT-MARKER-91c2"));
    let db = std::fs::read(&env.db).unwrap();
    assert!(!db.windows("산.jpg".len()).any(|w| w == "산.jpg".as_bytes()));

    // A tampered blob on the server is refused, not shown.
    let mut t = stored.clone();
    t[1000] ^= 1;
    std::fs::write(env.dir.join("attachments").join(&file.id), &t).unwrap();
    assert!(bob.download(&file).is_err());

    // A reference claiming other content (different hash) is refused.
    std::fs::write(env.dir.join("attachments").join(&file.id), &stored).unwrap();
    let mut lie = file.clone();
    lie.pt_sha256 = "00".repeat(32);
    assert!(bob.download(&lie).is_err());
    assert_eq!(bob.download(&file).unwrap(), photo);

    // The admin releases chat.media: nobody can send attachments.
    alice.set_chat_feature(&g, "chat.media", false, None).unwrap();
    bob.sync(0).unwrap();
    assert!(matches!(bob.send_file(&g, b"x", "x", "text/plain", false), Err(tree_client::Error::Feature(c)) if c == "LOCKED_BY_CHAT"));
    assert!(alice.send_file(&g, b"x", "x", "text/plain", false).is_err());
}
