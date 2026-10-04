//! Wave 4 through a real server: public groups and channels (not
//! end-to-end, `public.rs`) and private channels (end-to-end, `channel.rs`).
//! Every key is toggled both ways; for private channels a member whose own
//! checks are bypassed (`send_unchecked`: what a modified client sends) is
//! shown to be refused by every honest receiver.

mod common;

use common::Env;
use tree_client::payload::Payload;
use tree_client::{CommitOutcome, Error, Event, Session};

fn feature(r: Result<impl std::fmt::Debug, Error>, want: &str) -> bool {
    matches!(&r, Err(Error::Feature(c)) if c == want) || panic!("wanted {want}, got {r:?}")
}

fn server(r: Result<impl std::fmt::Debug, Error>, want: &str) -> bool {
    matches!(&r, Err(Error::Server { code, .. }) if code == want) || panic!("wanted {want}, got {r:?}")
}

fn dropped(ev: &[Event], why: &str) -> bool {
    ev.iter().any(|e| matches!(e, Event::Dropped { reason } if reason.contains(why)))
}

fn text(t: &str, re: Option<&str>) -> Payload {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).unwrap();
    Payload::Text { id: hex::encode(b), text: t.into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: None, re: re.map(str::to_string), kb: vec![] }
}

fn sync_all(s: &mut [&mut Session]) {
    for _ in 0..2 {
        for x in s.iter_mut() {
            x.sync(0).unwrap();
        }
    }
}

fn has_text(s: &Session, g: &[u8], t: &str) -> bool {
    s.history(g, 500).unwrap().iter().any(|m| m.text.as_deref() == Some(t) && !m.deleted)
}

#[test]
fn public_group_flow() {
    let env = Env::new("public-group");
    let alice = env.device("alice");
    let bob = env.device("bob");
    let g = alice.public_create("group", "Rust 모임", "@Rust_Meetup", "공개 모임", None).unwrap();
    assert!(g.is_public && !g.is_channel() && g.is_admin());
    // Found by handle, not in the directory until listed.
    let found = bob.public_find("rust_meetup").unwrap().unwrap();
    assert!(found.is_public && !found.subscribed());
    assert!(bob.public_find("nobody_here").unwrap().is_none());
    assert!(bob.public_directory("rust").unwrap().is_empty());
    alice.public_set_feature(&g.id, "chat.public_listing", true, None).unwrap();
    assert_eq!(bob.public_directory("rust").unwrap().iter().map(|s| s.handle.as_str()).collect::<Vec<_>>(), ["rust_meetup"]);
    alice.public_set_feature(&g.id, "chat.public_listing", false, None).unwrap();
    assert!(bob.public_directory("rust").unwrap().is_empty(), "released: unlisted");

    // Posting before joining is refused; joined, everyone posts.
    assert!(server(bob.public_post(&g.id, "hi", None), "NOT_MEMBER"));
    let old = alice.public_post(&g.id, "before bob joined", None).unwrap();
    assert!(old.is_public && old.mine);
    let joined = bob.public_join(&g.id).unwrap();
    assert!(joined.subscribed() && joined.members == 2);
    assert_eq!(bob.public_unread(&g.id).unwrap(), 0, "older posts are not unread");
    let p = bob.public_post(&g.id, "안녕하세요", None).unwrap();
    assert_eq!(p.author_name.as_deref(), Some("bob"), "the display name is published with a public post");
    alice.public_sync(&g.id).unwrap();
    assert_eq!(alice.public_unread(&g.id).unwrap(), 1);
    let posts = alice.public_posts(&g.id, 50).unwrap();
    assert_eq!(posts.iter().map(|p| p.text.clone().unwrap()).collect::<Vec<_>>(), ["before bob joined", "안녕하세요"]);
    assert!(posts.iter().all(|p| p.is_public));
    alice.public_mark_read(&g.id).unwrap();
    assert_eq!(alice.public_unread(&g.id).unwrap(), 0);
    // A reply, an edit and a deletion reach the other cache by the cursor.
    alice.public_post(&g.id, "welcome", Some(&p.id)).unwrap();
    bob.public_edit(&g.id, &p.id, "안녕하세요 (수정)").unwrap();
    assert!(server(alice.public_edit(&g.id, &p.id, "not mine"), "NOT_AUTHOR"));
    alice.public_sync(&g.id).unwrap();
    assert!(alice.public_posts(&g.id, 50).unwrap().iter().any(|x| x.text.as_deref() == Some("안녕하세요 (수정)") && x.edited_at.is_some()));
    alice.public_delete(&g.id, &p.id).unwrap();
    bob.public_sync(&g.id).unwrap();
    assert!(bob.public_posts(&g.id, 50).unwrap().iter().all(|x| x.id != p.id), "an admin's deletion reaches bob's copy");
    // Reports name the post; the operator sees the stored text.
    bob.public_report(&old.id, "spam").unwrap();
    let (_, v) = env.operator(reqwest::Method::GET, "/v1/reports");
    assert_eq!(v["reports"][0]["messages"][0]["payload"], "before bob joined");
    // Ban and unban.
    alice.public_ban(&g.id, bob.account_id(), true).unwrap();
    assert!(server(bob.public_post(&g.id, "back?", None), "BANNED"));
    assert!(bob.public_cached().unwrap().iter().all(|s| s.id != g.id) || bob.public_subscriptions().unwrap().iter().all(|s| s.id != g.id));
    alice.public_ban(&g.id, bob.account_id(), false).unwrap();
    bob.public_join(&g.id).unwrap();
    // Slow mode for members: apply with an option, release.
    alice.public_set_feature(&g.id, "chat.slow_mode", true, Some("1h")).unwrap();
    bob.public_post(&g.id, "one", None).unwrap();
    assert!(server(bob.public_post(&g.id, "two", None), "SLOW_MODE"));
    alice.public_set_feature(&g.id, "chat.slow_mode", false, None).unwrap();
    bob.public_post(&g.id, "two", None).unwrap();

    // The cache lives in the encrypted profile: it survives a restart.
    drop(bob);
    let (bob, _) = Session::open(&env.profile("bob"), "bob passphrase").unwrap();
    let cached = bob.public_cached().unwrap();
    assert_eq!(cached.len(), 1);
    assert!(cached[0].is_public);
    assert!(bob.public_posts(&g.id, 50).unwrap().iter().any(|x| x.text.as_deref() == Some("two")));
    // Leaving drops the kept copy.
    bob.public_leave(&g.id).unwrap();
    assert!(bob.public_cached().unwrap().is_empty() && bob.public_posts(&g.id, 50).unwrap().is_empty());
}

#[test]
fn public_channel_comments_and_signatures() {
    let env = Env::new("public-channel");
    let alice = env.device("alice");
    let bob = env.device("bob");
    let ch = alice.public_create("channel", "소식", "tree_news_ko", "", None).unwrap();
    assert!(ch.is_channel() && !ch.comments && !ch.signatures);
    bob.public_join(&ch.id).unwrap();
    assert!(server(bob.public_post(&ch.id, "a member's post", None), "NOT_ADMIN"));
    let post = alice.public_post(&ch.id, "첫 소식", None).unwrap();
    // Comments released: refused; applied: allowed; released again: refused.
    assert!(server(bob.public_post(&ch.id, "댓글", Some(&post.id)), "LOCKED_BY_CHAT"));
    assert!(server(bob.public_set_feature(&ch.id, "channel.comments", true, None), "NOT_ADMIN"));
    alice.public_set_feature(&ch.id, "channel.comments", true, None).unwrap();
    let c = bob.public_post(&ch.id, "댓글", Some(&post.id)).unwrap();
    assert_eq!(c.reply_to.as_deref(), Some(post.id.as_str()));
    alice.public_sync(&ch.id).unwrap();
    assert_eq!(alice.public_comments(&ch.id, &post.id).unwrap().len(), 1);
    assert_eq!(alice.public_posts(&ch.id, 50).unwrap().len(), 1, "comments are not posts");
    assert_eq!(alice.public_unread(&ch.id).unwrap(), 0, "comments do not count as unread posts");
    alice.public_set_feature(&ch.id, "channel.comments", false, None).unwrap();
    assert!(server(bob.public_post(&ch.id, "late", Some(&post.id)), "LOCKED_BY_CHAT"));

    // Signatures released: bob sees the channel, not the admin.
    bob.public_sync(&ch.id).unwrap();
    let seen = bob.public_posts(&ch.id, 50).unwrap();
    assert!(seen[0].author.is_none() && seen[0].author_name.is_none(), "{:?}", seen[0]);
    alice.public_set_feature(&ch.id, "channel.signatures", true, None).unwrap();
    bob.public_space(&ch.id).unwrap();
    bob.public_sync(&ch.id).unwrap();
    let seen = bob.public_posts(&ch.id, 50).unwrap();
    assert_eq!((seen[0].author.as_deref(), seen[0].author_name.as_deref()), (Some(alice.account_id()), Some("alice")));
    alice.public_set_feature(&ch.id, "channel.signatures", false, None).unwrap();
    bob.public_space(&ch.id).unwrap();
    bob.public_sync(&ch.id).unwrap();
    assert!(bob.public_posts(&ch.id, 50).unwrap()[0].author.is_none(), "released again: hidden again");
    // Admins: a new admin may post.
    alice.public_set_admin(&ch.id, bob.account_id(), true).unwrap();
    bob.public_post(&ch.id, "now an admin", None).unwrap();
    // Notifications for this space: apply and release.
    assert!(bob.public_set_notify(&ch.id, true).unwrap().notify);
    assert!(!bob.public_set_notify(&ch.id, false).unwrap().notify);

    // The operator releases public spaces: every call is refused.
    let (st, _) = env.operator(reqwest::Method::POST, "/v1/features/server.public_spaces/release");
    assert_eq!(st, 200);
    assert!(feature(bob.public_space(&ch.id), "LOCKED_BY_SERVER"));
    assert!(feature(alice.public_create("group", "x", "another_one", "", None), "LOCKED_BY_SERVER"));
    env.operator(reqwest::Method::POST, "/v1/features/server.public_spaces/apply");
    assert!(bob.public_space(&ch.id).is_ok());
}

#[test]
fn private_groups_never_become_public() {
    let env = Env::new("private-stays");
    let mut alice = env.device("alice");
    let g = alice.create_group().unwrap();
    assert!(feature(alice.set_chat_feature(&g, "chat.private_to_public", true, None), "RELEASED_ALWAYS"));
    assert!(feature(alice.set_chat_feature(&g, "chat.public_listing", true, None), "PUBLIC_SPACES_ONLY"));
    assert!(feature(alice.set_chat_feature(&g, "channel.comments", true, None), "CHANNELS_ONLY"));
    let keys: Vec<String> = alice.chat_features(&g).unwrap().into_iter().map(|f| f.key.to_string()).collect();
    assert!(!keys.iter().any(|k| k == "chat.public_listing" || k.starts_with("channel.")), "{keys:?}");
    // A group cannot become a channel either.
    let mut s = alice.group_settings(&g).unwrap();
    s.channel = true;
    assert!(alice.change_group_settings(&g, &s).is_err());
}

#[test]
fn private_channel_only_admins_post_with_comments_and_signatures() {
    let env = Env::new("private-channel");
    let mut alice = env.device("alice");
    let mut bob = env.device("bob");
    let mut carol = env.device("carol");
    bob.confirm_contact(alice.account_id()).unwrap();
    carol.confirm_contact(alice.account_id()).unwrap();
    let ch = alice.create_channel("비밀 채널").unwrap();
    alice.invite(&ch, bob.account_id()).unwrap();
    alice.invite(&ch, carol.account_id()).unwrap();
    sync_all(&mut [&mut bob, &mut carol, &mut alice]);
    for s in [&mut alice, &mut bob, &mut carol] {
        assert!(s.is_channel(&ch).unwrap());
    }
    assert!(alice.may_post(&ch).unwrap() && !bob.may_post(&ch).unwrap());
    let keys: Vec<String> = alice.chat_features(&ch).unwrap().into_iter().map(|f| f.key.to_string()).collect();
    assert!(keys.iter().any(|k| k == "channel.comments") && !keys.iter().any(|k| k == "chat.public_listing"));

    // Only admins post: bob's app refuses, and a modified client's post is
    // dropped by every honest device.
    assert!(feature(bob.send_text(&ch, "member post"), "NOT_ADMIN"));
    bob.send_unchecked(&ch, &text("forged post", None)).unwrap();
    let ev = carol.sync(0).unwrap();
    assert!(dropped(&ev, "only admins post"), "{ev:?}");
    assert!(dropped(&alice.sync(0).unwrap(), "only admins post"));
    assert!(!has_text(&carol, &ch, "forged post") && !has_text(&alice, &ch, "forged post"));
    let post = alice.send_text(&ch, "공지").unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(has_text(&bob, &ch, "공지"));

    // Comments released: refused on both sides.
    assert!(feature(bob.comment(&ch, &post, "댓글"), "LOCKED_BY_CHAT"));
    bob.send_unchecked(&ch, &text("forged comment", Some(&post))).unwrap();
    assert!(dropped(&carol.sync(0).unwrap(), "comments are released"));
    // Applied: comments arrive and are listed under the post.
    let o = alice.set_chat_feature(&ch, "channel.comments", true, None).unwrap();
    assert!(matches!(o, CommitOutcome::Accepted { .. }));
    sync_all(&mut [&mut bob, &mut carol]);
    assert!(bob.may_comment(&ch).unwrap());
    let c = bob.comment(&ch, &post, "좋아요").unwrap();
    carol.sync(0).unwrap();
    let cs = carol.comments(&ch, &post).unwrap();
    assert_eq!(cs.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), [c.as_str()]);
    assert!(feature(bob.send_text(&ch, "still no posts"), "NOT_ADMIN"));
    // A comment on a comment, or on an unknown post, is refused.
    assert!(matches!(bob.comment(&ch, &c, "nested"), Err(Error::Usage(_))));
    bob.send_unchecked(&ch, &text("orphan", Some(&"ab".repeat(16)))).unwrap();
    assert!(dropped(&carol.sync(0).unwrap(), "unknown post"));
    // Released again: dropped again.
    alice.set_chat_feature(&ch, "channel.comments", false, None).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    bob.send_unchecked(&ch, &text("after release", Some(&post))).unwrap();
    assert!(dropped(&carol.sync(0).unwrap(), "comments are released"));

    // Signatures: the post shows the channel until applied.
    let m = carol.history(&ch, 50).unwrap().into_iter().find(|m| m.id == post).unwrap();
    assert_eq!(carol.author_shown(&ch, &m).unwrap(), None);
    let cm = carol.history(&ch, 50).unwrap().into_iter().find(|m| m.id == c).unwrap();
    assert!(carol.author_shown(&ch, &cm).unwrap().is_some(), "commenters are always shown");
    alice.set_chat_feature(&ch, "channel.signatures", true, None).unwrap();
    carol.sync(0).unwrap();
    assert!(carol.shows_signatures(&ch).unwrap());
    assert_eq!(carol.author_shown(&ch, &m).unwrap().as_deref(), Some("alice"));
    alice.set_chat_feature(&ch, "channel.signatures", false, None).unwrap();
    carol.sync(0).unwrap();
    assert_eq!(carol.author_shown(&ch, &m).unwrap(), None);

    // An admin made by an admin may post; a channel never stops being one.
    let carol_id = carol.member_id();
    alice.make_admin(&ch, carol_id, true).unwrap();
    sync_all(&mut [&mut bob, &mut carol]);
    carol.send_text(&ch, "carol posts").unwrap();
    bob.sync(0).unwrap();
    assert!(has_text(&bob, &ch, "carol posts"));
    let mut s = alice.group_settings(&ch).unwrap();
    s.channel = false;
    assert!(alice.change_group_settings(&ch, &s).is_err());
    assert!(feature(alice.set_chat_feature(&ch, "chat.public_listing", true, None), "PUBLIC_SPACES_ONLY"));
}
