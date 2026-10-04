//! `tree` — command-line Tree client for development and demos.
//!
//! All logic is in `tree-client`; this file only parses arguments and prints.
//! The profile passphrase comes from `TREE_PASSPHRASE` (or the first line of
//! standard input).

use std::process::ExitCode;

use tree_client::{CommitOutcome, Event, Session, Words};

const USAGE: &str = "usage: tree --profile <file> <command>

commands:
  init <name> <server-url> [pow-bits]   create a profile and an account
  whoami                                 account id, device id, member id
  recover <name> <server-url> [revoke] [pow-bits]
                                         new device for my account from the recovery phrase
                                         (TREE_RECOVERY_PHRASE or stdin); revoke = remove all other devices
  recovery-phrase [12|24] [ko]           make a new recovery phrase (replaces the old one)
  recovery-release                       no recovery for this account (TREE_CURRENT_PHRASE: at once)
  recovery-status                        is recovery on; any pending change
  push <endpoint-url> | push off          content-free wake-ups through a push gateway
  groups                                 list groups
  create-group                           start a group, print its id
  invite <group> <account-id|@name>      add every device of an account
  invite-link <group> [hours] [uses]     make an invite link (admins; default 24 h, 10 uses)
  revoke-links <group>                   revoke my links, release chat.invite_link
  join <link>                            ask to join a group through its link
  username <name> [hidden]               set my @username (only its hash goes to the server)
  username-release                       drop my @username
  find <@name>                           account id behind a @username
  members <group>                        members, devices, names
  send <group> <text>                    send a message (prints its id)
  send-all <group> <text>                send with @all (chat.mention_all)
  send-voice <group> <path> <ms>         send a voice message (chat.voice)
  screenshot-block <group> on|off        my own screenshot block for this chat
  edit <group> <id> <text> | delete <group> <id> | react <group> <id> <emoji>
  history <group> | search <text>        messages kept on this device
  report <group> <reason> <id>...        report messages of one sender to the operator
  send-file <group> <path>               send an encrypted attachment
  download <file-id> <path>              fetch, check and save a received attachment
  sync [wait-seconds]                    receive and print
  remove <group> <member-id>             remove a member (device)
  refresh <group>                        refresh this device's keys
  refresh-all                            refresh keys in every group (suspected compromise)
  delete-account                         delete the account everywhere (TREE_CONFIRM=delete)
  leave <group>                          ask the others to remove this device
  code <group>                           verification code of the group state
  contacts                               known accounts and whether verified
  safety <account-id>                    safety number to compare out of band
  verify <account-id>                    mark verified after comparing
  add-contact <account-id>               trust this account (its chats are not requests)
  requests                               pending chat requests and invitations
  accept <group> | decline <group> [block]
  block <account-id> | unblock <account-id>
  settings                               my apply/release settings
  apply <feature> [option] | release <feature>
  group-settings <group>                 admins, name, chat settings (admins change them)
  make-admin | unmake-admin <group> <member-id>
  name <group> <text>                    set the group name
  group-apply <group> <chat.feature> [option] | group-release <group> <chat.feature>";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn passphrase() -> Result<String, String> {
    if let Ok(p) = std::env::var("TREE_PASSPHRASE") {
        return Ok(p);
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn hex_arg(s: &str) -> Result<Vec<u8>, String> {
    hex_decode(s).ok_or_else(|| format!("{s:?} is not hex"))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn outcome(o: CommitOutcome) -> String {
    match o {
        CommitOutcome::Accepted { epoch } => format!("accepted, epoch {epoch}"),
        CommitOutcome::Lost => "another commit won this epoch; run sync and try again".into(),
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (profile, rest) = match args.as_slice() {
        [flag, p, rest @ ..] if flag == "--profile" => (p.clone(), rest.to_vec()),
        _ => return Err(USAGE.into()),
    };
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    let e = |e: tree_client::Error| e.to_string();

    if let ["init", name, server, more @ ..] = rest.as_slice() {
        let bits = more.first().map(|b| b.parse().map_err(|_| "pow-bits must be a number")).transpose()?.unwrap_or(20);
        let s = Session::create(&profile, &passphrase()?, name, server, bits).map_err(e)?;
        println!("account {}", s.account_id());
        println!("device  {}", s.device_id());
        println!("member  {}", s.member_id());
        return Ok(());
    }

    if let ["recover", name, server, more @ ..] = rest.as_slice() {
        let revoke = more.contains(&"revoke");
        let bits = more.iter().find_map(|b| b.parse().ok()).unwrap_or(20);
        let phrase = match std::env::var("TREE_RECOVERY_PHRASE") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("recovery phrase:");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
                line
            }
        };
        let s = Session::recover(&profile, &passphrase()?, name, server, &phrase, revoke, bits).map_err(e)?;
        println!("account {} recovered on a new device", s.account_id());
        println!("device  {}", s.device_id());
        println!("contacts must add this device again; they will see a key change");
        return Ok(());
    }

    let (mut s, resubmitted) = Session::open(&profile, &passphrase()?).map_err(e)?;
    for o in resubmitted {
        println!("pending commit resubmitted: {}", outcome(o));
    }
    match rest.as_slice() {
        ["whoami"] => {
            println!("name    {}", s.name());
            if let Some(u) = s.username().map_err(e)? {
                println!("user    @{u}");
            }
            println!("account {}", s.account_id());
            println!("device  {}", s.device_id());
            println!("member  {}", s.member_id());
        }
        ["groups"] => {
            for g in s.group_ids().map_err(e)? {
                println!("{}  epoch {}", hex(&g), s.epoch(&g).map_err(e)?);
            }
        }
        ["recovery-phrase", more @ ..] => {
            let words = more.iter().find_map(|w| w.parse().ok()).unwrap_or(24);
            let list = if more.contains(&"ko") { Words::Korean } else { Words::English };
            let current = std::env::var("TREE_CURRENT_PHRASE").ok();
            let (p, st) = s.new_recovery_phrase(words, list, current.as_deref()).map_err(e)?;
            println!("{}", p.words());
            eprintln!("write these words down and keep them offline; they are shown only now.");
            eprintln!("whoever has them can take over this account.");
            if let Some((_, at)) = st.pending {
                eprintln!("the old phrase stays valid until {at} (unix time): give TREE_CURRENT_PHRASE to replace it at once");
            }
        }
        ["push", "off"] => {
            s.set_push_endpoint(None).map_err(e)?;
            println!("push wake-ups off");
        }
        ["push", url] => {
            s.set_push_endpoint(Some(url)).map_err(e)?;
            println!("push wake-ups to {url}");
        }
        ["recovery-release"] => {
            let current = std::env::var("TREE_CURRENT_PHRASE").ok();
            match s.release_recovery(current.as_deref()).map_err(e)?.pending {
                Some((_, at)) => println!("recovery ends at {at} (unix time); until then the phrase still works"),
                None => println!("recovery released: this account can no longer be recovered"),
            }
        }
        ["recovery-status"] => {
            let st = s.recovery_status().map_err(e)?;
            println!("recovery {}", if st.active { "on" } else { "off" });
            if let Some((action, at)) = st.pending {
                println!("!! pending {action} at {at} (unix time). If this was not you, recover the account with your phrase now.");
            }
        }
        ["invite-link", g, more @ ..] => {
            let hours: i64 = more.first().and_then(|h| h.parse().ok()).unwrap_or(24);
            let uses: u32 = more.get(1).and_then(|u| u.parse().ok()).unwrap_or(10);
            println!("{}", s.create_invite_link(&hex_arg(g)?, hours * 3600, uses).map_err(e)?);
            eprintln!("valid {hours} h, {uses} uses; anyone with the link can ask to join");
        }
        ["revoke-links", g] => {
            s.revoke_invite_links(&hex_arg(g)?).map_err(e)?;
            println!("links revoked; chat.invite_link released");
        }
        ["join", link] => {
            let owner = s.join_invite_link(link).map_err(e)?;
            println!("asked {owner} to add you; you join when their device syncs");
        }
        ["create-group"] => println!("{}", hex(&s.create_group().map_err(e)?)),
        ["invite", g, who] => {
            let account = if who.starts_with('@') {
                s.find(who).map_err(e)?.ok_or_else(|| format!("no one is called {who}"))?
            } else {
                who.to_string()
            };
            let (o, warnings) = s.invite(&hex_arg(g)?, &account).map_err(e)?;
            for w in &warnings {
                print_event(w);
            }
            println!("{}", outcome(o));
        }
        ["username", name] => {
            let n = s.set_username(name).map_err(e)?;
            let found = format!("{:?}", s.feature("user.discoverable").map_err(e)?.state) == "Applied";
            println!("you are @{n}{}", if found { "" } else { " (not findable: user.discoverable is released)" });
        }
        ["username", name, "hidden"] => {
            s.release_feature("user.discoverable").map_err(e)?;
            println!("you are @{} (not findable by search; `apply user.discoverable` to change)", s.set_username(name).map_err(e)?);
        }
        ["username-release"] => {
            s.release_username().map_err(e)?;
            println!("username released");
        }
        ["find", name] => match s.find(name).map_err(e)? {
            Some(a) => println!("{a}"),
            None => println!("no one is called {name} (or they hid their name)"),
        },
        ["send-file", g, path] => {
            let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let name = std::path::Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("file");
            let f = s.send_file(&hex_arg(g)?, &bytes, name, "application/octet-stream", false).map_err(e)?;
            println!("sent {} ({} bytes) as attachment {}", f.name, f.size, f.id);
        }
        ["download", id, out] => {
            let f = s.received_file(id).map_err(e)?.ok_or("no such received file")?;
            let bytes = s.download(&f).map_err(e)?;
            std::fs::write(out, &bytes).map_err(|e| format!("{out}: {e}"))?;
            println!("saved {} ({} bytes, checked) to {out}", f.name, bytes.len());
        }
        ["group-settings", g] => {
            let st = s.group_settings(&hex_arg(g)?).map_err(e)?;
            println!("name    {}", st.name.as_deref().unwrap_or("(none)"));
            for a in &st.admins {
                println!("admin   {a}");
            }
            for (k, v) in &st.features {
                println!("{k:<24} {}{}", if v.applied { "applied" } else { "released" }, v.option.as_deref().map(|o| format!(" {o}")).unwrap_or_default());
            }
        }
        ["make-admin", g, member] | ["unmake-admin", g, member] => {
            let id = tree_client::MemberId::from_hex(member).ok_or("member id must be 64 hex digits")?;
            let admin = rest[0] == "make-admin";
            println!("{}", outcome(s.make_admin(&hex_arg(g)?, id, admin).map_err(e)?));
        }
        ["name", g, name @ ..] => println!("{}", outcome(s.set_group_name(&hex_arg(g)?, Some(name.join(" "))).map_err(e)?)),
        ["group-apply", g, key, more @ ..] => {
            println!("{}", outcome(s.set_chat_feature(&hex_arg(g)?, key, true, more.first().map(|o| o.to_string())).map_err(e)?))
        }
        ["group-release", g, key] => println!("{}", outcome(s.set_chat_feature(&hex_arg(g)?, key, false, None).map_err(e)?)),
        ["requests"] => {
            for g in s.group_ids().map_err(e)? {
                if let tree_client::GroupStatus::Request { from } = s.group_status(&g).map_err(e)? {
                    println!("{}  from {}", hex(&g), from.as_deref().unwrap_or("(not known yet)"));
                }
            }
        }
        ["accept", g] => {
            s.accept_request(&hex_arg(g)?).map_err(e)?;
            println!("accepted");
        }
        ["decline", g, more @ ..] => {
            s.decline(&hex_arg(g)?, more.first() == Some(&"block")).map_err(e)?;
            println!("declined");
        }
        ["block", account] => {
            s.block(account).map_err(e)?;
            println!("{account} blocked");
        }
        ["unblock", account] => {
            s.unblock(account).map_err(e)?;
            println!("{account} unblocked");
        }
        ["add-contact", account] => {
            s.add_contact(account).map_err(e)?;
            println!("{account} added to contacts");
        }
        ["settings"] => {
            for f in s.features().map_err(e)? {
                let pending = s.release_pending(f.key).map_err(e)?;
                println!(
                    "{:<28} {:<8} {}{}{}",
                    f.key,
                    format!("{:?}", f.state).to_lowercase(),
                    f.option.as_deref().unwrap_or(""),
                    match &f.locked_by {
                        Some(r) => format!("  (locked: {r:?})"),
                        None => String::new(),
                    },
                    pending.map(|t| format!("  (release pending until {t}, unix time)")).unwrap_or_default(),
                );
            }
        }
        ["apply", key, more @ ..] => {
            let st = s.apply_feature(key, more.first().map(|o| o.to_string())).map_err(e)?;
            println!("{} {:?} {}", st.key, st.state, st.option.as_deref().unwrap_or(""));
        }
        ["release", key] => {
            let st = s.release_feature(key).map_err(e)?;
            match s.release_pending(key).map_err(e)? {
                Some(t) => println!("{} {:?}: release pending until {t} (unix time)", st.key, st.state),
                None => println!("{} {:?}", st.key, st.state),
            }
        }
        ["contacts"] => {
            for c in s.contacts().map_err(e)? {
                println!("{}  {} device(s)  {}", c.account, c.members.len(), if c.verified { "verified" } else { "not verified" });
            }
        }
        ["safety", account] => {
            println!("{}", s.safety_number(account).map_err(e)?);
            println!("compare these digits with {account} in person or on a call; then: tree verify {account}");
        }
        ["verify", account] => {
            s.verify(account, None).map_err(e)?;
            println!("{account} marked verified");
        }
        ["members", g] => {
            for m in s.members(&hex_arg(g)?).map_err(e)? {
                println!(
                    "{}  {:<22}  {}{}",
                    m.id,
                    m.device.as_deref().unwrap_or("(device unknown)"),
                    m.name.as_deref().unwrap_or("(name unknown)"),
                    if m.duplicate_name { "  [same name as another member]" } else { "" }
                );
            }
        }
        ["send", g, text @ ..] => println!("sent message {}", s.send_text(&hex_arg(g)?, &text.join(" ")).map_err(e)?),
        ["send-all", g, text @ ..] => {
            let o = tree_client::TextOptions { all: true, ..Default::default() };
            println!("sent message {}", s.send_text_with(&hex_arg(g)?, &text.join(" "), &o).map_err(e)?)
        }
        ["send-voice", g, path, ms] => {
            let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let ms: u64 = ms.parse().map_err(|_| "duration must be milliseconds")?;
            let f = s.send_voice(&hex_arg(g)?, &bytes, "audio/ogg", ms).map_err(e)?;
            println!("sent voice message {} ({} ms)", f.msg_id, ms);
        }
        ["screenshot-block", g, on] => {
            s.set_screenshot_block(&hex_arg(g)?, *on == "on").map_err(e)?;
            println!("screenshot block for this chat: {}", if s.screenshot_blocked(&hex_arg(g)?).map_err(e)? { "on" } else { "off" });
        }
        ["edit", g, id, text @ ..] => {
            s.edit(&hex_arg(g)?, id, &text.join(" ")).map_err(e)?;
            println!("edited");
        }
        ["delete", g, id] => {
            s.delete_for_all(&hex_arg(g)?, id).map_err(e)?;
            println!("deleted for everyone");
        }
        ["report", g, reason, ids @ ..] if !ids.is_empty() => {
            let r = s.report(&hex_arg(g)?, ids, reason).map_err(e)?;
            println!("report {} filed ({})", r.id, if r.verified { "verified" } else { "NOT verified" });
        }
        ["react", g, id, emoji] => {
            s.react(&hex_arg(g)?, id, emoji, false).map_err(e)?;
            println!("reacted");
        }
        ["history", g] => {
            for m in s.history(&hex_arg(g)?, 50).map_err(e)? {
                let body = if m.deleted { "(deleted)".to_string() } else { m.text.clone().unwrap_or_default() };
                let reacts: Vec<String> = m.reactions.iter().map(|(e, who)| format!("{e}{}", who.len())).collect();
                println!(
                    "{}  {}  {}{}{} {}",
                    m.id,
                    &m.sender[..8],
                    body,
                    if m.edited_at.is_some() { " (edited)" } else { "" },
                    if m.expires_at.is_some() { " (disappears)" } else { "" },
                    reacts.join(" ")
                );
            }
        }
        ["search", text @ ..] => {
            for m in s.search(&text.join(" ")).map_err(e)? {
                println!("[{}] {}  {}", &hex(&m.group_id)[..8], m.id, m.text.unwrap_or_default());
            }
        }
        ["sync", more @ ..] => {
            let wait = more.first().map(|w| w.parse().map_err(|_| "wait must be a number")).transpose()?.unwrap_or(0);
            for ev in s.sync(wait).map_err(e)? {
                print_event(&ev);
            }
        }
        ["remove", g, member] => {
            let id = tree_client::MemberId::from_hex(member).ok_or("member id must be 64 hex digits")?;
            println!("{}", outcome(s.remove(&hex_arg(g)?, &[id]).map_err(e)?));
        }
        ["refresh", g] => println!("{}", outcome(s.refresh_keys(&hex_arg(g)?).map_err(e)?)),
        ["delete-account"] => {
            if std::env::var("TREE_CONFIRM").as_deref() != Ok("delete") {
                return Err("this deletes the account everywhere; run again with TREE_CONFIRM=delete".into());
            }
            s.delete_account(&profile).map_err(e)?;
            println!("account deleted, profile removed");
            return Ok(());
        }
        ["refresh-all"] => {
            let done = s.refresh_all().map_err(e)?;
            println!("keys refreshed in {} group(s)", done.len());
        }
        ["leave", g] => {
            s.leave(&hex_arg(g)?).map_err(e)?;
            println!("leave request sent");
        }
        ["code", g] => println!("{}", hex(&s.verification_code(&hex_arg(g)?).map_err(e)?)),
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn print_event(ev: &Event) {
    match ev {
        Event::Text { group, id, from, name, text, request, mentions_me, .. } => println!(
            "[{}]{}{} {} ({}): {}   #{id}",
            &hex(group)[..8],
            if *request { " [request]" } else { "" },
            if *mentions_me { " [@you]" } else { "" },
            name.as_deref().unwrap_or("?"),
            &from.to_hex()[..8],
            text
        ),
        Event::Edited { group, id, from, text } => println!("[{}] {} edited #{id}: {text}", &hex(group)[..8], &from.to_hex()[..8]),
        Event::Deleted { group, id, from } => println!("[{}] {} deleted #{id}", &hex(group)[..8], &from.to_hex()[..8]),
        Event::Reaction { group, id, from, emoji, remove } => println!(
            "[{}] {} {} {emoji} on #{id}",
            &hex(group)[..8],
            &from.to_hex()[..8],
            if *remove { "took back" } else { "reacted" }
        ),
        Event::File { group, from, name, file, request } => println!(
            "[{}]{} {} ({}) sent a file: {} ({} bytes): tree download {} <path>",
            &hex(group)[..8],
            if *request { " [request]" } else { "" },
            name.as_deref().unwrap_or("?"),
            &from.to_hex()[..8],
            file.name,
            file.size,
            file.id
        ),
        Event::Request { group, from, direct } => println!(
            "[{}] {} from {from}: tree accept {} / tree decline {} [block]",
            &hex(group)[..8],
            if *direct { "chat request" } else { "group invitation" },
            hex(group),
            hex(group)
        ),
        Event::Declined { group, from, reason } => println!("[{}] declined (from {from}): {reason}", &hex(group)[..8]),
        Event::Joined { group } => println!("joined group {}", hex(group)),
        Event::Changed { group, added, removed, epoch, own_commit_discarded, settings_changed } => println!(
            "[{}] group changed: epoch {epoch}, {} added, {} removed{}{}",
            &hex(group)[..8],
            added.len(),
            removed.len(),
            if *settings_changed { ", settings changed (tree group-settings)" } else { "" },
            if *own_commit_discarded { " (our pending commit lost and was discarded)" } else { "" }
        ),
        Event::Profile { group, member, name } => println!("[{}] {} is {name}", &hex(group)[..8], &member.to_hex()[..8]),
        Event::RosterUpdated { group } => println!("[{}] member list updated", &hex(group)[..8]),
        Event::LeaveRequested { group, member, quiet } => {
            println!(
                "[{}] {} asks to leave{}: tree remove {} {}",
                &hex(group)[..8],
                &member.to_hex()[..8],
                if *quiet { " quietly" } else { "" },
                hex(group),
                member
            )
        }
        Event::RemovedFromGroup { group } => println!("[{}] this device was removed", &hex(group)[..8]),
        Event::KeyChanged { account, new_members, was_verified } => println!(
            "!! {account} has {} new device key(s){}: compare the safety number again (tree safety {account})",
            new_members.len(),
            if *was_verified { " since you verified it" } else { "" }
        ),
        Event::Held => println!("(a message was kept for later)"),
        Event::Dropped { reason } => println!("(dropped: {reason})"),
        Event::InviteLinkUsed { group, account } => println!("[{}] {account} joined through your invite link", &hex(group)[..8]),
        Event::Read { group, from, ids } => println!("[{}] {} read {} message(s)", &hex(group)[..8], &from.to_hex()[..8], ids.len()),
        Event::Typing { group, from, on } => {
            println!("[{}] {} {}", &hex(group)[..8], &from.to_hex()[..8], if *on { "is typing" } else { "stopped typing" })
        }
        Event::GroupSafetyNotice { group, adder } => {
            println!("[{}] !! {adder} is not a contact and added you to this group; check who is in it (tree members)", &hex(group)[..8])
        }
    }
}
