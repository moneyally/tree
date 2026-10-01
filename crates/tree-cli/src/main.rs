//! `tree` — command-line Tree client for development and demos.
//!
//! All logic is in `tree-client`; this file only parses arguments and prints.
//! The profile passphrase comes from `TREE_PASSPHRASE` (or the first line of
//! standard input).

use std::process::ExitCode;

use tree_client::{CommitOutcome, Event, Session};

const USAGE: &str = "usage: tree --profile <file> <command>

commands:
  init <name> <server-url> [pow-bits]   create a profile and an account
  whoami                                 account id, device id, member id
  groups                                 list groups
  create-group                           start a group, print its id
  invite <group> <account-id>            add every device of an account
  members <group>                        members, devices, names
  send <group> <text>                    send a message
  sync [wait-seconds]                    receive and print
  remove <group> <member-id>             remove a member (device)
  refresh <group>                        refresh this device's keys
  leave <group>                          ask the others to remove this device
  code <group>                           verification code of the group state";

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

    let (mut s, resubmitted) = Session::open(&profile, &passphrase()?).map_err(e)?;
    for o in resubmitted {
        println!("pending commit resubmitted: {}", outcome(o));
    }
    match rest.as_slice() {
        ["whoami"] => {
            println!("name    {}", s.name());
            println!("account {}", s.account_id());
            println!("device  {}", s.device_id());
            println!("member  {}", s.member_id());
        }
        ["groups"] => {
            for g in s.group_ids().map_err(e)? {
                println!("{}  epoch {}", hex(&g), s.epoch(&g).map_err(e)?);
            }
        }
        ["create-group"] => println!("{}", hex(&s.create_group().map_err(e)?)),
        ["invite", g, account] => println!("{}", outcome(s.invite(&hex_arg(g)?, account).map_err(e)?)),
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
        ["send", g, text @ ..] => {
            let n = s.send_text(&hex_arg(g)?, &text.join(" ")).map_err(e)?;
            println!("delivered to {n} device(s)");
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
        Event::Text { group, from, name, text } => {
            println!("[{}] {} ({}): {}", &hex(group)[..8], name.as_deref().unwrap_or("?"), &from.to_hex()[..8], text)
        }
        Event::Joined { group } => println!("joined group {}", hex(group)),
        Event::Changed { group, added, removed, epoch, own_commit_discarded } => println!(
            "[{}] group changed: epoch {epoch}, {} added, {} removed{}",
            &hex(group)[..8],
            added.len(),
            removed.len(),
            if *own_commit_discarded { " (our pending commit lost and was discarded)" } else { "" }
        ),
        Event::Profile { group, member, name } => println!("[{}] {} is {name}", &hex(group)[..8], &member.to_hex()[..8]),
        Event::RosterUpdated { group } => println!("[{}] member list updated", &hex(group)[..8]),
        Event::LeaveRequested { group, member } => {
            println!("[{}] {} asks to leave: tree remove {} {}", &hex(group)[..8], &member.to_hex()[..8], hex(group), member)
        }
        Event::RemovedFromGroup { group } => println!("[{}] this device was removed", &hex(group)[..8]),
        Event::Held => println!("(a message was kept for later)"),
        Event::Dropped { reason } => println!("(dropped: {reason})"),
    }
}
