//! `tree-bot-gateway` — runs a bot's device for the bot's own code
//! (docs/BOT_GATEWAY.md). Secrets never go on the command line (other users
//! of the machine can read it): the bot token comes from `TREE_BOT_TOKEN`
//! and the profile passphrase from `TREE_GATEWAY_PASSPHRASE` (or, if unset,
//! the first lines of standard input).

use std::io::BufRead;
use std::process::ExitCode;

use tree_bot_gateway::{Config, Gateway};
use tree_client::Session;

const USAGE: &str = "usage: tree-bot-gateway <command> --profile <file> [options]

commands:
  init --server <url>          register this machine as the bot's device (TREE_BOT_TOKEN)
  reregister                   register again after the owner rotated the token (TREE_BOT_TOKEN: the new one)
  run [--listen <addr>] [--allow-remote] [--poll <seconds>]
                               receive for the bot and serve its local API (default 127.0.0.1:8081)

The local API is authenticated with the bot token: Authorization: Bearer <token>
on /v1/<method>, or the path /bot<token>/<method>. Methods: getMe, getUpdates,
sendMessage, answerCallbackQuery, leaveChat, setWebhook, deleteWebhook,
getWebhookInfo.

Whoever runs the gateway reads everything the bot is sent.";

fn secret(var: &str, lines: &mut impl Iterator<Item = String>, what: &str) -> Result<String, String> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => lines.next().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).ok_or_else(|| format!("{what}: set {var} or give it on standard input")),
    }
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().cloned().ok_or(USAGE)?;
    let profile = arg(&args, "--profile").ok_or(USAGE)?;
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines().map_while(Result::ok);
    match cmd.as_str() {
        "init" => {
            let server = arg(&args, "--server").ok_or(USAGE)?;
            let pass = secret("TREE_GATEWAY_PASSPHRASE", &mut lines, "profile passphrase")?;
            let token = secret("TREE_BOT_TOKEN", &mut lines, "bot token")?;
            let s = Session::create_bot_device(&profile, &pass, &server, &token).map_err(|e| e.to_string())?;
            println!("registered: bot {} device {}", s.account_id(), s.device_id());
        }
        "reregister" => {
            let pass = secret("TREE_GATEWAY_PASSPHRASE", &mut lines, "profile passphrase")?;
            let token = secret("TREE_BOT_TOKEN", &mut lines, "bot token")?;
            let (mut s, _) = Session::open(&profile, &pass).map_err(|e| e.to_string())?;
            s.reregister_bot(&token).map_err(|e| e.to_string())?;
            println!("registered again: device {}", s.device_id());
        }
        "run" => {
            let pass = secret("TREE_GATEWAY_PASSPHRASE", &mut lines, "profile passphrase")?;
            let (s, _) = Session::open(&profile, &pass).map_err(|e| e.to_string())?;
            let mut cfg = Config { allow_remote: args.iter().any(|a| a == "--allow-remote"), ..Config::default() };
            if let Some(l) = arg(&args, "--listen") {
                cfg.listen = l.parse().map_err(|_| format!("--listen {l}: not an address"))?;
            }
            if let Some(p) = arg(&args, "--poll") {
                cfg.poll_secs = p.parse().map_err(|_| "--poll takes seconds".to_string())?;
            }
            let g = Gateway::start(s, cfg).map_err(|e| e.to_string())?;
            println!("bot gateway listening on {}", g.addr);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                if let Some(e) = g.last_error() {
                    eprintln!("receiving: {e}");
                }
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
