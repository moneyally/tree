//! Bots (PROTOCOL.md 8.16, APP_PROTOCOL.md 11): the bot factory for owners,
//! the bot label, bot lanes (privacy mode), inline buttons and callbacks,
//! `chat.bots`, and what a bot's gateway device needs.
//!
//! A bot is an ordinary MLS member: the device of a bot account, run by the
//! bot's gateway on the developer's server. Groups with bots stay end to end
//! encrypted; the bot's gateway (and so the bot's developer) reads what the
//! bot is sent.
//!
//! **Label.** A member is a bot when the server says so, never because a
//! roster says so: the server marks every message a bot's device sends
//! (`bot` in the mailbox), names bot devices and bot accounts in
//! [`Session::refresh_bots`] lookups, and says when a claimed account is a
//! bot. Labels are only ever added (`botmem/<group>`); no roster removes one.
//!
//! **Lane (privacy mode).** Senders decide what reaches a bot's device: with
//! `bot.privacy_mode` applied (the default) a bot gets, from honest clients,
//! only what is addressed to it: a command (`/cmd`, or `/cmd@itsname`), a
//! text that mentions it or replies to one of its messages, a press of one
//! of its buttons, and the group's rosters, names, topics and leave
//! requests (it needs them to answer). With it released it gets every
//! message. Never: shared history, another member's button press, answers
//! meant for others. Commits (adds, removals, group settings) reach every
//! member, bots too: MLS needs them. While `chat.bots` is released nothing
//! is sent to bots and what bots send is dropped.
//!
//! The bot's device holds the group's keys, so privacy mode protects against
//! the bot acting alone, not against a member's modified client forwarding
//! messages to it, nor against the server copying other members'
//! ciphertext into the bot's mailbox (the server sees every recipient list
//! and does not do this; a server that did would be detected by nobody).
//!
//! **Buttons.** A bot's text may carry rows of buttons; a press sends
//! [`Payload::Callback`] to that bot's devices only, the bot may answer the
//! presser only. A device accepts a press only for its own message and for
//! a button that message has; an answer only from the bot it pressed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tree_core::MemberId;
use zeroize::Zeroizing;

use crate::messages::{new_id, now};
use crate::payload::{Button, Payload};
use crate::{accounts_key, api, CommitOutcome, Error, Event, Session, StoredMessage};

/// Rows of buttons under one message, buttons per row.
pub const MAX_ROWS: usize = 8;
pub const MAX_PER_ROW: usize = 8;
/// Characters of a button's text and of its data.
pub const MAX_BUTTON_TEXT: usize = 64;
pub const MAX_BUTTON_DATA: usize = 64;
/// Characters of a bot's answer to a press.
pub const MAX_ANSWER: usize = 200;
/// A bot's settings as looked up are used this long (seconds).
pub const BOT_INFO_TTL: i64 = 300;

/// The profile of this device's bot, if it is a bot's gateway device.
const SELF: &str = "bot/self";
/// SHA-256 of the bot token this gateway device registered with.
const TOKEN_HASH: &str = "bot/token_sha256";
/// Until when (unix seconds) the server is taken to have the bot platform
/// released, after it said so.
const OFF_UNTIL: &str = "bot/platform_off_until";
/// How long that answer is used before asking again (seconds).
pub const OFF_RECHECK: i64 = 60;

fn info_key(account: &str) -> String {
    format!("botinfo/{account}")
}
fn lane_key(g: &[u8]) -> String {
    format!("botlane/{}", hex::encode(g))
}
fn members_key(g: &[u8]) -> String {
    format!("botmem/{}", hex::encode(g))
}
fn press_key(g: &[u8], id: &str) -> String {
    format!("botpress/{}/{id}", hex::encode(g))
}
fn query_key(g: &[u8], id: &str) -> String {
    format!("botquery/{}/{id}", hex::encode(g))
}
pub(crate) fn inner_key(local_id: &str) -> String {
    format!("botlane-item/{local_id}")
}

/// One command a bot lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BotCommand {
    pub command: String,
    #[serde(default)]
    pub description: String,
}

/// What anyone may know about a bot (from the server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BotInfo {
    pub account: String,
    pub username: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub commands: Vec<BotCommand>,
    /// `bot.privacy_mode`: only messages addressed to it.
    pub privacy_mode: bool,
    /// `bot.join_groups`: may be added to groups.
    pub join_groups: bool,
    /// `bot.inline`.
    pub inline: bool,
    /// `bot.directory`.
    pub directory: bool,
}

impl BotInfo {
    fn from_json(v: &Value) -> Option<Self> {
        let mut b: BotInfo = serde_json::from_value(v.clone()).ok()?;
        b.commands.retain(|c| !c.command.is_empty());
        (!b.account.is_empty()).then_some(b)
    }
}

/// One bot feature as the owner's screen draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotFeature {
    pub key: String,
    pub applied: bool,
    /// Why it can never be applied (the money features).
    pub locked: Option<String>,
}

/// A bot as its owner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedBot {
    pub info: BotInfo,
    /// A token works (none after a revoke).
    pub token_active: bool,
    /// The gateway device registered under the current token (0 or 1).
    pub gateway_devices: u32,
    /// People who contacted the bot.
    pub contacts: u32,
    /// Open reports about the bot.
    pub reports_open: u32,
    pub features: Vec<BotFeature>,
}

impl OwnedBot {
    fn from_json(v: &Value) -> Result<Self, Error> {
        let info = BotInfo::from_json(v).ok_or_else(|| Error::Protocol("bad bot from server".into()))?;
        let n = |k: &str| v[k].as_u64().unwrap_or(0) as u32;
        let features = v["features"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|f| BotFeature {
                key: f["key"].as_str().unwrap_or_default().to_string(),
                applied: f["state"] == "applied",
                locked: f["locked"].as_str().map(str::to_string),
            })
            .collect();
        Ok(OwnedBot {
            info,
            token_active: v["token_active"].as_bool().unwrap_or(false),
            gateway_devices: n("gateway_devices"),
            contacts: n("contacts"),
            reports_open: n("reports_open"),
            features,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Cached {
    /// `None`: the account is not a bot.
    info: Option<BotInfo>,
    at: i64,
}

/// What this device knows about the bots among a group's devices.
#[derive(Serialize, Deserialize, Default)]
struct Lane {
    /// Devices and accounts the server was asked about.
    checked: BTreeSet<String>,
    accounts: BTreeSet<String>,
    /// Bot device -> bot account.
    bots: BTreeMap<String, String>,
}

/// Fits the button limits: at most [`MAX_ROWS`] rows of at most
/// [`MAX_PER_ROW`] buttons, each with 1 to [`MAX_BUTTON_TEXT`] characters
/// of text and 1 to [`MAX_BUTTON_DATA`] of data, no control characters.
pub fn valid_keyboard(kb: &[Vec<Button>]) -> bool {
    let ok = |s: &str, max: usize| !s.is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control);
    kb.len() <= MAX_ROWS && kb.iter().all(|r| !r.is_empty() && r.len() <= MAX_PER_ROW && r.iter().all(|b| ok(&b.text, MAX_BUTTON_TEXT) && ok(&b.data, MAX_BUTTON_DATA)))
}

/// Adds the buttons to a stored text's data.
pub(crate) fn with_kb(data: Option<Vec<u8>>, kb: &[Vec<Button>]) -> Option<Vec<u8>> {
    if kb.is_empty() {
        return data;
    }
    let mut v: Value = data.as_deref().and_then(|d| serde_json::from_slice(d).ok()).unwrap_or_else(|| json!({}));
    v["kb"] = serde_json::to_value(kb).expect("JSON");
    Some(serde_json::to_vec(&v).expect("JSON"))
}

/// The buttons of a stored message (a bot's text), if any.
pub fn message_buttons(m: &StoredMessage) -> Vec<Vec<Button>> {
    m.data
        .as_deref()
        .and_then(|d| serde_json::from_slice::<Value>(d).ok())
        .and_then(|v| serde_json::from_value(v["kb"].clone()).ok())
        .unwrap_or_default()
}

/// Is `text` a command for the bot `username`: `/cmd` (every bot in the
/// group) or `/cmd@username`?
pub fn is_command_for(text: &str, username: &str) -> bool {
    let Some(first) = text.split_whitespace().next() else { return false };
    let Some(cmd) = first.strip_prefix('/') else { return false };
    match cmd.split_once('@') {
        None => !cmd.is_empty(),
        Some((c, name)) => !c.is_empty() && name.eq_ignore_ascii_case(username),
    }
}

fn valid_query_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Session {
    // --- the factory (owners) ---

    /// Creates a bot owned by this account: solves the same proof of work
    /// as a signup (`pow_bits`, the server's). Returns the bot and its token,
    /// which the server shows only this once: give it to the bot's gateway,
    /// never to anyone else.
    pub fn create_bot(&self, username: &str, pow_bits: u32) -> Result<(OwnedBot, String), Error> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| Error::Protocol(e.to_string()))?;
        let nonce = api::solve_bot_pow(&key, pow_bits);
        let body = json!({ "username": username, "pow_key": api::b64(&key), "pow_nonce": nonce });
        let v = self.api.bots(&self.creds, Method::POST, "/v1/bots", Some(&body))?;
        let token = v["token"].as_str().ok_or_else(|| Error::Protocol("no token from server".into()))?.to_string();
        Ok((OwnedBot::from_json(&v["bot"])?, token))
    }

    /// This account's bots.
    pub fn my_bots(&self) -> Result<Vec<OwnedBot>, Error> {
        let v = self.api.bots(&self.creds, Method::GET, "/v1/bots", None)?;
        v["bots"].as_array().into_iter().flatten().map(OwnedBot::from_json).collect()
    }

    /// One of this account's bots.
    pub fn owned_bot(&self, account: &str) -> Result<OwnedBot, Error> {
        let v = self.api.bots(&self.creds, Method::GET, &format!("/v1/bots/{account}"), None)?;
        if v.get("owner").is_none() {
            return Err(Error::Usage("not your bot".into()));
        }
        OwnedBot::from_json(&v)
    }

    /// Sets the bot's description and command list (`None`: unchanged).
    pub fn set_bot_profile(&self, account: &str, description: Option<&str>, commands: Option<&[BotCommand]>) -> Result<OwnedBot, Error> {
        let mut body = json!({});
        if let Some(d) = description {
            body["description"] = json!(d);
        }
        if let Some(c) = commands {
            body["commands"] = json!(c);
        }
        OwnedBot::from_json(&self.api.bots(&self.creds, Method::PUT, &format!("/v1/bots/{account}/profile"), Some(&body))?)
    }

    /// Applies or releases a bot feature (`bot.privacy_mode`,
    /// `bot.join_groups`, `bot.inline`, `bot.directory`). The money features
    /// (`bot.payments`, `bot.tips`, `bot.pay_out_points`) can never be
    /// applied: refused here and by the server.
    pub fn set_bot_feature(&self, account: &str, key: &str, apply: bool) -> Result<OwnedBot, Error> {
        use tree_core::features::{Caller, Plan, Registry, Scope};
        let mut r = Registry::standard();
        let owner = Caller { plan: Plan::Free, is_admin: true };
        if !r.list(Scope::Bot).iter().any(|s| s.key == key) {
            return Err(Error::Feature("UNKNOWN_FEATURE".into()));
        }
        let _ = if apply { r.apply(key, None, owner) } else { r.release(key, owner) }?;
        let action = if apply { "apply" } else { "release" };
        OwnedBot::from_json(&self.api.bots(&self.creds, Method::POST, &format!("/v1/bots/{account}/features/{key}/{action}"), None)?)
    }

    /// A new token for the bot (shown once). The old one, and the gateway
    /// device registered with it, stop working at once; the gateway
    /// registers again with the new token.
    pub fn rotate_bot_token(&self, account: &str) -> Result<String, Error> {
        let v = self.api.bots(&self.creds, Method::POST, &format!("/v1/bots/{account}/token/rotate"), None)?;
        v["token"].as_str().map(str::to_string).ok_or_else(|| Error::Protocol("no token from server".into()))
    }

    /// No token works for the bot any more (until a rotation makes one);
    /// its gateway device stops at once.
    pub fn revoke_bot_token(&self, account: &str) -> Result<OwnedBot, Error> {
        OwnedBot::from_json(&self.api.bots(&self.creds, Method::POST, &format!("/v1/bots/{account}/token/revoke"), None)?["bot"])
    }

    /// Deletes the bot (its account, gateway device and contacts).
    pub fn delete_bot(&self, account: &str) -> Result<(), Error> {
        self.api.bots(&self.creds, Method::DELETE, &format!("/v1/bots/{account}"), None)?;
        Ok(())
    }

    // --- finding bots (everyone) ---

    /// Bots listed in the directory (`bot.directory`) matching `query`.
    pub fn bot_directory(&self, query: &str) -> Result<Vec<BotInfo>, Error> {
        let q: String = query.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == ' ').collect();
        let v = self.api.bots(&self.creds, Method::GET, &format!("/v1/bots/directory?q={}", q.replace(' ', "+")), None)?;
        Ok(v["bots"].as_array().into_iter().flatten().filter_map(BotInfo::from_json).collect())
    }

    /// A bot by its exact @username (listed or not).
    pub fn find_bot(&self, username: &str) -> Result<Option<BotInfo>, Error> {
        let name: String = username.trim().trim_start_matches('@').chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        match self.api.bots(&self.creds, Method::GET, &format!("/v1/bots/by-username/{name}"), None) {
            Ok(v) => Ok(BotInfo::from_json(&v)),
            Err(Error::Server { status: 404 | 400, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Whether `account` is a bot, as this device last heard from the
    /// server (no network).
    pub fn cached_bot(&self, account: &str) -> Result<Option<BotInfo>, Error> {
        Ok(self.cache(account)?.and_then(|c| c.info))
    }

    fn cache(&self, account: &str) -> Result<Option<Cached>, Error> {
        Ok(self.client.app_data(&info_key(account))?.and_then(|v| serde_json::from_slice(&v).ok()))
    }

    fn save_cache(&self, account: &str, info: Option<BotInfo>) -> Result<(), Error> {
        let c = Cached { info, at: now() };
        Ok(self.client.set_app_data(&info_key(account), Some(&serde_json::to_vec(&c).expect("JSON")))?)
    }

    /// Whether `account` is a bot: the cached answer while fresh, else the
    /// server's. `None` also when the server cannot say (the bot platform
    /// is released: then no bot can act).
    pub fn bot_info(&self, account: &str) -> Result<Option<BotInfo>, Error> {
        if let Some(c) = self.cache(account)? {
            if now() - c.at < BOT_INFO_TTL {
                return Ok(c.info);
            }
        }
        match self.api.bots(&self.creds, Method::POST, "/v1/bots/lookup", Some(&json!({ "accounts": [account] }))) {
            Ok(v) => {
                let info = v["bots"].as_array().into_iter().flatten().filter_map(BotInfo::from_json).find(|b| b.account == account);
                self.save_cache(account, info.clone())?;
                Ok(info)
            }
            Err(Error::Server { status: 403, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The person stops the bot: it can no longer reach them outside the
    /// groups they share. [`Session::block`] of a bot also does this.
    pub fn stop_bot(&self, account: &str) -> Result<(), Error> {
        self.api.bots(&self.creds, Method::POST, &format!("/v1/bots/{account}/stop"), None)?;
        Ok(())
    }

    /// Blocks a bot: its messages are dropped, its chats declined, and the
    /// server no longer lets it reach this account (best effort).
    pub fn block_bot(&self, account: &str) -> Result<(), Error> {
        self.block(account)?;
        let _ = self.stop_bot(account);
        Ok(())
    }

    /// Adds a bot (account id or @username) to the group: refused while
    /// the group releases `chat.bots`, and for a group (not a 1:1) while
    /// the bot's owner releases `bot.join_groups`.
    pub fn add_bot(&mut self, gid: &[u8], who: &str) -> Result<(CommitOutcome, Vec<Event>), Error> {
        let account = if who.trim().starts_with('@') || !crate::is_device_id(who.trim()) {
            self.find_bot(who)?.ok_or_else(|| Error::Usage("no such bot".into()))?.account
        } else {
            who.trim().to_string()
        };
        if self.bot_info(&account)?.is_none() {
            return Err(Error::Usage("that account is not a bot".into()));
        }
        self.invite(gid, &account)
    }

    /// Checks before `account` is added to the group (from `invite`): a bot
    /// needs `chat.bots`, and `bot.join_groups` unless this is a 1:1 chat.
    /// Returns whether the account is a bot.
    pub(crate) fn check_bot_add(&mut self, gid: &[u8], account: &str) -> Result<bool, Error> {
        let Some(info) = self.bot_info(account)? else { return Ok(false) };
        if !self.chat_feature(gid, "chat.bots")?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        if !info.join_groups && self.group(gid)?.members().len() > 1 {
            return Err(Error::Feature("BOT_NO_GROUPS".into()));
        }
        Ok(true)
    }

    // --- labels ---

    fn bot_members(&self, gid: &[u8]) -> Result<BTreeMap<String, String>, Error> {
        Ok(self.map(&members_key(gid))?)
    }

    /// The bot account of member `m`, if the server said it is a bot.
    pub fn bot_member(&self, gid: &[u8], m: &MemberId) -> Result<Option<String>, Error> {
        Ok(self.bot_members(gid)?.get(&m.to_hex()).cloned())
    }

    /// Records that member `m` is a device of bot `bot` (from the server's
    /// word only). Never removed by anything a member sends.
    pub(crate) fn note_bot_member(&self, gid: &[u8], m: &MemberId, bot: &str) -> Result<(), Error> {
        if *m == self.member_id() {
            return Ok(());
        }
        let mut map = self.bot_members(gid)?;
        if map.get(&m.to_hex()).map(String::as_str) != Some(bot) {
            map.insert(m.to_hex(), bot.to_string());
            self.save_map(&members_key(gid), &map)?;
        }
        Ok(())
    }

    fn lane(&self, gid: &[u8]) -> Result<Lane, Error> {
        Ok(self.client.app_data(&lane_key(gid))?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default())
    }

    fn save_lane(&self, gid: &[u8], l: &Lane) -> Result<(), Error> {
        Ok(self.client.set_app_data(&lane_key(gid), Some(&serde_json::to_vec(l).expect("JSON")))?)
    }

    /// Asks the server which of the group's devices and account labels are
    /// bots, for those not asked about yet, and refreshes the settings of
    /// the group's bots once they are older than [`BOT_INFO_TTL`]. One
    /// request, and none when nothing is new. Never inside a receive batch
    /// (F-024): there the last answer is used.
    /// Forced: asks now, also for fresh settings.
    pub fn refresh_bots(&mut self, gid: &[u8]) -> Result<(), Error> {
        self.client.set_app_data(OFF_UNTIL, None)?;
        self.refresh_lane(gid, true)
    }

    /// The server said a moment ago that the bot platform is released.
    /// Meanwhile no bot reads or sends anything (the server refuses bots'
    /// devices and keeps nothing for them), so devices are not looked up.
    fn bots_off(&self) -> Result<bool, Error> {
        let until = self.client.app_data(OFF_UNTIL)?.and_then(|v| String::from_utf8(v).ok()).and_then(|s| s.parse::<i64>().ok());
        Ok(until.is_some_and(|t| now() < t))
    }

    pub(crate) fn refresh_lane(&mut self, gid: &[u8], force: bool) -> Result<(), Error> {
        if self.api.receiving() || (!force && self.bots_off()?) {
            return Ok(());
        }
        let roster = self.roster(gid)?;
        let accounts = self.map(&accounts_key(gid))?;
        let mut lane = self.lane(gid)?;
        let me = (self.creds.device_id.clone(), self.creds.account_id.clone());
        let devices: BTreeSet<String> = roster.values().filter(|d| **d != me.0 && !lane.checked.contains(*d)).cloned().collect();
        let mut ask: BTreeSet<String> = accounts.values().filter(|a| **a != me.1 && !lane.accounts.contains(*a)).cloned().collect();
        // The group's known bots whose settings are stale.
        let known: BTreeSet<String> = lane.bots.values().chain(self.bot_members(gid)?.values()).cloned().collect();
        for b in &known {
            if force || self.cache(b)?.is_none_or(|c| now() - c.at >= BOT_INFO_TTL) {
                ask.insert(b.clone());
            }
        }
        if devices.is_empty() && ask.is_empty() {
            return Ok(());
        }
        let ask: Vec<String> = ask.into_iter().take(crate::bots::MAX_LOOKUP).collect();
        let body = json!({ "accounts": ask, "devices": devices });
        let v = match self.api.bots(&self.creds, Method::POST, "/v1/bots/lookup", Some(&body)) {
            Ok(v) => v,
            // The platform is released: no bot can read or send (the server
            // refuses their devices and keeps nothing for them).
            Err(Error::Server { status: 403, .. }) => {
                self.client.set_app_data(OFF_UNTIL, Some((now() + OFF_RECHECK).to_string().as_bytes()))?;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let bots: HashMap<String, BotInfo> =
            v["bots"].as_array().into_iter().flatten().filter_map(BotInfo::from_json).map(|b| (b.account.clone(), b)).collect();
        for a in &ask {
            self.save_cache(a, bots.get(a).cloned())?;
        }
        for b in bots.values() {
            self.save_cache(&b.account, Some(b.clone()))?;
        }
        if let Some(map) = v["devices"].as_object() {
            for (d, b) in map {
                if let Some(b) = b.as_str() {
                    lane.bots.insert(d.clone(), b.to_string());
                }
            }
        }
        lane.checked.extend(devices);
        lane.accounts.extend(ask);
        // Labels: the members on bot devices, and members labelled with a
        // bot account (the bot-ness is the server's word).
        for (m, d) in &roster {
            if let (Some(b), Some(id)) = (lane.bots.get(d), MemberId::from_hex(m)) {
                self.note_bot_member(gid, &id, b)?;
            }
        }
        for (m, a) in &accounts {
            if let (true, Some(id)) = (bots.contains_key(a), MemberId::from_hex(m)) {
                self.note_bot_member(gid, &id, a)?;
            }
        }
        self.save_lane(gid, &lane)
    }

    /// The members of bot `bot` in the group, as this device knows them.
    fn members_of_bot(&self, gid: &[u8], bot: &str, lane: &Lane) -> Result<BTreeSet<String>, Error> {
        let mut out: BTreeSet<String> = self.bot_members(gid)?.into_iter().filter(|(_, b)| b == bot).map(|(m, _)| m).collect();
        for (m, d) in self.roster(gid)? {
            if lane.bots.get(&d).map(String::as_str) == Some(bot) {
                out.insert(m);
            }
        }
        Ok(out)
    }

    /// Is payload `p` for the bot `info` (whose members are `members`)?
    /// In a 1:1 chat with the bot everything is for it.
    fn lane_allows(&mut self, gid: &[u8], p: &Payload, info: Option<&BotInfo>, members: &BTreeSet<String>, direct: bool) -> Result<bool, Error> {
        Ok(match p {
            Payload::History { .. } => false,
            Payload::Roster { .. } | Payload::Profile { .. } | Payload::Leave { .. } | Payload::RemoveDevice { .. } | Payload::Topic { .. } | Payload::Topics { .. } => true,
            _ if direct => true,
            // Unknown settings: as privacy mode (the safe side).
            _ if info.is_some_and(|i| !i.privacy_mode) => true,
            Payload::Text { text, mentions, re, .. } => {
                info.is_some_and(|i| is_command_for(text, &i.username))
                    || mentions.iter().any(|m| members.contains(m))
                    || match re {
                        Some(r) => self.client.message(gid, r)?.is_some_and(|m| members.contains(&m.sender)),
                        None => false,
                    }
            }
            _ => false,
        })
    }

    /// The devices `inner` (an encoded payload) goes to out of `all`: the
    /// lane rules for bots' devices, and the one member a button press or
    /// its answer is for. Devices never looked up count as people; the
    /// second value says whether there were any.
    pub(crate) fn lane_recipients(&mut self, gid: &[u8], inner: &[u8], all: Vec<String>) -> Result<(Vec<String>, bool), Error> {
        let Some(p) = Payload::decode(inner) else { return Ok((all, false)) };
        let roster = self.roster(gid)?;
        if let Payload::Callback { bot: m, .. } | Payload::CallbackAnswer { to: m, .. } = &p {
            let target = roster.get(m).cloned();
            return Ok((all.into_iter().filter(|d| Some(d) == target.as_ref()).collect(), false));
        }
        let lane = self.lane(gid)?;
        let off = self.bots_off()?;
        if lane.bots.is_empty() {
            let unchecked = !off && all.iter().any(|d| !lane.checked.contains(d));
            return Ok((all, unchecked));
        }
        let bots_allowed = self.chat_feature(gid, "chat.bots")?.0;
        let direct = self.group(gid)?.members().len() <= 2;
        let mut out = Vec::new();
        let mut unchecked = false;
        for d in all {
            match lane.bots.get(&d).cloned() {
                Some(bot) => {
                    if !bots_allowed {
                        continue;
                    }
                    let info = self.cached_bot(&bot)?;
                    let members = self.members_of_bot(gid, &bot, &lane)?;
                    if self.lane_allows(gid, &p, info.as_ref(), &members, direct)? {
                        out.push(d);
                    }
                }
                None => {
                    unchecked |= !off && !lane.checked.contains(&d);
                    out.push(d);
                }
            }
        }
        Ok((out, unchecked))
    }

    // --- buttons and callbacks ---

    /// Sends a text with inline buttons. Only a bot's device sends them
    /// (people's apps never show buttons from people anyway).
    pub fn send_buttons(&mut self, gid: &[u8], text: &str, kb: Vec<Vec<Button>>, reply_to: Option<&str>) -> Result<String, Error> {
        if self.bot_self()?.is_none() {
            return Err(Error::Usage("only bots send buttons".into()));
        }
        if !valid_keyboard(&kb) {
            return Err(Error::Usage(format!(
                "at most {MAX_ROWS} rows of {MAX_PER_ROW} buttons, each with 1 to {MAX_BUTTON_TEXT} characters of text and data"
            )));
        }
        let o = crate::TextOptions { reply_to: reply_to.map(str::to_string), ..Default::default() };
        self.send_text_kb(gid, text, &o, kb)
    }

    /// The buttons under message `id` (a bot's text).
    pub fn buttons(&self, gid: &[u8], id: &str) -> Result<Vec<Vec<Button>>, Error> {
        Ok(self.client.message(gid, id)?.map(|m| message_buttons(&m)).unwrap_or_default())
    }

    /// The person presses button `data` under the bot's message `id`: the
    /// press goes to that bot's devices only. Returns the press id; the
    /// bot's answer arrives as [`Event::CallbackAnswer`].
    pub fn press_button(&mut self, gid: &[u8], id: &str, data: &str) -> Result<String, Error> {
        let m = self.client.message(gid, id)?.ok_or_else(|| Error::Usage("no such message".into()))?;
        let sender = MemberId::from_hex(&m.sender).ok_or_else(|| Error::Usage("no such message".into()))?;
        if self.bot_member(gid, &sender)?.is_none() {
            return Err(Error::Usage("only a bot's message has buttons".into()));
        }
        if !self.chat_feature(gid, "chat.bots")?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        if !message_buttons(&m).iter().flatten().any(|b| b.data == data) {
            return Err(Error::Usage("that message has no such button".into()));
        }
        let qid = new_id();
        self.client.set_app_data(&press_key(gid, &qid), Some(m.sender.as_bytes()))?;
        self.send_payload(gid, &Payload::Callback { id: qid.clone(), msg: id.to_string(), data: data.to_string(), bot: m.sender })?;
        Ok(qid)
    }

    /// The bot answers press `id` (only the presser gets it): `text` shown
    /// to them (`alert`: as a dialog), or nothing.
    pub fn answer_callback(&mut self, gid: &[u8], id: &str, text: Option<&str>, alert: bool) -> Result<(), Error> {
        let key = query_key(gid, id);
        let to = self.client.app_data(&key)?.and_then(|v| String::from_utf8(v).ok()).ok_or_else(|| Error::Usage("no such button press".into()))?;
        if text.is_some_and(|t| t.chars().count() > MAX_ANSWER) {
            return Err(Error::Usage(format!("an answer has at most {MAX_ANSWER} characters")));
        }
        self.send_payload(gid, &Payload::CallbackAnswer { id: id.to_string(), to, text: text.map(str::to_string), alert })?;
        self.client.set_app_data(&key, None)?;
        Ok(())
    }

    /// A press of one of this device's buttons (the bot's side).
    pub(crate) fn on_callback(&mut self, gid: &[u8], from: MemberId, id: String, msg: String, data: String, bot: String, events: &mut Vec<Event>) -> Result<(), Error> {
        let drop = |events: &mut Vec<Event>, why: &str| events.push(Event::Dropped { reason: format!("button press: {why}") });
        if bot != self.member_id().to_hex() {
            return Ok(drop(events, "for another member"));
        }
        if !valid_query_id(&id) {
            return Ok(drop(events, "malformed"));
        }
        if self.blocked_sender(gid, &from)? {
            return Ok(drop(events, "from a blocked account"));
        }
        // Only for this device's own message, and only a button it has.
        let Some(m) = self.client.message(gid, &msg)? else { return Ok(drop(events, "unknown message")) };
        if m.sender != self.member_id().to_hex() || m.deleted {
            return Ok(drop(events, "not this bot's message"));
        }
        if !message_buttons(&m).iter().flatten().any(|b| b.data == data) {
            return Ok(drop(events, "no such button"));
        }
        self.client.set_app_data(&query_key(gid, &id), Some(from.to_hex().as_bytes()))?;
        events.push(Event::CallbackQuery { group: gid.to_vec(), id, from, msg, data });
        Ok(())
    }

    /// A bot's answer to a press of this device.
    pub(crate) fn on_callback_answer(&mut self, gid: &[u8], from: MemberId, id: String, to: String, text: Option<String>, alert: bool, events: &mut Vec<Event>) -> Result<(), Error> {
        let key = press_key(gid, &id);
        let pressed_bot = self.client.app_data(&key)?.and_then(|v| String::from_utf8(v).ok());
        if to != self.member_id().to_hex() || pressed_bot.as_deref() != Some(from.to_hex().as_str()) || !valid_query_id(&id) {
            events.push(Event::Dropped { reason: "button answer: not for a press of this device".into() });
            return Ok(());
        }
        if text.as_ref().is_some_and(|t| t.chars().count() > MAX_ANSWER || t.chars().any(char::is_control)) {
            events.push(Event::Dropped { reason: "button answer: malformed".into() });
            return Ok(());
        }
        self.client.set_app_data(&key, None)?;
        events.push(Event::CallbackAnswer { group: gid.to_vec(), id, text, alert });
        Ok(())
    }

    // --- the bot's own device (its gateway) ---

    /// A new encrypted profile for a bot's gateway device: registers a new
    /// device key with the bot token (and a signature over the server's
    /// challenge), and sets the device up as a bot: groups it is added to
    /// are accepted (all of them, or with `bot.join_groups` released only
    /// 1:1 chats), no read receipts, typing or search index. The token is
    /// not stored: only its SHA-256, to check the gateway's local API.
    pub fn create_bot_device(path: &str, passphrase: &str, server: &str, token: &str) -> Result<Session, Error> {
        // The bot's username is the device's display name in its groups.
        let me = crate::Api::new(server)?.with_bot_token(Method::GET, "/v1/bots/gateway/me", token, None)?;
        let info = BotInfo::from_json(&me).ok_or_else(|| Error::Protocol("bad bot from server".into()))?;
        let s = Self::create_with(path, passphrase, &info.username, server, |api, key| api.bot_register(token, key))?;
        let account = s.creds.account_id.clone();
        s.client.set_app_data(SELF, Some(account.as_bytes()))?;
        s.set_token_hash(token)?;
        s.save_cache(&account, Some(info.clone()))?;
        s.apply_bot_settings(&info)?;
        Ok(s)
    }

    /// The gateway registers again after the owner rotated the token: the
    /// same device key, so the same device id and mailbox. Fresh key
    /// packages are uploaded (the server dropped the old ones).
    pub fn reregister_bot(&mut self, token: &str) -> Result<(), Error> {
        if self.bot_self()?.is_none() {
            return Err(Error::Usage("this is not a bot's device".into()));
        }
        let c = self.api.bot_register(token, &self.creds.key)?;
        if c.account_id != self.creds.account_id || c.device_id != self.creds.device_id {
            return Err(Error::Protocol("the server registered another device".into()));
        }
        self.set_token_hash(token)?;
        self.ensure_key_packages()?;
        let info = self.bot_info_fresh()?;
        self.apply_bot_settings(&info)
    }

    fn set_token_hash(&self, token: &str) -> Result<(), Error> {
        let h = Zeroizing::new(Sha256::digest(token.trim().as_bytes()).to_vec());
        Ok(self.client.set_app_data(TOKEN_HASH, Some(&h))?)
    }

    /// Is `token` the one this gateway device registered with? (Constant
    /// time, against the stored SHA-256.)
    pub fn bot_token_matches(&self, token: &str) -> Result<bool, Error> {
        let Some(want) = self.client.app_data(TOKEN_HASH)? else { return Ok(false) };
        Ok(bool::from(Sha256::digest(token.trim().as_bytes()).as_slice().ct_eq(&want)))
    }

    /// The SHA-256 of the token this gateway device registered with (the
    /// gateway keeps it in memory to check its local API).
    pub fn bot_token_sha256(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.client.app_data(TOKEN_HASH)?)
    }

    /// The bot account, if this is a bot's gateway device.
    pub fn bot_self(&self) -> Result<Option<String>, Error> {
        Ok(self.client.app_data(SELF)?.and_then(|v| String::from_utf8(v).ok()))
    }

    /// The gateway's own records in the encrypted profile (its update
    /// queue), under `gw/`.
    pub fn gateway_get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.client.app_data(&format!("gw/{key}"))?)
    }

    pub fn gateway_set(&self, key: &str, value: Option<&[u8]>) -> Result<(), Error> {
        Ok(self.client.set_app_data(&format!("gw/{key}"), value)?)
    }

    /// Keys under `gw/<prefix>`, without `gw/`, in order.
    pub fn gateway_keys(&self, prefix: &str) -> Result<Vec<String>, Error> {
        Ok(self.client.app_data_keys(&format!("gw/{prefix}"))?.into_iter().map(|k| k[3..].to_string()).collect())
    }

    /// This bot's settings, fresh from the server.
    pub fn bot_info_fresh(&self) -> Result<BotInfo, Error> {
        let account = self.bot_self()?.ok_or_else(|| Error::Usage("this is not a bot's device".into()))?;
        let v = self.api.bots(&self.creds, Method::POST, "/v1/bots/lookup", Some(&json!({ "accounts": [account] })))?;
        let info = v["bots"].as_array().into_iter().flatten().filter_map(BotInfo::from_json).find(|b| b.account == account);
        self.save_cache(&account, info.clone())?;
        info.ok_or_else(|| Error::Protocol("the server does not know this bot".into()))
    }

    /// The device's user settings as a bot needs them (from the owner's
    /// bot settings): accept chats people start, and groups only while
    /// `bot.join_groups` is applied; no receipts, typing or search index.
    pub fn apply_bot_settings(&self, info: &BotInfo) -> Result<(), Error> {
        self.change("user.message_requests", false, None)?;
        if info.join_groups {
            self.change("user.group_add", false, None)?;
        } else {
            self.change("user.group_add", true, Some("nobody".into()))?;
        }
        for k in ["user.read_receipts", "user.typing", "user.search_index", "user.group_safety_notice", "user.link_preview"] {
            self.change(k, false, None)?;
        }
        Ok(())
    }
}

/// Accounts per lookup (the server's limit).
pub const MAX_LOOKUP: usize = 256;

#[cfg(test)]
mod attack_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn b(t: &str, d: &str) -> Button {
        Button { text: t.into(), data: d.into() }
    }

    #[test]
    fn commands_are_addressed_by_name() {
        assert!(is_command_for("/start", "quiz_bot"));
        assert!(is_command_for("/start@Quiz_Bot now", "quiz_bot"));
        assert!(!is_command_for("/start@other_bot", "quiz_bot"));
        assert!(!is_command_for("hello /start", "quiz_bot"));
        assert!(!is_command_for("/", "quiz_bot"));
        assert!(!is_command_for("/@quiz_bot", "quiz_bot"));
        assert!(!is_command_for("", "quiz_bot"));
    }

    #[test]
    fn keyboards_have_limits() {
        assert!(valid_keyboard(&[vec![b("Yes", "y"), b("No", "n")]]));
        assert!(valid_keyboard(&[]));
        assert!(!valid_keyboard(&[vec![]]), "an empty row");
        assert!(!valid_keyboard(&[vec![b("", "y")]]));
        assert!(!valid_keyboard(&[vec![b("x", &"d".repeat(MAX_BUTTON_DATA + 1))]]));
        assert!(!valid_keyboard(&[vec![b("x\u{7}", "d")]]));
        assert!(!valid_keyboard(&vec![vec![b("x", "d")]; MAX_ROWS + 1]));
        assert!(!valid_keyboard(&[vec![b("x", "d"); MAX_PER_ROW + 1]]));
        let kb = vec![vec![b("A", "a")]];
        let data = with_kb(crate::messages::text_data(true, None, false), &kb);
        let m = StoredMessage {
            group_id: vec![],
            id: "1".into(),
            sender: "s".into(),
            received_at: 0,
            kind: "text".into(),
            text: None,
            data,
            edited_at: None,
            deleted: false,
            expires_at: None,
            reactions: Default::default(),
            franking: None,
        };
        assert_eq!(message_buttons(&m), kb);
    }

    #[test]
    fn payloads_round_trip() {
        let c = Payload::Callback { id: "0".repeat(32), msg: "m".into(), data: "d".into(), bot: "b".into() };
        assert_eq!(Payload::decode(&c.encode()), Some(c.clone()));
        assert!(!c.is_franked_kind());
        let a = Payload::CallbackAnswer { id: "0".repeat(32), to: "t".into(), text: None, alert: false };
        assert_eq!(String::from_utf8(a.encode()).unwrap(), format!(r#"{{"t":"callback_answer","id":"{}","to":"t"}}"#, "0".repeat(32)));
        let t = Payload::Text { id: "1".into(), text: "x".into(), fmt: false, mentions: vec![], all: false, preview: None, silent: false, fwd: false, topic: None, re: None, kb: vec![vec![b("A", "a")]] };
        assert_eq!(Payload::decode(&t.encode()), Some(t));
    }
}
