//! Tree client logic shared by every app (command line now, phone and
//! desktop apps later through UniFFI): one device's encrypted profile, the
//! server API, the receive loop, two-phase commits against the server's
//! commit ordering, and the member -> device roster of each group.
//!
//! Apps only draw screens; everything a client must do correctly lives here
//! or in `tree-core`.

pub mod admin_log;
pub mod api;
pub mod chat_events;
pub mod device;
pub mod community;
pub mod forward;
pub mod franking;
pub mod groups;
pub mod history_share;
pub mod invites;
pub mod link;
pub mod links;
pub mod location;
pub mod media;
pub mod messages;
pub mod organize;
pub mod outbox;
pub mod payload;
pub mod pins;
pub mod polls;
pub mod profile;
pub mod refresh;
pub mod relay;
pub mod requests;
pub mod rich;
pub mod rich_media;
pub mod schedule;
pub mod self_sync;
pub mod settings;
pub mod stickers;
pub mod storage_clean;
pub mod topics;
pub mod username;

pub use requests::GroupStatus;
pub use tree_core::storage::messages::StoredMessage;

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_core::{
    wire::{peek, Peek},
    Client, Group, Incoming, PendingCommit, StoredProvider, TreeError,
};
use zeroize::Zeroizing;

pub use api::{Api, Creds};
pub use link::{LinkStatus, NewDevice};
pub use media::{Downloader, MediaMeta, SendOptions, Source, Transfer, TransferState, Transfers};
pub use messages::TextOptions;
pub use tree_core::features::Network;
pub use outbox::OutboxEntry;
pub use tree_core::storage::outbox::OutboxState;
pub use payload::{FileInfo, Payload};
pub use tree_core::recovery::{Phrase, Words};
pub use tree_core::MemberId;


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] TreeError),
    #[error("server answered {status} {code}")]
    Server { status: u16, code: String },
    #[error("network: {0}")]
    Network(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("no such group")]
    NoSuchGroup,
    #[error("{0}")]
    Usage(String),
    /// A feature-registry error code (`LOCKED_ALWAYS`, `NOT_ADMIN`, ...).
    #[error("feature: {0}")]
    Feature(String),
    /// `INVALID_OPTION`: the option does not fit the feature; says what would.
    #[error("INVALID_OPTION: {0}")]
    InvalidOption(String),
}

impl From<tree_core::features::FeatureError> for Error {
    fn from(e: tree_core::features::FeatureError) -> Self {
        match e {
            tree_core::features::FeatureError::InvalidOption(why) => Error::InvalidOption(why),
            e => Error::Feature(e.code().into()),
        }
    }
}

/// Key packages kept on the server; topped up when fewer remain.
pub const KEY_PACKAGES_TARGET: usize = 20;
pub const KEY_PACKAGES_LOW: u64 = 10;
/// The last-resort key package is replaced this often; the one before the
/// previous is then forgotten, so a welcome made from it can no longer be
/// opened (PROTOCOL.md 5.3).
pub const LAST_RESORT_ROTATE: i64 = 7 * 86400;
/// Sync checks the key package supply at most this often.
pub const KEY_PACKAGE_CHECK: i64 = 3600;
/// Messages for unknown groups or future epochs kept for a retry (PROTOCOL.md 6.7).
pub const MAX_HELD: usize = 256;
/// Held messages per group id (F-035).
pub const MAX_HELD_PER_GROUP: usize = 32;
/// A held message older than this is dropped when room is needed.
pub const HELD_MAX_AGE: i64 = 86400;

/// Something the user should see after a sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `name` is the sender's display name if known (shared inside the group).
    /// `request`: the group is still a message request (not yet accepted).
    /// `formatted`: show Tree markup (sent with it and `chat.formatting`
    /// applied). `mentions_me`: this device's member is mentioned, or an
    /// @all the group allows.
    Text {
        group: Vec<u8>,
        id: String,
        from: MemberId,
        name: Option<String>,
        text: String,
        request: bool,
        formatted: bool,
        mentions_me: bool,
        /// The sender's link preview, if both sides want previews.
        preview: Option<payload::LinkPreview>,
        /// Sent silently: apps do not notify ([`Session::should_notify`]).
        silent: bool,
    },
    /// The sender edited its message `id`.
    Edited { group: Vec<u8>, id: String, from: MemberId, text: String },
    /// The sender deleted its message `id` for everyone.
    Deleted { group: Vec<u8>, id: String, from: MemberId },
    /// A member reacted to message `id` (or took the reaction back).
    Reaction { group: Vec<u8>, id: String, from: MemberId, emoji: String, remove: bool },
    /// An attachment arrived; fetch it with [`Session::download`].
    /// `auto_download`: `user.auto_download` says to fetch it now, without
    /// a tap (a contact's file, the right network, small enough).
    File { group: Vec<u8>, from: MemberId, name: Option<String>, file: FileInfo, request: bool, auto_download: bool },
    /// A stranger started a chat (`direct`) or added this device to a
    /// group; shown in the request inbox until accepted or declined.
    Request { group: Vec<u8>, from: String, direct: bool },
    /// A group was declined automatically (blocked adder, settings).
    Declined { group: Vec<u8>, from: String, reason: String },
    Joined { group: Vec<u8> },
    Changed { group: Vec<u8>, added: Vec<MemberId>, removed: Vec<MemberId>, epoch: u64, own_commit_discarded: bool, settings_changed: bool },
    /// A member announced its display name.
    Profile { group: Vec<u8>, member: MemberId, name: String },
    /// A contact's devices changed (new device or replaced key): compare the
    /// safety number again. Always reported (`user.key_change_warning` is
    /// permanently on). `was_verified`: the old set had been verified.
    KeyChanged { account: String, new_members: Vec<MemberId>, was_verified: bool },
    RosterUpdated { group: Vec<u8> },
    /// A member asks to be removed; `quiet`: its removal shows no "left"
    /// line in the chat history (the member list still changes).
    LeaveRequested { group: Vec<u8>, member: MemberId, quiet: bool },
    /// `by` asks the admins to remove `member`, another device of the same
    /// account by the roster's labels. For an admin to decide: the labels
    /// are other members' claims.
    RemoveDeviceRequested { group: Vec<u8>, member: MemberId, by: MemberId },
    RemovedFromGroup { group: Vec<u8> },
    /// Kept for a later retry (unknown group yet, or a future epoch).
    Held,
    /// Could not be used and was dropped.
    Dropped { reason: String },
    /// Someone used one of this device's invite links and was added.
    InviteLinkUsed { group: Vec<u8>, account: String },
    /// A member read these messages (shown only while this user's own
    /// `user.read_receipts` is applied: receipts go both ways or not at all).
    Read { group: Vec<u8>, from: MemberId, ids: Vec<String> },
    /// A member is typing (`user.typing`, both ways).
    Typing { group: Vec<u8>, from: MemberId, on: bool },
    /// This device was added to a group by someone who is not a contact
    /// (`user.group_safety_notice`): show who added you and who is in it.
    GroupSafetyNotice { group: Vec<u8>, adder: String },
    /// One of this device's messages waiting in the outbox reached the
    /// server (`id`: the history message, if the item carried one).
    Sent { group: Vec<u8>, id: Option<String> },
    /// An outbox item was given up: the server refused it, or every
    /// attempt failed. The app offers retry ([`Session::retry_send`]) and
    /// cancel ([`Session::cancel_send`]) with `local_id`.
    SendFailed { group: Vec<u8>, id: Option<String>, local_id: String, reason: String },
    /// Message `id` was pinned (or unpinned) for the chat (`chat.pins`);
    /// read the pins again with [`Session::pins`].
    Pinned { group: Vec<u8>, id: String, from: MemberId, pinned: bool },
    /// A poll arrived (`chat.polls`); see [`Session::poll`].
    Poll { group: Vec<u8>, id: String, from: MemberId, name: Option<String>, question: String, request: bool },
    /// Votes or the state of poll `id` changed; read it again.
    PollUpdated { group: Vec<u8>, id: String },
    /// A sticker arrived (`chat.stickers`): item `index` of pack `pack`
    /// (the manifest's attachment id); [`Session::sticker_image`] fetches it.
    Sticker { group: Vec<u8>, id: String, from: MemberId, name: Option<String>, pack: String, index: u32, emoji: String, request: bool },
    /// A place or a live location arrived (`chat.location`);
    /// [`Session::location`] gives its current state.
    Location { group: Vec<u8>, id: String, from: MemberId, name: Option<String>, live: bool, request: bool },
    /// A live location moved, or ended (`stopped`).
    LocationUpdated { group: Vec<u8>, id: String, from: MemberId, stopped: bool },
    /// An event arrived (`chat.events`); [`Session::chat_event`] gives it
    /// with its replies.
    ChatEvent { group: Vec<u8>, id: String, from: MemberId, name: Option<String>, title: String, request: bool },
    /// The creator changed or cancelled event `id`.
    ChatEventChanged { group: Vec<u8>, id: String, from: MemberId, cancelled: bool },
    /// A member answered event `id` (`going`, `maybe` or `not`).
    Rsvp { group: Vec<u8>, id: String, from: MemberId, answer: String },
    /// A member set (or `removed`) its profile photo in this group;
    /// [`Session::member_photo`] fetches it.
    ProfilePhoto { group: Vec<u8>, member: MemberId, removed: bool },
    /// Another device of this account changed these settings (app-data
    /// keys, `self_sync.rs`): read the settings again.
    SettingsSynced { keys: Vec<String> },
    /// This device just joined a group whose admins set a welcome text
    /// (`chat.welcome`); it is also a `welcome` line in the history.
    Welcome { group: Vec<u8>, text: String },
    /// The member that added this device shared `count` recent messages
    /// (`chat.history_share`); their authors are that member's claims.
    HistoryShared { group: Vec<u8>, by: MemberId, count: u32 },
    /// Someone used one of this device's invite links and waits for an
    /// admin's approval (`chat.join_approval`).
    JoinRequest { group: Vec<u8>, account: String },
    /// A message from `member` broke slow mode and was hidden (shown to
    /// admins only, `chat.slow_mode`).
    SlowModeHidden { group: Vec<u8>, member: MemberId },
    /// A topic was created or changed (`id` empty: several, from a topic
    /// list); read them again with [`Session::topics`].
    TopicChanged { group: Vec<u8>, id: String, from: MemberId },
    /// This admin device added `member` to `group` at its request through
    /// the community `community`.
    CommunityMemberAdded { community: Vec<u8>, group: Vec<u8>, member: MemberId },
}

/// Recovery as the server has it (PROTOCOL.md 8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryStatus {
    pub active: bool,
    /// `replace` or `release`, and when it takes effect (unix seconds).
    pub pending: Option<(String, i64)>,
}

impl RecoveryStatus {
    fn from_json(v: &Value) -> Self {
        RecoveryStatus {
            active: v["state"] == "applied",
            pending: v["pending"]["action"].as_str().map(|a| (a.to_string(), v["pending"]["effective_at"].as_i64().unwrap_or(0))),
        }
    }
}

/// Result of submitting a commit to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Merged; the group is now in `epoch`.
    Accepted { epoch: u64 },
    /// Another commit won this epoch; ours was discarded. Sync, then decide again.
    Lost,
}

/// Extra data of a pending commit that the server request needs.
#[derive(Default, Serialize, Deserialize)]
struct PendingExtra {
    /// (member id hex, device id) of added devices.
    added: Vec<(String, String)>,
    removed_devices: Vec<String>,
    /// Nonce (hex) of the invite link request the added account made.
    #[serde(default)]
    link: Option<String>,
}

type Roster = BTreeMap<String, String>;

const K_SERVER: &str = "server/url";
const K_ACCOUNT: &str = "server/account_id";
const K_DEVICE: &str = "server/device_id";
const K_AUTH_KEY: &str = "server/auth_key";
const LAST_RESORT_CUR: &str = "keypackages/last_resort";
const LAST_RESORT_PREV: &str = "keypackages/last_resort_prev";
const LAST_RESORT_AT: &str = "keypackages/last_resort_at";
const KEY_PACKAGES_CHECKED: &str = "keypackages/checked";

fn roster_key(g: &[u8]) -> String {
    format!("roster/{}", hex::encode(g))
}
fn pending_key(g: &[u8]) -> String {
    format!("pending/{}", hex::encode(g))
}
fn names_key(g: &[u8]) -> String {
    format!("names/{}", hex::encode(g))
}
fn announce_key(g: &[u8]) -> String {
    format!("announce/{}", hex::encode(g))
}
fn accounts_key(g: &[u8]) -> String {
    format!("accounts/{}", hex::encode(g))
}
fn contact_key(account: &str) -> String {
    format!("contact/{account}")
}

/// What this device knows about another account (trust on first use, then
/// pinned).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub account: String,
    /// Member ids (hex) of the account's devices seen so far: the pinned
    /// ones and the `unconfirmed` ones. The safety number covers all of
    /// them, so comparing it confirms or exposes every claimed device.
    pub members: Vec<String>,
    /// The user compared the safety number for exactly these devices.
    pub verified: bool,
    /// The user chose this contact (invited it or accepted its request).
    #[serde(default)]
    pub accepted: bool,
    #[serde(default)]
    pub blocked: bool,
    /// Devices (member ids, hex) that only a group roster claimed for this
    /// account: not named by the server in a key-package claim this device
    /// made, and not covered by a safety number the user verified. They do
    /// not count as this contact for anything (message requests,
    /// `user.group_add`, auto-download, photo visibility), also when they
    /// are the only devices seen for the account (F-021).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unconfirmed: Vec<String>,
}

impl Contact {
    pub fn member_ids(&self) -> Vec<MemberId> {
        self.members.iter().filter_map(|m| MemberId::from_hex(m)).collect()
    }

    /// Does this device count as this contact? Only if it is pinned: named
    /// by the server in a key-package claim this device made, carried from
    /// the account's own device by a confirmed device link, or covered by a
    /// verified safety number. A contact with no pinned device vouches for
    /// nobody (F-021): before, it vouched for any device that claimed it.
    pub fn vouches_for(&self, member: &str) -> bool {
        self.members.iter().any(|m| m == member) && !self.unconfirmed.iter().any(|m| m == member)
    }

    /// The pinned devices: seen and not unconfirmed.
    pub fn pinned(&self) -> Vec<String> {
        self.members.iter().filter(|m| !self.unconfirmed.contains(m)).cloned().collect()
    }
}

/// One member as the app shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub id: MemberId,
    pub device: Option<String>,
    /// Display name, if this device has learned it.
    pub name: Option<String>,
    /// Another member uses the same name: tell them apart by id (F-008).
    pub duplicate_name: bool,
    /// The member's account, if this device learned it (for safety numbers).
    pub account: Option<String>,
}

/// Pinning rule: devices the server names for an account in a key-package
/// claim this device made (`confirmed`) are pinned, the first time without
/// a warning (trust on first use of the server's answer); afterwards every
/// member id not seen before is a key change, reported, and clears
/// "verified". Returns the updated contact if anything changed.
///
/// Devices that only a group roster claims for the account are never
/// pinned, whether or not the account had devices before (F-018, F-021):
/// they are recorded as `unconfirmed` (so the safety number covers them),
/// get the warning if the account was known, and none of the contact's
/// trust until the user verifies the safety number or the server names them.
fn merge_pins(old: Option<Contact>, account: &str, members: &[MemberId], confirmed: bool) -> Option<(Contact, Option<Event>)> {
    let first = old.is_none();
    let mut c = old.unwrap_or_else(|| Contact { account: account.to_string(), ..Default::default() });
    let mut new: Vec<MemberId> = members.iter().filter(|m| !c.members.contains(&m.to_hex())).copied().collect();
    new.sort();
    new.dedup();
    let hex: Vec<String> = members.iter().map(MemberId::to_hex).collect();
    let confirms = confirmed && c.unconfirmed.iter().any(|m| hex.contains(m));
    if new.is_empty() && !first && !confirms {
        return None;
    }
    let event = (!first && !new.is_empty())
        .then(|| Event::KeyChanged { account: account.to_string(), new_members: new.clone(), was_verified: c.verified });
    if !first && !new.is_empty() {
        c.verified = false;
    }
    if confirmed {
        c.unconfirmed.retain(|m| !hex.contains(m));
    } else {
        c.unconfirmed.extend(new.iter().map(MemberId::to_hex));
    }
    c.members.extend(new.iter().map(MemberId::to_hex));
    Some((c, event))
}


/// One device: its encrypted profile, its server account and its groups.
pub struct Session {
    client: Client<StoredProvider>,
    api: Api,
    creds: Creds,
    groups: HashMap<Vec<u8>, Group>,
    refresh_policy: refresh::RefreshPolicy,
    /// A device link this device scanned and has not finished.
    link: Option<link::ExistingLink>,
    media: media::MediaState,
    /// The profile's database path (side files `.hdr`, `.pin` next to it).
    path: String,
    /// The server's arrival time (whole minutes) of the message being
    /// handled, if it came from the mailbox now (slow mode, `groups.rs`).
    server_time: Option<i64>,
    /// Inside [`Session::send_unchecked`]: the sending side's own group
    /// checks are skipped (tests of the receiving side only).
    unchecked: bool,
    /// Seconds added to this device's clock where expiries are judged
    /// locally (pins); only tests change it, to cross an expiry without
    /// waiting on the wall clock.
    clock_offset: i64,
}

impl Session {
    /// New device identity in a new encrypted profile, registered as a new
    /// account on `server`.
    pub fn create(path: &str, passphrase: &str, name: &str, server: &str, pow_bits: u32) -> Result<Self, Error> {
        Self::create_with(path, passphrase, name, server, |api, key| api.signup(key, pow_bits))
    }

    /// A new profile on a new device that joins an existing account with the
    /// recovery phrase (PROTOCOL.md 8.6). Groups and history are not
    /// restored: contacts add this device again and see a key change. With
    /// `revoke_others`, every other device of the account is removed.
    pub fn recover(
        path: &str,
        passphrase: &str,
        name: &str,
        server: &str,
        phrase: &str,
        revoke_others: bool,
        pow_bits: u32,
    ) -> Result<Self, Error> {
        let phrase = Phrase::parse(phrase)?;
        let rk = phrase.recovery_key();
        Self::create_with(path, passphrase, name, server, |api, key| {
            let ts = messages::now();
            let sig = rk.sign_recovery(&key.verifying_key().to_bytes(), revoke_others, ts);
            api.recover(key, &rk.public_key(), &sig, ts, revoke_others, pow_bits)
        })
    }

    fn create_with(
        path: &str,
        passphrase: &str,
        name: &str,
        server: &str,
        register: impl FnOnce(&Api, &SigningKey) -> Result<Creds, Error>,
    ) -> Result<Self, Error> {
        if std::path::Path::new(path).exists() {
            return Err(Error::Usage(format!("{path} already exists")));
        }
        let api = Api::new(server)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..]).map_err(|e| Error::Protocol(e.to_string()))?;
        let key = SigningKey::from_bytes(&seed);
        let creds = register(&api, &key)?;
        let client = Client::create(path, passphrase, name)?;
        client.set_app_data(K_SERVER, Some(server.as_bytes()))?;
        client.set_app_data(K_ACCOUNT, Some(creds.account_id.as_bytes()))?;
        client.set_app_data(K_DEVICE, Some(creds.device_id.as_bytes()))?;
        client.set_app_data(K_AUTH_KEY, Some(&seed[..]))?;
        let mut s = Self::from_parts(client, api, creds, path);
        s.ensure_key_packages()?;
        s.sync_search_index()?;
        Ok(s)
    }

    pub(crate) fn from_parts(client: Client<StoredProvider>, api: Api, creds: Creds, path: &str) -> Self {
        let media = media::MediaState::new(path);
        Self { client, api, creds, groups: HashMap::new(), refresh_policy: Default::default(), link: None, media, path: path.to_string(), server_time: None, unchecked: false, clock_offset: 0 }
    }

    /// Opens an existing profile and resubmits any commit that was waiting
    /// for the server when the app stopped (PROTOCOL.md 7.1 step 7). Outbox
    /// items an interrupted attempt left in `sending` become `retry`
    /// (PROTOCOL.md 6.13); the next sync sends them.
    pub fn open(path: &str, passphrase: &str) -> Result<(Self, Vec<CommitOutcome>), Error> {
        Self::open_with(path, &tree_core::Passphrase::new(passphrase)?)
    }

    /// [`Session::open`] with another way to rebuild the database key: a
    /// PIN ([`Session::open_with_pin`]) or a key the platform unwrapped
    /// (biometric unlock, `device.rs`).
    pub fn open_with(path: &str, source: &dyn tree_core::KeySource) -> Result<(Self, Vec<CommitOutcome>), Error> {
        let client = Client::open_with_key(path, source)?;
        client.outbox_recover(messages::now())?;
        let text = |k: &str| -> Result<String, Error> {
            let v = client.app_data(k)?.ok_or_else(|| Error::Protocol(format!("profile lacks {k}")))?;
            String::from_utf8(v).map_err(|_| Error::Protocol(format!("{k} is not text")))
        };
        let api = Api::new(&text(K_SERVER)?)?;
        let seed: Zeroizing<Vec<u8>> = Zeroizing::new(client.app_data(K_AUTH_KEY)?.unwrap_or_default());
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Protocol("bad auth key".into()))?;
        let creds = Creds { account_id: text(K_ACCOUNT)?, device_id: text(K_DEVICE)?, key: SigningKey::from_bytes(&seed) };
        let mut s = Self::from_parts(client, api, creds, path);
        // Plaintext temporary files a crash left behind (F-034).
        media::clean_partials(&s.media.dir);
        s.load_transfers()?;
        s.sync_search_index()?;
        let mut outcomes = Vec::new();
        for gid in s.client.group_ids()? {
            if s.group(&gid)?.pending_commit().is_some() {
                outcomes.push(s.submit(&gid)?);
            }
        }
        Ok((s, outcomes))
    }

    pub fn name(&self) -> &str {
        self.client.name()
    }

    /// A copy of the server connection and credentials, for waiting on the
    /// mailbox ([`Api::wait_pending`]) outside a lock on the session.
    pub fn waiter(&self) -> (Api, Creds) {
        (self.api.clone(), self.creds.clone())
    }
    pub fn account_id(&self) -> &str {
        &self.creds.account_id
    }
    pub fn device_id(&self) -> &str {
        &self.creds.device_id
    }
    pub fn member_id(&self) -> MemberId {
        self.client.member_id()
    }

    pub fn group_ids(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.client.group_ids()?)
    }

    fn group(&mut self, gid: &[u8]) -> Result<&mut Group, Error> {
        if !self.groups.contains_key(gid) {
            let g = self.client.load_group(gid).map_err(|e| match e {
                TreeError::NoSuchGroup => Error::NoSuchGroup,
                e => e.into(),
            })?;
            self.groups.insert(gid.to_vec(), g);
        }
        Ok(self.groups.get_mut(gid).expect("just inserted"))
    }

    /// Runs `f` on the group with the client next to it (split borrow).
    fn with<T>(&mut self, gid: &[u8], f: impl FnOnce(&mut Group, &Client<StoredProvider>) -> Result<T, TreeError>) -> Result<T, Error> {
        self.group(gid)?;
        let Self { groups, client, .. } = self;
        Ok(f(groups.get_mut(gid).expect("loaded"), client)?)
    }

    fn map(&self, key: &str) -> Result<Roster, Error> {
        Ok(match self.client.app_data(key)? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol(format!("damaged {key}")))?,
            None => Roster::new(),
        })
    }

    fn save_map(&self, key: &str, m: &Roster) -> Result<(), Error> {
        Ok(self.client.set_app_data(key, Some(&serde_json::to_vec(m).expect("JSON")))?)
    }

    /// Starts the per-group maps with this device's own entries.
    fn init_group_maps(&self, gid: &[u8]) -> Result<(), Error> {
        let me = self.member_id().to_hex();
        self.save_roster(gid, &[(me.clone(), self.creds.device_id.clone())].into())?;
        self.save_names(gid, &[(me.clone(), self.name().to_string())].into())?;
        self.save_map(&accounts_key(gid), &[(me, self.creds.account_id.clone())].into())
    }

    fn roster(&self, gid: &[u8]) -> Result<Roster, Error> {
        Ok(match self.client.app_data(&roster_key(gid))? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged roster".into()))?,
            None => Roster::new(),
        })
    }

    fn save_roster(&self, gid: &[u8], r: &Roster) -> Result<(), Error> {
        Ok(self.client.set_app_data(&roster_key(gid), Some(&serde_json::to_vec(r).expect("JSON")))?)
    }

    /// Devices of the other members, from the roster.
    fn other_devices(&self, gid: &[u8]) -> Result<Vec<String>, Error> {
        let mut v: Vec<String> =
            self.roster(gid)?.into_values().filter(|d| *d != self.creds.device_id).collect();
        v.sort();
        v.dedup();
        Ok(v)
    }

    fn names(&self, gid: &[u8]) -> Result<Roster, Error> {
        Ok(match self.client.app_data(&names_key(gid))? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged names".into()))?,
            None => Roster::new(),
        })
    }

    fn save_names(&self, gid: &[u8], n: &Roster) -> Result<(), Error> {
        Ok(self.client.set_app_data(&names_key(gid), Some(&serde_json::to_vec(n).expect("JSON")))?)
    }

    /// Current members with their device ids and display names as known here.
    pub fn members(&mut self, gid: &[u8]) -> Result<Vec<MemberInfo>, Error> {
        let roster = self.roster(gid)?;
        let names = self.names(gid)?;
        let accounts = self.map(&accounts_key(gid))?;
        let ids = self.group(gid)?.members();
        let name_of = |id: &MemberId| names.get(&id.to_hex()).cloned();
        // Counted once (not per member: groups have up to 1,000 members).
        let mut uses: HashMap<String, usize> = HashMap::new();
        for id in &ids {
            if let Some(n) = name_of(id) {
                *uses.entry(n).or_default() += 1;
            }
        }
        Ok(ids
            .iter()
            .map(|id| {
                let name = name_of(id);
                let duplicate_name = name.as_ref().is_some_and(|n| uses.get(n).copied().unwrap_or(0) > 1);
                MemberInfo {
                    id: *id,
                    device: roster.get(&id.to_hex()).cloned(),
                    name,
                    duplicate_name,
                    account: accounts.get(&id.to_hex()).cloned(),
                }
            })
            .collect())
    }

    pub fn epoch(&mut self, gid: &[u8]) -> Result<u64, Error> {
        Ok(self.group(gid)?.epoch())
    }

    pub fn verification_code(&mut self, gid: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.group(gid)?.verification_code())
    }

    /// Keeps enough one-time key packages on the server for others to add
    /// this device while it is offline, and a fresh last-resort one for when
    /// they run out (PROTOCOL.md 5.3).
    pub fn ensure_key_packages(&mut self) -> Result<(), Error> {
        let (count, has_last_resort) = self.api.key_package_status(&self.creds)?;
        if count < KEY_PACKAGES_LOW {
            let kps = (0..KEY_PACKAGES_TARGET).map(|_| self.client.key_package()).collect::<Result<Vec<_>, _>>()?;
            self.api.upload_key_packages(&self.creds, &kps)?;
        }
        let t = messages::now();
        let fresh = self.time_of(LAST_RESORT_AT)?.is_some_and(|at| t - at < self.refresh_policy.last_resort_rotate);
        if !has_last_resort || !fresh {
            let kp = self.client.last_resort_key_package()?;
            self.api.set_last_resort(&self.creds, &kp)?;
            if let Some(old) = self.client.app_data(LAST_RESORT_PREV)? {
                self.client.forget_key_package(&old)?;
            }
            if let Some(cur) = self.client.app_data(LAST_RESORT_CUR)? {
                self.client.set_app_data(LAST_RESORT_PREV, Some(&cur))?;
            }
            self.client.set_app_data(LAST_RESORT_CUR, Some(&kp))?;
            self.set_time(LAST_RESORT_AT, t)?;
        }
        self.set_time(KEY_PACKAGES_CHECKED, t)
    }

    /// Others may have claimed key packages since the last check.
    fn key_packages_due(&self) -> Result<bool, Error> {
        Ok(self.time_of(KEY_PACKAGES_CHECKED)?.is_none_or(|at| messages::now() - at >= self.refresh_policy.key_package_check))
    }

    /// Starts a group with only this device in it.
    pub fn create_group(&mut self) -> Result<Vec<u8>, Error> {
        let g = self.client.create_group()?;
        let gid = g.id();
        self.groups.insert(gid.clone(), g);
        self.init_group_maps(&gid)?;
        self.note_refreshed(&gid)?;
        Ok(gid)
    }

    /// Registers (or changes) this account's @username. The server stores
    /// only its hash. Whether others can find it follows
    /// `user.discoverable` (applied: findable; released: hidden from
    /// lookups, still reserved); changing that setting later updates the
    /// registration.
    pub fn set_username(&self, name: &str) -> Result<String, Error> {
        let n = username::normalise(name).map_err(|e| Error::Usage(e.into()))?;
        self.register_username(&n, self.is_applied(settings::DISCOVERABLE)?)?;
        self.client.set_app_data("profile/username", Some(n.as_bytes()))?;
        Ok(n)
    }

    pub(crate) fn register_username(&self, name: &str, discoverable: bool) -> Result<(), Error> {
        let h = username::hash(name).map_err(|e| Error::Usage(e.into()))?;
        self.api.username(&self.creds, "apply", Some(&json!({ "hash": api::b64(&h), "discoverable": discoverable })))?;
        Ok(())
    }

    /// Deletes the account: tells every group this device is leaving (so
    /// admins remove it), deletes the account and all its devices on the
    /// server, then the encrypted profile on this device (`path`, the same
    /// path the profile was created or opened with). Nothing of the account
    /// remains on the server except reports others filed about it.
    pub fn delete_account(mut self, path: &str) -> Result<(), Error> {
        for gid in self.group_ids()? {
            if self.group(&gid)?.is_member() {
                // Best effort: a group we cannot reach still loses us when
                // the server deletes our devices.
                let _ = self.leave(&gid);
            }
        }
        self.api.delete_account(&self.creds)?;
        let media = self.media.dir.clone();
        drop(self);
        // Blobs waiting for upload and partial downloads (ciphertext only).
        let _ = std::fs::remove_dir_all(media);
        tree_core::storage::pin::disable_pin(std::path::Path::new(path))?;
        for p in [path.to_string(), format!("{path}.hdr"), format!("{path}-wal"), format!("{path}-shm"), format!("{path}-journal")] {
            match std::fs::remove_file(&p) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Error::Usage(format!("{p}: {e}"))),
                _ => {}
            }
        }
        Ok(())
    }

    /// Registers the endpoint a push gateway gave this app (UnifiedPush
    /// style), or clears it. The server then sends only the word `wake`
    /// there when something arrives (PROTOCOL.md 8.8); the app syncs.
    pub fn set_push_endpoint(&self, endpoint: Option<&str>) -> Result<(), Error> {
        self.api.set_push(&self.creds, endpoint)
    }

    /// Makes a new recovery phrase for this account and registers its
    /// recovery key (PROTOCOL.md 8.6). The phrase is returned once to be
    /// shown to the user and is not stored. If the account already has a
    /// phrase, `current` (the old phrase) makes the change immediate;
    /// without it the change waits 7 days, during which the old phrase still
    /// recovers the account (see [`Session::recovery_status`]).
    pub fn new_recovery_phrase(&self, words: usize, list: Words, current: Option<&str>) -> Result<(Phrase, RecoveryStatus), Error> {
        let p = Phrase::generate(words, list)?;
        let rk = p.recovery_key();
        let account = self.account_id();
        let cur = current.map(Phrase::parse).transpose()?.map(|c| c.recovery_key().sign_change(account, Some(&rk.public_key())));
        let v = self.api.recovery_apply(&self.creds, &rk.public_key(), &rk.sign_set(account), cur.as_ref())?;
        let st = RecoveryStatus::from_json(&v);
        self.record_recovery(&st)?;
        Ok((p, st))
    }

    /// Drops the recovery key: immediate with the current phrase, otherwise
    /// after 7 days. Until then `user.recovery_phrase` stays applied with a
    /// pending release ([`Session::release_pending`]): the key still works.
    pub fn release_recovery(&self, current: Option<&str>) -> Result<RecoveryStatus, Error> {
        let cur = current.map(Phrase::parse).transpose()?.map(|c| c.recovery_key().sign_change(self.account_id(), None));
        let st = RecoveryStatus::from_json(&self.api.recovery_release(&self.creds, cur.as_ref())?);
        self.record_recovery(&st)?;
        Ok(st)
    }

    /// The server's view: active or not, and a pending change. Apps warn
    /// about a pending change ("if this was not you, recover now"). Also
    /// brings this device's `user.recovery_phrase` in line with it (another
    /// device may have made or released the phrase).
    pub fn recovery_status(&self) -> Result<RecoveryStatus, Error> {
        let st = RecoveryStatus::from_json(&self.api.recovery_status(&self.creds)?);
        self.record_recovery(&st)?;
        Ok(st)
    }

    /// Whether a recovery phrase can recover this account, as this device
    /// last heard from the server (also true while a release is pending).
    pub fn has_recovery(&self) -> Result<bool, Error> {
        Ok(self.feature(settings::RECOVERY)?.state == tree_core::features::State::Applied)
    }

    /// Drops the @username; the server drops its link too
    /// (`user.username_link` is released).
    pub fn release_username(&self) -> Result<(), Error> {
        self.api.username(&self.creds, "release", None)?;
        self.forget_username_link()?;
        Ok(self.client.set_app_data("profile/username", None)?)
    }

    pub fn username(&self) -> Result<Option<String>, Error> {
        Ok(self.client.app_data("profile/username")?.and_then(|v| String::from_utf8(v).ok()))
    }

    /// Account id behind a discoverable @username, if any.
    pub fn find(&self, name: &str) -> Result<Option<String>, Error> {
        let h = username::hash(name).map_err(|e| Error::Usage(e.into()))?;
        match self.api.username(&self.creds, "lookup", Some(&json!({ "hash": api::b64(&h) }))) {
            Ok(v) => Ok(v["account_id"].as_str().map(str::to_string)),
            Err(Error::Server { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn contact(&self, account: &str) -> Result<Option<Contact>, Error> {
        Ok(match self.client.app_data(&contact_key(account))? {
            Some(v) => Some(serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged contact".into()))?),
            None => None,
        })
    }

    pub fn contacts(&self) -> Result<Vec<Contact>, Error> {
        let mut out = Vec::new();
        for k in self.client.app_data_keys("contact/")? {
            if let Some(c) = self.contact(&k["contact/".len()..])? {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// Records that `members` belong to `account`. The first time they are
    /// trusted as they are; afterwards any member id not seen before is a
    /// key change and is reported (and clears "verified"). `confirmed`: the
    /// server named them (a key-package claim), not a group roster.
    fn pin(&self, account: &str, members: &[MemberId], confirmed: bool, events: &mut Vec<Event>) -> Result<(), Error> {
        if account == self.creds.account_id {
            return Ok(());
        }
        if let Some((c, ev)) = merge_pins(self.contact(account)?, account, members, confirmed) {
            self.client.set_app_data(&contact_key(account), Some(&serde_json::to_vec(&c).expect("JSON")))?;
            events.extend(ev);
        }
        Ok(())
    }

    /// Is `m` this device or another device of this account? Only devices
    /// learned through a confirmed device link (`own/members`, PROTOCOL.md
    /// 8.11) count: a roster's account label never makes a device "mine".
    pub(crate) fn is_own_device(&self, m: &MemberId) -> Result<bool, Error> {
        Ok(*m == self.member_id() || self.own_members()?.contains(&m.to_hex()))
    }

    /// The account `from` belongs to as far as this device trusts it: this
    /// account for its own devices ([`Session::is_own_device`]), otherwise
    /// the account the group's roster names for it, but only if that
    /// account's contact has the device pinned ([`Contact::vouches_for`]).
    /// `None`: a stranger, whatever it claims.
    pub(crate) fn vouched_account(&self, gid: &[u8], from: &MemberId) -> Result<Option<String>, Error> {
        if self.is_own_device(from)? {
            return Ok(Some(self.creds.account_id.clone()));
        }
        let Some(a) = self.map(&accounts_key(gid))?.get(&from.to_hex()).cloned() else { return Ok(None) };
        Ok(self.contact(&a)?.filter(|c| c.vouches_for(&from.to_hex())).map(|_| a))
    }

    /// Is `from` a device of a blocked account? Matched by the account the
    /// roster names for it and also by member id: a device ever seen for a
    /// blocked account (pinned or only claimed) stays blocked whatever label
    /// a later roster gives it (F-022).
    pub(crate) fn blocked_sender(&self, gid: &[u8], from: &MemberId) -> Result<bool, Error> {
        if let Some(a) = self.map(&accounts_key(gid))?.get(&from.to_hex()) {
            if self.is_blocked(a)? {
                return Ok(true);
            }
        }
        let hex = from.to_hex();
        Ok(self.contacts()?.iter().any(|c| c.blocked && c.members.contains(&hex)))
    }

    /// The safety number shared with `account` (60 digits), from this
    /// device and the account's pinned devices.
    pub fn safety_number(&self, account: &str) -> Result<String, Error> {
        let c = self.contact(account)?.ok_or_else(|| Error::Usage("unknown contact".into()))?;
        Ok(tree_core::safety::safety_number(&[self.member_id()], &c.member_ids()))
    }

    /// The QR payload this device shows for `account`.
    pub fn safety_qr(&self, account: &str) -> Result<Vec<u8>, Error> {
        let c = self.contact(account)?.ok_or_else(|| Error::Usage("unknown contact".into()))?;
        Ok(tree_core::safety::qr_payload(&[self.member_id()], &c.member_ids()))
    }

    /// Marks the contact verified after the user compared the safety number
    /// (or scanned the other side's QR code: pass it to check it first).
    pub fn verify(&self, account: &str, scanned_qr: Option<&[u8]>) -> Result<(), Error> {
        let mut c = self.contact(account)?.ok_or_else(|| Error::Usage("unknown contact".into()))?;
        if let Some(q) = scanned_qr {
            if !tree_core::safety::qr_matches(q, &[self.member_id()], &c.member_ids()) {
                return Err(Error::Usage("the scanned code does not match: do not trust this contact".into()));
            }
        }
        c.verified = true;
        // The user compared exactly these devices: no key change is left
        // unconfirmed.
        c.unconfirmed.clear();
        Ok(self.client.set_app_data(&contact_key(account), Some(&serde_json::to_vec(&c).expect("JSON")))?)
    }

    /// Adds every device of `account_id` in one commit. Returns the outcome
    /// and any key-change warnings for that account.
    pub fn invite(&mut self, gid: &[u8], account_id: &str) -> Result<(CommitOutcome, Vec<Event>), Error> {
        self.invite_via(gid, account_id, None)
    }

    /// [`Session::invite`], naming the nonce (hex) of the account's invite
    /// link request.
    pub(crate) fn invite_via(&mut self, gid: &[u8], account_id: &str, link: Option<String>) -> Result<(CommitOutcome, Vec<Event>), Error> {
        // Before key packages are claimed (spent): `chat.member_adds`.
        if !self.may_add(gid)? {
            return Err(Error::Feature("NOT_ADMIN".into()));
        }
        let claimed = self.api.claim(&self.creds, account_id)?;
        if claimed.is_empty() {
            return Err(Error::Usage("that account has no key packages left".into()));
        }
        let mut added = Vec::new();
        let mut ids = Vec::new();
        for (device, kp) in &claimed {
            let id = MemberId::of_key_package(kp)?;
            ids.push(id);
            added.push((id.to_hex(), device.clone()));
        }
        let mut events = Vec::new();
        self.pin(account_id, &ids, true, &mut events)?;
        self.accept_contact(account_id)?;
        let mut accounts = self.map(&accounts_key(gid))?;
        for i in &ids {
            accounts.insert(i.to_hex(), account_id.to_string());
        }
        self.save_map(&accounts_key(gid), &accounts)?;
        let kps: Vec<&[u8]> = claimed.iter().map(|(_, kp)| kp.as_slice()).collect();
        self.with(gid, |g, c| g.add(c, &kps))?;
        self.save_pending(gid, &PendingExtra { added, removed_devices: vec![], link })?;
        Ok((self.submit(gid)?, events))
    }

    /// Removes members (devices) in one commit.
    pub fn remove(&mut self, gid: &[u8], members: &[MemberId]) -> Result<CommitOutcome, Error> {
        let roster = self.roster(gid)?;
        let removed_devices = members.iter().filter_map(|m| roster.get(&m.to_hex()).cloned()).collect();
        self.with(gid, |g, c| g.remove(c, members))?;
        self.save_pending(gid, &PendingExtra { added: vec![], removed_devices, link: None })?;
        let o = self.submit(gid)?;
        if let CommitOutcome::Accepted { .. } = o {
            // A remove carries an UpdatePath: this device's keys are new.
            self.note_refreshed(gid)?;
        }
        Ok(o)
    }

    /// Refreshes this device's keys in the group (post-compromise security).
    pub fn refresh_keys(&mut self, gid: &[u8]) -> Result<CommitOutcome, Error> {
        self.with(gid, |g, c| g.refresh_keys(c))?;
        self.save_pending(gid, &PendingExtra::default())?;
        let o = self.submit(gid)?;
        if let CommitOutcome::Accepted { .. } = o {
            self.note_refreshed(gid)?;
        }
        Ok(o)
    }

    fn save_pending(&self, gid: &[u8], e: &PendingExtra) -> Result<(), Error> {
        Ok(self.client.set_app_data(&pending_key(gid), Some(&serde_json::to_vec(e).expect("JSON")))?)
    }

    /// Sends the pending commit of `gid` to the server and acts on the answer
    /// (PROTOCOL.md 7.1). A network error leaves the commit pending; call
    /// again (or reopen) to resubmit the same bytes.
    pub fn submit(&mut self, gid: &[u8]) -> Result<CommitOutcome, Error> {
        let p: PendingCommit = self.group(gid)?.pending_commit().ok_or_else(|| Error::Usage("nothing pending".into()))?;
        // The settings before the commit, for the admin log.
        let before = self.group(gid)?.settings();
        let extra: PendingExtra = match self.client.app_data(&pending_key(gid))? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged pending data".into()))?,
            None => PendingExtra::default(),
        };
        let added_devices: Vec<&String> = extra.added.iter().map(|(_, d)| d).collect();
        let req = json!({
            "group_id": api::b64(gid),
            "epoch": p.epoch,
            "recipients": self.other_devices(gid)?,
            "body": api::b64(&p.commit),
            "added": added_devices,
            "welcome": p.welcome.as_ref().map(|w| api::b64(w)),
            "removed": extra.removed_devices,
        });
        let reply = self.api.commit(&self.creds, &req)?;
        let won = match (reply.status.as_u16(), reply.code()) {
            (200, _) => true,
            (409, "COMMIT_CONFLICT") => {
                reply.body["winner_sha256"].as_str() == Some(hex::encode(Sha256::digest(&p.commit)).as_str())
            }
            _ => {
                // Not accepted and never will be: drop it.
                self.with(gid, |g, c| g.discard_commit(c))?;
                self.client.set_app_data(&pending_key(gid), None)?;
                return Err(Error::Server { status: reply.status.as_u16(), code: reply.code().to_string() });
            }
        };
        if !won {
            self.with(gid, |g, c| g.discard_commit(c))?;
            self.client.set_app_data(&pending_key(gid), None)?;
            return Ok(CommitOutcome::Lost);
        }
        let epoch = self.with(gid, |g, c| g.confirm_commit(c))?;
        self.note_departures(gid, &p.removed)?;
        let me = self.member_id();
        self.log_commit(gid, &me, &before, &p.added, &p.removed)?;
        let mut roster = self.roster(gid)?;
        for id in &p.removed {
            roster.remove(&id.to_hex());
        }
        for (m, d) in &extra.added {
            roster.insert(m.clone(), d.clone());
        }
        self.save_roster(gid, &roster)?;
        self.client.set_app_data(&pending_key(gid), None)?;
        if !extra.added.is_empty() {
            // Tell everyone, including the new devices, who is where.
            let names = self.names(gid)?;
            let members: std::collections::HashSet<String> = self.group(gid)?.members().iter().map(|m| m.to_hex()).collect();
            let mut accounts = self.map(&accounts_key(gid))?;
            accounts.retain(|m, _| members.contains(m));
            self.save_map(&accounts_key(gid), &accounts)?;
            self.send_payload(gid, &Payload::Roster { devices: roster, names, accounts, link: extra.link.clone() })?;
            // Topic names and recent history for the new members (best
            // effort: the add itself is done).
            let _ = self.send_topic_list(gid);
            let _ = self.share_history(gid, &p.added);
        }
        Ok(CommitOutcome::Accepted { epoch })
    }

    /// The settings every member of the group agrees on: admins, name, chat features.
    pub fn group_settings(&mut self, gid: &[u8]) -> Result<tree_core::group_settings::GroupSettings, Error> {
        Ok(self.group(gid)?.settings())
    }

    /// An admin changes the group settings (one commit through the server).
    pub fn change_group_settings(&mut self, gid: &[u8], new: &tree_core::group_settings::GroupSettings) -> Result<CommitOutcome, Error> {
        self.with(gid, |g, c| g.change_settings(c, new))?;
        self.save_pending(gid, &PendingExtra::default())?;
        let o = self.submit(gid)?;
        if let CommitOutcome::Accepted { .. } = o {
            self.note_refreshed(gid)?;
        }
        Ok(o)
    }

    pub fn make_admin(&mut self, gid: &[u8], member: MemberId, admin: bool) -> Result<CommitOutcome, Error> {
        let mut s = self.group_settings(gid)?;
        s.admins.retain(|a| *a != member);
        if admin {
            s.admins.push(member);
        }
        self.change_group_settings(gid, &s)
    }

    pub fn set_group_name(&mut self, gid: &[u8], name: Option<String>) -> Result<CommitOutcome, Error> {
        let mut s = self.group_settings(gid)?;
        s.name = name;
        self.change_group_settings(gid, &s)
    }

    /// An admin applies or releases a chat-scope feature for the whole group
    /// (checked against the registry: permanent locks, server locks).
    pub fn set_chat_feature(&mut self, gid: &[u8], key: &str, apply: bool, option: Option<String>) -> Result<CommitOutcome, Error> {
        use tree_core::features::{Caller, Plan, Registry, Scope};
        let mut r = Registry::standard();
        let admin = Caller { plan: Plan::Free, is_admin: true };
        let status = if apply { r.apply(key, option, admin) } else { r.release(key, admin) }
            .map_err(Error::from)?;
        if !r.list(Scope::Chat).iter().any(|s| s.key == status.key) {
            return Err(Error::Feature("NOT_A_CHAT_FEATURE".into()));
        }
        if status.locked_by.is_some() {
            // Applying an AlwaysOn key (releasing an AlwaysOff one) is a
            // no-op: a locked key is never written into the group settings.
            return Ok(CommitOutcome::Accepted { epoch: self.epoch(gid)? });
        }
        let mut s = self.group_settings(gid)?;
        s.features.insert(
            key.to_string(),
            tree_core::group_settings::ChatSetting { applied: status.state == tree_core::features::State::Applied, option: status.option },
        );
        self.change_group_settings(gid, &s)
    }


    /// Asks the others to remove this device (PROTOCOL.md 6.5). The
    /// group's only admin first names the next one
    /// (`chat.owner_succession`, `groups.rs`).
    pub fn leave(&mut self, gid: &[u8]) -> Result<usize, Error> {
        self.hand_over(gid)?;
        self.send_payload(gid, &Payload::Leave { quiet: false })
    }

    /// Quiet leave: as [`Session::leave`], but the other members' apps
    /// store no "left" line for this removal. The member list still changes
    /// for everyone (MLS), and a modified app could still announce it.
    pub fn leave_quietly(&mut self, gid: &[u8]) -> Result<usize, Error> {
        self.hand_over(gid)?;
        self.send_payload(gid, &Payload::Leave { quiet: true })
    }

    /// Encrypts an encoded payload for the group and sends it to `to` once,
    /// without the outbox (typing and presence only; see `outbox.rs`).
    fn send_encoded(&mut self, gid: &[u8], to: &[String], encoded: &[u8]) -> Result<usize, Error> {
        let bytes = self.with(gid, |g, c| g.send(c, encoded))?;
        self.note_traffic(gid)?;
        let v: Value = self.api.send(&self.creds, to, &bytes)?;
        Ok(v["delivered"].as_u64().unwrap_or(0) as usize)
    }

    /// Fetches and processes the mailbox (waiting up to `wait` seconds for
    /// something to arrive), acknowledges everything processed, retries
    /// held messages after any epoch change, and sends the outbox items
    /// that are due ([`Session::send_pending`]).
    pub fn sync(&mut self, wait: u64) -> Result<Vec<Event>, Error> {
        self.client.purge_expired_messages(messages::now())?;
        let msgs = self.api.fetch_timed(&self.creds, wait)?;
        let mut events = Vec::new();
        let mut ids = Vec::new();
        let mut moved = false;
        for (id, body, at) in msgs {
            self.server_time = Some(at);
            let r = self.handle_durably(&body, &mut events, true);
            self.server_time = None;
            moved |= r?;
            ids.push(id);
        }
        self.api.ack(&self.creds, &ids)?;
        while moved {
            moved = self.retry_held(&mut events)?;
        }
        if events.iter().any(|e| matches!(e, Event::Joined { .. })) || self.key_packages_due()? {
            self.ensure_key_packages()?;
        }
        self.handle_invite_requests(&mut events)?;
        self.handle_community_requests(&mut events)?;
        self.refresh_due_groups(&mut events)?;
        // After joining, tell the others our name once we know where they are.
        for key in self.client.app_data_keys("announce/")? {
            let gid = hex::decode(&key["announce/".len()..]).map_err(|_| Error::Protocol("bad key".into()))?;
            if !self.other_devices(&gid)?.is_empty() {
                let (name, chat) = self.profile_name_for(&gid)?;
                self.send_payload(&gid, &Payload::Profile { name, chat })?;
                self.client.set_app_data(&key, None)?;
            }
        }
        // Scheduled messages that came due, storage clean-up (`rich.rs`).
        events.extend(self.after_sync()?);
        // Live locations due for an update, profile photos and per-chat
        // profiles the groups should have (`rich_media.rs`).
        self.rich_sync()?;
        // Settings changed here go to the account's other devices
        // (`self_sync.rs`); a refusal must not stop the rest of the sync.
        if let Err(e) = self.push_settings() {
            events.push(Event::Dropped { reason: format!("settings sync: {e}") });
        }
        events.extend(self.send_pending()?);
        Ok(events)
    }

    /// Processes one received body. Returns true if an epoch changed or a
    /// group was joined (held messages may now be readable).
    fn handle(&mut self, body: &[u8], events: &mut Vec<Event>, may_hold: bool) -> Result<bool, Error> {
        let gid = match peek(body) {
            Some(Peek::Welcome) => {
                return match self.client.join_from(body) {
                    Ok((g, adder)) => {
                        let gid = g.id();
                        self.groups.insert(gid.clone(), g);
                        self.init_group_maps(&gid)?;
                        self.note_joined(&gid)?;
                        self.set_time(&history_share::joined_key(&gid), messages::now())?;
                        // The member that added this device, as MLS verified
                        // it (the welcome's signer): history sharing trusts
                        // only it, never the sender of some roster.
                        self.client.set_app_data(&history_share::adder_key(&gid), Some(adder.to_hex().as_bytes()))?;
                        self.client.set_app_data(&history_share::taken_key(&gid), None)?;
                        self.client.set_app_data(&announce_key(&gid), Some(b"1"))?;
                        self.set_group_status(&gid, &GroupStatus::Request { from: None })?;
                        self.accept_if_asked(&gid)?;
                        events.push(Event::Joined { group: gid.clone() });
                        self.on_joined(&gid, events)?;
                        Ok(true)
                    }
                    Err(e) => {
                        events.push(Event::Dropped { reason: format!("welcome: {e}") });
                        Ok(false)
                    }
                };
            }
            Some(Peek::Envelope { group_id, kind, .. }) => (group_id, kind),
            None => {
                events.push(Event::Dropped { reason: "not a Tree message".into() });
                return Ok(false);
            }
        };
        let (gid, kind) = gid;
        if !self.client.group_ids()?.contains(&gid) {
            return self.hold(body, events, may_hold, "unknown group");
        }
        if self.group_status(&gid)? == GroupStatus::Declined {
            return Ok(false); // ignored after declining
        }
        // The settings before a commit, for the admin log.
        let before = if kind == tree_core::wire::Kind::Commit { Some(self.group(&gid)?.settings()) } else { None };
        self.group(&gid)?;
        let incoming = self.groups.get_mut(&gid).expect("loaded").receive(&self.client, body);
        match incoming {
            Ok(Incoming::Message { from, body }) => {
                self.on_payload(&gid, from, &body, events)?;
                Ok(false)
            }
            Ok(Incoming::GroupChanged { added, removed, epoch, own_commit_discarded, settings_changed, by }) => {
                self.note_departures(&gid, &removed)?;
                if let Some(before) = &before {
                    self.log_commit(&gid, &by, before, &added, &removed)?;
                }
                let mut roster = self.roster(&gid)?;
                let mut names = self.names(&gid)?;
                for m in &removed {
                    roster.remove(&m.to_hex());
                    names.remove(&m.to_hex());
                }
                self.save_roster(&gid, &roster)?;
                self.save_names(&gid, &names)?;
                if own_commit_discarded {
                    self.client.set_app_data(&pending_key(&gid), None)?;
                }
                events.push(Event::Changed { group: gid, added, removed, epoch, own_commit_discarded, settings_changed });
                Ok(true)
            }
            Ok(Incoming::OwnCommitMerged { .. }) => {
                // Our own commit came back before the server's answer did.
                self.client.set_app_data(&pending_key(&gid), None)?;
                Ok(true)
            }
            Ok(Incoming::RemovedFromGroup) => {
                events.push(Event::RemovedFromGroup { group: gid });
                Ok(true)
            }
            Ok(Incoming::OwnEcho) => Ok(false),
            Err(TreeError::Rejected(why)) if why.contains("seal") => self.hold(body, events, may_hold, &why),
            Err(e) => {
                events.push(Event::Dropped { reason: e.to_string() });
                Ok(false)
            }
        }
    }

    fn on_payload(&mut self, gid: &[u8], from: MemberId, body: &[u8], events: &mut Vec<Event>) -> Result<(), Error> {
        let me = self.member_id().to_hex();
        let (payload, franking) = match Payload::decode(body) {
            Some(Payload::Franked { p, k, tag, m }) => match Payload::decode(p.as_bytes()) {
                Some(inner) if inner.is_franked_kind() => {
                    let rec = franking::Record { payload: p, key: k, tag, minute: m };
                    (Some(inner), Some(rec.encode()))
                }
                _ => {
                    events.push(Event::Dropped { reason: "malformed franked payload".into() });
                    return Ok(());
                }
            },
            // Every honest client franks chat messages; one that does not
            // would make its messages unreportable (PROTOCOL.md 8.5).
            Some(p) if p.is_franked_kind() => {
                events.push(Event::Dropped { reason: "unfranked message".into() });
                return Ok(());
            }
            other => (other, None),
        };
        // The account's self group (settings sync) is not a chat: group
        // roles, restrictions and slow mode never apply in it, and it has
        // no topics, shared history or community joins, whoever sends them.
        if self.is_self_group(gid)? {
            if matches!(payload, Some(Payload::Topic { .. } | Payload::Topics { .. } | Payload::History { .. } | Payload::JoinChat { .. })) {
                events.push(Event::Dropped { reason: "not taken in the self group".into() });
                return Ok(());
            }
        } else if let Some(p) = &payload {
            // Restricted members and slow mode (`groups.rs`).
            if !self.gate(gid, &from, p, events)? {
                return Ok(());
            }
        }
        match payload {
            Some(
                p @ (Payload::Text { .. }
                | Payload::Edit { .. }
                | Payload::Delete { .. }
                | Payload::React { .. }
                | Payload::File(_)
                | Payload::Sticker { .. }
                | Payload::Location(_)
                | Payload::LiveLocation { .. }
                | Payload::ChatEvent(_)
                | Payload::EventEdit { .. }
                | Payload::Rsvp { .. }
                | Payload::ProfilePhoto { .. }),
            ) => {
                if self.blocked_sender(gid, &from)? {
                    events.push(Event::Dropped { reason: "from a blocked account".into() });
                    return Ok(());
                }
                if rich_media::is_rich_media(&p) {
                    self.on_rich_media(gid, from, p, franking, events)?;
                } else {
                    self.on_message(gid, from, p, franking, events)?;
                }
            }
            Some(p @ (Payload::Pin { .. } | Payload::Poll(_) | Payload::Vote { .. } | Payload::PollClose { .. })) => {
                self.on_rich(gid, from, p, franking, events)?
            }
            Some(Payload::Topic { id, name, closed }) => self.on_topic(gid, from, id, name, closed, events)?,
            Some(Payload::Topics { list }) => self.on_topic_list(gid, from, list, events)?,
            Some(Payload::History { to, msgs }) => self.on_history(gid, from, to, msgs, events)?,
            Some(Payload::JoinChat { chat, account }) => self.on_join_chat(gid, from, chat, account, events)?,
            Some(Payload::Roster { devices, names, accounts, link }) => {
                // Only entries for current members are taken; names only as
                // hints where the member has not announced its own.
                let members: std::collections::HashSet<String> = self.group(gid)?.members().iter().map(|m| m.to_hex()).collect();
                // Device ids decide where this device's messages go, so a
                // member must not be able to point another member at a
                // bogus id (every send would then fail, F-038). Taken only
                // if well formed, and for another member only while it has
                // none yet or from a trusted sender (one of this account's
                // devices, or pinned for its account); the sender may
                // always give its own.
                let trusted_sender = {
                    let own = self.own_members()?;
                    let s = from.to_hex();
                    own.contains(&s)
                        || match self.map(&accounts_key(gid))?.get(&s) {
                            Some(a) if *a == self.creds.account_id => false,
                            Some(a) => self.contact(a)?.is_some_and(|c| c.vouches_for(&s)),
                            None => false,
                        }
                };
                let mut roster = self.roster(gid)?;
                for (m, d) in devices {
                    if !members.contains(&m) || m == me || !is_device_id(&d) {
                        continue;
                    }
                    if m == from.to_hex() || trusted_sender || !roster.contains_key(&m) {
                        roster.insert(m, d);
                    }
                }
                self.save_roster(gid, &roster)?;
                let mut known = self.names(gid)?;
                // The sender's entry for itself is its own word, like a Profile.
                let own = names.get(&from.to_hex()).cloned();
                for (m, n) in names {
                    if members.contains(&m) && m != me {
                        known.entry(m).or_insert(n);
                    }
                }
                if let Some(n) = own {
                    known.insert(from.to_hex(), n);
                }
                self.save_names(gid, &known)?;
                // Account labels (PROTOCOL.md 5.4, F-022). A label is a
                // claim, never trust: it is only taken
                // - for a current member other than this device, and never
                //   for this device's own account unless the member is one
                //   of its own linked devices (`own/members`);
                // - as the first label for that member: a later roster never
                //   relabels a member (so nobody escapes a block, or moves
                //   another member to an account, by relabelling);
                // - for the sender itself (its own word), or for another
                //   member only if the sender is trusted (one of this
                //   account's devices, or pinned for its account).
                let mut known_accounts = self.map(&accounts_key(gid))?;
                let own = self.own_members()?;
                let usable = |m: &str, a: &str| members.iter().any(|x| x == m) && m != me && (a != self.creds.account_id || own.iter().any(|o| o == m));
                let mut by_account: BTreeMap<String, Vec<MemberId>> = BTreeMap::new();
                let sender = from.to_hex();
                if let Some(a) = accounts.get(&sender) {
                    if usable(&sender, a) && !known_accounts.contains_key(&sender) {
                        known_accounts.insert(sender.clone(), a.clone());
                        by_account.entry(a.clone()).or_default().push(from);
                    }
                }
                let adder = known_accounts.get(&sender).cloned();
                // The sender counts as its account only if this device has
                // it pinned for that account (a key-package claim this
                // device made, a verified safety number, or a confirmed
                // device link). A device that only claims an account, also
                // one with no pinned device yet, is judged as a stranger,
                // so nobody gets past message requests or `user.group_add`
                // by naming one of the user's contacts (F-018, F-021).
                let vouched = match &adder {
                    Some(a) if *a == self.creds.account_id => own.contains(&sender),
                    Some(a) => self.contact(a)?.is_some_and(|c| c.vouches_for(&sender)),
                    None => false,
                };
                if vouched || own.contains(&sender) {
                    for (m, a) in &accounts {
                        if let (true, false, Some(id)) = (usable(m, a), known_accounts.contains_key(m), MemberId::from_hex(m)) {
                            known_accounts.insert(m.clone(), a.clone());
                            by_account.entry(a.clone()).or_default().push(id);
                        }
                    }
                }
                self.save_map(&accounts_key(gid), &known_accounts)?;
                for (a, ids) in by_account {
                    self.pin(&a, &ids, false, events)?;
                }
                // In the self group every member is one of this account's devices.
                if self.is_self_group(gid)? && members.contains(&from.to_hex()) {
                    let named: Vec<String> = roster.keys().cloned().collect();
                    self.note_own_devices(gid, &named)?;
                }
                // The roster's sender added us if we are still a request.
                // Another device of this account (known from a confirmed
                // device link, PROTOCOL.md 8.11) adds us to its own groups.
                if own.contains(&sender) {
                    if matches!(self.group_status(gid)?, GroupStatus::Request { .. }) {
                        self.set_group_status(gid, &GroupStatus::Accepted)?;
                    }
                } else if let Some(adder) = adder {
                    self.decide_request(gid, &adder, &from, vouched, link.as_deref(), events)?;
                }
                events.push(Event::RosterUpdated { group: gid.to_vec() });
            }
            Some(Payload::Profile { name, chat }) => {
                // A name for this chat only counts while the chat allows them.
                if chat && !self.chat_feature(gid, "chat.allow_per_chat_profiles")?.0 {
                    events.push(Event::Dropped { reason: "per-chat names are released in this group (chat.allow_per_chat_profiles)".into() });
                    return Ok(());
                }
                let mut known = self.names(gid)?;
                known.insert(from.to_hex(), name.clone());
                self.save_names(gid, &known)?;
                events.push(Event::Profile { group: gid.to_vec(), member: from, name });
            }
            Some(Payload::Leave { quiet }) => {
                self.note_leave_request(gid, &from, quiet)?;
                events.push(Event::LeaveRequested { group: gid.to_vec(), member: from, quiet })
            }
            Some(Payload::RemoveDevice { members }) => {
                // Only devices of the sender's own account, as this device
                // knows the accounts (PROTOCOL.md 8.11). The account labels
                // come from rosters other members send, so this is a request
                // for an admin to decide, never carried out automatically
                // (unlike a member's own leave request).
                let accounts = self.map(&accounts_key(gid))?;
                let current = self.group(gid)?.members();
                if let Some(acc) = accounts.get(&from.to_hex()) {
                    for m in members.iter().filter_map(|m| MemberId::from_hex(m)) {
                        if m != from && current.contains(&m) && accounts.get(&m.to_hex()) == Some(acc) {
                            events.push(Event::RemoveDeviceRequested { group: gid.to_vec(), member: m, by: from });
                        }
                    }
                }
            }
            Some(Payload::Read { ids }) => self.on_read(gid, from, ids, events)?,
            Some(Payload::Seen) => self.on_seen(gid, from)?,
            Some(Payload::Typing { on }) => {
                if self.is_applied("user.typing")? {
                    events.push(Event::Typing { group: gid.to_vec(), from, on });
                }
            }
            Some(Payload::Settings { s }) => self.on_settings(gid, from, s, events)?,
            Some(Payload::Franked { .. }) | None => events.push(Event::Dropped { reason: format!("unsupported message from {}", &from.to_hex()[..8]) }),
        }
        Ok(())
    }

    /// Keeps a message that cannot be read yet for a retry. Anyone who knows
    /// this device's id can send such messages, so a flood must not push
    /// out the genuine ones waiting for their welcome (F-035): at most
    /// [`MAX_HELD_PER_GROUP`] per group id, at most [`MAX_HELD`] in all;
    /// when full, messages older than [`HELD_MAX_AGE`] go first, and
    /// otherwise the new message is dropped, never an older one.
    fn hold(&mut self, body: &[u8], events: &mut Vec<Event>, may_hold: bool, why: &str) -> Result<bool, Error> {
        if !may_hold {
            return Err(Error::Protocol(format!("still held: {why}")));
        }
        // Keys: `held/<20 digits>`, the arrival time in seconds times a
        // million plus a sequence number, so they sort by age (older
        // counters from before sort first, as the oldest).
        let now = messages::now();
        let group = |b: &[u8]| match peek(b) {
            Some(Peek::Envelope { group_id, .. }) => Some(group_id),
            _ => None,
        };
        let mine = group(body);
        let mut keys = self.client.app_data_keys("held/")?;
        if keys.len() >= MAX_HELD {
            for k in keys.iter().filter(|k| k[5..].parse::<u64>().map_or(true, |n| (n / 1_000_000) as i64 + HELD_MAX_AGE < now)) {
                self.client.set_app_data(k, None)?;
            }
            keys = self.client.app_data_keys("held/")?;
        }
        let same_group = keys
            .iter()
            .filter(|k| self.client.app_data(k).ok().flatten().is_some_and(|b| group(&b) == mine))
            .count();
        if keys.len() >= MAX_HELD || same_group >= MAX_HELD_PER_GROUP {
            events.push(Event::Dropped { reason: format!("not readable yet ({why}) and no room to hold it") });
            return Ok(false);
        }
        let base = (now.max(0) as u64) * 1_000_000;
        let next = keys.last().and_then(|k| k[5..].parse::<u64>().ok()).map_or(base, |n| (n + 1).max(base));
        self.client.set_app_data(&format!("held/{next:020}"), Some(body))?;
        events.push(Event::Held);
        Ok(false)
    }

    /// [`Session::handle`] as one unit on disk: the group's new key state and
    /// the stored message land together, so a crash in between cannot use
    /// up a message's keys without keeping the message. The server copy is
    /// acknowledged only after this returns.
    ///
    /// No network request goes out inside the batch (F-024): whatever the
    /// handler sends (a decline's leave request, a roster, a profile) is
    /// only sealed and queued in the outbox, in the same batch, and the
    /// outbox is driven after the batch is committed (`sync` does it).
    /// Otherwise a crash after the server took a request but before the
    /// batch committed would roll back the keys used to seal it, and the
    /// next attempt would seal different bytes with the same keys.
    fn handle_durably(&mut self, body: &[u8], events: &mut Vec<Event>, may_hold: bool) -> Result<bool, Error> {
        self.client.begin_batch()?;
        self.api.set_receiving(true);
        let r = self.handle(body, events, may_hold);
        self.api.set_receiving(false);
        self.end_batch()?;
        r
    }

    fn end_batch(&mut self) -> Result<(), Error> {
        if let Err(e) = self.client.end_batch() {
            // Rolled back: the loaded groups are ahead of the disk.
            self.groups.clear();
            return Err(e.into());
        }
        Ok(())
    }

    /// Tries every held message once. Returns true if one changed an epoch.
    fn retry_held(&mut self, events: &mut Vec<Event>) -> Result<bool, Error> {
        let mut moved = false;
        for key in self.client.app_data_keys("held/")? {
            let Some(body) = self.client.app_data(&key)? else { continue };
            let mut ev = Vec::new();
            self.client.begin_batch()?;
            self.api.set_receiving(true);
            let r = self.handle(&body, &mut ev, false);
            self.api.set_receiving(false);
            let r = match r {
                Ok(m) => self.client.set_app_data(&key, None).map(|_| m).map_err(Error::from),
                e => e,
            };
            self.end_batch()?;
            match r {
                Ok(m) => {
                    moved |= m;
                    events.extend(ev);
                }
                Err(Error::Protocol(_)) => {} // still not readable: keep it
                Err(e) => return Err(e),
            }
        }
        Ok(moved)
    }
}

/// A server device id: 16 bytes, base64url without padding (22 characters).
pub(crate) fn is_device_id(s: &str) -> bool {
    use base64::Engine;
    s.len() == 22
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).is_ok_and(|v| v.len() == 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> MemberId {
        MemberId([b; 32])
    }

    #[test]
    fn per_group_keys_differ() {
        let (a, b) = ([1u8; 16], [2u8; 16]);
        for f in [roster_key, names_key, accounts_key, pending_key] {
            assert_ne!(f(&a), f(&b));
            assert!(f(&a).ends_with(&hex::encode(a)));
        }
        let all = [roster_key(&a), names_key(&a), accounts_key(&a), pending_key(&a)];
        for (i, x) in all.iter().enumerate() {
            for y in &all[i + 1..] {
                assert_ne!(x, y, "kinds do not collide");
            }
        }
    }

    #[test]
    fn pinning_rules() {
        // first contact named by the server: pinned as is, no warning
        let (c, ev) = merge_pins(None, "acc", &[id(1), id(1)], true).unwrap();
        assert_eq!((c.members.len(), c.verified, ev), (1, false, None));
        assert!(c.vouches_for(&id(1).to_hex()));
        // first contact only claimed by a roster: seen, not pinned (F-021)
        let (r, ev) = merge_pins(None, "acc", &[id(1)], false).unwrap();
        assert_eq!(ev, None);
        assert!(!r.vouches_for(&id(1).to_hex()) && r.pinned().is_empty());
        // same devices again: nothing to do
        assert!(merge_pins(Some(c.clone()), "acc", &[id(1)], false).is_none());
        // a device missing from a claim (no key packages left) is no change
        assert!(merge_pins(Some(c.clone()), "acc", &[], true).is_none());
        // verified, then a new device appears: warning, verification cleared
        let verified = Contact { verified: true, ..c };
        let (c2, ev) = merge_pins(Some(verified), "acc", &[id(1), id(2)], false).unwrap();
        assert_eq!(ev, Some(Event::KeyChanged { account: "acc".into(), new_members: vec![id(2)], was_verified: true }));
        assert!(!c2.verified);
        assert_eq!(c2.member_ids(), vec![id(1), id(2)]);
        // only a roster claimed it: not vouched for until the server names it
        assert!(c2.vouches_for(&id(1).to_hex()) && !c2.vouches_for(&id(2).to_hex()));
        let (c3, ev) = merge_pins(Some(c2.clone()), "acc", &[id(2)], true).unwrap();
        assert_eq!(ev, None, "no second warning");
        assert!(c3.vouches_for(&id(2).to_hex()));
        // unverified change is reported too
        let (_, ev) = merge_pins(Some(c2), "acc", &[id(3)], true).unwrap();
        assert!(matches!(ev, Some(Event::KeyChanged { was_verified: false, .. })));
        // a contact added by hand has no devices yet: it vouches for nobody,
        // and a roster claim does not pin its first device (F-021)
        let hand = Contact { account: "acc".into(), accepted: true, ..Default::default() };
        assert!(!hand.vouches_for(&id(9).to_hex()));
        let (c4, ev) = merge_pins(Some(hand.clone()), "acc", &[id(9)], false).unwrap();
        assert!(!c4.vouches_for(&id(9).to_hex()) && c4.pinned().is_empty());
        assert!(matches!(ev, Some(Event::KeyChanged { .. })), "warned");
        // the server naming it (a key-package claim this device made) pins it
        let (c5, _) = merge_pins(Some(c4), "acc", &[id(9)], true).unwrap();
        assert!(c5.vouches_for(&id(9).to_hex()));
        // so does a key-package claim on the empty contact directly
        let (c6, _) = merge_pins(Some(hand), "acc", &[id(9)], true).unwrap();
        assert!(c6.vouches_for(&id(9).to_hex()));
    }
}

