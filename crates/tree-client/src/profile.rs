//! Profile photos and per-chat profiles (APP_PROTOCOL.md 8.6, 8.7).
//!
//! **Profile photo.** The photo is uploaded as an encrypted attachment
//! with its own key; the reference and key go only inside MLS (a
//! `profile_photo` payload, like `profile`), to the groups the user's
//! `user.profile_photo_visibility` allows:
//!
//! | Option | Groups that get the photo |
//! | --- | --- |
//! | `chats` (default) | every accepted chat this device is in |
//! | `contacts` | chats whose other members are all contacts the user chose (and not blocked) |
//! | `nobody` (or released) | none |
//!
//! Every sync compares what each group should have with what it was last
//! sent and sends the difference: a new photo, or "removed" where it is
//! removed or no longer allowed, and again when members were added. The
//! server never learns names or photos, only opaque blobs. Receivers keep
//! the reference per group and member, fetch the photo once and cache it;
//! a removal deletes both. Attachments expire on the server after the
//! mailbox TTL (30 days), so the photo is uploaded again after 20 days.
//!
//! **Per-chat profile** (`user.per_chat_profile`, released by default,
//! and the chat's `chat.allow_per_chat_profiles`, applied by default): a
//! display name and photo shown in one chat only, sent with `chat: true`.
//! When either switch is released the device goes back to its main name
//! and photo in that chat, and receivers ignore per-chat names and photos
//! while the chat releases them. This is a presentation layer only: the
//! member keeps the same keys (and MLS member id) in every chat, so members
//! of two chats can still link the two names by comparing member ids or
//! safety numbers. Separate keys per chat (full unlinkability) is a later
//! step.

use serde::{Deserialize, Serialize};
use tree_core::MemberId;

use crate::messages::now;
use crate::payload::{BlobRef, Payload};
use crate::{accounts_key, Error, Event, GroupStatus, Session};

/// Largest photo.
pub const MAX_PHOTO_BYTES: u64 = 2 * 1024 * 1024;
/// A photo is uploaded again when it is this old (the server keeps blobs
/// for 30 days).
pub const PHOTO_REFRESH: i64 = 20 * 86400;
/// Per-chat display name (characters).
pub const MAX_CHAT_NAME: usize = 64;
const OWN_PHOTO: &str = "profile/photo";
pub(crate) const VISIBILITY: &str = "user.profile_photo_visibility";
pub(crate) const PER_CHAT: &str = "user.per_chat_profile";
const CHAT_KEY: &str = "chat.allow_per_chat_profiles";

/// A photo this device shares: its upload and the bytes (to upload again).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwnPhoto {
    blob: BlobRef,
    mime: String,
    uploaded_at: i64,
    #[serde(with = "b64")]
    bytes: Vec<u8>,
}

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(b))
    }
    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Vec<u8>, D::Error> {
        STANDARD.decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// This user's name and photo for one chat.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ChatProfile {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    photo: Option<OwnPhoto>,
}

/// What a group was last sent: the photo's attachment id ("" = removed),
/// whether it was a per-chat one, and the members then.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Shared {
    photo: String,
    chat: bool,
    members: Vec<String>,
}

/// A received photo reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Received {
    blob: BlobRef,
    mime: String,
    chat: bool,
}

/// A photo and its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Photo {
    pub bytes: Vec<u8>,
    pub mime: String,
}

/// This user's profile for one chat, as the chat settings screen shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatProfileView {
    pub name: Option<String>,
    pub has_photo: bool,
}

fn g(gid: &[u8]) -> String {
    hex::encode(gid)
}

fn check_photo(bytes: &[u8], mime: &str) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_PHOTO_BYTES || !mime.starts_with("image/") {
        return Err(Error::Usage(format!("a profile photo is an image of at most {} MiB", MAX_PHOTO_BYTES / (1024 * 1024))));
    }
    Ok(())
}

impl Session {
    fn new_photo(&self, bytes: &[u8], mime: &str) -> Result<OwnPhoto, Error> {
        check_photo(bytes, mime)?;
        Ok(OwnPhoto { blob: self.upload_blob(bytes)?, mime: mime.to_string(), uploaded_at: now(), bytes: bytes.to_vec() })
    }

    /// Sets the profile photo: uploads it encrypted and shares it with the
    /// chats `user.profile_photo_visibility` allows (now, and every sync).
    pub fn set_profile_photo(&mut self, bytes: &[u8], mime: &str) -> Result<(), Error> {
        let p = self.new_photo(bytes, mime)?;
        self.app_put(OWN_PHOTO, Some(&p))?;
        self.share_profiles()
    }

    /// Removes the profile photo; every chat that had it is told.
    pub fn remove_profile_photo(&mut self) -> Result<(), Error> {
        self.app_put::<OwnPhoto>(OWN_PHOTO, None)?;
        self.share_profiles()
    }

    /// This user's own photo, if set.
    pub fn profile_photo(&self) -> Result<Option<Photo>, Error> {
        Ok(self.app_get::<OwnPhoto>(OWN_PHOTO)?.map(|p| Photo { bytes: p.bytes, mime: p.mime }))
    }

    /// A member's photo in this group (fetched once, then cached), or none.
    /// This device's own member gets its own photo for the chat.
    pub fn member_photo(&self, gid: &[u8], member: &MemberId) -> Result<Option<Photo>, Error> {
        if *member == self.member_id() {
            if let Some(p) = self.app_get::<ChatProfile>(&format!("chatprofile/{}", g(gid)))?.and_then(|c| c.photo) {
                return Ok(Some(Photo { bytes: p.bytes, mime: p.mime }));
            }
            return self.profile_photo();
        }
        let Some(r) = self.app_get::<Received>(&format!("photo/{}/{}", g(gid), member.to_hex()))? else { return Ok(None) };
        let cache = format!("photocache/{}", r.blob.id);
        if let Some(b) = self.client.app_data(&cache)? {
            return Ok(Some(Photo { bytes: b, mime: r.mime }));
        }
        let b = self.download_blob(&r.blob, MAX_PHOTO_BYTES)?;
        self.client.set_app_data(&cache, Some(&b))?;
        Ok(Some(Photo { bytes: b.to_vec(), mime: r.mime }))
    }

    /// Sets this user's name and / or photo for one chat only
    /// (`user.per_chat_profile`, and the chat's
    /// `chat.allow_per_chat_profiles`). `None` keeps the main one.
    pub fn set_chat_profile(&mut self, gid: &[u8], name: Option<&str>, photo: Option<(&[u8], &str)>) -> Result<(), Error> {
        if !self.is_applied(PER_CHAT)? {
            return Err(Error::Feature("RELEASED".into()));
        }
        if !self.chat_feature(gid, CHAT_KEY)?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let name = name.map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
        if name.as_ref().is_some_and(|n| n.chars().count() > MAX_CHAT_NAME) {
            return Err(Error::Usage(format!("a name is at most {MAX_CHAT_NAME} characters")));
        }
        let photo = photo.map(|(b, m)| self.new_photo(b, m)).transpose()?;
        let cp = ChatProfile { name: name.clone(), photo };
        self.app_put(&format!("chatprofile/{}", g(gid)), Some(&cp))?;
        let (n, chat) = self.profile_name_for(gid)?;
        self.announce_name(gid, n, chat)?;
        self.share_profiles()
    }

    /// Back to the main name and photo in this chat.
    pub fn clear_chat_profile(&mut self, gid: &[u8]) -> Result<(), Error> {
        if self.app_get::<ChatProfile>(&format!("chatprofile/{}", g(gid)))?.is_none() {
            return Ok(());
        }
        self.app_put::<ChatProfile>(&format!("chatprofile/{}", g(gid)), None)?;
        self.announce_name(gid, self.name().to_string(), false)?;
        self.share_profiles()
    }

    /// This user's per-chat profile in this chat, if one is in use.
    pub fn chat_profile(&self, gid: &[u8]) -> Result<Option<ChatProfileView>, Error> {
        Ok(self.app_get::<ChatProfile>(&format!("chatprofile/{}", g(gid)))?.map(|c| ChatProfileView { name: c.name, has_photo: c.photo.is_some() }))
    }

    /// The name this device shows in the group, and whether it is a
    /// per-chat one.
    pub(crate) fn profile_name_for(&self, gid: &[u8]) -> Result<(String, bool), Error> {
        Ok(match self.app_get::<ChatProfile>(&format!("chatprofile/{}", g(gid)))?.and_then(|c| c.name) {
            Some(n) => (n, true),
            None => (self.name().to_string(), false),
        })
    }

    fn announce_name(&mut self, gid: &[u8], name: String, chat: bool) -> Result<(), Error> {
        let mut names = self.names(gid)?;
        names.insert(self.member_id().to_hex(), name.clone());
        self.save_names(gid, &names)?;
        if self.group(gid)?.is_member() {
            self.send_payload(gid, &Payload::Profile { name, chat })?;
        }
        Ok(())
    }

    /// May the main photo go to this group under the visibility setting?
    fn photo_allowed(&mut self, gid: &[u8]) -> Result<bool, Error> {
        let st = self.feature(VISIBILITY)?;
        if st.state != tree_core::features::State::Applied {
            return Ok(false);
        }
        match st.option.as_deref().unwrap_or("chats") {
            "chats" => Ok(true),
            "contacts" => {
                let me = self.member_id();
                let accounts = self.map(&accounts_key(gid))?;
                for m in self.group(gid)?.members() {
                    if m == me {
                        continue;
                    }
                    let Some(a) = accounts.get(&m.to_hex()) else { return Ok(false) };
                    if a == self.account_id() {
                        continue; // another device of this account
                    }
                    match self.contact(a)? {
                        Some(c) if c.accepted && !c.blocked && c.vouches_for(&m.to_hex()) => {}
                        _ => return Ok(false),
                    }
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Uploads a photo again if the server may have dropped it.
    fn fresh(&self, p: &mut OwnPhoto) -> Result<bool, Error> {
        if now() - p.uploaded_at < PHOTO_REFRESH {
            return Ok(false);
        }
        *p = self.new_photo(&p.bytes.clone(), &p.mime.clone())?;
        Ok(true)
    }

    /// Brings every group to the photo and per-chat profile it should have
    /// (see the module documentation). Runs after every sync.
    pub(crate) fn share_profiles(&mut self) -> Result<(), Error> {
        let per_chat_on = self.is_applied(PER_CHAT)?;
        let mut main = self.app_get::<OwnPhoto>(OWN_PHOTO)?;
        if let Some(p) = main.as_mut() {
            if self.fresh(p)? {
                self.app_put(OWN_PHOTO, Some(&*p))?;
            }
        }
        for gid in self.group_ids()? {
            if !self.group(&gid)?.is_member() || self.group_status(&gid)? != GroupStatus::Accepted || self.other_devices(&gid)?.is_empty() {
                continue;
            }
            let cp_key = format!("chatprofile/{}", g(&gid));
            let mut cp = self.app_get::<ChatProfile>(&cp_key)?;
            // Per-chat profile no longer allowed: back to the main one.
            if cp.is_some() && !(per_chat_on && self.chat_feature(&gid, CHAT_KEY)?.0) {
                self.app_put::<ChatProfile>(&cp_key, None)?;
                cp = None;
                self.announce_name(&gid, self.name().to_string(), false)?;
            }
            let mut chat_photo = cp.and_then(|c| c.photo);
            if let Some(p) = chat_photo.as_mut() {
                if self.fresh(p)? {
                    let mut c = self.app_get::<ChatProfile>(&cp_key)?.unwrap_or_default();
                    c.photo = Some(p.clone());
                    self.app_put(&cp_key, Some(&c))?;
                }
            }
            let (want, chat) = match (&chat_photo, &main) {
                (Some(p), _) => (Some(p.clone()), true),
                (None, Some(p)) if self.photo_allowed(&gid)? => (Some(p.clone()), false),
                _ => (None, false),
            };
            let mut members: Vec<String> = self.group(&gid)?.members().iter().map(MemberId::to_hex).collect();
            members.sort();
            let target = Shared { photo: want.as_ref().map(|p| p.blob.id.clone()).unwrap_or_default(), chat, members };
            let skey = format!("photoshared/{}", g(&gid));
            let last = self.app_get::<Shared>(&skey)?;
            let same = match &last {
                // Nothing was ever sent and there is nothing to send.
                None => target.photo.is_empty(),
                // Same photo, and nobody new to tell (removals need nothing).
                Some(l) => l.photo == target.photo && l.chat == target.chat && (target.photo.is_empty() || target.members.iter().all(|m| l.members.contains(m))),
            };
            if same {
                continue;
            }
            let p = Payload::ProfilePhoto { photo: want.as_ref().map(|p| p.blob.clone()), mime: want.map(|p| p.mime), chat };
            self.send_payload(&gid, &p)?;
            self.app_put(&skey, Some(&target))?;
        }
        Ok(())
    }

    pub(crate) fn on_profile_photo(
        &mut self,
        gid: &[u8],
        from: MemberId,
        photo: Option<BlobRef>,
        mime: Option<String>,
        chat: bool,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if chat && !self.chat_feature(gid, CHAT_KEY)?.0 {
            events.push(Event::Dropped { reason: "per-chat photos are released in this group (chat.allow_per_chat_profiles)".into() });
            return Ok(());
        }
        let key = format!("photo/{}/{}", g(gid), from.to_hex());
        if let Some(old) = self.app_get::<Received>(&key)? {
            if photo.as_ref().is_none_or(|p| p.id != old.blob.id) {
                self.client.set_app_data(&format!("photocache/{}", old.blob.id), None)?;
            }
        }
        match photo {
            Some(blob) => {
                let mime = mime.unwrap_or_default();
                if blob.size > MAX_PHOTO_BYTES || blob.id.is_empty() || blob.id.len() > 64 || !mime.starts_with("image/") {
                    events.push(Event::Dropped { reason: "malformed profile photo".into() });
                    return Ok(());
                }
                self.app_put(&key, Some(&Received { blob, mime, chat }))?;
                events.push(Event::ProfilePhoto { group: gid.to_vec(), member: from, removed: false });
            }
            None => {
                self.app_put::<Received>(&key, None)?;
                events.push(Event::ProfilePhoto { group: gid.to_vec(), member: from, removed: true });
            }
        }
        Ok(())
    }
}
