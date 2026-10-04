//! Sticker and custom emoji packs (`chat.stickers`, APP_PROTOCOL.md 8.1).
//!
//! A pack is a set of images, each uploaded as an encrypted attachment with
//! its own key, plus a manifest (title, item names, plain emoji, and each
//! image's reference and key), itself uploaded as an encrypted attachment.
//! A pack is shared by a link that carries the manifest's reference and key
//! (`tree://stickers/<base64url JSON>`), exactly like a file reference: who
//! has the link can open the pack; the server holds only opaque blobs and
//! never learns names, images or who installed what.
//!
//! A sticker message names the pack (its manifest reference) and the item
//! index; receivers fetch the manifest and the image with the keys. A
//! reaction can be a custom emoji from a pack; it carries the item's plain
//! emoji too, which older apps and chats with `chat.stickers` released show.
//!
//! On this device: installed packs `stickerpack/<manifest id>`, manifests
//! seen `stickermanifest/<id>`, cached images `stickerimg/<id>/<index>`,
//! pack references learned from messages `stickerref/<id>`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tree_core::MemberId;

use crate::payload::{BlobRef, Payload, StickerRef};
use crate::{Error, Event, Session};

/// Items per pack.
pub const MAX_PACK_ITEMS: usize = 120;
/// Size of one sticker image.
pub const MAX_STICKER_BYTES: u64 = 512 * 1024;
/// Size of a manifest.
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
/// Pack title, item name (characters).
pub const MAX_TITLE: usize = 64;
const LINK_PREFIX: &str = "tree://stickers/";

/// One item of a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackItem {
    pub name: String,
    /// The plain emoji it stands for (1 to 8 characters).
    pub emoji: String,
    pub mime: String,
    pub file: BlobRef,
}

/// What the manifest blob holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u32,
    pub title: String,
    /// A custom emoji pack (small images used inline and as reactions)
    /// rather than a sticker pack.
    #[serde(default)]
    pub emoji_pack: bool,
    pub items: Vec<PackItem>,
}

fn emoji_ok(e: &str) -> bool {
    !e.is_empty() && e.chars().count() <= 8
}

impl Manifest {
    fn check(&self) -> Result<(), Error> {
        let bad = |w: &str| Err(Error::Protocol(format!("sticker pack: {w}")));
        if self.v != 1 {
            return bad("unknown version");
        }
        if self.title.trim().is_empty() || self.title.chars().count() > MAX_TITLE {
            return bad("title");
        }
        if self.items.is_empty() || self.items.len() > MAX_PACK_ITEMS {
            return bad("number of items");
        }
        for i in &self.items {
            if i.name.chars().count() > MAX_TITLE || !emoji_ok(&i.emoji) || !i.mime.starts_with("image/") || i.file.size > MAX_STICKER_BYTES {
                return bad("item");
            }
        }
        Ok(())
    }
}

/// A new item for [`Session::create_sticker_pack`].
#[derive(Debug, Clone)]
pub struct NewSticker {
    pub name: String,
    pub emoji: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// A pack as the apps show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickerPack {
    /// The manifest's attachment id: names the pack in messages.
    pub id: String,
    /// The link that shares it.
    pub link: String,
    pub manifest: Manifest,
}

#[derive(Serialize, Deserialize)]
struct Installed {
    pack: BlobRef,
    manifest: Manifest,
}

/// The link for a pack's manifest reference.
pub fn pack_link(r: &BlobRef) -> String {
    format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(r).expect("JSON")))
}

/// The manifest reference in a pack link.
pub fn parse_pack_link(link: &str) -> Result<BlobRef, Error> {
    let bad = || Error::Usage("not a sticker pack link".into());
    let rest = link.trim().strip_prefix(LINK_PREFIX).ok_or_else(bad)?;
    if rest.len() > 2048 {
        return Err(bad());
    }
    let json = URL_SAFE_NO_PAD.decode(rest).map_err(|_| bad())?;
    let r: BlobRef = serde_json::from_slice(&json).map_err(|_| bad())?;
    if r.size > MAX_MANIFEST_BYTES || r.id.is_empty() || r.id.len() > 64 {
        return Err(bad());
    }
    Ok(r)
}

/// The reaction key a custom emoji is stored under: `sticker:<pack>:<index>`.
pub fn custom_emoji_key(pack: &str, index: u32) -> String {
    format!("sticker:{pack}:{index}")
}

/// The pack and index behind a reaction key, if it is a custom emoji.
pub fn parse_custom_emoji_key(key: &str) -> Option<(String, u32)> {
    let rest = key.strip_prefix("sticker:")?;
    let (pack, index) = rest.rsplit_once(':')?;
    Some((pack.to_string(), index.parse().ok()?))
}

impl Session {
    /// Uploads a new pack (each image and then the manifest as encrypted
    /// attachments), installs it on this device and returns it with its
    /// link.
    pub fn create_sticker_pack(&mut self, title: &str, items: &[NewSticker], emoji_pack: bool) -> Result<StickerPack, Error> {
        if items.is_empty() || items.len() > MAX_PACK_ITEMS {
            return Err(Error::Usage(format!("a pack has 1 to {MAX_PACK_ITEMS} items")));
        }
        for i in items {
            if i.bytes.len() as u64 > MAX_STICKER_BYTES || !i.mime.starts_with("image/") || !emoji_ok(&i.emoji) {
                return Err(Error::Usage(format!(
                    "each sticker is an image of at most {} KiB with one emoji",
                    MAX_STICKER_BYTES / 1024
                )));
            }
        }
        let mut list = Vec::new();
        for i in items {
            list.push(PackItem { name: i.name.clone(), emoji: i.emoji.clone(), mime: i.mime.clone(), file: self.upload_blob(&i.bytes)? });
        }
        let manifest = Manifest { v: 1, title: title.trim().to_string(), emoji_pack, items: list };
        manifest.check().map_err(|_| Error::Usage(format!("a pack needs a title of at most {MAX_TITLE} characters")))?;
        let pack = self.upload_blob(&serde_json::to_vec(&manifest).expect("JSON"))?;
        for (n, i) in items.iter().enumerate() {
            self.client.set_app_data(&format!("stickerimg/{}/{n}", pack.id), Some(&i.bytes))?;
        }
        self.keep_pack(&pack, &manifest, true)?;
        Ok(StickerPack { id: pack.id.clone(), link: pack_link(&pack), manifest })
    }

    fn keep_pack(&self, pack: &BlobRef, manifest: &Manifest, install: bool) -> Result<(), Error> {
        self.app_put(&format!("stickerref/{}", pack.id), Some(pack))?;
        self.app_put(&format!("stickermanifest/{}", pack.id), Some(manifest))?;
        if install {
            self.app_put(&format!("stickerpack/{}", pack.id), Some(&Installed { pack: pack.clone(), manifest: manifest.clone() }))?;
        }
        Ok(())
    }

    /// The manifest of a pack: cached, or fetched and checked.
    fn manifest(&self, pack: &BlobRef) -> Result<Manifest, Error> {
        if let Some(m) = self.app_get::<Manifest>(&format!("stickermanifest/{}", pack.id))? {
            return Ok(m);
        }
        let bytes = self.download_blob(pack, MAX_MANIFEST_BYTES)?;
        let m: Manifest = serde_json::from_slice(&bytes).map_err(|_| Error::Protocol("sticker pack: damaged manifest".into()))?;
        m.check()?;
        self.keep_pack(pack, &m, false)?;
        Ok(m)
    }

    /// Opens a pack link: fetches the manifest and every image (so the pack
    /// works later without the server) and installs it.
    pub fn install_sticker_pack(&mut self, link: &str) -> Result<StickerPack, Error> {
        let pack = parse_pack_link(link)?;
        let manifest = self.manifest(&pack)?;
        for n in 0..manifest.items.len() {
            self.sticker_image(&pack.id, n as u32)?;
        }
        self.keep_pack(&pack, &manifest, true)?;
        Ok(StickerPack { id: pack.id.clone(), link: pack_link(&pack), manifest })
    }

    /// Removes an installed pack and its cached images from this device.
    /// Stickers others sent from it can still be fetched with their keys.
    pub fn remove_sticker_pack(&self, id: &str) -> Result<(), Error> {
        self.client.set_app_data(&format!("stickerpack/{id}"), None)?;
        for k in self.client.app_data_keys(&format!("stickerimg/{id}/"))? {
            self.client.set_app_data(&k, None)?;
        }
        Ok(())
    }

    /// The packs installed on this device.
    pub fn sticker_packs(&self) -> Result<Vec<StickerPack>, Error> {
        let mut out = Vec::new();
        for k in self.client.app_data_keys("stickerpack/")? {
            if let Some(i) = self.app_get::<Installed>(&k)? {
                out.push(StickerPack { id: i.pack.id.clone(), link: pack_link(&i.pack), manifest: i.manifest });
            }
        }
        Ok(out)
    }

    /// The image of item `index` of a pack this device knows (installed,
    /// or named by a message it received): cached, or fetched with its key.
    pub fn sticker_image(&self, pack_id: &str, index: u32) -> Result<Vec<u8>, Error> {
        let key = format!("stickerimg/{pack_id}/{index}");
        if let Some(b) = self.client.app_data(&key)? {
            return Ok(b);
        }
        let pack: BlobRef =
            self.app_get(&format!("stickerref/{pack_id}"))?.ok_or_else(|| Error::Usage("unknown sticker pack".into()))?;
        let m = self.manifest(&pack)?;
        let item = m.items.get(index as usize).ok_or_else(|| Error::Protocol("no such sticker in the pack".into()))?;
        let bytes = self.download_blob(&item.file, MAX_STICKER_BYTES)?;
        self.client.set_app_data(&key, Some(&bytes))?;
        Ok(bytes.to_vec())
    }

    /// The pack and index of sticker message `id` of the group, if it is one.
    pub fn sticker_in(&self, gid: &[u8], id: &str) -> Result<Option<(String, u32)>, Error> {
        Ok(self.client.message(gid, id)?.as_ref().and_then(sticker_of))
    }

    /// The pack reference and item of a sticker this device can send.
    fn own_item(&self, pack_id: &str, index: u32) -> Result<(BlobRef, PackItem), Error> {
        let i: Installed =
            self.app_get(&format!("stickerpack/{pack_id}"))?.ok_or_else(|| Error::Usage("install the pack first".into()))?;
        let item = i.manifest.items.get(index as usize).cloned().ok_or_else(|| Error::Usage("no such sticker in the pack".into()))?;
        Ok((i.pack, item))
    }

    /// Sends item `index` of an installed pack (`chat.stickers`); returns
    /// the message id.
    pub fn send_sticker(&mut self, gid: &[u8], pack_id: &str, index: u32) -> Result<String, Error> {
        if !self.chat_feature(gid, "chat.stickers")?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let (pack, item) = self.own_item(pack_id, index)?;
        let id = crate::messages::new_id();
        let me = self.member_id();
        let data = serde_json::to_vec(&serde_json::json!({ "pack": pack.id, "index": index })).expect("JSON");
        let p = Payload::Sticker { id: id.clone(), pack, index, emoji: item.emoji.clone() };
        self.queue_payload(gid, &p, Some(&id), |s| s.store(gid, &id, &me, "sticker", Some(item.emoji), Some(data), None).map(|_| ()))?;
        Ok(id)
    }

    /// Reacts with a custom emoji from an installed pack (`chat.reactions`
    /// and `chat.stickers`); `remove` takes it back. Stored under
    /// [`custom_emoji_key`].
    pub fn react_sticker(&mut self, gid: &[u8], msg_id: &str, pack_id: &str, index: u32, remove: bool) -> Result<(), Error> {
        if !self.chat_feature(gid, "chat.reactions")?.0 || !self.chat_feature(gid, "chat.stickers")?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let (pack, item) = self.own_item(pack_id, index)?;
        let m = self.client.message(gid, msg_id)?.ok_or_else(|| Error::Usage("no such message".into()))?;
        if m.deleted {
            return Err(Error::Usage("the message was deleted".into()));
        }
        let me = self.member_id().to_hex();
        let key = custom_emoji_key(&pack.id, index);
        let p = Payload::React { id: msg_id.into(), emoji: item.emoji, remove, sticker: Some(StickerRef { pack, index }) };
        self.queue_payload(gid, &p, None, |s| Ok(s.client.react(gid, msg_id, &me, &key, remove)?))?;
        Ok(())
    }

    /// The key a received custom emoji reaction is stored under, or `None`
    /// (use the plain emoji) while the chat has `chat.stickers` released.
    pub(crate) fn custom_reaction_key(&mut self, gid: &[u8], st: &StickerRef) -> Result<Option<String>, Error> {
        if !self.chat_feature(gid, "chat.stickers")?.0 || st.pack.id.is_empty() || st.pack.id.len() > 64 || st.pack.size > MAX_MANIFEST_BYTES {
            return Ok(None);
        }
        self.app_put(&format!("stickerref/{}", st.pack.id), Some(&st.pack))?;
        Ok(Some(custom_emoji_key(&st.pack.id, st.index)))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_sticker(
        &mut self,
        gid: &[u8],
        from: MemberId,
        id: String,
        pack: BlobRef,
        index: u32,
        emoji: String,
        franking: Option<Vec<u8>>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if !self.chat_feature(gid, "chat.stickers")?.0 {
            events.push(Event::Dropped { reason: "stickers are released in this group (chat.stickers)".into() });
            return Ok(());
        }
        if id.is_empty() || id.len() > crate::rich_media::MAX_ID || !emoji_ok(&emoji) || pack.id.is_empty() || pack.id.len() > 64 || pack.size > MAX_MANIFEST_BYTES || index as usize >= MAX_PACK_ITEMS {
            events.push(Event::Dropped { reason: "malformed sticker".into() });
            return Ok(());
        }
        let data = serde_json::to_vec(&serde_json::json!({ "pack": pack.id, "index": index })).expect("JSON");
        if !self.store(gid, &id, &from, "sticker", Some(emoji.clone()), Some(data), franking)? {
            events.push(Event::Dropped { reason: "duplicate message id".into() });
            return Ok(());
        }
        self.app_put(&format!("stickerref/{}", pack.id), Some(&pack))?;
        self.on_new_message(gid, false)?;
        let name = self.names(gid)?.get(&from.to_hex()).cloned();
        let request = self.is_request(gid)?;
        events.push(Event::Sticker { group: gid.to_vec(), id, from, name, pack: pack.id, index, emoji, request });
        Ok(())
    }
}

/// The pack and index of a stored sticker message.
pub fn sticker_of(m: &crate::StoredMessage) -> Option<(String, u32)> {
    if m.kind != "sticker" {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(m.data.as_deref()?).ok()?;
    Some((v["pack"].as_str()?.to_string(), v["index"].as_u64()? as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_and_keys() {
        let r = BlobRef { id: "abc".into(), key: "k".into(), size: 10, pt_sha256: "p".into(), v: tree_core::attachment::VERSION };
        let l = pack_link(&r);
        assert!(l.starts_with("tree://stickers/"));
        assert_eq!(parse_pack_link(&l).unwrap(), r);
        assert!(parse_pack_link("tree://u/abc").is_err());
        assert!(parse_pack_link("tree://stickers/!!!").is_err());
        let big = BlobRef { size: MAX_MANIFEST_BYTES + 1, ..r };
        assert!(parse_pack_link(&pack_link(&big)).is_err());
        assert_eq!(parse_custom_emoji_key(&custom_emoji_key("abc", 7)), Some(("abc".into(), 7)));
        assert_eq!(parse_custom_emoji_key("👍"), None);
    }
}
