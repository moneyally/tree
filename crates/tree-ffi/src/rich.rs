//! Rich chats for the apps (Wave 2 part B): stickers and custom emoji,
//! GIFs through the relay, locations, events with replies, video notes,
//! profile photos and per-chat profiles. Only type conversions; the
//! behaviour is in `tree_client`.

use tree_client::chat_events::{ChatEventView, EventDraft};
use tree_client::location::LocationView;
use tree_client::stickers::{NewSticker, StickerPack};

use crate::{member, unhex, Attachment, TreeSession, R};

/// One sticker of a pack: its name and plain emoji (the image comes from
/// `sticker_image`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct StickerItem {
    pub name: String,
    pub emoji: String,
}

/// A sticker or custom emoji pack installed on this device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Pack {
    /// Names the pack in messages and in `sticker_image`.
    pub id: String,
    /// The link that shares it (`tree://stickers/...`).
    pub link: String,
    pub title: String,
    pub emoji_pack: bool,
    pub items: Vec<StickerItem>,
}

impl From<StickerPack> for Pack {
    fn from(p: StickerPack) -> Self {
        Pack {
            id: p.id,
            link: p.link,
            title: p.manifest.title,
            emoji_pack: p.manifest.emoji_pack,
            items: p.manifest.items.into_iter().map(|i| StickerItem { name: i.name, emoji: i.emoji }).collect(),
        }
    }
}

/// A new sticker for `create_sticker_pack`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NewStickerItem {
    pub name: String,
    pub emoji: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// A GIF search result (ids valid for an hour on this server).
#[derive(Debug, Clone, uniffi::Record)]
pub struct GifResult {
    pub media: String,
    pub preview: Option<String>,
    pub title: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

impl From<tree_client::relay::Gif> for GifResult {
    fn from(g: tree_client::relay::Gif) -> Self {
        GifResult { media: g.media, preview: g.preview, title: g.title, width: g.width, height: g.height }
    }
}

impl From<GifResult> for tree_client::relay::Gif {
    fn from(g: GifResult) -> Self {
        tree_client::relay::Gif { media: g.media, preview: g.preview, title: g.title, width: g.width, height: g.height }
    }
}

/// Which relays the server offers: apps hide the GIF button without `gif`
/// and show coordinates (and "open in maps app") without `map`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Relays {
    pub gif: bool,
    pub map: bool,
}

/// A location message as a card shows it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Place {
    pub id: String,
    pub sender: String,
    pub lat: f64,
    pub lon: f64,
    pub accuracy_m: Option<u32>,
    pub label: Option<String>,
    /// Still live: show the countdown to `live_until`.
    pub live: bool,
    pub live_until: Option<i64>,
    /// Was live and is over: "live location ended".
    pub ended: bool,
    pub updated_at: i64,
    /// `geo:` link for "open in maps app".
    pub geo_uri: String,
}

impl From<LocationView> for Place {
    fn from(v: LocationView) -> Self {
        Place {
            geo_uri: tree_client::location::geo_uri(v.lat, v.lon, v.label.as_deref()),
            id: v.id,
            sender: v.sender,
            lat: v.lat,
            lon: v.lon,
            accuracy_m: v.accuracy_m,
            label: v.label,
            live: v.live,
            live_until: v.live_until,
            ended: v.ended,
            updated_at: v.updated_at,
        }
    }
}

/// An event with the tally this device counted.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatEventInfo {
    pub id: String,
    pub creator: String,
    pub title: String,
    pub starts_at: i64,
    pub ends_at: Option<i64>,
    pub place: Option<String>,
    pub description: Option<String>,
    pub cancelled: bool,
    pub edited: bool,
    pub going: Vec<String>,
    pub maybe: Vec<String>,
    pub not: Vec<String>,
    /// This device's answer: `going`, `maybe`, `not` or none.
    pub mine: Option<String>,
}

impl From<ChatEventView> for ChatEventInfo {
    fn from(v: ChatEventView) -> Self {
        ChatEventInfo {
            id: v.id,
            creator: v.creator,
            title: v.title,
            starts_at: v.starts_at,
            ends_at: v.ends_at,
            place: v.place,
            description: v.description,
            cancelled: v.cancelled,
            edited: v.edited,
            going: v.going,
            maybe: v.maybe,
            not: v.not,
            mine: v.mine,
        }
    }
}

/// A photo and its type.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PhotoData {
    pub bytes: Vec<u8>,
    pub mime: String,
}

impl From<tree_client::profile::Photo> for PhotoData {
    fn from(p: tree_client::profile::Photo) -> Self {
        PhotoData { bytes: p.bytes, mime: p.mime }
    }
}

/// This user's name / photo for one chat.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatProfileInfo {
    pub name: Option<String>,
    pub has_photo: bool,
}

/// Live location durations to offer (seconds).
#[uniffi::export]
pub fn live_location_choices() -> Vec<u32> {
    tree_client::location::LIVE_CHOICES.to_vec()
}

/// The pack and index behind a reaction key (`sticker:<pack>:<index>`),
/// or none for a plain emoji.
#[uniffi::export]
pub fn custom_emoji_of(reaction: String) -> Option<StickerRefInfo> {
    tree_client::stickers::parse_custom_emoji_key(&reaction).map(|(pack, index)| StickerRefInfo { pack, index })
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct StickerRefInfo {
    pub pack: String,
    pub index: u32,
}

fn draft(title: String, starts_at: i64, ends_at: Option<i64>, place: Option<String>, description: Option<String>) -> EventDraft {
    EventDraft { title, starts_at, ends_at, place, description }
}

#[uniffi::export]
impl TreeSession {
    // --- stickers and custom emoji ---

    /// Uploads a new pack and installs it; returns it with its link.
    pub fn create_sticker_pack(&self, title: String, items: Vec<NewStickerItem>, emoji_pack: bool) -> R<Pack> {
        let items: Vec<NewSticker> = items.into_iter().map(|i| NewSticker { name: i.name, emoji: i.emoji, mime: i.mime, bytes: i.bytes }).collect();
        Ok(self.s().create_sticker_pack(&title, &items, emoji_pack)?.into())
    }

    pub fn install_sticker_pack(&self, link: String) -> R<Pack> {
        Ok(self.s().install_sticker_pack(&link)?.into())
    }

    pub fn remove_sticker_pack(&self, id: String) -> R<()> {
        Ok(self.s().remove_sticker_pack(&id)?)
    }

    pub fn sticker_packs(&self) -> R<Vec<Pack>> {
        Ok(self.s().sticker_packs()?.into_iter().map(Into::into).collect())
    }

    pub fn sticker_image(&self, pack: String, index: u32) -> R<Vec<u8>> {
        Ok(self.s().sticker_image(&pack, index)?)
    }

    /// The pack and index of a sticker message, if it is one.
    pub fn sticker_of(&self, group: String, id: String) -> R<Option<StickerRefInfo>> {
        let gid = unhex(&group, "group")?;
        Ok(self.s().sticker_in(&gid, &id)?.map(|(pack, index)| StickerRefInfo { pack, index }))
    }

    pub fn send_sticker(&self, group: String, pack: String, index: u32) -> R<String> {
        Ok(self.s().send_sticker(&unhex(&group, "group")?, &pack, index)?)
    }

    pub fn react_sticker(&self, group: String, id: String, pack: String, index: u32, remove: bool) -> R<()> {
        Ok(self.s().react_sticker(&unhex(&group, "group")?, &id, &pack, index, remove)?)
    }

    // --- GIFs and map tiles through the relay ---

    pub fn relay_status(&self) -> R<Relays> {
        let r = self.s().relay_status()?;
        Ok(Relays { gif: r.gif, map: r.map })
    }

    pub fn gif_search(&self, query: String, limit: u32) -> R<Vec<GifResult>> {
        Ok(self.s().gif_search(&query, limit)?.into_iter().map(Into::into).collect())
    }

    /// The bytes of a GIF or preview (to show while picking).
    pub fn gif_media(&self, media: String) -> R<Vec<u8>> {
        Ok(self.s().gif_media(&media)?.0)
    }

    pub fn send_gif(&self, group: String, gif: GifResult) -> R<Attachment> {
        Ok(self.s().send_gif(&unhex(&group, "group")?, &gif.into())?.into())
    }

    pub fn map_tile(&self, z: u32, x: u32, y: u32) -> R<Vec<u8>> {
        Ok(self.s().map_tile(z, x, y)?)
    }

    // --- location ---

    pub fn send_location(&self, group: String, lat: f64, lon: f64, accuracy_m: Option<u32>, label: Option<String>) -> R<String> {
        Ok(self.s().send_location(&unhex(&group, "group")?, lat, lon, accuracy_m, label.as_deref())?)
    }

    /// `seconds`: one of `live_location_choices`.
    pub fn start_live_location(&self, group: String, lat: f64, lon: f64, accuracy_m: Option<u32>, seconds: u32) -> R<String> {
        Ok(self.s().start_live_location(&unhex(&group, "group")?, lat, lon, accuracy_m, seconds)?)
    }

    /// True if sent now; false if kept for a later sync (30 s interval).
    pub fn update_live_location(&self, group: String, id: String, lat: f64, lon: f64, accuracy_m: Option<u32>) -> R<bool> {
        Ok(self.s().update_live_location(&unhex(&group, "group")?, &id, lat, lon, accuracy_m)?)
    }

    pub fn stop_live_location(&self, group: String, id: String) -> R<()> {
        Ok(self.s().stop_live_location(&unhex(&group, "group")?, &id)?)
    }

    pub fn location(&self, group: String, id: String) -> R<Option<Place>> {
        Ok(self.s().location(&unhex(&group, "group")?, &id)?.map(Into::into))
    }

    // --- events ---

    pub fn create_event(
        &self,
        group: String,
        title: String,
        starts_at: i64,
        ends_at: Option<i64>,
        place: Option<String>,
        description: Option<String>,
    ) -> R<String> {
        Ok(self.s().create_event(&unhex(&group, "group")?, &draft(title, starts_at, ends_at, place, description))?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn edit_event(
        &self,
        group: String,
        id: String,
        title: String,
        starts_at: i64,
        ends_at: Option<i64>,
        place: Option<String>,
        description: Option<String>,
    ) -> R<()> {
        Ok(self.s().edit_event(&unhex(&group, "group")?, &id, &draft(title, starts_at, ends_at, place, description))?)
    }

    pub fn cancel_event(&self, group: String, id: String) -> R<()> {
        Ok(self.s().cancel_event(&unhex(&group, "group")?, &id)?)
    }

    /// `answer`: `going`, `maybe` or `not`.
    pub fn rsvp(&self, group: String, id: String, answer: String) -> R<()> {
        Ok(self.s().rsvp(&unhex(&group, "group")?, &id, &answer)?)
    }

    pub fn chat_event(&self, group: String, id: String) -> R<Option<ChatEventInfo>> {
        Ok(self.s().chat_event(&unhex(&group, "group")?, &id)?.map(Into::into))
    }

    // --- video notes ---

    pub fn send_video_note(&self, group: String, bytes: Vec<u8>, mime: String, duration_ms: u64) -> R<Attachment> {
        Ok(self.s().send_video_note(&unhex(&group, "group")?, &bytes, &mime, duration_ms)?.into())
    }

    // --- profile photo and per-chat profile ---

    pub fn set_profile_photo(&self, bytes: Vec<u8>, mime: String) -> R<()> {
        Ok(self.s().set_profile_photo(&bytes, &mime)?)
    }

    pub fn remove_profile_photo(&self) -> R<()> {
        Ok(self.s().remove_profile_photo()?)
    }

    pub fn profile_photo(&self) -> R<Option<PhotoData>> {
        Ok(self.s().profile_photo()?.map(Into::into))
    }

    pub fn member_photo(&self, group: String, member_id: String) -> R<Option<PhotoData>> {
        Ok(self.s().member_photo(&unhex(&group, "group")?, &member(&member_id)?)?.map(Into::into))
    }

    /// A name (and photo) shown in this chat only; none keeps the main one.
    pub fn set_chat_profile(&self, group: String, name: Option<String>, photo: Option<PhotoData>) -> R<()> {
        let gid = unhex(&group, "group")?;
        let photo = photo.as_ref().map(|p| (p.bytes.as_slice(), p.mime.as_str()));
        Ok(self.s().set_chat_profile(&gid, name.as_deref(), photo)?)
    }

    pub fn clear_chat_profile(&self, group: String) -> R<()> {
        Ok(self.s().clear_chat_profile(&unhex(&group, "group")?)?)
    }

    pub fn chat_profile(&self, group: String) -> R<Option<ChatProfileInfo>> {
        Ok(self.s().chat_profile(&unhex(&group, "group")?)?.map(|c| ChatProfileInfo { name: c.name, has_photo: c.has_photo }))
    }
}
