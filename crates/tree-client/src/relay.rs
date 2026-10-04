//! GIF search and map tiles through the server's relays (PROTOCOL.md 8.12).
//!
//! The server fetches for the device, so the GIF provider and the tile
//! server never see the user's address; the Tree server sees the search
//! words and which tiles are looked at (it does not store them). A GIF the
//! user picks is downloaded through the relay by the sender's device and
//! sent as a normal encrypted attachment flagged `gif` (`chat.gifs`):
//! receivers never contact the relay or the provider.
//!
//! Without a relay (`relay_status`), apps hide the GIF button and show
//! locations as coordinates with an "open in maps app" action.

use reqwest::Method;
use serde_json::json;

use crate::messages::FileKind;
use crate::payload::FileInfo;
use crate::{Error, Session};

/// Which relays the server offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayStatus {
    pub gif: bool,
    pub map: bool,
}

/// One GIF search result. `media` and `preview` are opaque ids valid for
/// an hour on this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gif {
    pub media: String,
    pub preview: Option<String>,
    pub title: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Largest GIF sent.
pub const MAX_GIF_BYTES: usize = 8 * 1024 * 1024;

impl Session {
    /// Which relays the server offers now (both false if it cannot say).
    pub fn relay_status(&self) -> Result<RelayStatus, Error> {
        let v = self.api.request(&self.creds.key, &self.creds.device_id, Method::GET, "/v1/relay", None)?;
        if !v.status.is_success() {
            return Ok(RelayStatus::default());
        }
        Ok(RelayStatus { gif: v.body["gif"] == true, map: v.body["map"] == true })
    }

    /// Searches GIFs through the relay. `503 RELAY_UNAVAILABLE` when the
    /// server offers none.
    pub fn gif_search(&self, query: &str, limit: u32) -> Result<Vec<Gif>, Error> {
        let body = json!({ "q": query, "limit": limit });
        let r = self.api.request(&self.creds.key, &self.creds.device_id, Method::POST, "/v1/relay/gif/search", Some(&body))?;
        if !r.status.is_success() {
            return Err(Error::Server { status: r.status.as_u16(), code: r.code().to_string() });
        }
        let s = |v: &serde_json::Value| v.as_str().map(str::to_string);
        Ok(r.body["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| {
                Some(Gif {
                    media: s(&x["media"])?,
                    preview: s(&x["preview"]),
                    title: s(&x["title"]).unwrap_or_default(),
                    width: x["width"].as_u64().map(|n| n as u32),
                    height: x["height"].as_u64().map(|n| n as u32),
                })
            })
            .collect())
    }

    /// The bytes and type behind a media id (a GIF or its preview).
    pub fn gif_media(&self, media: &str) -> Result<(Vec<u8>, String), Error> {
        if media.is_empty() || media.len() > 64 || !media.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(Error::Usage("not a media id".into()));
        }
        self.api.get_bytes(&self.creds, &format!("/v1/relay/gif/media/{media}"))
    }

    /// Sends a GIF from a search (`chat.gifs` and `chat.media`): this
    /// device fetches it through the relay and uploads it as a normal
    /// encrypted attachment.
    pub fn send_gif(&mut self, gid: &[u8], gif: &Gif) -> Result<FileInfo, Error> {
        if !self.chat_feature(gid, "chat.gifs")?.0 || !self.chat_feature(gid, "chat.media")?.0 {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let (bytes, mime) = self.gif_media(&gif.media)?;
        if bytes.len() > MAX_GIF_BYTES {
            return Err(Error::Usage("the GIF is too large".into()));
        }
        let name = if gif.title.is_empty() { "GIF".to_string() } else { gif.title.chars().take(100).collect() };
        self.send_attachment_as(gid, &bytes, &name, &mime, false, None, FileKind { gif: true, video_note: None })
    }

    /// One map tile (`z`/`x`/`y`, standard web tiles) through the server's
    /// map relay; `503 RELAY_UNAVAILABLE` when it offers none.
    pub fn map_tile(&self, z: u32, x: u32, y: u32) -> Result<Vec<u8>, Error> {
        Ok(self.api.get_bytes(&self.creds, &format!("/v1/relay/map/{z}/{x}/{y}"))?.0)
    }
}
