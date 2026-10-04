//! Forwarding (`chat.forwarding`) and chat export (`chat.export`).
//!
//! **Forwarding** sends a copy of a text, or of a file reference (the same
//! encrypted attachment, its key inside the new chat's MLS message), to
//! another chat as a new message marked `fwd`. The original sender is not
//! named. While the source chat's admins released `chat.forwarding`, this
//! client refuses to forward its messages and the apps hide forward, save
//! and copy for them. That binds honest apps only: a modified app, a
//! screenshot or a camera cannot be stopped, and the destination chat
//! cannot tell where a forwarded message came from, so it cannot check the
//! source chat's setting.
//!
//! **Export** writes the chat's history as this device has it to local
//! files (plain text and JSON) while `chat.export` is applied. The files
//! are not encrypted: they are as safe as the place the user puts them.
//! Franking records, keys and file contents are not exported (files appear
//! by name).

use serde_json::json;

use crate::messages::{new_id, now, text_data};
use crate::payload::{FileInfo, Payload};
use crate::{Error, Session, StoredMessage};

/// Adds the forwarded mark to a text's stored data.
pub(crate) fn with_fwd(data: Option<Vec<u8>>, fwd: bool) -> Option<Vec<u8>> {
    if !fwd {
        return data;
    }
    let mut v: serde_json::Value = data.as_deref().and_then(|d| serde_json::from_slice(d).ok()).unwrap_or_else(|| json!({}));
    v["fwd"] = true.into();
    Some(serde_json::to_vec(&v).expect("JSON"))
}

/// Was this stored message forwarded from another chat?
pub fn is_forwarded(m: &StoredMessage) -> bool {
    let v: serde_json::Value = m.data.as_deref().and_then(|d| serde_json::from_slice(d).ok()).unwrap_or_default();
    v["fwd"] == true
}

/// A chat's history as export files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatExport {
    /// One line per message: time (UTC), sender, text.
    pub text: String,
    /// The same as JSON (`messages`: id, sender, name, at, kind, text, ...).
    pub json: String,
}

/// `YYYY-MM-DD HH:MM` (UTC) for unix seconds.
pub(crate) fn utc(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, secs % 3600 / 60)
}

impl Session {
    /// May messages of this chat be forwarded, saved or copied
    /// (`chat.forwarding`)? Apps hide those actions while it is false.
    pub fn forwarding_allowed(&mut self, gid: &[u8]) -> Result<bool, Error> {
        self.chat_on(gid, "chat.forwarding")
    }

    /// May this chat be exported (`chat.export`)?
    pub fn export_allowed(&mut self, gid: &[u8]) -> Result<bool, Error> {
        self.chat_on(gid, "chat.export")
    }

    /// Forwards message `id` of chat `from` to chat `to` as a new message
    /// marked forwarded, without the original sender. Texts and files (not
    /// view-once ones); refused while `from` released `chat.forwarding`.
    /// Returns the new message id.
    pub fn forward(&mut self, from: &[u8], id: &str, to: &[u8]) -> Result<String, Error> {
        if !self.forwarding_allowed(from)? {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let m = self.client.message(from, id)?.filter(|m| !m.deleted).ok_or_else(|| Error::Usage("no such message".into()))?;
        let me = self.member_id();
        match m.kind.as_str() {
            "text" => {
                let text = m.text.clone().unwrap_or_default();
                let was_fmt = serde_json::from_slice::<serde_json::Value>(m.data.as_deref().unwrap_or(b"{}")).is_ok_and(|v| v["fmt"] == true);
                let fmt = was_fmt && self.chat_on(to, "chat.formatting")?;
                let new = new_id();
                let p = Payload::Text { id: new.clone(), text: text.clone(), fmt, mentions: vec![], all: false, preview: None, silent: false, fwd: true, topic: None };
                let data = with_fwd(text_data(fmt, None, false), true);
                self.queue_payload(to, &p, Some(&new), |s| s.store(to, &new, &me, "text", Some(text), data, None).map(|_| ()))?;
                Ok(new)
            }
            "file" => {
                let info: FileInfo = m
                    .data
                    .as_deref()
                    .and_then(|d| serde_json::from_slice(d).ok())
                    .ok_or_else(|| Error::Usage("this file can no longer be forwarded".into()))?;
                if info.view_once {
                    return Err(Error::Usage("view-once files cannot be forwarded".into()));
                }
                if !self.chat_on(to, "chat.media")? || (info.voice && !self.chat_on(to, "chat.voice")?) {
                    return Err(Error::Feature("LOCKED_BY_CHAT".into()));
                }
                let info = FileInfo { msg_id: new_id(), fwd: true, topic: None, ..info };
                let data = serde_json::to_vec(&info).expect("JSON");
                let new = info.msg_id.clone();
                self.queue_payload(to, &Payload::File(info.clone()), Some(&new), |s| {
                    s.store(to, &new, &me, "file", Some(info.name.clone()), Some(data), None).map(|_| ())
                })?;
                Ok(new)
            }
            _ => Err(Error::Usage("only texts and files can be forwarded".into())),
        }
    }

    /// The chat's history on this device as plain text and JSON
    /// (`chat.export`; refused while released).
    pub fn export_chat(&mut self, gid: &[u8]) -> Result<ChatExport, Error> {
        if !self.export_allowed(gid)? {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        let names = self.names(gid)?;
        let me = self.member_id().to_hex();
        let title = self.group_settings(gid)?.name.unwrap_or_default();
        let msgs = self.history(gid, u32::MAX)?;
        let mut text = format!("Tree chat export: {title}\nExported {} UTC from this device.\n\n", utc(now()));
        let mut rows = Vec::new();
        for m in &msgs {
            let who = names.get(&m.sender).cloned().unwrap_or_else(|| m.sender.chars().take(8).collect());
            let fwd = is_forwarded(m);
            let mut body = match (m.kind.as_str(), m.deleted) {
                (_, true) => "(deleted)".to_string(),
                ("file", _) => format!("[file] {}", m.text.clone().unwrap_or_default()),
                ("poll", _) => {
                    let p = self.poll(gid, &m.id)?;
                    let opts = p.map(|p| p.options.iter().zip(&p.counts).map(|(o, c)| format!("{o} ({c})")).collect::<Vec<_>>().join(", "));
                    format!("[poll] {}: {}", m.text.clone().unwrap_or_default(), opts.unwrap_or_default())
                }
                ("left", _) | ("removed", _) => format!("({})", m.kind),
                _ => m.text.clone().unwrap_or_default(),
            };
            if fwd {
                body = format!("[forwarded] {body}");
            }
            if m.edited_at.is_some() {
                body.push_str(" (edited)");
            }
            text.push_str(&format!("{}  {}: {}\n", utc(m.received_at), if m.sender == me { "me".to_string() } else { who.clone() }, body));
            rows.push(json!({
                "id": m.id, "sender": m.sender, "name": who, "at": m.received_at, "kind": m.kind,
                "text": if m.deleted { None } else { m.text.clone() }, "edited": m.edited_at.is_some(),
                "deleted": m.deleted, "forwarded": fwd, "reactions": m.reactions,
            }));
        }
        let json = serde_json::to_string_pretty(&json!({
            "format": "tree-chat-export/1",
            "group": hex::encode(gid),
            "name": title,
            "exported_at": now(),
            "messages": rows,
        }))
        .expect("JSON");
        Ok(ChatExport { text, json })
    }

    /// Writes [`Session::export_chat`] to `<path_prefix>.txt` and
    /// `<path_prefix>.json`; returns both paths.
    pub fn export_chat_to(&mut self, gid: &[u8], path_prefix: &str) -> Result<(String, String), Error> {
        let e = self.export_chat(gid)?;
        let (t, j) = (format!("{path_prefix}.txt"), format!("{path_prefix}.json"));
        for (p, c) in [(&t, &e.text), (&j, &e.json)] {
            std::fs::write(p, c).map_err(|err| Error::Usage(format!("{p}: {err}")))?;
        }
        Ok((t, j))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00");
        assert_eq!(utc(1_791_115_200 + 3600 + 120), "2026-10-04 13:02");
    }

    #[test]
    fn forwarded_mark() {
        assert_eq!(with_fwd(None, false), None);
        let d = with_fwd(Some(br#"{"silent":true}"#.to_vec()), true).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&d).unwrap();
        assert!(v["fwd"] == true && v["silent"] == true);
    }
}
