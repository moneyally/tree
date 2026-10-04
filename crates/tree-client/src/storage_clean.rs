//! Downloaded media on this device and its clean-up (`user.storage_clean`).
//!
//! [`Session::download_to_cache`] opens an attachment into the app's media
//! folder and records it (`media/<attachment id>`: path, when, size). That
//! file is the decrypted copy (the cached plaintext). While
//! `user.storage_clean` is applied (option: a duration of 1 s to 365 days,
//! default `90d`; the apps offer 30 days, 90 days and a year), every sync
//! (at most once an hour) and [`Session::clean_storage`] delete cached files
//! downloaded longer ago than that, with their records. Message texts and
//! file references stay: a cleaned file can be downloaded again while the
//! server still keeps the encrypted blob (30 days). Files the user saved
//! elsewhere are the user's and are never touched. Released (the default):
//! nothing is deleted.

use serde::{Deserialize, Serialize};
use tree_core::features::{option_seconds, State};

use crate::messages::now;
use crate::payload::FileInfo;
use crate::{Error, Session};

pub const STORAGE_CLEAN: &str = "user.storage_clean";
/// How often a sync checks for old media.
pub const CLEAN_EVERY: i64 = 3600;
const CLEANED_AT: &str = "media_clean/last";

/// One downloaded file kept on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedMedia {
    pub attachment_id: String,
    pub path: String,
    /// When it was downloaded (unix seconds).
    pub at: i64,
    pub size: u64,
}

/// What a clean-up removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanReport {
    pub files: u32,
    pub bytes: u64,
}

/// A file name safe inside the media folder: the attachment id (base64url
/// from the server) and the extension of the sender's name.
fn cache_name(f: &FileInfo) -> String {
    let id: String = f.id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(64).collect();
    let ext: String = f
        .name
        .rsplit_once('.')
        .map(|(_, e)| e.chars().filter(char::is_ascii_alphanumeric).take(8).collect())
        .unwrap_or_default();
    if ext.is_empty() { id } else { format!("{id}.{ext}") }
}

impl Session {
    /// Downloads, checks and decrypts an attachment into `dir` (the app's
    /// media folder) and records it for [`Session::clean_storage`]; returns
    /// the file's path. A file already there is not fetched again.
    /// View-once files are never cached (open them with `download`).
    pub fn download_to_cache(&self, f: &FileInfo, dir: &str) -> Result<String, Error> {
        if f.view_once {
            return Err(Error::Usage("view-once files are not kept on the device".into()));
        }
        let key = format!("media/{}", f.id);
        if let Some(c) = self.client.app_data(&key)?.and_then(|v| serde_json::from_slice::<CachedMedia>(&v).ok()) {
            if std::path::Path::new(&c.path).exists() {
                return Ok(c.path);
            }
        }
        let bytes = self.download(f)?;
        std::fs::create_dir_all(dir).map_err(|e| Error::Usage(format!("{dir}: {e}")))?;
        let path = std::path::Path::new(dir).join(cache_name(f)).display().to_string();
        std::fs::write(&path, &bytes).map_err(|e| Error::Usage(format!("{path}: {e}")))?;
        let c = CachedMedia { attachment_id: f.id.clone(), path: path.clone(), at: now(), size: bytes.len() as u64 };
        self.client.set_app_data(&key, Some(&serde_json::to_vec(&c).expect("JSON")))?;
        Ok(path)
    }

    /// Downloaded files this device keeps, oldest first.
    pub fn cached_media(&self) -> Result<Vec<CachedMedia>, Error> {
        let mut out = Vec::new();
        for k in self.client.app_data_keys("media/")? {
            if let Some(c) = self.client.app_data(&k)?.and_then(|v| serde_json::from_slice::<CachedMedia>(&v).ok()) {
                out.push(c);
            }
        }
        out.sort_by_key(|c| c.at);
        Ok(out)
    }

    /// The clean-up period in seconds, while `user.storage_clean` is applied.
    pub fn storage_clean_period(&self) -> Result<Option<i64>, Error> {
        let st = self.feature(STORAGE_CLEAN)?;
        if st.state != State::Applied {
            return Ok(None);
        }
        Ok(option_seconds(STORAGE_CLEAN, st.option.as_deref()))
    }

    /// Deletes downloaded files older than the `user.storage_clean` period
    /// now (refused while it is released).
    pub fn clean_storage(&self) -> Result<CleanReport, Error> {
        let period = self.storage_clean_period()?.ok_or_else(|| Error::Feature("RELEASED".into()))?;
        self.clean_older_than(now() - period)
    }

    fn clean_older_than(&self, before: i64) -> Result<CleanReport, Error> {
        let mut r = CleanReport::default();
        for c in self.cached_media()?.into_iter().filter(|c| c.at < before) {
            match std::fs::remove_file(&c.path) {
                Ok(()) => {
                    r.files += 1;
                    r.bytes += c.size;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::Usage(format!("{}: {e}", c.path))),
            }
            self.client.set_app_data(&format!("media/{}", c.attachment_id), None)?;
        }
        self.client.set_app_data(CLEANED_AT, Some(now().to_string().as_bytes()))?;
        Ok(r)
    }

    /// Sync runs the clean-up at most once an hour while applied.
    pub(crate) fn clean_storage_if_due(&self) -> Result<(), Error> {
        let Some(period) = self.storage_clean_period()? else { return Ok(()) };
        let last = self.client.app_data(CLEANED_AT)?.and_then(|v| String::from_utf8(v).ok()).and_then(|s| s.parse::<i64>().ok());
        if last.is_none_or(|l| now() - l >= CLEAN_EVERY) {
            self.clean_older_than(now() - period)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_names_stay_in_the_folder() {
        let f = FileInfo {
            msg_id: String::new(),
            view_once: false,
            voice: false,
            duration_ms: None,
            id: "../../etc/passwd".into(),
            key: String::new(),
            size: 0,
            pt_sha256: String::new(),
            name: "photo.../../x.JPG".into(),
            mime: String::new(),
            v: tree_core::attachment::VERSION,
            width: None,
            height: None,
            thumb: None,
            fwd: false,
        };
        assert_eq!(cache_name(&f), "etcpasswd.JPG");
    }
}
