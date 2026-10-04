//! Media: large files in parts, through the outbox, with progress, pause
//! and resume; downloads that resume; auto-download by network type
//! (PROTOCOL.md 6.12, 6.13).
//!
//! Sending a file:
//!
//! 1. The file is encrypted ([`tree_core::attachment`], format v2: padded to
//!    a size bucket, 1 MiB STREAM chunks, key commitment) into a blob in the
//!    profile's media folder (`<profile>.media/out/`). The blob is
//!    ciphertext; its key exists only inside the encrypted profile.
//! 2. The message (name, type, size, picture size, length and the
//!    sender-made preview picture, all inside the end-to-end encrypted
//!    payload) goes into the outbox in the same transaction as the history
//!    entry and the upload record (`upload/<local id>`). It waits there
//!    unsealed: the attachment id is not known before the upload.
//! 3. An attempt uploads the blob part by part (`/v1/uploads`). The server
//!    keeps how many parts it has; an interrupted upload (network, crash,
//!    app closed) resumes from there. An upload the server dropped after a
//!    day starts again. Passing errors retry with the outbox's backoff (an
//!    attempt that moved the upload on does not use up an attempt); a
//!    refusal (too large, quota) fails the message, which the user can
//!    retry or cancel.
//! 4. When the last part is in, the reference gets the attachment id, the
//!    message is sealed and sent like any other, and the blob is deleted.
//!
//! Items of a chat stay in order: later messages of the same chat wait
//! while a file of that chat uploads or is paused.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tree_core::attachment::{self, FileKey};
use tree_core::features::{AutoDownload, Network, State, AUTO_DOWNLOAD_DEFAULT};
use tree_core::storage::outbox::OutboxState;
use zeroize::Zeroizing;

use crate::api::{self, Api, Creds};
use crate::payload::{FileInfo, Payload, MAX_MIME, MAX_NAME, MAX_THUMB};
use crate::{Error, GroupStatus, MemberId, Session};

/// What the sender's app knows about a file; it travels inside the
/// encrypted message, never to the server as a separate object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaMeta {
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Voice, video or other recording length.
    pub duration_ms: Option<u64>,
    /// A small preview picture (JPEG or PNG, at most 32 KiB), made by the app.
    pub thumb: Option<Vec<u8>>,
}

/// Where the plaintext comes from.
#[derive(Debug, Clone, Copy)]
pub enum Source<'a> {
    Bytes(&'a [u8]),
    /// A file on this device, read once while it is encrypted.
    Path(&'a Path),
}

#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    pub view_once: bool,
    pub voice: bool,
    pub meta: MediaMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Waiting for its turn or for the network.
    Queued,
    Running,
    /// Paused by the user.
    Paused,
    /// The last attempt failed (see the outbox for retry / cancel).
    Failed,
}

/// One upload or download as a progress bar shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub message_id: String,
    pub upload: bool,
    /// Ciphertext bytes moved so far, of `total`.
    pub done: u64,
    pub total: u64,
    pub state: TransferState,
}

/// Progress of the transfers of one session, by message id. A clone reads
/// it without holding the session (apps poll it while a transfer runs).
#[derive(Clone, Default)]
pub struct Transfers(Arc<Mutex<BTreeMap<String, Transfer>>>);

impl Transfers {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Transfer>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn list(&self) -> Vec<Transfer> {
        self.lock().values().cloned().collect()
    }
    pub fn get(&self, message_id: &str) -> Option<Transfer> {
        self.lock().get(message_id).cloned()
    }
    fn set(&self, t: Transfer) {
        self.lock().insert(t.message_id.clone(), t);
    }
    fn state(&self, message_id: &str, state: TransferState) {
        if let Some(t) = self.lock().get_mut(message_id) {
            t.state = state;
        }
    }
    fn remove(&self, message_id: &str) {
        self.lock().remove(message_id);
    }
}

/// The upload of one outbox item, kept in the encrypted profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UploadState {
    pub group: String,
    pub msg_id: String,
    /// Blob size (padded ciphertext).
    pub total: u64,
    #[serde(default)]
    pub upload_id: Option<String>,
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub paused: bool,
}

fn upload_key(local_id: &str) -> String {
    format!("upload/{local_id}")
}

/// What driving an upload came to.
pub(crate) enum Up {
    /// Complete: the attachment id.
    Done(String),
    /// Paused, or this pass's share is used up: try again later, keep order.
    Hold,
    Failed { error: Error, progressed: bool },
}

/// Server ids are base64url; anything else (from a modified sender) must
/// never reach a file name.
fn safe_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn io(e: std::io::Error) -> Error {
    Error::Usage(format!("file: {e}"))
}

fn new_hex_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    hex::encode(b)
}

/// The decryption key of a reference.
fn file_key(f: &FileInfo) -> Result<FileKey, Error> {
    let bad = || Error::Protocol("malformed file reference".into());
    if !f.is_valid() || !safe_id(&f.id) {
        return Err(bad());
    }
    let secret: [u8; 32] = api::unb64(&f.key)?.try_into().map_err(|_| bad())?;
    let pt: [u8; 32] = hex::decode(&f.pt_sha256).map_err(|_| bad())?.try_into().map_err(|_| bad())?;
    Ok(FileKey { secret: Zeroizing::new(secret), size: f.size, plaintext_sha256: pt })
}

/// Fetches and opens attachments without holding the session (a clone of
/// the connection, the media folder and the progress board). Downloads
/// resume: the ciphertext received so far stays in `<profile>.media/in/`.
#[derive(Clone)]
pub struct Downloader {
    api: Api,
    creds: Creds,
    dir: PathBuf,
    transfers: Transfers,
}

impl Downloader {
    /// Downloads the whole blob (resuming), checks its size against the
    /// reference, and returns the path of the complete ciphertext.
    fn fetch_blob(&self, f: &FileInfo) -> Result<PathBuf, Error> {
        file_key(f)?;
        let total = attachment::ciphertext_len(f.size);
        let dir = self.dir.join("in");
        fs::create_dir_all(&dir).map_err(io)?;
        let part = dir.join(format!("{}.part", f.id));
        let mut file = OpenOptions::new().create(true).append(true).open(&part).map_err(io)?;
        let mut have = file.metadata().map_err(io)?.len();
        if have > total {
            file.set_len(0).map_err(io)?;
            have = 0;
        }
        let t = |done, state| Transfer { message_id: f.msg_id.clone(), upload: false, done, total, state };
        self.transfers.set(t(have, TransferState::Running));
        while have < total {
            let (bytes, server_total) = match self.api.download_range(&self.creds, &f.id, have) {
                Ok(r) => r,
                Err(e) => {
                    self.transfers.set(t(have, TransferState::Failed));
                    return Err(e);
                }
            };
            if server_total != total || bytes.is_empty() || have + bytes.len() as u64 > total {
                drop(file);
                let _ = fs::remove_file(&part);
                self.transfers.remove(&f.msg_id);
                return Err(Error::Core(tree_core::TreeError::Rejected("attachment: size does not match the message".into())));
            }
            file.write_all(&bytes).map_err(io)?;
            have += bytes.len() as u64;
            self.transfers.set(t(have, TransferState::Running));
        }
        file.sync_data().map_err(io)?;
        Ok(part)
    }

    /// Opens the downloaded blob into `out`; a blob that does not open is
    /// deleted (the next try fetches it again).
    fn open_blob(&self, f: &FileInfo, part: &Path, out: impl Write) -> Result<(), Error> {
        let r = File::open(part).map_err(io).and_then(|b| Ok(attachment::decrypt_stream(BufReader::new(b), &file_key(f)?, out)?));
        if r.is_err() {
            let _ = fs::remove_file(part);
        }
        self.transfers.remove(&f.msg_id);
        r
    }

    /// Downloads, checks and decrypts into memory.
    pub fn fetch(&self, f: &FileInfo) -> Result<Vec<u8>, Error> {
        let part = self.fetch_blob(f)?;
        let mut out = Vec::with_capacity(f.size as usize);
        self.open_blob(f, &part, &mut out)?;
        let _ = fs::remove_file(&part);
        Ok(out)
    }

    /// Downloads, checks and decrypts into the file `dest`. The plaintext
    /// goes to a temporary file next to it, renamed only when everything
    /// matched the message.
    pub fn fetch_to(&self, f: &FileInfo, dest: &Path) -> Result<(), Error> {
        let part = self.fetch_blob(f)?;
        let mut tmp = dest.as_os_str().to_owned();
        tmp.push(".tree-part");
        let tmp = PathBuf::from(tmp);
        let r = File::create(&tmp).map_err(io).and_then(|w| self.open_blob(f, &part, BufWriter::new(w)));
        if let Err(e) = r {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        fs::rename(&tmp, dest).map_err(io)?;
        let _ = fs::remove_file(&part);
        Ok(())
    }
}

impl Session {
    fn media_dir(&self) -> &Path {
        &self.media.dir
    }

    fn blob_path(&self, local_id: &str) -> PathBuf {
        self.media_dir().join("out").join(format!("{local_id}.blob"))
    }

    /// Progress of uploads and downloads (readable without the session).
    pub fn transfers(&self) -> Transfers {
        self.media.transfers.clone()
    }

    /// A downloader for use without holding the session.
    pub fn downloader(&self) -> Downloader {
        Downloader { api: self.api.clone(), creds: self.creds.clone(), dir: self.media.dir.clone(), transfers: self.media.transfers.clone() }
    }

    /// At most this many bytes are uploaded per pass over the outbox
    /// (`None`: no limit, a send returns when the upload is done). Apps set
    /// a limit so a long upload does not hold the session; their sync loop
    /// keeps calling [`Session::send_pending`] while [`Session::uploading`].
    pub fn set_upload_slice(&mut self, bytes: Option<u64>) {
        self.media.slice = bytes;
    }

    /// An upload is waiting for its next slice (not paused, not failed).
    pub fn uploading(&self) -> Result<bool, Error> {
        for item in self.client.outbox_unsent(None)? {
            if item.state != OutboxState::Failed {
                if let Some(u) = self.upload_state(&item.local_id)? {
                    if !u.paused && !u.done {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// The network the device is on, as the app reports it (decides
    /// auto-download; `Network::None` until the app says).
    pub fn set_network(&mut self, n: Network) {
        self.media.network = n;
    }

    pub fn network(&self) -> Network {
        self.media.network
    }

    /// Sends a file: checked against the chat's settings, encrypted into
    /// the media folder and queued; the upload and the message follow
    /// through the outbox (now, or when the server can be reached).
    /// Returns the reference as it will be sent (`id` empty while the
    /// upload has not finished).
    pub fn send_media(&mut self, gid: &[u8], src: Source<'_>, name: &str, mime: &str, o: &SendOptions) -> Result<FileInfo, Error> {
        if !self.chat_feature(gid, "chat.media")?.0
            || (o.view_once && !self.chat_feature(gid, "chat.view_once")?.0)
            || (o.voice && !self.chat_feature(gid, "chat.voice")?.0)
        {
            return Err(Error::Feature("LOCKED_BY_CHAT".into()));
        }
        if name.chars().count() > MAX_NAME || mime.chars().count() > MAX_MIME {
            return Err(Error::Usage("file name or type too long".into()));
        }
        if o.meta.thumb.as_ref().is_some_and(|t| t.len() > MAX_THUMB) {
            return Err(Error::Usage(format!("preview picture larger than {MAX_THUMB} bytes")));
        }
        let size = match src {
            Source::Bytes(b) => b.len() as u64,
            Source::Path(p) => fs::metadata(p).map_err(io)?.len(),
        };
        if size > attachment::MAX_FILE {
            return Err(Error::Usage("files can be at most 2 GiB".into()));
        }
        let local_id = new_hex_id();
        let blob = self.blob_path(&local_id);
        fs::create_dir_all(blob.parent().expect("in the media folder")).map_err(io)?;
        let sealed = File::create(&blob).map_err(io).and_then(|f| {
            let out = BufWriter::new(f);
            Ok(match src {
                Source::Bytes(b) => attachment::encrypt_stream(b, size, out)?,
                Source::Path(p) => attachment::encrypt_stream(BufReader::new(File::open(p).map_err(io)?), size, out)?,
            })
        });
        let fk = match sealed {
            Ok(fk) => fk,
            Err(e) => {
                let _ = fs::remove_file(&blob);
                return Err(e);
            }
        };
        let info = FileInfo {
            msg_id: new_hex_id(),
            view_once: o.view_once,
            voice: o.voice,
            duration_ms: o.meta.duration_ms,
            id: String::new(),
            key: api::b64(&fk.secret[..]),
            size,
            pt_sha256: hex::encode(fk.plaintext_sha256),
            name: name.to_string(),
            mime: mime.to_string(),
            v: attachment::VERSION,
            width: o.meta.width,
            height: o.meta.height,
            thumb: o.meta.thumb.as_deref().map(api::b64),
        };
        let total = attachment::ciphertext_len(size);
        let st = UploadState { group: hex::encode(gid), msg_id: info.msg_id.clone(), total, upload_id: None, done: false, paused: false };
        self.media.transfers.set(Transfer { message_id: info.msg_id.clone(), upload: true, done: 0, total, state: TransferState::Queued });
        // The sender keeps no reference to a view-once file.
        let data = (!o.view_once).then(|| serde_json::to_vec(&info).expect("JSON"));
        let me = self.member_id();
        let msg_id = info.msg_id.clone();
        let file_name = info.name.clone();
        let r = self.queue_item(gid, &Payload::File(info.clone()), Some(&msg_id), Some((local_id.clone(), st)), |s| {
            s.store_file_message(gid, &msg_id, &me, &file_name, data)
        });
        if r.is_err() && self.client.outbox_item(&local_id)?.is_none() {
            let _ = fs::remove_file(&blob);
            self.media.transfers.remove(&msg_id);
        }
        r?;
        let mut info = info;
        if let Some(id) = self.media.uploaded.remove(&local_id) {
            info.id = id;
        }
        Ok(info)
    }

    pub(crate) fn upload_state(&self, local_id: &str) -> Result<Option<UploadState>, Error> {
        Ok(match self.client.app_data(&upload_key(local_id))? {
            Some(v) => Some(serde_json::from_slice(&v).map_err(|_| Error::Protocol("damaged upload record".into()))?),
            None => None,
        })
    }

    pub(crate) fn save_upload(&self, local_id: &str, st: &UploadState) -> Result<(), Error> {
        Ok(self.client.set_app_data(&upload_key(local_id), Some(&serde_json::to_vec(st).expect("JSON")))?)
    }

    /// Moves the upload of an outbox item on (at most one slice).
    pub(crate) fn drive_upload(&mut self, local_id: &str, mut st: UploadState) -> Up {
        if st.done {
            if let Some(id) = st.upload_id.clone() {
                return Up::Done(id);
            }
        }
        if st.paused {
            self.media.transfers.state(&st.msg_id, TransferState::Paused);
            return Up::Hold;
        }
        let mut progressed = false;
        match self.upload_parts(local_id, &mut st, &mut progressed) {
            Ok(Some(id)) => Up::Done(id),
            Ok(None) => {
                self.media.transfers.state(&st.msg_id, TransferState::Queued);
                Up::Hold
            }
            Err(error) => {
                self.media.transfers.state(&st.msg_id, TransferState::Failed);
                Up::Failed { error, progressed }
            }
        }
    }

    fn upload_parts(&mut self, local_id: &str, st: &mut UploadState, progressed: &mut bool) -> Result<Option<String>, Error> {
        let creds = self.creds.clone();
        // The server knows how far it got; ask it (a lost answer, a crash
        // or a restart lose nothing).
        let known = match st.upload_id.clone() {
            Some(id) => match self.api.upload_status(&creds, &id) {
                Err(Error::Server { status: 404, .. }) => None,
                r => Some(r?),
            },
            None => None,
        };
        let mut status = match known {
            Some(s) => s,
            None => {
                let s = self.api.upload_create(&creds, st.total)?;
                st.upload_id = Some(s.id.clone());
                self.save_upload(local_id, st)?;
                s
            }
        };
        if status.size != st.total {
            return Err(Error::Protocol("the server's upload does not match the file".into()));
        }
        let id = status.id.clone();
        let cs = status.chunk_size;
        let total = st.total;
        let mut blob = File::open(self.blob_path(local_id)).map_err(io)?;
        let mut buf = vec![0u8; cs as usize];
        let (mut sent, mut conflicts) = (0u64, 0);
        let msg = st.msg_id.clone();
        let show = |t: &Transfers, received: u64, state| {
            t.set(Transfer { message_id: msg.clone(), upload: true, done: (received * cs).min(total), total, state })
        };
        while !status.complete && status.received < status.chunks {
            if self.media.slice.is_some_and(|b| sent >= b) {
                return Ok(None);
            }
            show(&self.media.transfers, status.received, TransferState::Running);
            let index = status.received;
            let len = (total - index * cs).min(cs) as usize;
            blob.seek(SeekFrom::Start(index * cs)).map_err(io)?;
            blob.read_exact(&mut buf[..len]).map_err(io)?;
            match self.api.upload_part(&creds, &id, index, &buf[..len]) {
                Ok(s) => {
                    status = s;
                    sent += len as u64;
                    *progressed = true;
                    show(&self.media.transfers, status.received, TransferState::Running);
                }
                // Another attempt moved it on meanwhile: ask where it is.
                Err(Error::Server { status: 409, .. }) if conflicts < 3 => {
                    conflicts += 1;
                    status = self.api.upload_status(&creds, &id)?;
                }
                // Dropped by the server (unfinished for a day): start again.
                Err(Error::Server { status: 404, .. }) => {
                    st.upload_id = None;
                    self.save_upload(local_id, st)?;
                    return Err(Error::Network("the server dropped the unfinished upload; starting again".into()));
                }
                Err(e) => return Err(e),
            }
        }
        show(&self.media.transfers, status.chunks, TransferState::Running);
        st.done = true;
        self.save_upload(local_id, st)?;
        drop(blob);
        let _ = fs::remove_file(self.blob_path(local_id));
        // The sender's own history entry learns the id.
        if let Ok(gid) = hex::decode(&st.group) {
            if let Some(m) = self.client.message(&gid, &st.msg_id)? {
                if let Some(mut f) = m.data.as_deref().and_then(|d| serde_json::from_slice::<FileInfo>(d).ok()) {
                    f.id = id.clone();
                    self.client.set_message_data(&gid, &st.msg_id, Some(&serde_json::to_vec(&f).expect("JSON")))?;
                }
            }
        }
        self.media.uploaded.insert(local_id.to_string(), id.clone());
        Ok(Some(id))
    }

    /// The item carrying the upload was sent (or cancelled): the record,
    /// the blob and the progress entry go.
    pub(crate) fn upload_finished(&mut self, local_id: &str) -> Result<(), Error> {
        if let Some(st) = self.upload_state(local_id)? {
            self.client.set_app_data(&upload_key(local_id), None)?;
            self.media.transfers.remove(&st.msg_id);
        }
        let _ = fs::remove_file(self.blob_path(local_id));
        Ok(())
    }

    /// The user cancelled: as [`Session::upload_finished`], and the server
    /// may drop the partial upload now (best effort; it goes after a day
    /// anyway).
    pub(crate) fn upload_cancelled(&mut self, local_id: &str) -> Result<(), Error> {
        if let Some(st) = self.upload_state(local_id)? {
            if let (Some(id), false) = (&st.upload_id, st.done) {
                let _ = self.api.upload_cancel(&self.creds, id);
            }
        }
        self.upload_finished(local_id)
    }

    fn upload_of(&self, message_id: &str) -> Result<(String, UploadState), Error> {
        for item in self.client.outbox_unsent(None)? {
            if item.message_id.as_deref() == Some(message_id) {
                if let Some(u) = self.upload_state(&item.local_id)? {
                    return Ok((item.local_id, u));
                }
            }
        }
        Err(Error::Usage("no such upload".into()))
    }

    /// Pauses the upload of a file message. Later messages of the same chat
    /// wait until it is resumed or cancelled.
    pub fn pause_transfer(&mut self, message_id: &str) -> Result<(), Error> {
        let (local, mut u) = self.upload_of(message_id)?;
        if u.done {
            return Err(Error::Usage("the upload is complete".into()));
        }
        u.paused = true;
        self.save_upload(&local, &u)?;
        self.media.transfers.state(message_id, TransferState::Paused);
        Ok(())
    }

    /// Resumes a paused upload now. Returns true if the message went out.
    pub fn resume_transfer(&mut self, message_id: &str) -> Result<bool, Error> {
        let (local, mut u) = self.upload_of(message_id)?;
        u.paused = false;
        self.save_upload(&local, &u)?;
        self.media.transfers.state(message_id, TransferState::Queued);
        let gid = hex::decode(&u.group).map_err(|_| Error::Protocol("damaged upload record".into()))?;
        let sent = self.drive_outbox(Some(&gid))?;
        Ok(sent.iter().any(|(id, a)| *id == local && matches!(a, crate::outbox::Attempt::Sent(_))))
    }

    /// Reloads the progress board from the stored uploads (after opening).
    pub(crate) fn load_transfers(&self) -> Result<(), Error> {
        for item in self.client.outbox_unsent(None)? {
            if let Some(u) = self.upload_state(&item.local_id)? {
                let state = if item.state == OutboxState::Failed {
                    TransferState::Failed
                } else if u.paused {
                    TransferState::Paused
                } else {
                    TransferState::Queued
                };
                let done = if u.done { u.total } else { 0 };
                self.media.transfers.set(Transfer { message_id: u.msg_id, upload: true, done, total: u.total, state });
            }
        }
        Ok(())
    }

    /// A file reference received earlier, by attachment id (gone after a
    /// view-once file was opened).
    pub fn received_file(&self, id: &str) -> Result<Option<FileInfo>, Error> {
        Ok(match self.client.app_data(&format!("file/{id}"))? {
            Some(v) => Some(serde_json::from_slice::<StoredFile>(&v).map_err(|_| Error::Protocol("damaged file reference".into()))?.info),
            None => None,
        })
    }

    pub(crate) fn remember_file(&self, gid: &[u8], file: &FileInfo) -> Result<(), Error> {
        let stored = StoredFile { group: hex::encode(gid), info: file.clone() };
        Ok(self.client.set_app_data(&format!("file/{}", file.id), Some(&serde_json::to_vec(&stored).expect("JSON")))?)
    }

    /// Downloads, checks and opens an attachment into memory; fails if
    /// anything does not match the message (tampering, wrong key, other
    /// content or size). A view-once file's reference is deleted after it
    /// opened once.
    pub fn download(&self, f: &FileInfo) -> Result<Vec<u8>, Error> {
        let plain = self.downloader().fetch(f)?;
        self.opened(f)?;
        Ok(plain)
    }

    /// As [`Session::download`], into the file `dest` (resumable; for large
    /// files and "save as").
    pub fn download_to(&self, f: &FileInfo, dest: &Path) -> Result<(), Error> {
        self.downloader().fetch_to(f, dest)?;
        self.opened(f)
    }

    /// After a file was opened (by a [`Downloader`] outside the session):
    /// a view-once file's references are deleted.
    pub fn opened(&self, f: &FileInfo) -> Result<(), Error> {
        if !f.view_once {
            return Ok(());
        }
        if let Some(v) = self.client.app_data(&format!("file/{}", f.id))? {
            if let Ok(sf) = serde_json::from_slice::<StoredFile>(&v) {
                if let Ok(g) = hex::decode(&sf.group) {
                    self.client.set_message_data(&g, &f.msg_id, None)?;
                }
            }
        }
        self.client.set_app_data(&format!("file/{}", f.id), None)?;
        Ok(())
    }

    /// Whether a received file downloads by itself (`user.auto_download`):
    /// the setting is applied, the device's network and the file's size fit
    /// its option, the sender is one of this user's contacts (accepted, not
    /// blocked) or this user's own device, the chat is not a request, and
    /// the file is not view-once. Files from strangers never do.
    pub fn auto_download_allowed(&mut self, gid: &[u8], from: &MemberId, f: &FileInfo) -> Result<bool, Error> {
        if f.view_once || matches!(self.group_status(gid)?, GroupStatus::Request { .. }) {
            return Ok(false);
        }
        let st = self.feature("user.auto_download")?;
        if st.state != State::Applied {
            return Ok(false);
        }
        let Some(policy) = AutoDownload::parse(st.option.as_deref().unwrap_or(AUTO_DOWNLOAD_DEFAULT)) else { return Ok(false) };
        if !policy.allows(self.media.network, f.size) {
            return Ok(false);
        }
        let Some(account) = self.map(&crate::accounts_key(gid))?.get(&from.to_hex()).cloned() else { return Ok(false) };
        if account == self.creds.account_id {
            return Ok(true);
        }
        Ok(self.contact(&account)?.is_some_and(|c| c.accepted && !c.blocked))
    }
}

/// A stored file reference: which group and message it belongs to.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredFile {
    group: String,
    info: FileInfo,
}

/// Per-session media state.
pub(crate) struct MediaState {
    pub dir: PathBuf,
    pub network: Network,
    pub transfers: Transfers,
    pub slice: Option<u64>,
    /// Attachment ids of uploads finished in this session, by local id
    /// (for [`Session::send_media`]'s answer).
    pub uploaded: std::collections::HashMap<String, String>,
}

impl MediaState {
    pub fn new(profile: &str) -> Self {
        MediaState {
            dir: PathBuf::from(format!("{profile}.media")),
            network: Network::None,
            transfers: Transfers::default(),
            slice: None,
            uploaded: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_that_reach_file_names() {
        assert!(safe_id("AbC-_09xyzAbC-_09xyzAb"));
        for bad in ["", "../x", "a/b", "a.b", "x\0", &"a".repeat(65)] {
            assert!(!safe_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn transfers_board() {
        let t = Transfers::default();
        t.set(Transfer { message_id: "m".into(), upload: true, done: 1, total: 4, state: TransferState::Running });
        t.state("m", TransferState::Paused);
        assert_eq!(t.get("m").unwrap().state, TransferState::Paused);
        let other = t.clone();
        other.remove("m");
        assert!(t.list().is_empty());
    }
}
