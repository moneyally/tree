//! Public groups and channels (Wave 4, PROTOCOL.md 8.15, APP_PROTOCOL.md 10).
//!
//! **Not end-to-end encrypted.** Everything here goes to the server in
//! plaintext and anyone signed in can read it: the space's name, @handle and
//! description, posts, comments, the display name published with a post, who
//! is subscribed. Every object carries `is_public: true` and the apps show a
//! "Public" badge wherever it appears. It is a separate path: nothing here
//! touches MLS groups, mailboxes or this device's history of private chats,
//! and no private group can be made public (`chat.private_to_public` is
//! permanently released; the server API has no way to name a private group).
//!
//! Posts of subscribed spaces are cached in the encrypted profile (app data
//! `public/<space id>`, at most [`CACHE_POSTS`] per space) with the server's
//! change cursor, so a sync fetches only what changed (also edits and
//! deletions) and unread counts work offline.
//!
//! Space settings are feature keys with apply and release, set by the
//! space's admins on the server ([`Session::public_set_feature`]):
//! `chat.public_listing`, `channel.comments`, `channel.signatures`,
//! `chat.slow_mode` (option: 10 s to 1 h).

use std::collections::BTreeMap;

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Error, Session};

/// Posts kept per space on this device (the newest).
pub const CACHE_POSTS: usize = 1000;
/// Posts fetched per request.
pub const PAGE: u32 = 50;
/// Longest post, in characters (as the server).
pub const MAX_TEXT: usize = 4096;
/// Tries of one post when the network fails (same id: stored once).
const POST_TRIES: usize = 3;

const LIST_KEY: &str = "public/list";

fn cache_key(space: &str) -> String {
    format!("public/{space}")
}

/// A public group or channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSpace {
    pub id: String,
    /// Always true: not end-to-end encrypted, readable by the server and by
    /// anyone signed in. Apps show "Public".
    pub is_public: bool,
    /// `group` or `channel`.
    pub kind: String,
    pub handle: String,
    pub name: String,
    pub description: String,
    pub avatar: Option<String>,
    pub members: u64,
    /// `chat.public_listing`: in the directory and in search.
    pub listed: bool,
    /// `channel.comments`.
    pub comments: bool,
    /// `channel.signatures`.
    pub signatures: bool,
    /// `chat.slow_mode`: seconds, if applied.
    pub slow_mode: Option<i64>,
    /// This account's role: `owner`, `admin`, `member`, or none.
    pub role: Option<String>,
    pub notify: bool,
    pub banned: bool,
    /// Admin accounts (only shown to admins).
    pub admins: Vec<String>,
    /// Banned accounts (only shown to admins).
    pub bans: Vec<String>,
    /// Unread posts on this device (subscribed spaces).
    pub unread: u32,
}

impl PublicSpace {
    pub fn is_channel(&self) -> bool {
        self.kind == "channel"
    }

    pub fn is_admin(&self) -> bool {
        matches!(self.role.as_deref(), Some("owner" | "admin"))
    }

    pub fn subscribed(&self) -> bool {
        self.role.is_some()
    }

    fn from_json(v: &Value) -> Result<Self, Error> {
        let s = |k: &str| v[k].as_str().map(str::to_string).ok_or_else(|| Error::Protocol(format!("public space lacks {k}")));
        let strings = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        if v["is_public"] != true {
            return Err(Error::Protocol("a public space must say so".into()));
        }
        Ok(PublicSpace {
            id: s("id")?,
            is_public: true,
            kind: s("kind")?,
            handle: s("handle")?,
            name: s("name")?,
            description: v["description"].as_str().unwrap_or_default().to_string(),
            avatar: v["avatar"].as_str().map(str::to_string),
            members: v["members"].as_u64().unwrap_or(0),
            listed: v["features"]["chat.public_listing"] == true,
            comments: v["features"]["channel.comments"] == true,
            signatures: v["features"]["channel.signatures"] == true,
            slow_mode: v["features"]["chat.slow_mode"].as_i64(),
            role: v["role"].as_str().map(str::to_string),
            notify: v["notify"] == true,
            banned: v["banned"] == true,
            admins: strings("admins"),
            bans: strings("bans"),
            unread: 0,
        })
    }
}

/// A post or a comment in a public space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicPost {
    pub id: String,
    pub space: String,
    /// Always true (see [`PublicSpace::is_public`]).
    pub is_public: bool,
    pub seq: i64,
    pub rev: i64,
    /// A comment (channels) or a reply (groups): the post it answers.
    pub reply_to: Option<String>,
    /// None once deleted.
    pub text: Option<String>,
    pub attachment: Option<String>,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub deleted: bool,
    /// Written by this account.
    pub mine: bool,
    /// The author's account and published name; none for a channel post
    /// while `channel.signatures` is released (shown as the channel).
    pub author: Option<String>,
    pub author_name: Option<String>,
    /// Comments on a channel post.
    pub comments: u32,
}

impl PublicPost {
    fn from_json(v: &Value) -> Result<Self, Error> {
        let s = |k: &str| v[k].as_str().map(str::to_string);
        if v["is_public"] != true {
            return Err(Error::Protocol("a public post must say so".into()));
        }
        Ok(PublicPost {
            id: s("id").ok_or_else(|| Error::Protocol("post lacks id".into()))?,
            space: s("space").unwrap_or_default(),
            is_public: true,
            seq: v["seq"].as_i64().unwrap_or(0),
            rev: v["rev"].as_i64().unwrap_or(0),
            reply_to: s("reply_to"),
            text: s("text"),
            attachment: s("attachment"),
            created_at: v["created_at"].as_i64().unwrap_or(0),
            edited_at: v["edited_at"].as_i64(),
            deleted: v["deleted"] == true,
            mine: v["mine"] == true,
            author: s("author"),
            author_name: s("author_name"),
            comments: v["comments"].as_u64().unwrap_or(0) as u32,
        })
    }
}

/// What this device keeps of one subscribed space.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Cache {
    space: Value,
    /// seq -> post JSON as the server sent it.
    posts: BTreeMap<i64, Value>,
    /// The server's change cursor this cache is up to date with.
    rev: i64,
    /// Posts up to this seq were read.
    read_seq: i64,
    /// The first page was fetched.
    #[serde(default)]
    started: bool,
}

impl Cache {
    /// Takes posts the server sent in answer to a sync (the cursor moves on).
    fn merge(&mut self, posts: &[Value]) {
        self.merge_with(posts, true)
    }

    /// `advance`: false for answers to this device's own actions (a post,
    /// an edit), which say nothing about other changes before them.
    fn merge_with(&mut self, posts: &[Value], advance: bool) {
        for p in posts {
            let (Some(seq), Some(rev)) = (p["seq"].as_i64(), p["rev"].as_i64()) else { continue };
            if advance {
                self.rev = self.rev.max(rev);
            }
            let newer = self.posts.get(&seq).and_then(|o| o["rev"].as_i64()).is_none_or(|old| old <= rev);
            if newer {
                self.posts.insert(seq, p.clone());
            }
        }
        while self.posts.len() > CACHE_POSTS {
            let first = *self.posts.keys().next().expect("not empty");
            self.posts.remove(&first);
        }
    }

    fn unread(&self, channel: bool) -> u32 {
        self.posts
            .range(self.read_seq + 1..)
            .filter(|(_, p)| p["deleted"] != true && p["mine"] != true && !(channel && !p["reply_to"].is_null()))
            .count() as u32
    }
}

fn check_text(text: &str) -> Result<(), Error> {
    let n = text.chars().count();
    if n == 0 || n > MAX_TEXT {
        return Err(Error::Usage(format!("a post is 1 to {MAX_TEXT} characters")));
    }
    Ok(())
}

/// A new post id: 16 random bytes, base64url (the server's id format).
fn post_id() -> String {
    use base64::Engine;
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn feature_error(e: Error) -> Error {
    match e {
        Error::Server { status: 403, code } if code == "LOCKED_BY_SERVER" => Error::Feature(code),
        e => e,
    }
}

impl Session {
    fn pub_call(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value, Error> {
        self.api.public(&self.creds, method, path, body).map_err(feature_error)
    }

    fn pub_cache(&self, space: &str) -> Result<Option<Cache>, Error> {
        self.app_get(&cache_key(space))
    }

    fn pub_list(&self) -> Result<Vec<String>, Error> {
        Ok(self.app_get(LIST_KEY)?.unwrap_or_default())
    }

    /// Remembers a space answer: its cache entry if subscribed (dropped if
    /// not), and the list of subscribed spaces.
    fn pub_remember(&self, v: &Value) -> Result<PublicSpace, Error> {
        let mut s = PublicSpace::from_json(v)?;
        let mut list = self.pub_list()?;
        if s.subscribed() {
            let mut c = self.pub_cache(&s.id)?.unwrap_or_default();
            // Who is shown with channel posts changed (`channel.signatures`,
            // or this account's admin role): the kept copies are refetched.
            let shown = |x: &Value| (x["features"]["channel.signatures"] == true, x["role"].clone());
            if c.started && shown(&c.space) != shown(v) {
                c.posts.clear();
                c.started = false;
            }
            c.space = v.clone();
            s.unread = c.unread(s.is_channel());
            self.app_put(&cache_key(&s.id), Some(&c))?;
            if !list.contains(&s.id) {
                list.push(s.id.clone());
                self.app_put(LIST_KEY, Some(&list))?;
            }
        } else if list.contains(&s.id) {
            list.retain(|x| *x != s.id);
            self.app_put(LIST_KEY, Some(&list))?;
            self.app_put::<Cache>(&cache_key(&s.id), None)?;
        }
        Ok(s)
    }

    // --- spaces ---

    /// Creates a public group (`kind` = `group`) or channel (`channel`)
    /// owned by this account. Not end-to-end encrypted: the apps say so
    /// before calling this.
    pub fn public_create(&self, kind: &str, name: &str, handle: &str, description: &str, avatar: Option<&str>) -> Result<PublicSpace, Error> {
        if kind != "group" && kind != "channel" {
            return Err(Error::Usage("a public space is a group or a channel".into()));
        }
        let body = json!({ "kind": kind, "name": name.trim(), "handle": handle.trim(), "description": description.trim(), "avatar": avatar });
        let v = self.pub_call(Method::POST, "/v1/public/spaces", Some(&body))?;
        self.pub_remember(&v)
    }

    /// A space as the server has it now.
    pub fn public_space(&self, space: &str) -> Result<PublicSpace, Error> {
        let v = self.pub_call(Method::GET, &format!("/v1/public/spaces/{space}"), None)?;
        self.pub_remember(&v)
    }

    /// The space with this exact @handle (listed or not), if any.
    pub fn public_find(&self, handle: &str) -> Result<Option<PublicSpace>, Error> {
        let h = handle.trim().trim_start_matches('@');
        if h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Ok(None);
        }
        match self.pub_call(Method::GET, &format!("/v1/public/handles/{h}"), None) {
            Ok(v) => Ok(Some(self.pub_remember(&v)?)),
            Err(Error::Server { status: 404 | 400, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Listed spaces (`chat.public_listing`) whose handle starts with, or
    /// whose name contains, `query`.
    pub fn public_directory(&self, query: &str) -> Result<Vec<PublicSpace>, Error> {
        let q: String = query.trim().chars().take(64).collect();
        let enc: String = q
            .bytes()
            .map(|b| if b.is_ascii_alphanumeric() || b == b'_' { (b as char).to_string() } else { format!("%{b:02X}") })
            .collect();
        let v = self.pub_call(Method::GET, &format!("/v1/public/directory?q={enc}"), None)?;
        v["spaces"].as_array().into_iter().flatten().map(PublicSpace::from_json).collect()
    }

    /// This account's spaces, from the server (also those joined on
    /// another device); refreshes the list kept here.
    pub fn public_subscriptions(&self) -> Result<Vec<PublicSpace>, Error> {
        let v = self.pub_call(Method::GET, "/v1/public/subscriptions", None)?;
        let mut out = Vec::new();
        let mut ids = Vec::new();
        for s in v["spaces"].as_array().into_iter().flatten() {
            let sp = self.pub_remember(s)?;
            ids.push(sp.id.clone());
            out.push(sp);
        }
        for gone in self.pub_list()?.into_iter().filter(|i| !ids.contains(i)) {
            self.app_put::<Cache>(&cache_key(&gone), None)?;
        }
        self.app_put(LIST_KEY, Some(&ids))?;
        Ok(out)
    }

    /// The subscribed spaces as this device last saw them, with unread
    /// counts (no network).
    pub fn public_cached(&self) -> Result<Vec<PublicSpace>, Error> {
        let mut out = Vec::new();
        for id in self.pub_list()? {
            if let Some(c) = self.pub_cache(&id)? {
                if let Ok(mut s) = PublicSpace::from_json(&c.space) {
                    s.unread = c.unread(s.is_channel());
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    pub fn public_join(&self, space: &str) -> Result<PublicSpace, Error> {
        let v = self.pub_call(Method::POST, &format!("/v1/public/spaces/{space}/join"), None)?;
        self.pub_remember(&v)?;
        self.public_sync(space)?;
        // What was there before joining is not "unread".
        self.public_mark_read(space)?;
        self.public_space(space)
    }

    /// Unsubscribes; the cached posts are deleted from this device.
    pub fn public_leave(&self, space: &str) -> Result<(), Error> {
        let v = self.pub_call(Method::POST, &format!("/v1/public/spaces/{space}/leave"), None)?;
        self.pub_remember(&v)?;
        Ok(())
    }

    /// Content-free wake-ups for new posts in this space (subscribers).
    pub fn public_set_notify(&self, space: &str, on: bool) -> Result<PublicSpace, Error> {
        let a = if on { "apply" } else { "release" };
        let v = self.pub_call(Method::POST, &format!("/v1/public/spaces/{space}/notify/{a}"), None)?;
        self.pub_remember(&v)
    }

    /// An admin applies or releases a space setting (`chat.public_listing`,
    /// `channel.comments`, `channel.signatures`, `chat.slow_mode` with a
    /// duration option).
    pub fn public_set_feature(&self, space: &str, key: &str, apply: bool, option: Option<&str>) -> Result<PublicSpace, Error> {
        let a = if apply { "apply" } else { "release" };
        let body = option.map(|o| json!({ "option": o }));
        let v = self.pub_call(Method::POST, &format!("/v1/public/spaces/{space}/features/{key}/{a}"), body.as_ref())?;
        self.pub_remember(&v)
    }

    /// An admin makes another subscriber admin, or drops the role.
    pub fn public_set_admin(&self, space: &str, account: &str, admin: bool) -> Result<PublicSpace, Error> {
        let a = if admin { "apply" } else { "release" };
        let v = self.pub_call(Method::POST, &format!("/v1/public/spaces/{space}/admins/{account}/{a}"), None)?;
        self.pub_remember(&v)
    }

    /// An admin bans an account (unsubscribed, may not join or post) or
    /// lifts the ban.
    pub fn public_ban(&self, space: &str, account: &str, ban: bool) -> Result<PublicSpace, Error> {
        let a = if ban { "apply" } else { "release" };
        let v = self.pub_call(Method::POST, &format!("/v1/public/spaces/{space}/bans/{account}/{a}"), None)?;
        self.pub_remember(&v)
    }

    /// An admin changes the name or description (None: unchanged).
    pub fn public_update(&self, space: &str, name: Option<&str>, description: Option<&str>) -> Result<PublicSpace, Error> {
        let body = json!({ "name": name.map(str::trim), "description": description.map(str::trim) });
        let v = self.pub_call(Method::POST, &format!("/v1/public/spaces/{space}/profile"), Some(&body))?;
        self.pub_remember(&v)
    }

    /// The owner deletes the space and everything in it.
    pub fn public_delete_space(&self, space: &str) -> Result<(), Error> {
        self.pub_call(Method::DELETE, &format!("/v1/public/spaces/{space}"), None)?;
        let mut list = self.pub_list()?;
        list.retain(|x| x != space);
        self.app_put(LIST_KEY, Some(&list))?;
        self.app_put::<Cache>(&cache_key(space), None)
    }

    // --- posts ---

    /// Posts in a public space (a channel: admins only), or with `reply_to`
    /// comments on a channel post (`channel.comments`) / answers in a
    /// group. The post carries this user's display name, published with
    /// it. A post id chosen here makes a retry after a network failure
    /// land once.
    pub fn public_post(&self, space: &str, text: &str, reply_to: Option<&str>) -> Result<PublicPost, Error> {
        check_text(text)?;
        let name = self.name().trim().to_string();
        let body = json!({ "id": post_id(), "text": text, "reply_to": reply_to, "author_name": (!name.is_empty()).then_some(name) });
        let path = format!("/v1/public/spaces/{space}/posts");
        let mut last = None;
        for _ in 0..POST_TRIES {
            match self.pub_call(Method::POST, &path, Some(&body)) {
                Ok(v) => {
                    self.pub_merge(space, std::slice::from_ref(&v))?;
                    return PublicPost::from_json(&v);
                }
                Err(Error::Network(e)) => last = Some(Error::Network(e)),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| Error::Network("no answer".into())))
    }

    /// The author edits its post.
    pub fn public_edit(&self, space: &str, post: &str, text: &str) -> Result<PublicPost, Error> {
        check_text(text)?;
        let v = self.pub_call(Method::PUT, &format!("/v1/public/posts/{post}"), Some(&json!({ "text": text })))?;
        self.pub_merge(space, std::slice::from_ref(&v))?;
        PublicPost::from_json(&v)
    }

    /// The author, or an admin of the space, deletes a post.
    pub fn public_delete(&self, space: &str, post: &str) -> Result<(), Error> {
        self.pub_call(Method::DELETE, &format!("/v1/public/posts/{post}"), None)?;
        self.public_sync(space).map(|_| ())
    }

    /// Reports a public post to the operator (the server holds it, so the
    /// report names it; `user.report` is always on).
    pub fn public_report(&self, post: &str, reason: &str) -> Result<(), Error> {
        self.pub_call(Method::POST, "/v1/public/reports", Some(&json!({ "post": post, "reason": reason })))?;
        Ok(())
    }

    fn pub_merge(&self, space: &str, posts: &[Value]) -> Result<(), Error> {
        if let Some(mut c) = self.pub_cache(space)? {
            c.merge_with(posts, false);
            self.app_put(&cache_key(space), Some(&c))?;
        }
        Ok(())
    }

    /// Brings this device's copy of a subscribed space up to date: the
    /// newest page the first time, then every change after the cursor
    /// (new posts and comments, edits, deletions). Returns how many
    /// changes arrived. Not subscribed: nothing is kept.
    pub fn public_sync(&self, space: &str) -> Result<u32, Error> {
        let Some(mut c) = self.pub_cache(space)? else { return Ok(0) };
        let mut n = 0;
        if !c.started {
            // The cursor the space reported before the page: changes after
            // it come with the next sync (again, merged by revision).
            let from = c.space["last_rev"].as_i64().unwrap_or(0);
            let v = self.pub_call(Method::GET, &format!("/v1/public/spaces/{space}/posts?limit={PAGE}"), None)?;
            let posts = v["posts"].as_array().cloned().unwrap_or_default();
            n += posts.len() as u32;
            c.merge_with(&posts, false);
            // A channel's page holds posts only: their comments come along.
            for p in posts.iter().filter(|p| p["comments"].as_u64().unwrap_or(0) > 0) {
                let id = p["id"].as_str().unwrap_or_default();
                let v = self.pub_call(Method::GET, &format!("/v1/public/spaces/{space}/posts?reply_to={id}&limit=200"), None)?;
                c.merge_with(v["posts"].as_array().map(Vec::as_slice).unwrap_or_default(), false);
            }
            c.rev = c.rev.max(from);
            c.started = true;
        } else {
            loop {
                let v = self.pub_call(Method::GET, &format!("/v1/public/spaces/{space}/posts?after_rev={}&limit=200", c.rev), None)?;
                let posts = v["posts"].as_array().cloned().unwrap_or_default();
                n += posts.len() as u32;
                c.merge(&posts);
                if posts.len() < 200 {
                    break;
                }
            }
        }
        self.app_put(&cache_key(space), Some(&c))?;
        Ok(n)
    }

    /// Syncs every subscribed space; returns the spaces with changes.
    pub fn public_sync_all(&self) -> Result<Vec<String>, Error> {
        let mut changed = Vec::new();
        for id in self.pub_list()? {
            if self.public_sync(&id)? > 0 {
                changed.push(id);
            }
        }
        Ok(changed)
    }

    /// The newest posts of any space, oldest first, without keeping them
    /// (to look into a space before subscribing).
    pub fn public_peek(&self, space: &str) -> Result<Vec<PublicPost>, Error> {
        let v = self.pub_call(Method::GET, &format!("/v1/public/spaces/{space}/posts?limit={PAGE}"), None)?;
        let mut out: Vec<PublicPost> = v["posts"].as_array().into_iter().flatten().map(PublicPost::from_json).collect::<Result<_, _>>()?;
        out.reverse();
        Ok(out)
    }

    /// Fetches the page before the oldest kept post (scrolling back).
    /// Returns how many arrived.
    pub fn public_load_older(&self, space: &str) -> Result<u32, Error> {
        let Some(mut c) = self.pub_cache(space)? else { return Ok(0) };
        let before = c.posts.keys().next().copied().unwrap_or(i64::MAX);
        let v = self.pub_call(Method::GET, &format!("/v1/public/spaces/{space}/posts?before={before}&limit={PAGE}"), None)?;
        let posts = v["posts"].as_array().cloned().unwrap_or_default();
        c.merge_with(&posts, false);
        self.app_put(&cache_key(space), Some(&c))?;
        Ok(posts.len() as u32)
    }

    /// Fetches the comments of a channel post into the cache.
    pub fn public_load_comments(&self, space: &str, post: &str) -> Result<Vec<PublicPost>, Error> {
        let v = self.pub_call(Method::GET, &format!("/v1/public/spaces/{space}/posts?reply_to={post}&limit=200"), None)?;
        let posts = v["posts"].as_array().cloned().unwrap_or_default();
        self.pub_merge(space, &posts)?;
        self.public_comments(space, post)
    }

    /// Kept posts of a space, oldest first, the newest `limit`: in a
    /// channel the posts (comments separately, [`Session::public_comments`]);
    /// in a group everything. Deleted ones are left out.
    pub fn public_posts(&self, space: &str, limit: usize) -> Result<Vec<PublicPost>, Error> {
        let Some(c) = self.pub_cache(space)? else { return Ok(vec![]) };
        let channel = c.space["kind"] == "channel";
        let mut v: Vec<PublicPost> = c
            .posts
            .values()
            .filter(|p| p["deleted"] != true && !(channel && !p["reply_to"].is_null()))
            .filter_map(|p| PublicPost::from_json(p).ok())
            .collect();
        let skip = v.len().saturating_sub(limit);
        v.drain(..skip);
        Ok(v)
    }

    /// Kept comments of a post, oldest first.
    pub fn public_comments(&self, space: &str, post: &str) -> Result<Vec<PublicPost>, Error> {
        let Some(c) = self.pub_cache(space)? else { return Ok(vec![]) };
        Ok(c.posts.values().filter(|p| p["deleted"] != true && p["reply_to"] == post).filter_map(|p| PublicPost::from_json(p).ok()).collect())
    }

    /// Unread posts of a subscribed space on this device.
    pub fn public_unread(&self, space: &str) -> Result<u32, Error> {
        Ok(self.pub_cache(space)?.map(|c| c.unread(c.space["kind"] == "channel")).unwrap_or(0))
    }

    /// Everything kept so far counts as read.
    pub fn public_mark_read(&self, space: &str) -> Result<(), Error> {
        if let Some(mut c) = self.pub_cache(space)? {
            c.read_seq = c.posts.keys().next_back().copied().unwrap_or(0).max(c.read_seq);
            self.app_put(&cache_key(space), Some(&c))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(seq: i64, rev: i64, extra: Value) -> Value {
        let mut v = json!({ "id": format!("p{seq}"), "is_public": true, "seq": seq, "rev": rev, "reply_to": null, "text": "t" });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    }

    #[test]
    fn cache_merges_by_rev_and_counts_unread() {
        let mut c = Cache::default();
        c.merge(&[p(1, 1, json!({})), p(2, 2, json!({ "mine": true })), p(3, 3, json!({ "reply_to": "p1" }))]);
        assert_eq!(c.rev, 3);
        assert_eq!(c.unread(false), 2, "own posts are not unread");
        assert_eq!(c.unread(true), 1, "comments do not count in a channel");
        // An older revision never overwrites a newer one.
        c.merge(&[p(1, 5, json!({ "text": "edited" }))]);
        c.merge(&[p(1, 4, json!({ "text": "stale" }))]);
        assert_eq!(c.posts[&1]["text"], "edited");
        c.merge(&[p(1, 6, json!({ "deleted": true }))]);
        assert_eq!(c.unread(false), 1, "deleted posts are not unread");
        c.read_seq = 3;
        assert_eq!(c.unread(false), 0);
        for i in 10..(10 + CACHE_POSTS as i64 + 5) {
            c.merge(&[p(i, i, json!({}))]);
        }
        assert_eq!(c.posts.len(), CACHE_POSTS, "only the newest are kept");
        assert!(!c.posts.contains_key(&1));
    }

    #[test]
    fn objects_must_say_public() {
        assert!(PublicPost::from_json(&json!({ "id": "x", "seq": 1 })).is_err());
        let s = json!({ "id": "x", "is_public": true, "kind": "channel", "handle": "news_x", "name": "N", "features": { "channel.comments": true } });
        let sp = PublicSpace::from_json(&s).unwrap();
        assert!(sp.is_public && sp.is_channel() && sp.comments && !sp.signatures && !sp.subscribed());
    }
}
