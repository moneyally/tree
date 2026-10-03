//! Commit ordering (docs/PROTOCOL.md 7.4).
//!
//! MLS needs every member to apply the same commits in the same order. The
//! server is the sequencer: it accepts the first commit per (group, epoch)
//! and answers every later one with a conflict naming the winner. A retry of
//! the winner gets the same answer again. Only devices the server has seen in
//! the group may take the next slot, so an outsider who learns a group id
//! cannot freeze the group with a junk commit. The welcome for added devices
//! travels in the same request and is delivered only if the commit wins.

use std::collections::{BTreeSet, HashSet};

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::messages::deliver;
use crate::util::{b64_exceeds, check_id, new_id, unb64, ID_LEN};
use crate::{json_body, wire, AppState};

/// Accepted commits remembered per group (for retries and conflict answers).
pub const KEEP_WINNERS: i64 = 64;
/// MLS group ids created by Tree are 16 bytes; the field allows up to 255.
const MAX_GROUP_ID: usize = 255;

#[derive(Deserialize)]
pub struct CommitReq {
    pub group_id: String,
    pub epoch: u64,
    #[serde(default)]
    pub recipients: Vec<String>,
    pub body: String,
    #[serde(default)]
    pub added: Vec<String>,
    pub welcome: Option<String>,
    #[serde(default)]
    pub removed: Vec<String>,
}
json_body!(CommitReq, |cfg| (cfg.max_commit_bytes
    + cfg.max_welcome_bytes)
    .div_ceil(3)
    * 4
    + 3 * cfg.max_recipients * (ID_LEN + 4)
    + 4096);

#[derive(Serialize)]
pub struct CommitResp {
    pub accepted: bool,
    /// Same for a retry of the same commit.
    pub id: String,
    pub epoch: u64,
    /// Mailboxes the commit was put into (0 for a retry).
    pub delivered: usize,
    /// Recipient or added ids that are not registered devices.
    pub unknown_devices: Vec<String>,
    /// Devices whose mailbox is full: they missed the commit and must be
    /// removed and added again.
    pub full_devices: Vec<String>,
}

fn unique_ids(ids: Vec<String>, what: &'static str) -> ApiResult<Vec<String>> {
    let mut seen = HashSet::with_capacity(ids.len());
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        check_id(&id, what)?;
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    Ok(out)
}

/// `POST /v1/commits`
pub async fn submit(
    State(state): State<AppState>,
    req: Signed<CommitReq>,
) -> ApiResult<Json<CommitResp>> {
    let cfg = &state.cfg;
    let sender = req.device.device_id.clone();
    let CommitReq {
        group_id,
        epoch,
        recipients,
        body,
        added,
        welcome,
        removed,
    } = req.body;

    let recipients = unique_ids(recipients, "recipient")?;
    let added = unique_ids(added, "added device")?;
    let removed = unique_ids(removed, "removed device")?;
    if recipients.len() + added.len() > cfg.max_recipients || removed.len() > cfg.max_recipients {
        return Err(ApiError::too_large(format!(
            "at most {} devices",
            cfg.max_recipients
        )));
    }
    let group_id = unb64(&group_id, "group_id")?;
    if group_id.is_empty() || group_id.len() > MAX_GROUP_ID {
        return Err(ApiError::bad_request("group_id has a wrong length"));
    }
    let epoch_db = i64::try_from(epoch).map_err(|_| ApiError::bad_request("epoch too large"))?;

    if b64_exceeds(&body, cfg.max_commit_bytes) {
        return Err(ApiError::too_large("commit too large"));
    }
    let body = unb64(&body, "body")?;
    if body.len() > cfg.max_commit_bytes {
        return Err(ApiError::too_large("commit too large"));
    }
    let header = wire::envelope_header(&body)
        .map_err(|why| ApiError::bad_request(format!("body: {why}")))?;
    if header.content_type != wire::COMMIT {
        return Err(ApiError::bad_request("body is not a commit"));
    }
    if header.group_id != group_id.as_slice() || header.epoch != epoch {
        return Err(ApiError::bad_request(
            "group_id or epoch differ from the commit header",
        ));
    }

    let welcome = match (welcome, added.is_empty()) {
        (None, true) => None,
        (Some(_), true) => return Err(ApiError::bad_request("welcome without added devices")),
        (None, false) => return Err(ApiError::bad_request("added devices need a welcome")),
        (Some(w), false) => {
            if b64_exceeds(&w, cfg.max_welcome_bytes) {
                return Err(ApiError::too_large("welcome too large"));
            }
            let w = unb64(&w, "welcome")?;
            if w.len() > cfg.max_welcome_bytes {
                return Err(ApiError::too_large("welcome too large"));
            }
            if !wire::is_welcome(&w) {
                return Err(ApiError::bad_request("welcome is not an MLS welcome"));
            }
            Some(w)
        }
    };
    let hash: [u8; 32] = Sha256::digest(&body).into();
    state.rate_device(&sender, ((recipients.len() + added.len()) / 100) as f64)?;

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let last: Option<i64> = sqlx::query("SELECT last_epoch FROM groups WHERE group_id = ?")
        .bind(&group_id)
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| r.try_get("last_epoch"))
        .transpose()?;

    if last.is_none()
        && (epoch_db != 0
            || !recipients.is_empty()
            || !added.is_empty()
            || !removed.is_empty()
            || welcome.is_some())
    {
        return Err(ApiError::bad_request(
            "initial group commit must be epoch 0 with no recipients or membership changes",
        ));
    }

    if let Some(last) = last {
        if epoch_db <= last {
            let winner = sqlx::query(
                "SELECT sha256, id FROM group_winners WHERE group_id = ? AND epoch = ?",
            )
            .bind(&group_id)
            .bind(epoch_db)
            .fetch_optional(&mut *tx)
            .await?;
            let winner: Option<(Vec<u8>, String)> = match winner {
                Some(r) => Some((r.try_get("sha256")?, r.try_get("id")?)),
                None => None,
            };
            return match winner {
                Some((h, id)) if h == hash => Ok(Json(CommitResp {
                    accepted: true,
                    id,
                    epoch,
                    delivered: 0,
                    unknown_devices: vec![],
                    full_devices: vec![],
                })),
                other => Err(ApiError::conflict(
                    "COMMIT_CONFLICT",
                    "another commit won this epoch",
                )
                .with(
                    "winner_sha256",
                    other.map_or(json!(null), |(h, _)| json!(hex::encode(h))),
                )),
            };
        }
        let eligible =
            sqlx::query("SELECT 1 FROM group_devices WHERE group_id = ? AND device_id = ?")
                .bind(&group_id)
                .bind(&sender)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
        if !eligible {
            return Err(ApiError::forbidden(
                "NOT_ELIGIBLE",
                "this device is not a member the server knows",
            ));
        }
        if epoch_db != last + 1 {
            return Err(
                ApiError::conflict("EPOCH_MISMATCH", "epoch is ahead of the group")
                    .with("last_epoch", json!(last)),
            );
        }

        // For the next epoch, the caller must describe the current roster
        // faithfully. The server cannot decrypt the MLS commit, but it can
        // prevent a malicious member from silently dropping devices from
        // server-side routing metadata.
        let current_members: HashSet<String> = sqlx::query(
            "SELECT device_id FROM group_devices WHERE group_id = ? ORDER BY device_id",
        )
        .bind(&group_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|r| r.try_get("device_id"))
        .collect::<Result<HashSet<_>, _>>()?;
        let removed_set: HashSet<&String> = removed.iter().collect();
        if removed.iter().any(|d| d == &sender)
            || !removed.iter().all(|d| current_members.contains(d))
        {
            return Err(ApiError::bad_request(
                "removed devices must be current group members and cannot remove the sender",
            ));
        }
        if added.iter().any(|d| current_members.contains(d)) {
            return Err(ApiError::bad_request(
                "added devices must not already be group members",
            ));
        }
        if recipients.iter().any(|d| !current_members.contains(d)) {
            return Err(ApiError::bad_request(
                "recipients must be current group members",
            ));
        }
        if added.iter().any(|d| recipients.contains(d)) {
            return Err(ApiError::bad_request(
                "added devices cannot also be recipients",
            ));
        }
        let required_recipients: HashSet<String> = current_members
            .iter()
            .filter(|d| *d != &sender)
            .cloned()
            .collect();
        let recipient_set: HashSet<String> = recipients.iter().cloned().collect();
        if !required_recipients.is_subset(&recipient_set) {
            return Err(ApiError::bad_request(
                "recipients must include every current member not being removed",
            ));
        }
    }

    // Accept.
    let id = new_id();
    sqlx::query(
        "INSERT INTO groups (group_id, last_epoch) VALUES (?1, ?2) \
         ON CONFLICT (group_id) DO UPDATE SET last_epoch = ?2",
    )
    .bind(&group_id)
    .bind(epoch_db)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO group_winners (group_id, epoch, sha256, id) VALUES (?, ?, ?, ?)")
        .bind(&group_id)
        .bind(epoch_db)
        .bind(hash.as_slice())
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM group_winners WHERE group_id = ? AND epoch <= ?")
        .bind(&group_id)
        .bind(epoch_db - KEEP_WINNERS)
        .execute(&mut *tx)
        .await?;

    // eligible = ({sender} ∪ recipients ∪ added) \ removed, known devices only
    let removed_set: HashSet<&String> = removed.iter().collect();
    let eligible: BTreeSet<&String> = std::iter::once(&sender)
        .chain(&recipients)
        .chain(&added)
        .filter(|d| !removed_set.contains(d))
        .collect();
    sqlx::query("DELETE FROM group_devices WHERE group_id = ?")
        .bind(&group_id)
        .execute(&mut *tx)
        .await?;
    for d in eligible {
        sqlx::query(
            "INSERT INTO group_devices (group_id, device_id) \
             SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM devices WHERE id = ?2)",
        )
        .bind(&group_id)
        .bind(d)
        .execute(&mut *tx)
        .await?;
    }

    // Deliver: the commit to the existing members, then the welcome to the
    // added devices, in the same transaction (before any message of the new
    // epoch can exist).
    let mut d = deliver(&mut tx, cfg, &body, recipients).await?;
    if let Some(w) = welcome {
        let dw = deliver(&mut tx, cfg, &w, added).await?;
        d.delivered.extend(dw.delivered);
        d.unknown_devices.extend(dw.unknown_devices);
        d.full_devices.extend(dw.full_devices);
    }
    tx.commit().await?;

    for dev in &d.delivered {
        state.waiters.notify(dev);
    }
    Ok(Json(CommitResp {
        accepted: true,
        id,
        epoch,
        delivered: d.delivered.len(),
        unknown_devices: d.unknown_devices,
        full_devices: d.full_devices,
    }))
}
