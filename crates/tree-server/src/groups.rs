//! Read-only group routing state exposed to authenticated members.
//!
//! The server already needs this device set to sequence commits and deliver
//! mail. The endpoint exposes only the device ids of a group and only to a
//! device that is currently eligible to commit in that group.

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use sqlx::Row;

use crate::auth::NoBody;
use crate::auth::Signed;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Serialize)]
pub struct GroupDevicesResp {
    pub group_id: String,
    pub devices: Vec<String>,
}

/// GET /v1/groups/{group_id}/devices
pub async fn list_devices(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    req: Signed<NoBody>,
) -> ApiResult<Json<GroupDevicesResp>> {
    // Group ids are returned as hex here so they are safe as URL path
    // components without padding or '/' characters.
    let group_bytes =
        hex::decode(&group_id).map_err(|_| ApiError::bad_request("group_id must be hex"))?;
    if group_bytes.is_empty() || group_bytes.len() > 255 {
        return Err(ApiError::bad_request("group_id has a wrong length"));
    }

    let exists = sqlx::query("SELECT 1 FROM groups WHERE group_id = ?")
        .bind(&group_bytes)
        .fetch_optional(&state.db)
        .await?
        .is_some();
    if !exists {
        return Err(ApiError::not_found("no such group"));
    }

    let member = sqlx::query("SELECT 1 FROM group_devices WHERE group_id = ? AND device_id = ?")
        .bind(&group_bytes)
        .bind(&req.device.device_id)
        .fetch_optional(&state.db)
        .await?
        .is_some();
    if !member {
        return Err(ApiError::forbidden(
            "NOT_ELIGIBLE",
            "this device is not a member the server knows",
        ));
    }

    let devices: Vec<String> =
        sqlx::query("SELECT device_id FROM group_devices WHERE group_id = ? ORDER BY device_id")
            .bind(&group_bytes)
            .fetch_all(&state.db)
            .await?
            .iter()
            .map(|r| r.try_get("device_id"))
            .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(GroupDevicesResp {
        group_id: group_id.to_lowercase(),
        devices,
    }))
}
