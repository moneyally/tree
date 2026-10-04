//! Persistent user-scope feature state.
//!
//! Only user preferences are stored here. Chat features stay inside the E2E
//! group state, while server/bot features stay on the server. The serialized
//! blob is stored through TreeProvider metadata, so StoredProvider keeps it
//! inside SQLCipher.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::TreeError;
use crate::features::{Caller, FeatureError, Registry, Scope, State, Status};
use crate::provider::TreeProvider;

const META_USER_FEATURES: &str = "user_features_v1";
const VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DiskEntry {
    state: u8,
    option: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DiskState {
    version: u8,
    entries: BTreeMap<String, DiskEntry>,
}

#[derive(Debug)]
pub enum UserFeatureError {
    Feature(FeatureError),
    Storage(TreeError),
}

impl From<FeatureError> for UserFeatureError {
    fn from(value: FeatureError) -> Self {
        Self::Feature(value)
    }
}

impl From<TreeError> for UserFeatureError {
    fn from(value: TreeError) -> Self {
        Self::Storage(value)
    }
}

fn state_to_u8(state: State) -> u8 {
    match state {
        State::Applied => 1,
        State::Released => 2,
    }
}

fn state_from_u8(v: u8) -> Result<State, TreeError> {
    match v {
        1 => Ok(State::Applied),
        2 => Ok(State::Released),
        _ => Err(TreeError::Storage("invalid user feature state".into())),
    }
}

fn load<P: TreeProvider>(
    provider: &P,
) -> Result<BTreeMap<String, (State, Option<String>)>, TreeError> {
    let Some(bytes) = provider.meta_optional(META_USER_FEATURES)? else {
        return Ok(BTreeMap::new());
    };
    let disk: DiskState = serde_json::from_slice(&bytes)
        .map_err(|_| TreeError::Storage("user feature state is damaged".into()))?;
    if disk.version != VERSION {
        return Err(TreeError::Storage(
            "unsupported user feature state version".into(),
        ));
    }
    let mut entries = BTreeMap::new();
    for (key, value) in disk.entries {
        entries.insert(key, (state_from_u8(value.state)?, value.option));
    }
    Ok(entries)
}

fn save<P: TreeProvider>(
    provider: &P,
    entries: &BTreeMap<String, (State, Option<String>)>,
) -> Result<(), TreeError> {
    let disk = DiskState {
        version: VERSION,
        entries: entries
            .iter()
            .map(|(key, (state, option))| {
                (
                    key.clone(),
                    DiskEntry {
                        state: state_to_u8(*state),
                        option: option.clone(),
                    },
                )
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&disk)
        .map_err(|_| TreeError::Storage("could not serialize user feature state".into()))?;
    provider.put_meta(META_USER_FEATURES, &bytes)
}

/// Loads the standard registry plus encrypted user-scope state.
pub fn registry<P: TreeProvider>(provider: &P) -> Result<Registry, UserFeatureError> {
    let mut registry = Registry::standard();
    let entries = load(provider)?;
    registry.restore_user_state(&entries);
    Ok(registry)
}

pub fn list<P: TreeProvider>(provider: &P) -> Result<Vec<Status>, UserFeatureError> {
    Ok(registry(provider)?.list(Scope::User))
}

pub fn status<P: TreeProvider>(provider: &P, key: &str) -> Result<Status, UserFeatureError> {
    Ok(registry(provider)?.status(key)?)
}

pub fn apply<P: TreeProvider>(
    provider: &P,
    key: &str,
    option: Option<String>,
    plan: crate::features::Plan,
) -> Result<Status, UserFeatureError> {
    let mut registry = registry(provider)?;
    let status = registry.apply(
        key,
        option,
        Caller {
            plan,
            is_admin: false,
        },
    )?;
    let snapshot = registry.user_state_snapshot();
    save(provider, &snapshot)?;
    Ok(status)
}

pub fn release<P: TreeProvider>(
    provider: &P,
    key: &str,
    plan: crate::features::Plan,
) -> Result<Status, UserFeatureError> {
    let mut registry = registry(provider)?;
    let status = registry.release(
        key,
        Caller {
            plan,
            is_admin: false,
        },
    )?;
    let snapshot = registry.user_state_snapshot();
    save(provider, &snapshot)?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;

    #[test]
    fn memory_provider_round_trip_is_noop() {
        let client = Client::new("alice").unwrap();
        let status = apply(
            &client.provider,
            "user.notification_content",
            Some("name_only".into()),
            crate::features::Plan::Free,
        )
        .unwrap();
        assert_eq!(status.state, State::Applied);
        assert_eq!(status.option.as_deref(), Some("name_only"));
    }

    #[test]
    fn encrypted_profile_persists_user_feature_state() {
        let dir = std::env::temp_dir().join(format!("tree-user-features-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alice.db");
        {
            let client = Client::create(&path, "feature-pass", "alice").unwrap();
            let status = apply(
                &client.provider,
                "user.notification_content",
                Some("name_only".into()),
                crate::features::Plan::Free,
            )
            .unwrap();
            assert_eq!(status.state, State::Applied);
            drop(client);
        }
        let client = Client::open(&path, "feature-pass").unwrap();
        let status = status(&client.provider, "user.notification_content").unwrap();
        assert_eq!(status.option.as_deref(), Some("name_only"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn permanent_security_locks_still_apply() {
        let client = Client::new("alice").unwrap();
        assert!(matches!(
            release(&client.provider, "chat.e2e", crate::features::Plan::Free),
            Err(UserFeatureError::Feature(FeatureError::LockedAlways(_)))
        ));
        assert!(matches!(
            apply(
                &client.provider,
                "points.send_to_user",
                None,
                crate::features::Plan::Free
            ),
            Err(UserFeatureError::Feature(FeatureError::ReleasedAlways(_)))
        ));
    }
}
