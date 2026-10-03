//! What the Tree core needs from a provider beyond OpenMLS itself.

use openmls_traits::OpenMlsProvider;

use crate::{error::TreeError, DefaultProvider, LibcruxProvider};

/// An OpenMLS provider the Tree core can run on.
///
/// In-memory providers use the defaults (nothing to persist). The encrypted
/// [`crate::storage::StoredProvider`] overrides both methods.
pub trait TreeProvider: OpenMlsProvider {
    /// Runs one complete operation (send, receive, add, ...) transactionally.
    /// A successful operation is committed; an error is rolled back.
    fn atomically<T>(&self, op: impl FnOnce() -> Result<T, TreeError>) -> Result<T, TreeError> {
        op()
    }

    /// Records a group this device belongs to, so it can be listed and loaded
    /// after a restart.
    fn remember_group(&self, _group_id: &[u8]) -> Result<(), TreeError> {
        Ok(())
    }

    /// Saves Tree's own state of a group (pending commit, past envelope
    /// keys, ...), inside the running [`TreeProvider::atomically`] operation.
    /// In-memory providers keep it only in the [`crate::Group`].
    fn save_group_state(&self, _group_id: &[u8], _state: &[u8]) -> Result<(), TreeError> {
        Ok(())
    }

    /// Stores small device-local metadata. StoredProvider encrypts it with
    /// SQLCipher; in-memory providers intentionally discard it.
    fn put_meta(&self, _key: &str, _value: &[u8]) -> Result<(), TreeError> {
        Ok(())
    }

    fn meta_optional(&self, _key: &str) -> Result<Option<Vec<u8>>, TreeError> {
        Ok(None)
    }

    fn delete_meta(&self, _key: &str) -> Result<(), TreeError> {
        Ok(())
    }
}

impl TreeProvider for DefaultProvider {}
impl TreeProvider for LibcruxProvider {}
