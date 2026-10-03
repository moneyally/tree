//! Tree's own per-group state, kept next to the OpenMLS group state and
//! saved in the same transaction.
//!
//! * the pending commit's sealed bytes and welcome (two-phase commit, F-003),
//!   so that exactly the same bytes can be resubmitted after a restart;
//! * envelope keys and member ids of the retained past epochs (F-002);
//! * hashes of this device's own confirmed commits (echo recognition, F-004).
//!
//! Encoding (version 4; decoder accepts versions 1 through 3), integers big-endian, `bytes` = u32 length + data:
//!
//! ```text
//! 0x01
//! u8 has_pending; if 1: u64 epoch, bytes commit, u8 has_welcome, [bytes welcome]
//! u8 should_refresh
//! u8 n_past;  n_past x (u64 epoch, [32] envelope_key, u32 n, n x (u32 leaf, [32] member_id))
//! u16 n_sent; n_sent x (u64 epoch, [32] sha256)
//! ```

use zeroize::Zeroizing;

use crate::{error::TreeError, group::MemberId};

const VERSION: u8 = 4;

/// A commit this device created that the server has not accepted yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pending {
    /// Epoch the commit was created in (and sealed for).
    pub epoch: u64,
    /// Sealed commit envelope.
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

/// What Tree keeps of an epoch after leaving it.
pub(crate) struct PastEpoch {
    pub epoch: u64,
    pub envelope_key: Zeroizing<[u8; 32]>,
    /// Leaf index -> member id of that epoch (application messages of a past
    /// epoch name their sender by leaf; the leaf may hold someone else now).
    pub members: Vec<(u32, MemberId)>,
}

pub(crate) struct PendingEnvelope {
    pub epoch: u64,
    pub received_at: i64,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct GroupState {
    pub pending: Option<Pending>,
    /// Single deterministic administrator in v1. The value is a member id;
    /// if absent in a legacy state it is initialized by Group::new.
    pub admin: Option<MemberId>,
    /// Set on join: the device should send one key refresh soon, so the key
    /// from its one-time key package (which sat on the server) is replaced.
    pub should_refresh: bool,
    /// Newest first, at most [`crate::Group::PAST_EPOCHS`] entries.
    pub past: Vec<PastEpoch>,
    /// SHA-256 of own confirmed commit envelopes with the epoch they were
    /// sealed in. Dropped together with that epoch.
    pub sent: Vec<(u64, [u8; 32])>,
    /// SHA-256 of envelopes successfully processed, dropped with their epoch.
    pub processed: Vec<(u64, [u8; 32])>,
    /// Future-epoch envelopes held locally until the corresponding commit is merged.
    pub future: Vec<PendingEnvelope>,
    /// Server-independent group settings carried inside authenticated MLS
    /// application messages. Only the deterministic admin may change them.
    pub title: Option<String>,
    pub disappearing_seconds: u32,
    pub last_control_seq: u64,
}

impl GroupState {
    /// Forgets everything that belongs to epochs before `oldest`.
    pub fn prune(&mut self, oldest: u64) {
        self.past.retain(|p| p.epoch >= oldest);
        self.sent.retain(|(e, _)| *e >= oldest);
        self.processed.retain(|(e, _)| *e >= oldest);
    }

    pub fn prune_future(&mut self, now: i64) {
        const MAX_FUTURE: usize = 64;
        const MAX_AGE: i64 = 7 * 86_400;
        self.future.retain(|p| p.received_at + MAX_AGE >= now);
        if self.future.len() > MAX_FUTURE {
            self.future.sort_by_key(|p| p.received_at);
            let drop_n = self.future.len() - MAX_FUTURE;
            self.future.drain(0..drop_n);
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        match &self.pending {
            None => out.push(0),
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.epoch.to_be_bytes());
                put_bytes(&mut out, &p.commit);
                match &p.welcome {
                    None => out.push(0),
                    Some(w) => {
                        out.push(1);
                        put_bytes(&mut out, w);
                    }
                }
            }
        }
        out.push(self.should_refresh as u8);
        match self.admin {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
        }
        out.push(self.past.len() as u8);
        for p in &self.past {
            out.extend_from_slice(&p.epoch.to_be_bytes());
            out.extend_from_slice(&p.envelope_key[..]);
            out.extend_from_slice(&(p.members.len() as u32).to_be_bytes());
            for (leaf, id) in &p.members {
                out.extend_from_slice(&leaf.to_be_bytes());
                out.extend_from_slice(id.as_bytes());
            }
        }
        out.extend_from_slice(&(self.sent.len() as u16).to_be_bytes());
        for (e, h) in &self.sent {
            out.extend_from_slice(&e.to_be_bytes());
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&(self.processed.len() as u16).to_be_bytes());
        for (e, h) in &self.processed {
            out.extend_from_slice(&e.to_be_bytes());
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&(self.future.len() as u16).to_be_bytes());
        for p in &self.future {
            out.extend_from_slice(&p.epoch.to_be_bytes());
            out.extend_from_slice(&p.received_at.to_be_bytes());
            put_bytes(&mut out, &p.bytes);
        }
        if let Some(title) = &self.title {
            out.push(1);
            put_bytes(&mut out, title.as_bytes());
        } else {
            out.push(0);
        }
        out.extend_from_slice(&self.disappearing_seconds.to_be_bytes());
        out.extend_from_slice(&self.last_control_seq.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if !matches!(version, 1..=VERSION) {
            return Err(damaged());
        }
        let pending = match r.u8()? {
            0 => None,
            1 => {
                let epoch = r.u64()?;
                let commit = r.bytes()?;
                let welcome = match r.u8()? {
                    0 => None,
                    1 => Some(r.bytes()?),
                    _ => return Err(damaged()),
                };
                Some(Pending { epoch, commit, welcome })
            }
            _ => return Err(damaged()),
        };
        let should_refresh = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(damaged()),
        };
        let admin = if version >= 3 {
            match r.u8()? {
                0 => None,
                1 => Some(MemberId(r.array()?)),
                _ => return Err(damaged()),
            }
        } else {
            None
        };
        let mut past = Vec::new();
        for _ in 0..r.u8()? {
            let epoch = r.u64()?;
            let envelope_key = Zeroizing::new(r.array()?);
            let n = r.u32()?;
            let mut members = Vec::new();
            for _ in 0..n {
                members.push((r.u32()?, MemberId(r.array()?)));
            }
            past.push(PastEpoch { epoch, envelope_key, members });
        }
        let mut sent = Vec::new();
        for _ in 0..r.u16()? {
            sent.push((r.u64()?, r.array()?));
        }
        let mut processed = Vec::new();
        let mut future = Vec::new();
        if version >= 2 {
            for _ in 0..r.u16()? {
                processed.push((r.u64()?, r.array()?));
            }
            for _ in 0..r.u16()? {
                let epoch = r.u64()?;
                let received_at = i64::from_be_bytes(r.array()?);
                let bytes = r.bytes()?;
                future.push(PendingEnvelope { epoch, received_at, bytes });
            }
        }
        let (title, disappearing_seconds, last_control_seq) = if version >= 4 {
            let title = match r.u8()? {
                0 => None,
                1 => Some(String::from_utf8(r.bytes()?).map_err(|_| damaged())?),
                _ => return Err(damaged()),
            };
            let disappearing_seconds = r.u32()?;
            let last_control_seq = r.u64()?;
            (title, disappearing_seconds, last_control_seq)
        } else {
            (None, 0, 0)
        };
        if !r.0.is_empty() {
            return Err(damaged());
        }
        Ok(Self {
            pending,
            admin,
            should_refresh,
            past,
            sent,
            processed,
            future,
            title,
            disappearing_seconds,
            last_control_seq,
        })
    }
}

fn damaged() -> TreeError {
    TreeError::Storage("stored group state is damaged".into())
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], TreeError> {
        if self.0.len() < n {
            return Err(damaged());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], TreeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u8(&mut self) -> Result<u8, TreeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TreeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, TreeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, TreeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, TreeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GroupState {
        GroupState {
            pending: Some(Pending { epoch: 7, commit: vec![1, 2, 3], welcome: Some(vec![0, 9]) }),
            admin: Some(MemberId([3; 32])),
            should_refresh: true,
            past: vec![
                PastEpoch {
                    epoch: 6,
                    envelope_key: Zeroizing::new([6; 32]),
                    members: vec![(0, MemberId([1; 32])), (3, MemberId([2; 32]))],
                },
                PastEpoch { epoch: 5, envelope_key: Zeroizing::new([5; 32]), members: vec![] },
            ],
            sent: vec![(6, [0xaa; 32]), (5, [0xbb; 32])],
            processed: vec![(6, [0xcc; 32])],
            future: vec![PendingEnvelope { epoch: 8, received_at: 100, bytes: vec![9, 9] }],
            title: Some("Test Group".into()),
            disappearing_seconds: 86400,
            last_control_seq: 12,
        }
    }

    fn same(a: &GroupState, b: &GroupState) -> bool {
        a.pending == b.pending
            && a.admin == b.admin
            && a.should_refresh == b.should_refresh
            && a.sent == b.sent
            && a.processed == b.processed
            && a.future.iter().map(|p| (p.epoch, p.received_at, &p.bytes)).collect::<Vec<_>>()
                == b.future.iter().map(|p| (p.epoch, p.received_at, &p.bytes)).collect::<Vec<_>>()
            && a.title == b.title
            && a.disappearing_seconds == b.disappearing_seconds
            && a.last_control_seq == b.last_control_seq
            && a.past.len() == b.past.len()
            && a.past.iter().zip(&b.past).all(|(x, y)| {
                x.epoch == y.epoch && *x.envelope_key == *y.envelope_key && x.members == y.members
            })
    }

    #[test]
    fn round_trip() {
        for s in [GroupState::default(), sample()] {
            let enc = s.encode();
            assert!(same(&GroupState::decode(&enc).unwrap(), &s));
        }
        let mut s = sample();
        s.pending.as_mut().unwrap().welcome = None;
        assert!(same(&GroupState::decode(&s.encode()).unwrap(), &s));
    }

    #[test]
    fn damaged_input_refused() {
        let enc = sample().encode();
        for n in 0..enc.len() {
            assert!(GroupState::decode(&enc[..n]).is_err(), "truncated at {n}");
        }
        let mut long = enc.clone();
        long.push(0);
        assert!(GroupState::decode(&long).is_err(), "trailing byte");
        let mut v = enc.clone();
        v[0] = 4;
        assert!(GroupState::decode(&v).is_err(), "version");
        let mut p = enc.clone();
        p[1] = 2;
        assert!(GroupState::decode(&p).is_err(), "pending flag");
        let empty = GroupState::default().encode();
        let mut r = empty.clone();
        r[2] = 2;
        assert!(GroupState::decode(&r).is_err(), "refresh flag");
        // welcome flag sits after version, flag, epoch, length, 3 commit bytes
        let mut w = enc.clone();
        w[1 + 1 + 8 + 4 + 3] = 2;
        assert!(GroupState::decode(&w).is_err(), "welcome flag");
    }

    #[test]
    fn decodes_version_three_state_without_settings() {
        let v4 = GroupState::default().encode();
        let mut v3 = v4[..v4.len() - 13].to_vec();
        v3[0] = 3;
        let decoded = GroupState::decode(&v3).unwrap();
        assert!(decoded.admin.is_none());
        assert!(decoded.processed.is_empty());
        assert!(decoded.future.is_empty());
        assert!(decoded.title.is_none());
    }

    #[test]
    fn decodes_version_two_state_without_admin_or_settings() {
        let v4 = GroupState::default().encode();
        let mut v3 = v4[..v4.len() - 13].to_vec();
        v3[0] = 3;
        let mut v2 = v3;
        v2[0] = 2;
        v2.remove(1 + 1 + 1); // admin flag
        let decoded = GroupState::decode(&v2).unwrap();
        assert!(decoded.admin.is_none());
        assert!(decoded.processed.is_empty());
        assert!(decoded.future.is_empty());
        assert!(decoded.title.is_none());
        assert_eq!(decoded.disappearing_seconds, 0);
        assert_eq!(decoded.last_control_seq, 0);
    }

    #[test]
    fn decodes_legacy_version_one_state() {
        let v4 = GroupState::default().encode();
        let mut v3 = v4[..v4.len() - 13].to_vec();
        v3[0] = 3;
        let mut v2 = v3;
        v2[0] = 2;
        v2.remove(1 + 1 + 1); // admin flag
        let mut v1 = v2;
        v1[0] = 1;
        v1.truncate(v1.len() - 4); // processed/future counters
        let decoded = GroupState::decode(&v1).unwrap();
        assert!(decoded.admin.is_none());
        assert!(decoded.processed.is_empty());
        assert!(decoded.future.is_empty());
    }

    #[test]
    fn prune_future_is_bounded_and_expires() {
        let mut s = GroupState {
            future: (0..70)
                .map(|i| PendingEnvelope {
                    epoch: 8,
                    received_at: 100 + i,
                    bytes: vec![i as u8],
                })
                .collect(),
            ..GroupState::default()
        };
        s.prune_future(100);
        assert_eq!(s.future.len(), 64);
        s.prune_future(7 * 86_400 + 101);
        assert!(s.future.is_empty());
    }

    #[test]
    fn prune_drops_old_epochs() {
        let mut s = sample();
        s.prune(6);
        assert_eq!(s.past.len(), 1);
        assert_eq!(s.past[0].epoch, 6);
        assert_eq!(s.sent, vec![(6, [0xaa; 32])]);
        assert_eq!(s.processed.len(), 1);
    }
}
