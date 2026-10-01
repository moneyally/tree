//! Tree's own per-group state, kept next to the OpenMLS group state and
//! saved in the same transaction.
//!
//! * the pending commit's sealed bytes and welcome (two-phase commit, F-003),
//!   so that exactly the same bytes can be resubmitted after a restart;
//! * envelope keys and member ids of the retained past epochs (F-002);
//! * hashes of this device's own confirmed commits (echo recognition, F-004).
//!
//! Encoding (version 1), integers big-endian, `bytes` = u32 length + data:
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

const VERSION: u8 = 1;

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

#[derive(Default)]
pub(crate) struct GroupState {
    pub pending: Option<Pending>,
    /// Set on join: the device should send one key refresh soon, so the key
    /// from its one-time key package (which sat on the server) is replaced.
    pub should_refresh: bool,
    /// Newest first, at most [`crate::Group::PAST_EPOCHS`] entries.
    pub past: Vec<PastEpoch>,
    /// SHA-256 of own confirmed commit envelopes with the epoch they were
    /// sealed in. Dropped together with that epoch.
    pub sent: Vec<(u64, [u8; 32])>,
}

impl GroupState {
    /// Forgets everything that belongs to epochs before `oldest`.
    pub fn prune(&mut self, oldest: u64) {
        self.past.retain(|p| p.epoch >= oldest);
        self.sent.retain(|(e, _)| *e >= oldest);
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
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        let mut r = Reader(bytes);
        if r.u8()? != VERSION {
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
        if !r.0.is_empty() {
            return Err(damaged());
        }
        Ok(Self { pending, should_refresh, past, sent })
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
        }
    }

    fn same(a: &GroupState, b: &GroupState) -> bool {
        a.pending == b.pending
            && a.should_refresh == b.should_refresh
            && a.sent == b.sent
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
        v[0] = 2;
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
    fn prune_drops_old_epochs() {
        let mut s = sample();
        s.prune(6);
        assert_eq!(s.past.len(), 1);
        assert_eq!(s.past[0].epoch, 6);
        assert_eq!(s.sent, vec![(6, [0xaa; 32])]);
    }
}
