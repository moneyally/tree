//! Safety numbers: what two people compare out of band (spoken, or by
//! scanning a QR code) to be sure no one is in the middle (PROTOCOL.md 5.4).
//!
//! A person is the set of their devices' member ids (each a hash of an MLS
//! signature key, `MemberId`). Each side's fingerprint is a hash of its sorted
//! member ids; the safety number shows both fingerprints as digits, in a fixed
//! order, so both people see the same 60 digits. A new or replaced device
//! changes the number.
//!
//! This is only an encoding of public keys for humans (SHA-256 and decimal
//! digits); it adds no cryptographic mechanism.

use sha2::{Digest, Sha256};

use crate::group::MemberId;

const LABEL: &[u8] = b"tree/safety-number/v1";
/// Digits per side: 6 groups of 5 (about 100 bits).
pub const DIGITS_PER_SIDE: usize = 30;

/// Fingerprint of one person's devices (order does not matter, duplicates
/// count once).
pub fn fingerprint(devices: &[MemberId]) -> [u8; 32] {
    let mut ids: Vec<&MemberId> = devices.iter().collect();
    ids.sort();
    ids.dedup();
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update((ids.len() as u32).to_be_bytes());
    for id in ids {
        h.update(id.as_bytes());
    }
    h.finalize().into()
}

/// 30 decimal digits of a fingerprint: 6 groups, each the big-endian value of
/// 5 bytes modulo 100000 (bias below 2^-20 per group).
pub fn digits(fp: &[u8; 32]) -> String {
    fp.chunks(5)
        .take(DIGITS_PER_SIDE / 5)
        .map(|c| {
            let v = c.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            format!("{:05}", v % 100_000)
        })
        .collect()
}

/// The 60-digit safety number of two people, the same on both sides,
/// written as 12 groups of 5 digits separated by spaces.
pub fn safety_number(mine: &[MemberId], theirs: &[MemberId]) -> String {
    let mut sides = [digits(&fingerprint(mine)), digits(&fingerprint(theirs))];
    sides.sort();
    let all = sides.concat();
    all.as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).expect("ASCII digits"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// QR payload: version byte and both fingerprints, the scanner's own first.
/// The scanner checks that the other half equals the fingerprint it holds
/// for the person shown.
pub fn qr_payload(mine: &[MemberId], theirs: &[MemberId]) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&fingerprint(mine));
    v.extend_from_slice(&fingerprint(theirs));
    v
}

/// Checks a scanned QR payload made by the other person's device: it must
/// list their fingerprint first and ours second.
pub fn qr_matches(scanned: &[u8], mine: &[MemberId], theirs: &[MemberId]) -> bool {
    use subtle::ConstantTimeEq;
    scanned.len() == 65 && bool::from(scanned.ct_eq(&qr_payload(theirs, mine)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> MemberId {
        MemberId([b; 32])
    }

    #[test]
    fn same_on_both_sides_and_order_free() {
        let a = [id(1), id(2)];
        let b = [id(3)];
        let n = safety_number(&a, &b);
        assert_eq!(n, safety_number(&b, &a));
        assert_eq!(n, safety_number(&[id(2), id(1), id(1)], &b));
        assert_eq!(n.len(), 60 + 11);
        assert!(n.split(' ').all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn any_device_change_changes_it() {
        let a = [id(1)];
        let b = [id(3)];
        let n = safety_number(&a, &b);
        assert_ne!(n, safety_number(&a, &[id(4)]), "replaced key");
        assert_ne!(n, safety_number(&a, &[id(3), id(4)]), "added device");
        assert_ne!(n, safety_number(&[id(1), id(9)], &b));
        assert_ne!(fingerprint(&[]), fingerprint(&[id(0)]));
    }

    #[test]
    fn digits_are_the_documented_encoding() {
        let mut fp = [0u8; 32];
        fp[..5].copy_from_slice(&[0, 0, 0, 0x01, 0x00]); // 256
        fp[5..10].copy_from_slice(&[0xff; 5]); // 2^40-1 = 1099511627775 -> 27775
        let d = digits(&fp);
        assert_eq!(d.len(), DIGITS_PER_SIDE);
        assert_eq!(&d[..10], "0025627775");
        assert_eq!(&d[10..], "00000000000000000000");
    }

    #[test]
    fn fingerprint_is_labelled_sha256() {
        let mut h = Sha256::new();
        h.update(b"tree/safety-number/v1");
        h.update(2u32.to_be_bytes());
        h.update([1u8; 32]);
        h.update([2u8; 32]);
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(fingerprint(&[id(2), id(1)]), want);
    }

    #[test]
    fn qr_round_trip() {
        let a = [id(1)];
        let b = [id(3)];
        let shown_by_b = qr_payload(&b, &a);
        assert!(qr_matches(&shown_by_b, &a, &b));
        assert!(!qr_matches(&shown_by_b, &a, &[id(4)]), "different key");
        assert!(!qr_matches(&qr_payload(&a, &b), &a, &b), "own code scanned");
        assert!(!qr_matches(&shown_by_b[..64], &a, &b));
        let mut bad = shown_by_b.clone();
        bad[0] = 2;
        assert!(!qr_matches(&bad, &a, &b));
    }
}
