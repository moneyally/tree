//! Device linking with a two-sided confirmation code (PROTOCOL.md 8.11).
//!
//! A new device joins an account only after the person compared the same
//! six-digit code on both devices. The code is a short authentication
//! string over the whole link transcript, with a hash commitment so that
//! nobody in the middle can search for a key that gives a matching code:
//!
//! 1. The new device makes its MLS key packages first (8 one-time, then 1
//!    last-resort), then shows an invitation (QR code or text link): a
//!    random link id, its request-signing key, an HPKE (X25519) public key,
//!    its MLS member id and `SHA-256(lp("tree/link/commit/v2", nonce,
//!    kp_digest))` for a secret 32-byte nonce and the digest of exactly
//!    those key packages.
//! 2. The existing device reads it and answers through the server with an
//!    offer: account id, its device id, its MLS member id, its
//!    request-signing key and a fresh HPKE (X25519) public key of its own.
//! 3. Only then does the new device reveal the nonce and the key packages.
//!    The existing device checks both against the commitment, and checks
//!    every key package (valid, naming the member id of the invitation,
//!    no duplicates, the last-resort one last).
//! 4. Both hash the transcript and show `code(transcript hash)`. Whoever
//!    swapped a value on the way had to fix it before it could know the
//!    nonce, and nothing revealed afterwards can be changed (it is all
//!    committed), so its codes match only by chance (one in a million,
//!    once: a link is used once).
//! 5. After the person confirmed on both devices, the new device signs the
//!    transcript hash, the existing device signs its authorisation, and the
//!    existing device sends the account data sealed with HPKE in Auth mode
//!    (RFC 9180, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305)
//!    from its offer key to the invitation key, with the transcript hash in
//!    the HPKE `info`.
//!
//! `lp(a, b, ...)` is the concatenation of each input preceded by its length
//! as a 4-byte big-endian number. Every hash and signature input starts with
//! its own label.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::rustcrypto::HpkeRustCrypto;
use hpke_rs::{Hpke, HpkeKeyPair, HpkePublicKey, Mode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::TreeError;

/// Text form of an invitation: this prefix, then base64url.
pub const LINK_PREFIX: &str = "tree://link/";
/// Version 2: the invitation carries the new device's member id and the
/// commitment covers the key packages (F-020). Version 1 links are refused
/// (a link lives 10 minutes, so none is left to keep working).
const VERSION: u8 = 2;
const LABEL_COMMIT: &[u8] = b"tree/link/commit/v2";
const LABEL_TRANSCRIPT: &[u8] = b"tree/link/transcript/v2";
const LABEL_KEY_PACKAGES: &[u8] = b"tree/link/key-packages/v1";
const LABEL_CODE: &[u8] = b"tree/link/code/v1";
const LABEL_SEAL: &[u8] = b"tree/link/seal/v1";
/// The new device's confirmation (signed with its request key).
pub const CONFIRM_CONTEXT: &[u8] = b"tree/link/confirm/v1";
/// The existing device's authorisation (signed with its request key).
pub const AUTHORISE_CONTEXT: &[u8] = b"tree/link/authorise/v1";
/// Key packages a new device offers, exactly: 8 one-time ones, then its
/// last-resort one.
pub const MAX_KEY_PACKAGES: usize = 9;

fn err(why: &str) -> TreeError {
    TreeError::Malformed(format!("device link: {why}"))
}

/// Length-prefixed concatenation: each part preceded by its length as a
/// 4-byte big-endian number.
pub fn lp(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 4).sum());
    for p in parts {
        out.extend_from_slice(&u32::try_from(p.len()).expect("part under 4 GiB").to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("operating system random number generator failed");
    b
}

fn hpke() -> Hpke<HpkeRustCrypto> {
    Hpke::new(Mode::Auth, KemAlgorithm::DhKem25519, KdfAlgorithm::HkdfSha256, AeadAlgorithm::ChaCha20Poly1305)
}

/// An X25519 key pair for HPKE, kept as its 32-byte seed (RFC 9180 DeriveKeyPair).
pub struct HpkeKey {
    seed: Zeroizing<[u8; 32]>,
}

impl HpkeKey {
    pub fn generate() -> Self {
        Self { seed: Zeroizing::new(random()) }
    }

    fn pair(&self) -> HpkeKeyPair {
        hpke().derive_key_pair(&self.seed[..]).expect("X25519 key derivation does not fail")
    }

    pub fn public(&self) -> [u8; 32] {
        self.pair().public_key().as_slice().try_into().expect("X25519 public keys are 32 bytes")
    }
}

/// `SHA-256(lp("tree/link/key-packages/v1", kp_1, ..., kp_n))`, in the order sent.
pub fn key_package_digest(key_packages: &[Vec<u8>]) -> [u8; 32] {
    let refs: Vec<&[u8]> = std::iter::once(LABEL_KEY_PACKAGES).chain(key_packages.iter().map(Vec::as_slice)).collect();
    sha256(&lp(&refs))
}

/// Commitment to everything the new device reveals later: its nonce and
/// (through their digest) its key packages, in order.
pub fn commitment(nonce: &[u8; 32], kp_digest: &[u8; 32]) -> [u8; 32] {
    sha256(&lp(&[LABEL_COMMIT, nonce, kp_digest]))
}

/// Checks the key packages of a reveal that already matched the
/// commitment: exactly [`MAX_KEY_PACKAGES`], no two equal, each valid
/// (`inspect` checks the signature and returns the member id it names and
/// whether it is marked last-resort; [`crate::Client::check_key_package`]),
/// all naming the member id from the invitation, and only the last one
/// marked last-resort.
pub fn check_key_packages(
    inv: &Invitation,
    key_packages: &[Vec<u8>],
    inspect: impl Fn(&[u8]) -> Result<([u8; 32], bool), TreeError>,
) -> Result<(), TreeError> {
    let refuse = |why: &str| TreeError::Rejected(format!("device link: {why}"));
    if key_packages.len() != MAX_KEY_PACKAGES {
        return Err(refuse("wrong number of key packages"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, kp) in key_packages.iter().enumerate() {
        if !seen.insert(kp.as_slice()) {
            return Err(refuse("a key package is repeated"));
        }
        let (member, last_resort) = inspect(kp).map_err(|_| refuse("an invalid key package"))?;
        if member != inv.member_id {
            return Err(refuse("a key package of another device"));
        }
        if last_resort != (i == MAX_KEY_PACKAGES - 1) {
            return Err(refuse("the last-resort key package must come last, and only once"));
        }
    }
    Ok(())
}

/// What the new device shows (QR code or text link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub link_id: [u8; 16],
    /// The new device's request-signing key (Ed25519).
    pub auth_pub: [u8; 32],
    /// The new device's HPKE key (X25519).
    pub hpke_pub: [u8; 32],
    /// The new device's MLS member id (SHA-256 of its MLS signature key,
    /// PROTOCOL.md 5.2): every key package it reveals must name it.
    pub member_id: [u8; 32],
    /// [`commitment`] of the nonce and key packages revealed later.
    pub commitment: [u8; 32],
}

impl Invitation {
    pub fn encode(&self) -> String {
        let mut b = vec![VERSION];
        b.extend_from_slice(&self.link_id);
        b.extend_from_slice(&self.auth_pub);
        b.extend_from_slice(&self.hpke_pub);
        b.extend_from_slice(&self.member_id);
        b.extend_from_slice(&self.commitment);
        format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(b))
    }

    pub fn parse(text: &str) -> Result<Self, TreeError> {
        let t = text.trim().strip_prefix(LINK_PREFIX).ok_or_else(|| err("not a device link"))?;
        let b = URL_SAFE_NO_PAD.decode(t).map_err(|_| err("damaged device link"))?;
        if b.len() != 1 + 16 + 32 * 4 || b[0] != VERSION {
            return Err(err("unknown device link version"));
        }
        let take = |i: usize| -> [u8; 32] { b[i..i + 32].try_into().expect("length checked") };
        Ok(Self {
            link_id: b[1..17].try_into().expect("length checked"),
            auth_pub: take(17),
            hpke_pub: take(49),
            member_id: take(81),
            commitment: take(113),
        })
    }

    /// The link id as the server knows it (base64url, 22 characters).
    pub fn link_id_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.link_id)
    }
}

/// The existing device's answer, relayed by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub account_id: String,
    pub device_id: String,
    /// Its MLS member id (hex): the new device trusts group additions by
    /// this member as coming from its own account.
    pub member_id: String,
    /// Its request-signing key (Ed25519), base64url.
    pub auth_pub: String,
    /// Its fresh HPKE key (X25519), base64url.
    pub hpke_pub: String,
}

impl Offer {
    pub fn auth_pub(&self) -> Result<[u8; 32], TreeError> {
        key32(&self.auth_pub)
    }
    pub fn hpke_pub(&self) -> Result<[u8; 32], TreeError> {
        key32(&self.hpke_pub)
    }
}

/// The new device's reveal, relayed by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reveal {
    /// base64url
    pub nonce: String,
    /// MLS key packages (base64url): one-time ones, the last-resort one last.
    pub key_packages: Vec<String>,
}

impl Reveal {
    pub fn nonce(&self) -> Result<[u8; 32], TreeError> {
        key32(&self.nonce)
    }
    pub fn key_packages(&self) -> Result<Vec<Vec<u8>>, TreeError> {
        if self.key_packages.len() != MAX_KEY_PACKAGES {
            return Err(err("wrong number of key packages"));
        }
        self.key_packages.iter().map(|k| URL_SAFE_NO_PAD.decode(k).map_err(|_| err("damaged key package"))).collect()
    }
}

pub fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn key32(s: &str) -> Result<[u8; 32], TreeError> {
    URL_SAFE_NO_PAD.decode(s).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| err("a key must be 32 bytes"))
}

/// SHA-256 over the whole transcript. Fails if the nonce and key packages
/// (in this order) do not match the invitation's commitment.
pub fn transcript_hash(inv: &Invitation, offer: &Offer, reveal: &Reveal) -> Result<[u8; 32], TreeError> {
    let nonce = reveal.nonce()?;
    let kps = reveal.key_packages()?;
    let kp_digest = key_package_digest(&kps);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&commitment(&nonce, &kp_digest)[..], &inv.commitment[..])) {
        return Err(TreeError::Rejected("device link: the reveal does not match the invitation".into()));
    }
    Ok(sha256(&lp(&[
        LABEL_TRANSCRIPT,
        &inv.link_id,
        &inv.auth_pub,
        &inv.hpke_pub,
        &inv.member_id,
        &inv.commitment,
        offer.account_id.as_bytes(),
        offer.device_id.as_bytes(),
        offer.member_id.as_bytes(),
        &offer.auth_pub()?,
        &offer.hpke_pub()?,
        &nonce,
        &kp_digest,
    ])))
}

/// The six digits both devices show, as "123 456".
pub fn code(transcript_hash: &[u8; 32]) -> String {
    let d = sha256(&lp(&[LABEL_CODE, transcript_hash]));
    let n = u64::from_be_bytes(d[..8].try_into().expect("8 bytes")) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// What the new device signs once its person confirmed the code.
pub fn confirm_message(link_id: &[u8; 16], transcript_hash: &[u8; 32]) -> Vec<u8> {
    lp(&[CONFIRM_CONTEXT, link_id, transcript_hash])
}

/// What the existing device signs to add the new device to its account.
pub fn authorise_message(link_id: &[u8; 16], account_id: &str, new_auth_pub: &[u8; 32], transcript_hash: &[u8; 32]) -> Vec<u8> {
    lp(&[AUTHORISE_CONTEXT, link_id, account_id.as_bytes(), new_auth_pub, transcript_hash])
}

/// Seals `plaintext` from the existing device (`sender`, its offer key) to
/// the new device (`recipient_pub`, the invitation key). Output: `enc || ct`.
pub fn seal(sender: &HpkeKey, recipient_pub: &[u8; 32], transcript_hash: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, TreeError> {
    let info = lp(&[LABEL_SEAL, transcript_hash]);
    let s = sender.pair();
    let (enc, ct) = hpke()
        .seal(&HpkePublicKey::new(recipient_pub.to_vec()), &info, &[], plaintext, None, None, Some(s.private_key()))
        .map_err(|e| TreeError::Group(format!("device link seal: {e:?}")))?;
    let mut out = enc;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens what [`seal`] made; fails unless sender key, recipient key and
/// transcript hash are all the same on both sides.
pub fn open(recipient: &HpkeKey, sender_pub: &[u8; 32], transcript_hash: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, TreeError> {
    if sealed.len() < 32 {
        return Err(err("sealed data too short"));
    }
    let info = lp(&[LABEL_SEAL, transcript_hash]);
    let r = recipient.pair();
    hpke()
        .open(&sealed[..32], r.private_key(), &info, &[], &sealed[32..], None, None, Some(&HpkePublicKey::new(sender_pub.to_vec())))
        .map_err(|_| TreeError::Rejected("device link: the sealed account data does not open".into()))
}

/// The new device's secrets while a link is open.
pub struct NewDeviceLink {
    pub invitation: Invitation,
    pub hpke: HpkeKey,
    nonce: Zeroizing<[u8; 32]>,
    key_packages: Vec<Vec<u8>>,
}

impl NewDeviceLink {
    /// A fresh link for a device whose request-signing key is `auth_pub`
    /// and whose MLS member id is `member_id`, committing to exactly these
    /// key packages ([`MAX_KEY_PACKAGES`]: the one-time ones, the
    /// last-resort one last), chosen before the invitation is shown.
    pub fn new(auth_pub: [u8; 32], member_id: [u8; 32], key_packages: Vec<Vec<u8>>) -> Result<Self, TreeError> {
        if key_packages.len() != MAX_KEY_PACKAGES {
            return Err(err("wrong number of key packages"));
        }
        let nonce = Zeroizing::new(random::<32>());
        let hpke = HpkeKey::generate();
        let commitment = commitment(&nonce, &key_package_digest(&key_packages));
        let invitation = Invitation { link_id: random(), auth_pub, hpke_pub: hpke.public(), member_id, commitment };
        Ok(Self { invitation, hpke, nonce, key_packages })
    }

    /// The reveal, sent only after the offer arrived: the nonce and the
    /// committed key packages.
    pub fn reveal(&self) -> Reveal {
        Reveal { nonce: b64url(&self.nonce[..]), key_packages: self.key_packages.iter().map(|k| b64url(k)).collect() }
    }

    /// The committed key packages (the last one is the last-resort one).
    pub fn key_packages(&self) -> &[Vec<u8>] {
        &self.key_packages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kps(tag: u8) -> Vec<Vec<u8>> {
        (0..MAX_KEY_PACKAGES as u8).map(|i| vec![tag, i, 0xAA]).collect()
    }

    fn fixture() -> (NewDeviceLink, HpkeKey, Offer, Reveal) {
        let n = NewDeviceLink::new([7; 32], [3; 32], kps(1)).unwrap();
        let e = HpkeKey::generate();
        let offer = Offer { account_id: "acc".into(), device_id: "dev".into(), member_id: "ab".into(), auth_pub: b64url(&[9; 32]), hpke_pub: b64url(&e.public()) };
        let reveal = n.reveal();
        (n, e, offer, reveal)
    }

    #[test]
    fn lp_is_unambiguous() {
        assert_ne!(lp(&[b"ab", b"c"]), lp(&[b"a", b"bc"]));
        assert_eq!(lp(&[b"x"]), vec![0, 0, 0, 1, b'x']);
    }

    #[test]
    fn invitation_round_trip() {
        let (n, ..) = fixture();
        let text = n.invitation.encode();
        assert!(text.starts_with(LINK_PREFIX));
        assert_eq!(Invitation::parse(&format!(" {text}\n")).unwrap(), n.invitation);
        assert!(Invitation::parse(&text[..text.len() - 2]).is_err());
        assert!(Invitation::parse("tree://join/abc").is_err());
        assert_eq!(n.invitation.link_id_text().len(), 22);
        // A version 1 invitation (no member id, commitment over the nonce only) is refused.
        let mut v1 = vec![1u8];
        v1.extend_from_slice(&[0; 16 + 32 * 3]);
        assert!(Invitation::parse(&format!("{LINK_PREFIX}{}", b64url(&v1))).is_err());
        // The key packages are fixed before the invitation exists.
        assert!(NewDeviceLink::new([7; 32], [3; 32], kps(1)[..8].to_vec()).is_err());
    }

    /// Both sides compute the same code from the same transcript, and any
    /// change to any input changes it.
    #[test]
    fn code_is_a_function_of_the_whole_transcript() {
        let (n, _, offer, reveal) = fixture();
        let inv = n.invitation.clone();
        let h = transcript_hash(&inv, &offer, &reveal).unwrap();
        assert_eq!(h, transcript_hash(&Invitation::parse(&inv.encode()).unwrap(), &offer.clone(), &reveal.clone()).unwrap());
        let c = code(&h);
        assert_eq!(c.len(), 7);
        assert!(c.chars().enumerate().all(|(i, ch)| if i == 3 { ch == ' ' } else { ch.is_ascii_digit() }));

        let mut changed: Vec<[u8; 32]> = Vec::new();
        let mut i2 = inv.clone();
        i2.link_id[0] ^= 1;
        changed.push(transcript_hash(&i2, &offer, &reveal).unwrap());
        let mut i2 = inv.clone();
        i2.auth_pub[0] ^= 1;
        changed.push(transcript_hash(&i2, &offer, &reveal).unwrap());
        let mut i2 = inv.clone();
        i2.hpke_pub[0] ^= 1;
        changed.push(transcript_hash(&i2, &offer, &reveal).unwrap());
        let mut i2 = inv.clone();
        i2.member_id[0] ^= 1;
        changed.push(transcript_hash(&i2, &offer, &reveal).unwrap());
        let o = |f: &dyn Fn(&mut Offer)| {
            let mut o = offer.clone();
            f(&mut o);
            transcript_hash(&inv, &o, &reveal).unwrap()
        };
        changed.push(o(&|o| o.account_id.push('x')));
        changed.push(o(&|o| o.device_id.push('x')));
        changed.push(o(&|o| o.member_id.push('x')));
        changed.push(o(&|o| o.auth_pub = b64url(&[8; 32])));
        changed.push(o(&|o| o.hpke_pub = b64url(&HpkeKey::generate().public())));
        for x in &changed {
            assert_ne!(*x, h);
        }
        // A different nonce or key package breaks the commitment instead.
        let mut r = reveal.clone();
        r.nonce = b64url(&[0; 32]);
        assert!(transcript_hash(&inv, &offer, &r).is_err());
        let mut r = reveal.clone();
        r.key_packages[1] = b64url(&[5]);
        assert!(transcript_hash(&inv, &offer, &r).is_err());
        let mut i2 = inv.clone();
        i2.commitment[0] ^= 1;
        assert!(transcript_hash(&i2, &offer, &reveal).is_err());
        // The code follows the hash (6 digits: rarely equal by chance).
        assert_ne!(code(&h), code(&changed[0]));
    }

    /// Heap's algorithm: the first `limit` orderings of `items`, in a fixed order.
    fn orderings(items: &[Vec<u8>], limit: usize) -> Vec<Vec<Vec<u8>>> {
        let mut a = items.to_vec();
        let mut c = vec![0usize; a.len()];
        let mut out = vec![a.clone()];
        let mut i = 1;
        while i < a.len() && out.len() < limit {
            if c[i] < i {
                a.swap(if i % 2 == 0 { 0 } else { c[i] }, i);
                out.push(a.clone());
                c[i] += 1;
                i = 1;
            } else {
                c[i] = 0;
                i += 1;
            }
        }
        out
    }

    /// F-020. The relay saw the reveal (nonce and key packages) and gave the
    /// new device an offer of its own; it now searches for a reveal toward
    /// the existing device whose code equals the new device's. Every
    /// reordering, repetition, substitution, removal or addition of key
    /// packages is refused by the commitment before any code is computed,
    /// so the only reveal the existing device accepts is the genuine one,
    /// whose transcript has the genuine offer in it.
    #[test]
    fn a_relay_cannot_grind_the_reveal_after_seeing_it() {
        let (n, _, offer, reveal) = fixture();
        let inv = n.invitation.clone();
        let mut relay_offer = offer.clone();
        relay_offer.account_id = "mallory".into();
        relay_offer.hpke_pub = b64url(&HpkeKey::generate().public());
        let new_side = transcript_hash(&inv, &relay_offer, &reveal).unwrap();
        let genuine = n.key_packages().to_vec();
        let foreign = kps(2);

        let mut variants: Vec<Vec<Vec<u8>>> = orderings(&genuine, 20_000);
        assert_eq!(variants.len(), 20_000);
        for i in 0..genuine.len() {
            for j in 0..genuine.len() {
                let mut v = genuine.clone();
                v[i] = genuine[j].clone(); // repeat j over i (j == i: unchanged)
                variants.push(v);
                let mut v = genuine.clone();
                v[i] = foreign[j].clone(); // substitute
                variants.push(v);
            }
            let mut v = genuine.clone();
            v.remove(i);
            variants.push(v.clone());
            v.push(foreign[i].clone());
            variants.push(v);
            let mut v = genuine.clone();
            v.rotate_left(i);
            variants.push(v);
        }
        let mut accepted = 0;
        for v in &variants {
            let r = Reveal { nonce: reveal.nonce.clone(), key_packages: v.iter().map(|k| b64url(k)).collect() };
            match transcript_hash(&inv, &offer, &r) {
                Ok(h) => {
                    assert_eq!(v, &genuine, "only the committed list passes");
                    assert_ne!(h, new_side, "and it gives the existing device its own transcript");
                    accepted += 1;
                }
                Err(e) => assert!(matches!(e, TreeError::Rejected(_) | TreeError::Malformed(_)), "{e:?}"),
            }
        }
        assert!(accepted >= 1);
        assert!(variants.iter().filter(|v| **v != genuine).count() > 20_000);
    }

    #[test]
    fn key_packages_are_checked_one_by_one() {
        let dev = crate::Client::new("new").unwrap();
        let other = crate::Client::new("other").unwrap();
        let mut good: Vec<Vec<u8>> = (0..MAX_KEY_PACKAGES - 1).map(|_| dev.key_package().unwrap()).collect();
        good.push(dev.last_resort_key_package().unwrap());
        let n = NewDeviceLink::new([7; 32], *dev.member_id().as_bytes(), good.clone()).unwrap();
        let inspect = |k: &[u8]| other.check_key_package(k).map(|(m, lr)| (*m.as_bytes(), lr));
        check_key_packages(&n.invitation, &good, inspect).unwrap();

        let refused = |kps: Vec<Vec<u8>>| check_key_packages(&n.invitation, &kps, inspect).is_err();
        assert!(refused(good[..8].to_vec()), "one too few");
        let mut v = good.clone();
        v.push(dev.key_package().unwrap());
        assert!(refused(v), "one too many");
        let mut v = good.clone();
        v[1] = v[0].clone();
        assert!(refused(v), "a repeat");
        let mut v = good.clone();
        v[2] = other.key_package().unwrap();
        assert!(refused(v), "another device's key package");
        let mut v = good.clone();
        v.swap(0, 8);
        assert!(refused(v), "last-resort not last");
        let mut v = good.clone();
        v[8] = dev.key_package().unwrap();
        assert!(refused(v), "no last-resort one");
        let mut v = good.clone();
        v[3] = dev.last_resort_key_package().unwrap();
        assert!(refused(v), "a second last-resort one");
        let mut v = good.clone();
        let last = v[4].len() - 1;
        v[4][last] ^= 1;
        assert!(refused(v), "a bad signature");
        let mut v = good.clone();
        v[5] = vec![1, 2, 3];
        assert!(refused(v), "not a key package");
        let mut inv = n.invitation.clone();
        inv.member_id[0] ^= 1;
        assert!(check_key_packages(&inv, &good, inspect).is_err(), "the invitation names another member");
    }

    #[test]
    fn known_answer() {
        // Fixed vector so both ends of the documented format stay in step.
        assert_eq!(code(&[0u8; 32]), {
            let d = sha256(&lp(&[b"tree/link/code/v1", &[0u8; 32]]));
            let n = u64::from_be_bytes(d[..8].try_into().unwrap()) % 1_000_000;
            format!("{:03} {:03}", n / 1000, n % 1000)
        });
        assert_eq!(
            commitment(&[1; 32], &[2; 32]),
            sha256(&[&[0, 0, 0, 19][..], b"tree/link/commit/v2", &[0, 0, 0, 32], &[1; 32], &[0, 0, 0, 32], &[2; 32]].concat())
        );
        assert_eq!(key_package_digest(&[vec![9]]), sha256(&[&[0, 0, 0, 25][..], b"tree/link/key-packages/v1", &[0, 0, 0, 1], &[9]].concat()));
    }

    #[test]
    fn sealed_data_is_bound_to_keys_and_transcript() {
        let (n, e, offer, reveal) = fixture();
        let h = transcript_hash(&n.invitation, &offer, &reveal).unwrap();
        let sealed = seal(&e, &n.invitation.hpke_pub, &h, b"account data").unwrap();
        assert_eq!(open(&n.hpke, &e.public(), &h, &sealed).unwrap(), b"account data");
        let mut h2 = h;
        h2[0] ^= 1;
        assert!(open(&n.hpke, &e.public(), &h2, &sealed).is_err(), "other transcript");
        let mallory = HpkeKey::generate();
        assert!(open(&n.hpke, &mallory.public(), &h, &sealed).is_err(), "other sender");
        let forged = seal(&mallory, &n.invitation.hpke_pub, &h, b"evil").unwrap();
        assert!(open(&n.hpke, &e.public(), &h, &forged).is_err(), "a relay cannot forge the sender");
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&n.hpke, &e.public(), &h, &bad).is_err());
    }
}
