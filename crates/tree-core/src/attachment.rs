//! Attachments, format v2 (PROTOCOL.md 6.12): each file is encrypted with
//! its own random secret, padded to a size bucket and uploaded in parts as
//! one opaque blob; the secret travels only inside the end-to-end encrypted
//! message that refers to the file.
//!
//! Nothing here is new cryptography. Every piece is a published
//! construction used as published, from audited library code:
//!
//! * **Keys.** A fresh 32-byte file secret `s` per file. HKDF-SHA256
//!   (RFC 5869) with salt `tree/attachment/v2` derives three independent
//!   values, each under its own label: the AES-256-GCM key
//!   (`tree/attachment/v2/aead-key`), the 7-byte STREAM nonce prefix
//!   (`tree/attachment/v2/nonce-prefix`) and the commitment key
//!   (`tree/attachment/v2/commit-key`). No key is used for two purposes and
//!   `s` itself is never used as a key.
//! * **Cipher.** AES-256-GCM in the STREAM construction (Hoang,
//!   Reyhanitabar, Rogaway, Vizár, CRYPTO 2015) as implemented by RustCrypto
//!   `aead::stream::StreamBE32`: 1 MiB plaintext chunks, nonce = prefix ‖
//!   32-bit big-endian chunk index ‖ last-chunk flag. Every (key, nonce)
//!   pair is used once: the key is unique to the file and the index grows.
//!   Reordered, dropped, repeated or truncated chunks fail to decrypt; the
//!   flag makes a cut on a chunk boundary fail too.
//! * **Key commitment.** AES-GCM alone is not key-committing (one
//!   ciphertext can be built to open under two keys). The blob starts with
//!   `HMAC-SHA256(commit-key, "tree/attachment/v2/key-commitment")`; the
//!   receiver recomputes it from the secret in the message and compares in
//!   constant time before decrypting. Two different secrets give the same
//!   value only through an HMAC/HKDF collision. The message also carries
//!   SHA-256 of the plaintext, checked after decryption.
//! * **Padding.** The plaintext is padded with zero bytes to
//!   [`padded_len`] before encryption (the padding is encrypted and
//!   authenticated, and must be zero when opened): at least 1 KiB, the next
//!   power of two up to 1 MiB, above that Padmé (Nikitin et al., PETS 2019;
//!   at most about 3 % overhead from 1 MiB up, sizes leak O(log log n)
//!   bits). The server sees only `ciphertext_len(size)`, a function of the
//!   bucket.
//!
//! Blob layout: `commitment (32) ‖ chunk_0 ‖ ... ‖ chunk_{n-1}`, each chunk
//! `CHUNK` plaintext bytes + 16-byte tag, the last one shorter or equal.

use std::io::{Read, Write};

use aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::TreeError;

/// Format version carried in the message.
pub const VERSION: u32 = 2;
/// Plaintext bytes per AEAD chunk.
pub const CHUNK: usize = 1 << 20;
/// AES-GCM tag per chunk.
pub const TAG: usize = 16;
/// Key commitment at the start of the blob.
pub const HEADER: usize = 32;
/// Smallest padded size.
pub const MIN_PADDED: u64 = 1024;
/// Up to this size the padded size is the next power of two; Padmé above.
pub const POW2_LIMIT: u64 = 1 << 20;
/// Largest plaintext a file may have (2 GiB, design: free limit).
pub const MAX_FILE: u64 = 2 << 30;

const PREFIX: usize = 7;
const SALT: &[u8] = b"tree/attachment/v2";
const L_AEAD: &[u8] = b"tree/attachment/v2/aead-key";
const L_NONCE: &[u8] = b"tree/attachment/v2/nonce-prefix";
const L_COMMIT: &[u8] = b"tree/attachment/v2/commit-key";
const COMMIT_MSG: &[u8] = b"tree/attachment/v2/key-commitment";

/// Everything a recipient needs to open a file, except where it is stored.
/// Sent only inside end-to-end encrypted messages.
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey {
    /// The file secret (input to HKDF, never a key itself).
    pub secret: Zeroizing<[u8; 32]>,
    /// Plaintext length in bytes (without padding).
    pub size: u64,
    pub plaintext_sha256: [u8; 32],
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey").field("size", &self.size).finish_non_exhaustive()
    }
}

/// Padded plaintext length for a file of `size` bytes (see the module docs).
pub fn padded_len(size: u64) -> u64 {
    if size <= MIN_PADDED {
        MIN_PADDED
    } else if size <= POW2_LIMIT {
        size.next_power_of_two()
    } else {
        padme(size)
    }
}

/// Padmé: keep the top `S = floor(log2 E) + 1` bits below the leading one of
/// `E = floor(log2 L)`, round the rest up.
fn padme(l: u64) -> u64 {
    let e = 63 - u64::from(l.leading_zeros());
    let s = 64 - u64::from(e.leading_zeros());
    let mask = (1u64 << (e - s)) - 1;
    l.checked_add(mask).map(|v| v & !mask).unwrap_or(u64::MAX)
}

/// Number of AEAD chunks of a file of `size` bytes (at least one).
pub fn chunk_count(size: u64) -> u64 {
    padded_len(size).div_ceil(CHUNK as u64).max(1)
}

/// Length of the blob (what the server stores) for `size` plaintext bytes.
pub fn ciphertext_len(size: u64) -> u64 {
    HEADER as u64 + padded_len(size) + chunk_count(size) * TAG as u64
}

struct Derived {
    cipher: Aes256Gcm,
    prefix: [u8; PREFIX],
    commitment: [u8; 32],
}

fn derive(secret: &[u8; 32]) -> Derived {
    let hk = Hkdf::<Sha256>::new(Some(SALT), secret);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut prefix = [0u8; PREFIX];
    let mut ck = Zeroizing::new([0u8; 32]);
    // Lengths are far below HKDF's 255 * 32 byte limit.
    hk.expand(L_AEAD, &mut key[..]).expect("HKDF length");
    hk.expand(L_NONCE, &mut prefix).expect("HKDF length");
    hk.expand(L_COMMIT, &mut ck[..]).expect("HKDF length");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&ck[..]).expect("HMAC takes any key length");
    mac.update(COMMIT_MSG);
    Derived {
        cipher: Aes256Gcm::new_from_slice(&key[..]).expect("32-byte key"),
        prefix,
        commitment: mac.finalize().into_bytes().into(),
    }
}

fn random<const N: usize>() -> Result<[u8; N], TreeError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| TreeError::Identity(format!("random: {e}")))?;
    Ok(b)
}

fn io(e: std::io::Error) -> TreeError {
    TreeError::Storage(format!("attachment i/o: {e}"))
}

fn bad(why: &str) -> TreeError {
    TreeError::Rejected(format!("attachment: {why}"))
}

/// Reads up to `buf.len()` bytes (fewer only at the end of the input).
fn fill(r: &mut impl Read, buf: &mut [u8]) -> Result<usize, TreeError> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e)),
        }
    }
    Ok(n)
}

/// Encrypts exactly `size` bytes from `input` with a fresh secret, writing
/// the blob (`ciphertext_len(size)` bytes) to `out`. Fails if the input is
/// shorter or longer than `size`, or larger than [`MAX_FILE`].
pub fn encrypt_stream(mut input: impl Read, size: u64, mut out: impl Write) -> Result<FileKey, TreeError> {
    if size > MAX_FILE {
        return Err(TreeError::Malformed("file larger than 2 GiB".into()));
    }
    let secret = Zeroizing::new(random::<32>()?);
    let d = derive(&secret);
    out.write_all(&d.commitment).map_err(io)?;
    let mut enc = Some(EncryptorBE32::from_aead(d.cipher, (&d.prefix).into()));
    let (padded, chunks) = (padded_len(size), chunk_count(size));
    let mut hash = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut read_total = 0u64;
    let failed = |_| TreeError::Malformed("encrypt".into());
    for i in 0..chunks {
        let len = (padded - i * CHUNK as u64).min(CHUNK as u64) as usize;
        let want = size.saturating_sub(read_total).min(len as u64) as usize;
        let got = fill(&mut input, &mut buf[..want])?;
        if got != want {
            return Err(TreeError::Malformed("file shorter than its size".into()));
        }
        hash.update(&buf[..got]);
        read_total += got as u64;
        buf[got..len].fill(0);
        let sealed = match enc.take() {
            Some(e) if i + 1 == chunks => e.encrypt_last(&buf[..len]),
            Some(mut e) => {
                let r = e.encrypt_next(&buf[..len]);
                enc = Some(e);
                r
            }
            None => unreachable!("the last chunk ends the loop"),
        }
        .map_err(failed)?;
        out.write_all(&sealed).map_err(io)?;
    }
    if fill(&mut input, &mut [0u8; 1])? != 0 {
        return Err(TreeError::Malformed("file longer than its size".into()));
    }
    out.flush().map_err(io)?;
    Ok(FileKey { secret, size, plaintext_sha256: hash.finalize().into() })
}

/// Checks and decrypts a blob from `input`, writing the `fk.size` plaintext
/// bytes to `out`. Plaintext is written chunk by chunk as each chunk
/// authenticates; only an `Ok` return means the whole file matched the
/// message (commitment, every chunk, padding, length and plaintext hash), so
/// callers write to a temporary place and keep it only on `Ok`.
pub fn decrypt_stream(mut input: impl Read, fk: &FileKey, mut out: impl Write) -> Result<(), TreeError> {
    if fk.size > MAX_FILE {
        return Err(bad("larger than 2 GiB"));
    }
    let d = derive(&fk.secret);
    let mut head = [0u8; HEADER];
    if fill(&mut input, &mut head)? != HEADER || !bool::from(head.ct_eq(&d.commitment)) {
        return Err(bad("key does not match the file"));
    }
    let mut dec = Some(DecryptorBE32::from_aead(d.cipher, (&d.prefix).into()));
    let (padded, chunks) = (padded_len(fk.size), chunk_count(fk.size));
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; CHUNK + TAG];
    let mut written = 0u64;
    for i in 0..chunks {
        let len = (padded - i * CHUNK as u64).min(CHUNK as u64) as usize + TAG;
        if fill(&mut input, &mut buf[..len])? != len {
            return Err(bad("truncated"));
        }
        let last = i + 1 == chunks;
        let opened = match dec.take() {
            Some(d) if last => d.decrypt_last(&buf[..len]),
            Some(mut d) => {
                let r = d.decrypt_next(&buf[..len]);
                dec = Some(d);
                r
            }
            None => unreachable!("the last chunk ends the loop"),
        };
        let plain = Zeroizing::new(opened.map_err(|_| bad("decryption failed"))?);
        let keep = fk.size.saturating_sub(written).min(plain.len() as u64) as usize;
        if plain[keep..].iter().any(|b| *b != 0) {
            return Err(bad("padding is not zero"));
        }
        hash.update(&plain[..keep]);
        out.write_all(&plain[..keep]).map_err(io)?;
        written += keep as u64;
    }
    if fill(&mut input, &mut [0u8; 1])? != 0 {
        return Err(bad("longer than its size"));
    }
    let h: [u8; 32] = hash.finalize().into();
    if written != fk.size || !bool::from(h.ct_eq(&fk.plaintext_sha256)) {
        return Err(bad("content does not match the message"));
    }
    out.flush().map_err(io)?;
    Ok(())
}

/// [`encrypt_stream`] in memory.
pub fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, FileKey), TreeError> {
    let mut out = Vec::with_capacity(ciphertext_len(plaintext.len() as u64) as usize);
    let fk = encrypt_stream(plaintext, plaintext.len() as u64, &mut out)?;
    Ok((out, fk))
}

/// [`decrypt_stream`] in memory.
pub fn decrypt(blob: &[u8], fk: &FileKey) -> Result<Vec<u8>, TreeError> {
    if blob.len() as u64 != ciphertext_len(fk.size) {
        return Err(bad("wrong length"));
    }
    let mut out = Vec::with_capacity(fk.size as usize);
    decrypt_stream(blob, fk, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;
    const MIB: u64 = 1 << 20;

    /// PROTOCOL.md 6.12: the buckets.
    #[test]
    fn padding_buckets() {
        let cases = [
            (0, KIB),
            (1, KIB),
            (KIB, KIB),
            (KIB + 1, 2 * KIB),
            (5000, 8 * KIB),
            (300 * KIB, 512 * KIB),
            (MIB - 1, MIB),
            (MIB, MIB),
            // Padmé from here on: E = 20, S = 5 -> multiples of 32 KiB.
            (MIB + 1, MIB + 32 * KIB),
            (3 * MIB / 2 + 1, 3 * MIB / 2 + 32 * KIB),
            // E = 30, S = 5 -> multiples of 32 MiB.
            ((1 << 30) + 1, (1 << 30) + (32 << 20)),
            (MAX_FILE, MAX_FILE),
        ];
        for (size, want) in cases {
            assert_eq!(padded_len(size), want, "size {size}");
        }
        // Never smaller than the file, overhead small above 1 MiB, and the
        // server learns only the bucket.
        for size in (0..4000u64).map(|i| i * 7919 + i * i * 977) {
            let p = padded_len(size);
            assert!(p >= size);
            if size > MIB {
                assert!((p - size) as f64 / size as f64 <= 0.04, "{size} -> {p}");
            }
            assert_eq!(padded_len(p), p, "a bucket pads to itself");
        }
        let distinct: std::collections::BTreeSet<u64> = (MIB..MIB * 64).step_by(4099).map(padded_len).collect();
        assert!(distinct.len() < 200, "{} buckets between 1 and 64 MiB", distinct.len());
        assert_eq!(ciphertext_len(10), 32 + 1024 + 16);
        assert_eq!(ciphertext_len(3 * MIB), 32 + 3 * MIB + 3 * 16);
        assert_eq!(chunk_count(0), 1);
    }

    #[test]
    fn round_trip_sizes_and_streaming() {
        let c = CHUNK;
        for n in [0, 1, 1023, 1025, c - 1, c, c + 1, 2 * c + 17] {
            let pt: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            let (ct, fk) = encrypt(&pt).unwrap();
            assert_eq!(ct.len() as u64, ciphertext_len(n as u64), "n={n}");
            assert_eq!(decrypt(&ct, &fk).unwrap(), pt, "n={n}");
            // A reader that returns small pieces gives the same result.
            let mut out = Vec::new();
            decrypt_stream(Trickle(&ct[..], 1000), &fk, &mut out).unwrap();
            assert_eq!(out, pt);
        }
        // Size must match the input exactly.
        assert!(encrypt_stream(&b"abc"[..], 4, Vec::new()).is_err());
        assert!(encrypt_stream(&b"abcd"[..], 3, Vec::new()).is_err());
        assert!(encrypt_stream(std::io::empty(), MAX_FILE + 1, Vec::new()).is_err());
    }

    struct Trickle<'a>(&'a [u8], usize);
    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.1.min(buf.len()).min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    /// One secret per file; the three derived values differ from each other
    /// and from the secret; the key never shows up in logs.
    #[test]
    fn fresh_secret_and_separate_keys() {
        let (c1, k1) = encrypt(b"same").unwrap();
        let (c2, k2) = encrypt(b"same").unwrap();
        assert_ne!(c1, c2);
        assert_ne!(*k1.secret, *k2.secret);
        assert_eq!(k1.plaintext_sha256, k2.plaintext_sha256);
        let hk = Hkdf::<Sha256>::new(Some(SALT), &k1.secret[..]);
        let mut outs = Vec::new();
        for l in [L_AEAD, L_NONCE, L_COMMIT] {
            let mut v = [0u8; 32];
            hk.expand(l, &mut v).unwrap();
            outs.push(v);
        }
        assert!(outs[0] != outs[1] && outs[1] != outs[2] && outs[0] != outs[2]);
        assert!(outs.iter().all(|o| o != &*k1.secret));
        let d = derive(&k1.secret);
        assert_eq!(&c1[..HEADER], &d.commitment);
        assert_eq!(d.prefix, outs[1][..PREFIX]);
        let dbg = format!("{k1:?}");
        assert!(dbg.starts_with("FileKey") && dbg.contains("size: 4") && !dbg.contains("secret"), "{dbg}");
    }

    #[test]
    fn truncation_reorder_and_bit_flips_detected() {
        let pt = vec![5u8; 2 * CHUNK + 10];
        let (ct, fk) = encrypt(&pt).unwrap();
        let n = CHUNK + TAG;
        let body = &ct[HEADER..];
        let with = |b: &[u8]| [&ct[..HEADER], b].concat();
        let mut cases = vec![
            ("truncated by one byte", ct[..ct.len() - 1].to_vec()),
            ("one byte too many", [&ct[..], &[0]].concat()),
            ("first chunk dropped", with(&body[n..])),
            ("chunks swapped", with(&[&body[n..2 * n], &body[..n], &body[2 * n..]].concat())),
            ("chunk repeated", with(&[&body[..n], &body[..n], &body[2 * n..]].concat())),
            ("cut on a chunk boundary", with(&body[..2 * n])),
            ("commitment changed", [&[0u8; HEADER][..], body].concat()),
        ];
        for at in [0, HEADER, HEADER + 5, HEADER + n + 1, ct.len() - 1] {
            let mut f = ct.clone();
            f[at] ^= 1;
            cases.push(("bit flip", f));
        }
        for (why, bad) in cases {
            assert!(decrypt(&bad, &fk).is_err(), "{why}");
            assert!(decrypt_stream(&bad[..], &fk, Vec::new()).is_err(), "{why} (stream)");
        }
        // A cut on a chunk boundary is refused by the last-chunk flag even
        // when the reference claims the shorter size.
        let cut = with(&body[..2 * n]);
        let short = FileKey { size: 2 * CHUNK as u64, ..fk.clone() };
        assert_eq!(ciphertext_len(short.size), cut.len() as u64);
        assert!(decrypt(&cut, &short).is_err());
        assert_eq!(decrypt(&ct, &fk).unwrap(), pt);
    }

    /// The design's "not yet run" test: one blob must not open to different
    /// content under two secrets or two claimed contents.
    #[test]
    fn key_commitment() {
        let (ct, fk) = encrypt(b"the real picture").unwrap();
        let wrong = FileKey { secret: Zeroizing::new([9; 32]), ..fk.clone() };
        let e = decrypt(&ct, &wrong).unwrap_err().to_string();
        assert!(e.contains("key does not match"), "{e}");
        let other_content = FileKey { plaintext_sha256: Sha256::digest(b"another picture").into(), ..fk.clone() };
        assert!(decrypt(&ct, &other_content).is_err());
        let wrong_size = FileKey { size: fk.size + 1, ..fk.clone() };
        assert!(decrypt_stream(&ct[..], &wrong_size, Vec::new()).is_err());
        // Padding must be zero: a sender cannot hide data past the size.
        let (ct2, fk2) = encrypt(b"short").unwrap();
        let claims_less = FileKey { size: 3, plaintext_sha256: Sha256::digest(b"sho").into(), ..fk2.clone() };
        assert!(decrypt(&ct2, &claims_less).unwrap_err().to_string().contains("padding"));
        assert_eq!(decrypt(&ct, &fk).unwrap(), b"the real picture");
    }
}
