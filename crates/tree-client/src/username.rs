//! @username format and hash (PROTOCOL.md 8.4). The server only ever sees
//! `SHA-256("tree/username/v1" || normalised name)`.

use sha2::{Digest, Sha256};

/// Lowercase ASCII letters, digits and `_`; 3 to 32 characters; starts with
/// a letter. A leading `@` and surrounding spaces are ignored; upper case is
/// folded. Returns the normalised name or why it is not allowed.
pub fn normalise(name: &str) -> Result<String, &'static str> {
    let n = name.trim().trim_start_matches('@').to_ascii_lowercase();
    if !(3..=32).contains(&n.len()) {
        return Err("a username has 3 to 32 characters");
    }
    if !n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err("a username uses only letters a-z, digits and _");
    }
    if !n.as_bytes()[0].is_ascii_lowercase() {
        return Err("a username starts with a letter");
    }
    Ok(n)
}

pub fn hash(name: &str) -> Result<[u8; 32], &'static str> {
    let n = normalise(name)?;
    Ok(Sha256::new().chain_update(b"tree/username/v1").chain_update(n.as_bytes()).finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation() {
        assert_eq!(normalise(" @Tree_Fan9 "), Ok("tree_fan9".into()));
        assert_eq!(hash("@Alice").unwrap(), hash("alice").unwrap());
        assert_ne!(hash("alice").unwrap(), hash("alice2").unwrap());
        for bad in ["ab", "a".repeat(33).as_str(), "9lives", "_x_", "한글이름", "a b c", "a-b", ""] {
            assert!(normalise(bad).is_err(), "{bad:?}");
        }
        assert!(normalise(&"a".repeat(32)).is_ok());
        assert!(normalise("abc").is_ok());
    }

    #[test]
    fn hash_is_labelled_sha256() {
        let want: [u8; 32] = Sha256::digest(b"tree/username/v1alice").into();
        assert_eq!(hash("alice").unwrap(), want);
    }
}
