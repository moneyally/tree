//! The little the server reads of a message body (PROTOCOL.md 4.1, 7.4).
//!
//! The server cannot check the envelope tag (it has no key). It only reads
//! the cleartext MLS header so that commits go through the ordering endpoint,
//! proposals are refused and welcomes travel only with their commit.

/// RFC 9420 content types.
pub const APPLICATION: u8 = 1;
pub const PROPOSAL: u8 = 2;
pub const COMMIT: u8 = 3;

const ENVELOPE_V1: u8 = 1;
const TAG_LEN: usize = 32;
const MLS10: [u8; 2] = [0x00, 0x01];
const PRIVATE_MESSAGE: [u8; 2] = [0x00, 0x02];
const WELCOME: [u8; 2] = [0x00, 0x03];

/// Cleartext header of a sealed MLS PrivateMessage.
#[derive(Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub content_type: u8,
}

/// Reads `0x01 || tag || MLSMessage(PrivateMessage)` up to the content type.
pub fn envelope_header(body: &[u8]) -> Result<Header<'_>, &'static str> {
    let mut r = body;
    if take(&mut r, 1)? != [ENVELOPE_V1] {
        return Err("not a Tree envelope");
    }
    take(&mut r, TAG_LEN)?;
    if take(&mut r, 2)? != MLS10 {
        return Err("unsupported MLS version");
    }
    if take(&mut r, 2)? != PRIVATE_MESSAGE {
        return Err("not an MLS private message");
    }
    let len = varint(&mut r)?;
    let group_id = take(&mut r, len)?;
    let epoch = u64::from_be_bytes(take(&mut r, 8)?.try_into().map_err(|_| "truncated")?);
    let content_type = take(&mut r, 1)?[0];
    if !(APPLICATION..=COMMIT).contains(&content_type) {
        return Err("unknown content type");
    }
    Ok(Header { group_id, epoch, content_type })
}

/// True for a bare MLSMessage carrying a Welcome.
pub fn is_welcome(body: &[u8]) -> bool {
    body.len() > 4 && body[..2] == MLS10 && body[2..4] == WELCOME
}

fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], &'static str> {
    if r.len() < n {
        return Err("truncated");
    }
    let (head, rest) = r.split_at(n);
    *r = rest;
    Ok(head)
}

/// RFC 9420 section 2.1.2 variable-length integer, minimum encoding only.
fn varint(r: &mut &[u8]) -> Result<usize, &'static str> {
    let first = take(r, 1)?[0];
    let (len, mut v) = match first >> 6 {
        0 => (1, u32::from(first & 0x3f)),
        1 => (2, u32::from(first & 0x3f)),
        2 => (4, u32::from(first & 0x3f)),
        _ => return Err("invalid length prefix"),
    };
    for b in take(r, len - 1)? {
        v = (v << 8) | u32::from(*b);
    }
    let minimal = match len {
        1 => true,
        2 => v >= 64,
        _ => v >= 16384,
    };
    if !minimal {
        return Err("length prefix not minimal");
    }
    Ok(v as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn envelope(group_id: &[u8], epoch: u64, content_type: u8) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&[0xaa; 32]);
        v.extend_from_slice(&[0, 1, 0, 2]);
        assert!(group_id.len() < 64);
        v.push(group_id.len() as u8);
        v.extend_from_slice(group_id);
        v.extend_from_slice(&epoch.to_be_bytes());
        v.push(content_type);
        v.extend_from_slice(b"rest of the private message");
        v
    }

    #[test]
    fn reads_header() {
        let g = [7u8; 16];
        for ct in [APPLICATION, PROPOSAL, COMMIT] {
            let e = envelope(&g, 0x0102_0304_0506_0708, ct);
            assert_eq!(
                envelope_header(&e),
                Ok(Header { group_id: &g, epoch: 0x0102_0304_0506_0708, content_type: ct })
            );
        }
    }

    #[test]
    fn rejects_malformed() {
        let e = envelope(&[7u8; 16], 3, COMMIT);
        // every truncation up to the content type fails
        for n in 0..(1 + 32 + 4 + 1 + 16 + 8 + 1) {
            assert!(envelope_header(&e[..n]).is_err(), "len {n}");
        }
        for (i, v) in [(0, 2u8), (33, 1), (34, 0), (35, 1), (36, 0), (37, 3)] {
            let mut bad = e.clone();
            bad[i] = v;
            assert!(envelope_header(&bad).is_err(), "byte {i}={v}");
        }
        for ct in [0u8, 4, 255] {
            let mut bad = e.clone();
            bad[1 + 32 + 4 + 1 + 16 + 8] = ct;
            assert_eq!(envelope_header(&bad), Err("unknown content type"));
        }
        let mut bad = e.clone();
        bad[37] = 0xc0; // 11xxxxxx prefix
        assert_eq!(envelope_header(&bad), Err("invalid length prefix"));
    }

    #[test]
    fn varints() {
        let ok = |b: &[u8]| varint(&mut &b[..]);
        assert_eq!(ok(&[0x25]), Ok(0x25));
        assert_eq!(ok(&[0x40, 0x40]), Ok(64));
        assert_eq!(ok(&[0x7f, 0xff]), Ok(16383));
        assert_eq!(ok(&[0x80, 0x00, 0x40, 0x00]), Ok(16384));
        assert_eq!(ok(&[0x40, 0x3f]), Err("length prefix not minimal"));
        assert_eq!(ok(&[0x80, 0x00, 0x3f, 0xff]), Err("length prefix not minimal"));
        assert_eq!(ok(&[0x40]), Err("truncated"));
        // a 2-byte group id length works end to end
        let mut e = vec![1u8];
        e.extend_from_slice(&[0; 32]);
        e.extend_from_slice(&[0, 1, 0, 2, 0x40, 64]);
        e.extend_from_slice(&[9; 64]);
        e.extend_from_slice(&5u64.to_be_bytes());
        e.push(APPLICATION);
        assert_eq!(envelope_header(&e).unwrap().group_id.len(), 64);
    }

    #[test]
    fn welcome_detection() {
        assert!(is_welcome(&[0, 1, 0, 3, 9]));
        assert!(!is_welcome(&[0, 1, 0, 3]));
        assert!(!is_welcome(&[0, 1, 0, 2, 9]));
        assert!(!is_welcome(&[0, 2, 0, 3, 9]));
        assert!(!is_welcome(&envelope(&[1; 16], 1, COMMIT)));
    }
}
