//! A minimal SHA-256 content digest used by the archive transaction executor
//! to verify exact preimage/postimage byte identity.
//!
//! This is deliberately smaller than `mpd`'s domain-separated canonical
//! digest (`mpd::digest::Digest`, in the `mpd` crate): openspec-core hashes
//! raw file bytes for transactional integrity only, not the composite,
//! phase-scoped content-addressing scheme that gives release-closure receipts
//! their meaning. `mpd` depends on `openspec-core` (never the reverse), so
//! that richer concept cannot live here; the two `Digest` types are a
//! deliberate translation boundary between two distinct bounded concepts
//! (generic filesystem integrity vs. release-closure evidence), not
//! accidental duplication. Callers convert explicitly (`to_hex`/`from_hex`)
//! at the crate boundary.

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;

/// The exact lowercase-hex length of a SHA-256 digest.
const HEX_LEN: usize = 64;

/// A lowercase-hex-encoded SHA-256 digest over exact bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Hash `bytes` directly (single-shot; callers streaming large files use
    /// [`Digest::hasher`] instead).
    pub fn of_bytes(bytes: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Digest(hasher.finalize().into())
    }

    /// Parse a digest from exactly 64 lowercase hex characters. Uppercase or
    /// any other length is rejected rather than silently normalized, so a
    /// tampered/foreign digest string never round-trips into a differently
    /// cased "equal" value.
    pub fn from_hex(s: &str) -> Result<Digest, String> {
        let bytes = s.as_bytes();
        if bytes.len() != HEX_LEN {
            return Err(format!("digest must be exactly {HEX_LEN} hex characters"));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = (hex_nibble(bytes[2 * i])? << 4) | hex_nibble(bytes[2 * i + 1])?;
        }
        Ok(Digest(out))
    }

    /// Lowercase hex encoding.
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(HEX_LEN);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The raw 32 digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct directly from a finalized 32-byte digest. Crate-internal: the
    /// transaction executor streams large files through an incremental
    /// `Sha256` hasher rather than buffering them for [`Digest::of_bytes`];
    /// external callers always go through `of_bytes`/`from_hex`.
    pub(crate) fn from_raw(bytes: [u8; 32]) -> Digest {
        Digest(bytes)
    }
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(format!("digest byte {b:#04x} is not lowercase hex")),
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Digest, D::Error> {
        let s = String::deserialize(deserializer)?;
        Digest::from_hex(&s).map_err(DeError::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn of_bytes_is_deterministic_and_distinguishes_input() {
        let a = Digest::of_bytes(b"hello");
        let b = Digest::of_bytes(b"hello");
        let c = Digest::of_bytes(b"hellp");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hex_round_trips() {
        let d = Digest::of_bytes(b"round trip me");
        let hex = d.to_hex();
        assert_eq!(hex.len(), 64);
        let back = Digest::from_hex(&hex).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn from_hex_rejects_wrong_length_and_uppercase() {
        assert!(Digest::from_hex("abc").is_err());
        assert!(Digest::from_hex(&"a".repeat(63)).is_err());
        assert!(Digest::from_hex(&"a".repeat(65)).is_err());
        assert!(Digest::from_hex(&"A".repeat(64)).is_err());
        assert!(Digest::from_hex(&"g".repeat(64)).is_err());
        assert!(Digest::from_hex(&"0".repeat(64)).is_ok());
    }

    #[test]
    fn serde_json_round_trip() {
        let d = Digest::of_bytes(b"serde me");
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{}\"", d.to_hex()));
        let back: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn serde_json_rejects_malformed_digest_string() {
        let err = serde_json::from_str::<Digest>("\"not-a-digest\"");
        assert!(err.is_err());
    }
}
