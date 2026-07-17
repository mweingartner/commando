//! Canonical, domain-separated SHA-256 content digests.
//!
//! This is the composite content-addressing scheme release-closure evidence
//! is bound to: `scope`, `source`, `governance`, `config`, tool identity, and
//! receipt IDs are all instances of [`canonical_digest`] over a different
//! `domain` string and [`Entry`] set. Feeding a single unambiguous binary
//! stream (never concatenated text) is what makes two different logical
//! inputs unable to collide into the same digest by construction: every
//! field is length- or count-prefixed, kind/mode/deletion are explicit, and
//! entries are sorted by canonical path before hashing so insertion order
//! never matters.
//!
//! This is a distinct, richer concept than `openspec_core::digest::Digest`
//! (a plain SHA-256 of exact bytes, used only for transactional file-image
//! verification) — see that module's doc comment for the boundary rationale.
//!
//! `crate::closure` is the sole production caller: it builds `Entry` sets from
//! manifest scope, worktree/Git content, hermetic inputs, and archive-scope
//! snapshots, then calls [`canonical_digest`] to bind every evidence receipt,
//! `scope`/`source`/`governance`/`config` value, and the archive's final
//! scoped digest. `#![allow(dead_code)]` remains because this is a binary
//! crate (no external library consumer): a handful of `pub` constants and
//! accessors (`MAX_PATH_BYTES`, `MAX_DOMAIN_BYTES`, `STREAM_SCHEMA`,
//! `Entry::path`) are part of this module's documented API surface and covered
//! by its own tests even though nothing outside `digest.rs` calls them today.
#![allow(dead_code)]

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

/// The exact lowercase-hex length of a SHA-256 digest.
const HEX_LEN: usize = 64;

/// Domain-separation magic prepended to every canonical stream.
const MAGIC: &[u8; 4] = b"mpd\0";

/// Schema version of the canonical entry-stream *byte layout* itself —
/// distinct from (and versioned independently of) any particular domain's
/// own schema number (e.g. [`crate::closure::RECEIPT_SCHEMA`]).
pub const STREAM_SCHEMA: u32 = 1;

/// A maximum single path length accepted into an [`Entry`] (defense in depth
/// against unbounded adversarial input; real repository paths are far
/// shorter). Matches common filesystem path limits with headroom.
pub const MAX_PATH_BYTES: usize = 4096;

/// A maximum domain-string length (these are short, fixed, code-defined
/// labels like `"scope"` — never user input).
pub const MAX_DOMAIN_BYTES: usize = 256;

/// A typed, lowercase-hex SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Hash `bytes` directly.
    pub fn of_bytes(bytes: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Digest(hasher.finalize().into())
    }

    /// Parse a digest from exactly 64 lowercase hex characters. Uppercase, a
    /// wrong length, or any non-hex byte is rejected rather than normalized —
    /// a tampered or foreign digest string must never silently round-trip
    /// into an "equal" value.
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

/// The kind of a canonical entry. `Deleted` is an explicit, first-class
/// entry (never modeled as "absent from the set") so a digest can prove a
/// path was actively removed, not merely never seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular tracked file.
    File,
    /// A symbolic link, hashed by its link-text target (never followed).
    Symlink,
    /// A Git submodule reference, hashed by its gitlink OID.
    Gitlink,
    /// An explicit deletion of a previously present path.
    Deleted,
}

impl EntryKind {
    fn tag(self) -> u8 {
        match self {
            EntryKind::File => 1,
            EntryKind::Symlink => 2,
            EntryKind::Gitlink => 3,
            EntryKind::Deleted => 4,
        }
    }
}

/// One canonical content-addressed entry: a repository-relative path bound
/// to its kind, Git-style mode, and content identity (length + digest of the
/// *content bytes*, hashed once and carried as a digest here rather than raw
/// bytes — see [`Entry::file`] / [`Entry::symlink`] / [`Entry::gitlink`] for
/// how "content" is defined per kind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    path: String,
    kind: EntryKind,
    mode: u32,
    content_length: u64,
    content_digest: Digest,
}

/// An error constructing an [`Entry`] or computing a [`canonical_digest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// The path is empty, absolute, contains `.`/`..`, a NUL/backslash, a
    /// control character, or exceeds [`MAX_PATH_BYTES`].
    UnsafePath(String),
    /// The domain string is empty or exceeds [`MAX_DOMAIN_BYTES`].
    UnsafeDomain,
    /// Two entries claimed the same path — ambiguous input, refused rather
    /// than silently picking one (fail closed).
    DuplicatePath(String),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalError::UnsafePath(p) => write!(f, "unsafe canonical path: {p:?}"),
            CanonicalError::UnsafeDomain => write!(f, "unsafe or oversized digest domain"),
            CanonicalError::DuplicatePath(p) => {
                write!(f, "duplicate path in canonical entry set: {p:?}")
            }
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Validate a repository-relative canonical path: non-empty, `/`-separated
/// UTF-8 (guaranteed by `&str`), no leading `/`, no NUL, no backslash, no
/// ASCII control character, no `.`/`..`/empty path component, and bounded
/// length. This is the base safety rule `digest.rs` itself enforces before
/// any path enters a hashed stream — higher layers (manifest scope patterns)
/// may add further, stricter rules on top.
pub fn validate_canonical_path(path: &str) -> Result<(), CanonicalError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(CanonicalError::UnsafePath(path.to_string()));
    }
    if path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(CanonicalError::UnsafePath(path.to_string()));
    }
    if path.chars().any(|c| c.is_control()) {
        return Err(CanonicalError::UnsafePath(path.to_string()));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(CanonicalError::UnsafePath(path.to_string()));
        }
    }
    Ok(())
}

impl Entry {
    /// A regular tracked file: `content` is the exact file bytes (already
    /// hashed once, e.g. by [`hash_file_non_following`] for real files, or
    /// directly for small in-memory content such as tests/fixtures).
    pub fn file(
        path: impl Into<String>,
        mode: u32,
        content_length: u64,
        content_digest: Digest,
    ) -> Result<Entry, CanonicalError> {
        let path = path.into();
        validate_canonical_path(&path)?;
        Ok(Entry {
            path,
            kind: EntryKind::File,
            mode,
            content_length,
            content_digest,
        })
    }

    /// A symbolic link: `target` is the link's raw text, hashed *without*
    /// following it (the filesystem object the link points at is never read
    /// here).
    pub fn symlink(path: impl Into<String>, target: &str) -> Result<Entry, CanonicalError> {
        let path = path.into();
        validate_canonical_path(&path)?;
        let bytes = target.as_bytes();
        Ok(Entry {
            path,
            kind: EntryKind::Symlink,
            mode: 0o120000,
            content_length: bytes.len() as u64,
            content_digest: Digest::of_bytes(bytes),
        })
    }

    /// A Git submodule reference: identity is the gitlink's object id (as
    /// lowercase hex text), never the submodule's own file content.
    pub fn gitlink(path: impl Into<String>, oid_hex: &str) -> Result<Entry, CanonicalError> {
        let path = path.into();
        validate_canonical_path(&path)?;
        let bytes = oid_hex.as_bytes();
        Ok(Entry {
            path,
            kind: EntryKind::Gitlink,
            mode: 0o160000,
            content_length: bytes.len() as u64,
            content_digest: Digest::of_bytes(bytes),
        })
    }

    /// An explicit deletion of `path`.
    pub fn deleted(path: impl Into<String>) -> Result<Entry, CanonicalError> {
        let path = path.into();
        validate_canonical_path(&path)?;
        Ok(Entry {
            path,
            kind: EntryKind::Deleted,
            mode: 0,
            content_length: 0,
            content_digest: Digest::of_bytes(b""),
        })
    }

    /// The entry's canonical path.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Write a `u32`-length-prefixed byte string to `hasher`.
fn write_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn write_entry(hasher: &mut Sha256, e: &Entry) {
    write_len_prefixed(hasher, e.path.as_bytes());
    hasher.update([e.kind.tag()]);
    hasher.update(e.mode.to_be_bytes());
    hasher.update(e.content_length.to_be_bytes());
    hasher.update(e.content_digest.as_bytes());
}

/// Compute the canonical digest of `entries` under `domain` (a short,
/// code-defined label like `"scope"` or `"source"`) and `schema` (the
/// caller's own domain-specific schema number, independent of
/// [`STREAM_SCHEMA`]).
///
/// The stream is: magic `mpd\0`, `schema` (`u32` BE), `domain` length+bytes,
/// then every entry — sorted by canonical path bytes so insertion order never
/// affects the result — each as length-prefixed path, kind tag, mode (`u32`
/// BE), content length (`u64` BE), and content digest (32 raw bytes).
pub fn canonical_digest(
    domain: &str,
    schema: u32,
    mut entries: Vec<Entry>,
) -> Result<Digest, CanonicalError> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_BYTES {
        return Err(CanonicalError::UnsafeDomain);
    }
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    for w in entries.windows(2) {
        if w[0].path == w[1].path {
            return Err(CanonicalError::DuplicatePath(w[0].path.clone()));
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(MAGIC);
    // The stream's own byte-layout version, separate from the caller's
    // domain-specific `schema`: bumping this forces every digest in the
    // system to change, which is the explicit, reviewed event the golden
    // vectors above exist to catch.
    hasher.update(STREAM_SCHEMA.to_be_bytes());
    hasher.update(schema.to_be_bytes());
    write_len_prefixed(&mut hasher, domain.as_bytes());
    for e in &entries {
        write_entry(&mut hasher, e);
    }
    Ok(Digest(hasher.finalize().into()))
}

/// The result of hashing a filesystem object's content: its exact byte
/// length and content digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentDigest {
    /// Exact byte length of the hashed content.
    pub length: u64,
    /// SHA-256 of the exact content bytes.
    pub digest: Digest,
}

/// On Linux/macOS, the value of `O_NOFOLLOW` — used so the final `open(2)`
/// itself refuses to follow a symlink planted between the pre-open
/// `symlink_metadata` check and the open call (closing the TOCTOU window a
/// metadata-check-then-open pair alone leaves open). No `libc`/unsafe FFI is
/// needed: `OpenOptionsExt::custom_flags` is a safe standard-library API:
/// it just records an integer to OR into the `open(2)` flags.
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;

#[cfg(unix)]
fn open_options_non_following() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW);
    }
    opts
}

#[cfg(not(unix))]
fn open_options_non_following() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true);
    opts
}

/// Hash a regular file's content from a handle that refuses to follow a
/// symlink, verifying it is a regular file both before opening and after
/// reading (never a FIFO, device, socket, directory, or symlink). Streams the
/// content in bounded chunks rather than buffering the whole file.
///
/// Security-plan requirement: "Hash regular files from non-following handles
/// and verify kind/mode before and after streaming."
pub fn hash_file_non_following(path: &Path) -> io::Result<ContentDigest> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to follow symlink at {}", path.display()),
        ));
    }
    if !before.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut file = open_options_non_following().open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    // Re-verify via the open handle itself (fstat, not a fresh path lookup)
    // that what we streamed was in fact a regular file the whole time.
    let opened_kind = file.metadata()?;
    if !opened_kind.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} changed identity while hashing", path.display()),
        ));
    }
    // Re-check the path itself post-read: catches a same-name symlink swap
    // performed after our handle was opened (best-effort; the bytes we
    // already hashed came from the originally opened, verified-regular fd
    // regardless of what now sits at `path`).
    let after = fs::symlink_metadata(path)?;
    if after.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} became a symlink during hashing", path.display()),
        ));
    }
    Ok(ContentDigest {
        length: total,
        digest: Digest(hasher.finalize().into()),
    })
}

/// Hash a symlink's link-text target without following it. Refuses a
/// non-UTF-8 target (fail closed — matches the canonical-path UTF-8
/// requirement).
pub fn hash_symlink_non_following(path: &Path) -> io::Result<ContentDigest> {
    let md = fs::symlink_metadata(path)?;
    if !md.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a symlink", path.display()),
        ));
    }
    let target = fs::read_link(path)?;
    let text = target.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} has a non-UTF-8 symlink target", path.display()),
        )
    })?;
    let bytes = text.as_bytes();
    Ok(ContentDigest {
        length: bytes.len() as u64,
        digest: Digest::of_bytes(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn e_file(path: &str, mode: u32, content: &[u8]) -> Entry {
        Entry::file(path, mode, content.len() as u64, Digest::of_bytes(content)).unwrap()
    }

    // --- Golden vectors -----------------------------------------------
    //
    // These hex strings are this implementation's own fixed, regression-
    // pinned output for the given inputs (there is no external reference
    // encoder for mpd's canonical stream to compare against — the "golden"
    // property is that this value must never silently change across a
    // refactor without an explicit, reviewed schema bump).

    #[test]
    fn golden_vector_mixed_entry_set() {
        let entries = vec![
            e_file("crates/mpd/src/cli.rs", 0o100644, b"fn main() {}"),
            Entry::symlink("crates/mpd/src/link.rs", "cli.rs").unwrap(),
            Entry::gitlink("vendor/sub", &"ab".repeat(20)).unwrap(),
            Entry::deleted("crates/mpd/src/old.rs").unwrap(),
        ];
        let digest = canonical_digest("golden-mixed", 1, entries).unwrap();
        assert_eq!(
            digest.to_hex(),
            "3335bf14594a040c5ea84aaa0238893acadf96c37dd6c2e3c2fb3d357cd4dc63",
            "canonical golden vector changed — this must only happen with an \
             explicit, reviewed schema/format bump"
        );
    }

    #[test]
    fn golden_vector_empty_entry_set() {
        let digest = canonical_digest("golden-empty", 7, vec![]).unwrap();
        assert_eq!(
            digest.to_hex(),
            "48621682532e22b8cd8546ece6b982bf94a16075a7276abbed764ea63ad77f00"
        );
    }

    #[test]
    fn insertion_order_does_not_affect_digest() {
        let a = vec![
            e_file("b.rs", 0o100644, b"B"),
            e_file("a.rs", 0o100644, b"A"),
        ];
        let b = vec![
            e_file("a.rs", 0o100644, b"A"),
            e_file("b.rs", 0o100644, b"B"),
        ];
        let da = canonical_digest("order", 1, a).unwrap();
        let db = canonical_digest("order", 1, b).unwrap();
        assert_eq!(da, db);
    }

    #[test]
    fn mode_change_changes_digest() {
        let d1 = canonical_digest("mode", 1, vec![e_file("x.sh", 0o100644, b"same")]).unwrap();
        let d2 = canonical_digest("mode", 1, vec![e_file("x.sh", 0o100755, b"same")]).unwrap();
        assert_ne!(d1, d2, "executable bit must change the digest");
    }

    #[test]
    fn delete_differs_from_file_and_from_absence() {
        let with_file = canonical_digest("del", 1, vec![e_file("x", 0o100644, b"c")]).unwrap();
        let with_delete = canonical_digest("del", 1, vec![Entry::deleted("x").unwrap()]).unwrap();
        let empty = canonical_digest("del", 1, vec![]).unwrap();
        assert_ne!(with_file, with_delete);
        assert_ne!(
            with_delete, empty,
            "a deletion is a distinct entry, not silence"
        );
    }

    #[test]
    fn symlink_hashes_target_text_not_pointee_content() {
        // Two symlinks with the same target text but at different paths still
        // differ (path is part of the stream); the key property under test
        // is that changing the *target text* changes the digest while the
        // symlink's own bytes (never read here) are irrelevant by construction.
        let d1 = canonical_digest("sym", 1, vec![Entry::symlink("l", "a").unwrap()]).unwrap();
        let d2 = canonical_digest("sym", 1, vec![Entry::symlink("l", "b").unwrap()]).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn gitlink_uses_oid_not_path_content() {
        let oid_a = "a".repeat(40);
        let oid_b = "b".repeat(40);
        let d1 = canonical_digest("gl", 1, vec![Entry::gitlink("sub", &oid_a).unwrap()]).unwrap();
        let d2 = canonical_digest("gl", 1, vec![Entry::gitlink("sub", &oid_b).unwrap()]).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn domain_and_schema_are_bound_into_the_digest() {
        let entries = || vec![e_file("x", 0o100644, b"c")];
        let d1 = canonical_digest("domain-a", 1, entries()).unwrap();
        let d2 = canonical_digest("domain-b", 1, entries()).unwrap();
        let d3 = canonical_digest("domain-a", 2, entries()).unwrap();
        assert_ne!(d1, d2, "domain must be part of the hashed stream");
        assert_ne!(d1, d3, "schema must be part of the hashed stream");
    }

    #[test]
    fn duplicate_path_is_refused() {
        let entries = vec![e_file("x", 0o100644, b"a"), e_file("x", 0o100644, b"b")];
        assert!(matches!(
            canonical_digest("dup", 1, entries),
            Err(CanonicalError::DuplicatePath(p)) if p == "x"
        ));
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        for bad in [
            "", "/abs", "a/../b", "a/./b", "a//b", "a\\b", "a\0b", "a\tb",
        ] {
            assert!(
                Entry::file(bad, 0o100644, 0, Digest::of_bytes(b"")).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        assert!(Entry::file(
            "a".repeat(MAX_PATH_BYTES + 1),
            0o100644,
            0,
            Digest::of_bytes(b"")
        )
        .is_err());
    }

    #[test]
    fn empty_or_oversized_domain_is_rejected() {
        assert!(matches!(
            canonical_digest("", 1, vec![]),
            Err(CanonicalError::UnsafeDomain)
        ));
        let huge = "d".repeat(MAX_DOMAIN_BYTES + 1);
        assert!(matches!(
            canonical_digest(&huge, 1, vec![]),
            Err(CanonicalError::UnsafeDomain)
        ));
    }

    #[test]
    fn digest_hex_round_trips() {
        let d = Digest::of_bytes(b"round trip");
        let back = Digest::from_hex(&d.to_hex()).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn from_hex_rejects_uppercase_and_wrong_length() {
        assert!(Digest::from_hex(&"A".repeat(64)).is_err());
        assert!(Digest::from_hex(&"a".repeat(63)).is_err());
        assert!(Digest::from_hex(&"g".repeat(64)).is_err());
    }

    #[test]
    fn serde_json_round_trip_and_rejects_malformed() {
        let d = Digest::of_bytes(b"serde");
        let json = serde_json::to_string(&d).unwrap();
        let back: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
        assert!(serde_json::from_str::<Digest>("\"nope\"").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn hash_file_non_following_refuses_symlink() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("mpd-digest-sym-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.txt");
        fs::write(&target, b"secret").unwrap();
        let link = dir.join("link.txt");
        symlink(&target, &link).unwrap();
        assert!(hash_file_non_following(&link).is_err());
        // The real file still hashes fine and matches direct computation.
        let got = hash_file_non_following(&target).unwrap();
        assert_eq!(got.digest, Digest::of_bytes(b"secret"));
        assert_eq!(got.length, 6);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn hash_symlink_non_following_hashes_target_text_only() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("mpd-digest-symtext-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("pointee.txt");
        fs::write(&target, b"this content must never be read").unwrap();
        let link = dir.join("l");
        symlink("pointee.txt", &link).unwrap();
        let got = hash_symlink_non_following(&link).unwrap();
        assert_eq!(got.digest, Digest::of_bytes(b"pointee.txt"));
        assert_eq!(got.length, "pointee.txt".len() as u64);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn hash_file_non_following_refuses_fifo() {
        // A FIFO is neither a symlink nor a regular file; refuse without
        // opening/blocking on it.
        let dir = std::env::temp_dir().join(format!("mpd-digest-fifo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("f");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        if matches!(status, Ok(s) if s.success()) {
            assert!(hash_file_non_following(&fifo).is_err());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    proptest! {
        /// Any two orderings of the same entry set produce the same digest —
        /// the core "content-addressed, not insertion-order-addressed"
        /// property. Uses a small alphabet of distinct paths so entries stay
        /// unique after sorting.
        #[test]
        fn prop_permutation_invariance(
            seed in prop::collection::vec(0u8..8, 1..8)
        ) {
            let paths = ["a", "b", "c", "d", "e", "f", "g", "h"];
            let mut entries: Vec<Entry> = seed
                .iter()
                .enumerate()
                .map(|(i, _)| e_file(paths[i % paths.len()], 0o100644, &[i as u8]))
                .collect();
            // Deduplicate by path (constructing from a seed can repeat paths).
            entries.sort_by(|a, b| a.path().cmp(b.path()));
            entries.dedup_by(|a, b| a.path() == b.path());
            let forward = entries.clone();
            let mut reversed = entries.clone();
            reversed.reverse();
            let d1 = canonical_digest("prop", 1, forward).unwrap();
            let d2 = canonical_digest("prop", 1, reversed).unwrap();
            prop_assert_eq!(d1, d2);
        }

        /// `from_hex` never panics on arbitrary input, and any digest that
        /// does parse round-trips exactly.
        #[test]
        fn prop_from_hex_never_panics(s in ".*") {
            let _ = Digest::from_hex(&s);
        }

        /// A digest computed from arbitrary bytes always round-trips through
        /// its own hex encoding.
        #[test]
        fn prop_of_bytes_hex_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let d = Digest::of_bytes(&bytes);
            prop_assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
        }

        /// Metamorphic: adding a *fresh-path* entry always changes the
        /// digest — a newly present fact can never be invisible. The base
        /// set is drawn from paths "a".."g"; the added entry always uses
        /// "h", so it is guaranteed distinct (never a duplicate-path
        /// refusal).
        #[test]
        fn prop_adding_a_fresh_entry_changes_the_digest(
            seed in prop::collection::vec(0u8..7, 0..7),
            extra in any::<u8>(),
        ) {
            let paths = ["a", "b", "c", "d", "e", "f", "g"];
            let mut entries: Vec<Entry> = seed
                .iter()
                .enumerate()
                .map(|(i, b)| e_file(paths[i % paths.len()], 0o100644, &[*b]))
                .collect();
            entries.sort_by(|a, b| a.path().cmp(b.path()));
            entries.dedup_by(|a, b| a.path() == b.path());
            let base = canonical_digest("meta", 1, entries.clone()).unwrap();
            entries.push(e_file("h", 0o100644, &[extra]));
            let grown = canonical_digest("meta", 1, entries).unwrap();
            prop_assert_ne!(base, grown);
        }

        /// Metamorphic: mutating a single entry's content bytes always
        /// changes the digest. `orig ^ 0xFF` is guaranteed to differ from
        /// `orig` for every `u8`, so the content genuinely changed.
        #[test]
        fn prop_mutating_entry_content_changes_the_digest(
            idx in 0usize..6,
            orig in any::<u8>(),
        ) {
            let paths = ["a", "b", "c", "d", "e", "f"];
            let entries: Vec<Entry> = paths
                .iter()
                .map(|p| e_file(p, 0o100644, &[orig]))
                .collect();
            let i = idx % paths.len();
            let mut mutated = entries.clone();
            mutated[i] = e_file(paths[i], 0o100644, &[orig ^ 0xFF]);
            let d1 = canonical_digest("meta", 1, entries).unwrap();
            let d2 = canonical_digest("meta", 1, mutated).unwrap();
            prop_assert_ne!(d1, d2);
        }

        /// Metamorphic: removing an entry always changes the digest — a
        /// dropped fact is never silently equal to keeping it.
        #[test]
        fn prop_removing_an_entry_changes_the_digest(
            seed in prop::collection::vec(0u8..7, 2..7),
        ) {
            let paths = ["a", "b", "c", "d", "e", "f", "g"];
            let mut entries: Vec<Entry> = seed
                .iter()
                .enumerate()
                .map(|(i, b)| e_file(paths[i % paths.len()], 0o100644, &[*b]))
                .collect();
            entries.sort_by(|a, b| a.path().cmp(b.path()));
            entries.dedup_by(|a, b| a.path() == b.path());
            prop_assume!(entries.len() >= 2);
            let full = canonical_digest("meta", 1, entries.clone()).unwrap();
            entries.pop();
            let reduced = canonical_digest("meta", 1, entries).unwrap();
            prop_assert_ne!(full, reduced);
        }

        /// Metamorphic: the domain label is bound into the stream, so two
        /// distinct domains never collide for the same entry set — `scope`
        /// evidence can never be mistaken for `source` evidence.
        #[test]
        fn prop_distinct_domains_never_collide(a in any::<u8>(), b in any::<u8>()) {
            let entries = || vec![e_file("x", 0o100644, &[a]), e_file("y", 0o100644, &[b])];
            let d_scope = canonical_digest("scope", 1, entries()).unwrap();
            let d_source = canonical_digest("source", 1, entries()).unwrap();
            prop_assert_ne!(d_scope, d_source);
        }
    }
}
