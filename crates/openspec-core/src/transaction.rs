//! The archive transaction plan, durable state-machine types, and the
//! crash-safe filesystem executor that drives them.
//!
//! Normative reference: `openspec/changes/content-addressed-release-closure/
//! archive-transaction.md`. This module defines both the *types* the
//! crash-safe filesystem executor operates on and the executor itself.
//! `Project::plan_archive` (see [`crate::project`]) remains the pure semantic
//! planner that computes merged spec postimages and the directory move; the
//! `mpd` CLI composes those outputs, the durable documentation copy, and the
//! final ledger/closure postimage into one [`ArchiveTransactionPlan`] via
//! [`build_plan`], then drives it durably with [`prepare`] and [`drive`].
//! `mpd closure recover`/`abandon` call [`inspect`], [`recover_apply`], and
//! [`abandon_apply`] — the same functions a normal (non-crash) archive uses,
//! so there is exactly one code path for "apply" whether or not a process
//! termination happened in between.

use crate::digest::Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Current schema version for [`ArchiveTransactionPlan`].
pub const TRANSACTION_SCHEMA: u32 = 1;
/// Current schema version for [`PendingClosurePointer`].
pub const PENDING_POINTER_SCHEMA: u32 = 1;

/// Maximum number of ordinary file targets a single transaction may carry
/// (defense in depth against an unbounded/adversarial plan; real archives
/// touch a handful of spec/doc files). Excludes the single `closure_ledger`
/// target.
pub const MAX_TARGETS: usize = 64;
/// Maximum total bytes staged across every target in one transaction.
pub const MAX_STAGED_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes any single target's postimage may be.
pub const MAX_TARGET_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum bytes accepted when reading back a journal file.
pub const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum bytes accepted when reading back the pending-closure pointer.
pub const MAX_POINTER_BYTES: u64 = 8 * 1024;

/// A repository-relative path, already validated as safe (no `..`, absolute
/// prefix, empty component, backslash, NUL, or control character). Stored as
/// `String` rather than `PathBuf` so it serializes portably and compares
/// byte-for-byte.
pub type RelativePath = String;

/// A Git object id, stored as already-validated lowercase hex text. Syntax
/// and semantics belong to `mpd::git`; this module only carries the value.
pub type OidText = String;

/// A precomputed, versioned plan for the crash-safe archive mutation: every
/// target's preimage/postimage, the directory move, and the digest the fully
/// applied result must match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveTransactionPlan {
    /// Schema version (see [`TRANSACTION_SCHEMA`]).
    pub version: u32,
    /// Identity of this plan — a digest of its own complete content excluding
    /// this field (and excluding every `staged` path, which is itself
    /// derived from this id), used to name the journal directory and pending
    /// pointer.
    pub id: Digest,
    /// The change being archived.
    pub change: String,
    /// The commit HEAD must descend from for a closure commit to be coherent.
    pub base_commit: OidText,
    /// Every ordinary file target this transaction will create or replace
    /// (merged specs, durable docs), sorted by canonical path and applied in
    /// that order during `Applying`. Excludes the closure-ledger target,
    /// which is applied separately and only during `RecordingClosure` (see
    /// [`ArchiveTransactionPlan::closure_ledger`]).
    pub targets: Vec<TransactionTarget>,
    /// The active → archive directory rename.
    pub directory_move: DirectoryMove,
    /// The final ledger/closure postimage. Applied last, only after every
    /// ordinary target and the directory move are verified exact, matching
    /// `archive-transaction.md`'s `RecordingClosure` stage.
    pub closure_ledger: TransactionTarget,
    /// The digest the fully-applied scoped result must match. Computed by
    /// the caller from planned postimages, so the staged ledger can carry it
    /// without a self-reference (ledger bytes are excluded from this
    /// digest). Not independently recomputed by this executor — recovery
    /// never reruns the scope-hashing logic that produced it.
    pub final_scoped_digest: Digest,
}

/// One file this transaction will bring from `preimage` to `postimage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionTarget {
    /// The real repository-relative path this target replaces.
    pub target: RelativePath,
    /// The exact state `target` must be in before this step may apply.
    pub preimage: ImageState,
    /// The exact state `target` must be in after this step applies.
    pub postimage: FileImage,
    /// The durably staged file already written and synced with the
    /// postimage bytes, ready to be renamed over `target`. Lives under this
    /// transaction's own `.mpd/tmp/archive/<id>/staged/` directory (a
    /// deliberate, documented deviation from "preferably a hidden sibling":
    /// per-id staging keeps every transaction's footprint in one
    /// containable, fully-cleanable subtree while remaining on the same
    /// filesystem as the repository root in every realistic layout).
    pub staged: RelativePath,
}

/// The state a transaction target is expected to be in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ImageState {
    /// The target does not exist yet (a new file).
    Absent,
    /// The target exists with exactly this content/mode/length.
    File(FileImage),
}

/// A file's content identity: digest, Git-style mode, and byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileImage {
    /// SHA-256 of the exact file bytes.
    pub digest: Digest,
    /// The POSIX/Git mode bits (e.g. `0o100644`, `0o100755`).
    pub mode: u32,
    /// Exact byte length (redundant with `digest` but cheap to check first).
    pub length: u64,
}

/// The active-change → archive directory rename, identified by a digest of
/// the tree's contents so a partially-applied rename can be recognized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryMove {
    /// The active change directory (source of the rename).
    pub source: RelativePath,
    /// The dated archive directory (destination of the rename).
    pub destination: RelativePath,
    /// A digest identifying the directory tree being moved, so recovery can
    /// tell "not yet renamed" (exact source, absent destination) apart from
    /// "already renamed" (absent source, exact destination) without relying
    /// on directory existence alone.
    pub tree_digest: Digest,
}

/// The durable transaction state machine. Recovery loads the pointer/journal
/// and drives forward only along this sequence; it never reruns semantic
/// merge, render, or documentation synthesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionState {
    /// Staging postimages and writing the journal; no project target has
    /// changed yet.
    Preparing,
    /// The journal and every staged postimage are durably written and
    /// verified; the pending pointer has entered this state.
    Prepared,
    /// File targets are being brought from preimage to postimage in
    /// canonical path order.
    Applying,
    /// All file targets are exact postimages; the directory rename is being
    /// applied or verified.
    Renaming,
    /// The directory move is complete; the final closure-ledger postimage is
    /// being written.
    RecordingClosure,
    /// Every target, the directory rename, and the closure ledger are
    /// verified exact. Only a commit of this result remains; `recover`
    /// resolves to completion-only from here, and `abandon --yes` may run.
    AwaitingCommit,
}

/// The ignored, crash-recoverable pointer to an in-flight archive
/// transaction (`.mpd/pending-closure`). The sole authoritative type for
/// that file's contents — `mpd::closure` re-exports it rather than defining
/// a second shape, so the pointer's on-disk format has exactly one
/// definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingClosurePointer {
    /// Schema version (see [`PENDING_POINTER_SCHEMA`]).
    pub version: u32,
    /// The transaction this pointer resolves (see
    /// [`ArchiveTransactionPlan::id`]).
    pub transaction_id: Digest,
    /// The change being archived.
    pub change: String,
    /// The transaction's current durable stage.
    pub stage: TransactionState,
}

/// Any error the transaction executor can surface. `ManualRecoveryRequired`
/// is reported through [`DriveOutcome`]/[`TransactionView`], not this type —
/// it is an expected, safe, no-mutation terminal state, not a bug.
#[derive(Debug)]
pub enum TransactionError {
    /// An underlying I/O failure (message preserved, never raw error debug
    /// output that could leak more than intended).
    Io(String),
    /// A journal, pointer, or staged file failed a structural/containment/
    /// size check. Always fails closed: never treated as "absent" or
    /// silently repaired.
    Corrupt(String),
    /// A count/size limit was exceeded.
    LimitExceeded(String),
    /// The caller asked for a mutation that is refused given the current
    /// durable state (e.g. `recover --yes` on an ineligible transaction,
    /// `abandon --yes` outside `AwaitingCommit`). No mutation occurred.
    Refused(String),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::Io(m) => write!(f, "io error: {m}"),
            TransactionError::Corrupt(m) => write!(f, "corrupt transaction state: {m}"),
            TransactionError::LimitExceeded(m) => write!(f, "limit exceeded: {m}"),
            TransactionError::Refused(m) => write!(f, "refused: {m}"),
        }
    }
}

impl std::error::Error for TransactionError {}

impl From<io::Error> for TransactionError {
    fn from(e: io::Error) -> Self {
        TransactionError::Io(e.to_string())
    }
}

/// Convenience alias.
pub type TxResult<T> = Result<T, TransactionError>;

// =====================================================================
// Paths
// =====================================================================

fn mpd_dir(root: &Path) -> PathBuf {
    root.join(".mpd")
}

/// `.mpd/pending-closure` — the ignored, atomically-replaced pointer.
pub fn pointer_path(root: &Path) -> PathBuf {
    mpd_dir(root).join("pending-closure")
}

fn transaction_dir(root: &Path, id: Digest) -> PathBuf {
    mpd_dir(root).join("tmp").join("archive").join(id.to_hex())
}

fn journal_path(root: &Path, id: Digest) -> PathBuf {
    transaction_dir(root, id).join("journal.json")
}

fn staged_dir(root: &Path, id: Digest) -> PathBuf {
    transaction_dir(root, id).join("staged")
}

/// Join `root` with a caller-declared relative path and assert it stays
/// contained (rejects `..`, absolute prefixes, and symlinked intermediate
/// components — see [`crate::project::assert_contained`]).
fn contained(root: &Path, rel: &str) -> TxResult<PathBuf> {
    if rel.is_empty() {
        return Err(TransactionError::Corrupt("empty relative path".into()));
    }
    let joined = root.join(rel);
    crate::project::assert_contained(root, &joined)
        .map_err(|e| TransactionError::Corrupt(e.to_string()))?;
    Ok(joined)
}

/// Like [`contained`], but only ancestor directories are checked for
/// symlinks/illegal components — the leaf itself may legitimately be a
/// symlink. Used wherever the leaf's current state is about to be
/// classified rather than written through: a symlink swapped into a target
/// or staged path is an explicit third state the caller must classify and
/// report (`archive-transaction.md`: "...changed type/mode, or symlink:
/// stop manual-recovery-required"), not a hard containment error. Every
/// write path still goes through the strict [`contained`].
fn contained_leaf(root: &Path, rel: &str) -> TxResult<PathBuf> {
    if rel.is_empty() {
        return Err(TransactionError::Corrupt("empty relative path".into()));
    }
    let joined = root.join(rel);
    let stripped = joined
        .strip_prefix(root)
        .map_err(|_| TransactionError::Corrupt(format!("path {rel:?} escapes the project root")))?;
    let mut components: Vec<std::path::Component> = stripped.components().collect();
    let Some(leaf) = components.pop() else {
        return Err(TransactionError::Corrupt(format!(
            "path {rel:?} has no components"
        )));
    };
    if !matches!(leaf, std::path::Component::Normal(_)) {
        return Err(TransactionError::Corrupt(format!(
            "illegal path component in {rel:?}"
        )));
    }
    let mut cur = root.to_path_buf();
    for comp in &components {
        if !matches!(comp, std::path::Component::Normal(_)) {
            return Err(TransactionError::Corrupt(format!(
                "illegal path component in {rel:?}"
            )));
        }
        cur.push(comp);
        if let Ok(md) = fs::symlink_metadata(&cur) {
            if md.file_type().is_symlink() {
                return Err(TransactionError::Corrupt(format!(
                    "refusing to follow symlink at {}",
                    cur.display()
                )));
            }
        }
    }
    cur.push(leaf);
    Ok(cur)
}

// =====================================================================
// Non-following capture/hashing
// =====================================================================

/// What was found at a path, captured without following a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Captured {
    Absent,
    File(FileImage),
    /// A symlink, directory, or special file (FIFO/device/socket) — never
    /// silently treated as absent or as a file.
    Other,
}

#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;

#[cfg(unix)]
fn open_non_following() -> OpenOptions {
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
fn open_non_following() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true);
    opts
}

#[cfg(unix)]
fn file_mode(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if md.permissions().mode() & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    }
}
#[cfg(not(unix))]
fn file_mode(_md: &fs::Metadata) -> u32 {
    0o100644
}

/// Capture the current state at `path` without following a symlink,
/// verifying kind both before and after streaming (security-plan
/// requirement: "Hash regular files from non-following handles and verify
/// kind/mode before and after streaming").
fn capture(path: &Path) -> io::Result<Captured> {
    let before = match fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Captured::Absent),
        Err(e) => return Err(e),
    };
    let ft = before.file_type();
    if ft.is_symlink() || (!ft.is_file() && !ft.is_dir()) {
        return Ok(Captured::Other);
    }
    if ft.is_dir() {
        return Ok(Captured::Other);
    }
    if before.len() > MAX_TARGET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} exceeds the {MAX_TARGET_BYTES}-byte transaction limit",
                path.display()
            ),
        ));
    }
    let mut file = open_non_following().open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_TARGET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} exceeds the {MAX_TARGET_BYTES}-byte transaction limit",
                    path.display()
                ),
            ));
        }
        hasher.update(&buf[..n]);
    }
    let opened_md = file.metadata()?;
    if !opened_md.file_type().is_file() {
        return Ok(Captured::Other);
    }
    // Re-check the path post-read: catches a same-name symlink swap
    // performed after the handle was opened.
    let after = fs::symlink_metadata(path)?;
    if after.file_type().is_symlink() {
        return Ok(Captured::Other);
    }
    Ok(Captured::File(FileImage {
        digest: Digest::from_raw(hasher.finalize().into()),
        mode: file_mode(&before),
        length: total,
    }))
}

fn captured_matches_image(captured: Captured, image: &ImageState) -> bool {
    match (captured, image) {
        (Captured::Absent, ImageState::Absent) => true,
        (Captured::File(a), ImageState::File(b)) => a == *b,
        _ => false,
    }
}

fn captured_matches_file(captured: Captured, image: &FileImage) -> bool {
    matches!(captured, Captured::File(a) if a == *image)
}

/// Recursively hash a directory tree from non-following handles: sorted
/// relative paths, each a length-implicit `(path, mode, content-digest)`
/// tuple. Refuses any symlink or special file inside the tree (fails closed
/// rather than silently skipping it) — real change directories are plain
/// markdown/YAML files only.
fn tree_digest_of(dir: &Path) -> io::Result<Digest> {
    let mut entries: Vec<(String, FileImage)> = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let full = dir.join(&rel);
        for entry in fs::read_dir(&full)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-UTF-8 path in directory tree",
                )
            })?;
            let child_rel = if rel.as_os_str().is_empty() {
                PathBuf::from(name)
            } else {
                rel.join(name)
            };
            let md = entry.file_type()?;
            if md.is_dir() {
                stack.push(child_rel);
            } else if md.is_file() {
                let child_full = dir.join(&child_rel);
                match capture(&child_full)? {
                    Captured::File(image) => {
                        let key = child_rel.to_string_lossy().replace('\\', "/");
                        entries.push((key, image));
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{} changed identity while hashing a directory tree",
                                child_full.display()
                            ),
                        ))
                    }
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "refusing symlink/special file in directory tree: {}",
                        child_rel.display()
                    ),
                ));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    hasher.update(b"mpd-tx-tree\0");
    for (path, image) in &entries {
        hasher.update((path.len() as u32).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update(image.mode.to_be_bytes());
        hasher.update(image.length.to_be_bytes());
        hasher.update(image.digest.as_bytes());
    }
    Ok(Digest::from_raw(hasher.finalize().into()))
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    match File::open(path) {
        Ok(f) => io_fsync(&f, path),
        // A best-effort durability aid; a directory that vanished underneath
        // us is reported by the caller's own subsequent existence checks.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

// =====================================================================
// Durability-op seam (test-only fault injection)
// =====================================================================
//
// Every durability-critical filesystem operation the transaction relies on —
// file `sync_all`, directory fsync, and `rename` — is routed through one of
// these two wrappers. In a production build they are `#[inline]` pass-throughs
// with byte-identical codegen and zero overhead (no branch, no state read);
// `#![forbid(unsafe_code)]` is preserved. Under `#[cfg(test)]` they first
// consult a thread-local fault plan so a test can force one specific sync or
// rename to fail with an I/O error and prove the transaction still fails closed
// and stays recoverable. Process-restart simulation reconstructs a
// *hypothesized* interruption point on disk; this seam instead exercises the
// executor's real error-propagation path when the OS itself fails a durability
// step (e.g. a `rename` that succeeds but whose following `sync_all` fails).

#[cfg(not(test))]
#[inline]
fn io_fsync(f: &File, _path: &Path) -> io::Result<()> {
    f.sync_all()
}
#[cfg(not(test))]
#[inline]
fn io_rename(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(test)]
fn io_fsync(f: &File, path: &Path) -> io::Result<()> {
    faults::check(faults::FaultOp::Fsync, path)?;
    f.sync_all()
}
#[cfg(test)]
fn io_rename(from: &Path, to: &Path) -> io::Result<()> {
    // A rename is identified by the durable destination name it installs.
    faults::check(faults::FaultOp::Rename, to)?;
    fs::rename(from, to)
}

#[cfg(test)]
mod faults {
    use std::cell::RefCell;
    use std::io;
    use std::path::Path;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum FaultOp {
        Fsync,
        Rename,
    }

    thread_local! {
        // (op, path-substring). The next matching durability op fails once.
        static PLAN: RefCell<Option<(FaultOp, String)>> = const { RefCell::new(None) };
    }

    /// Disarms the thread-local fault on drop, so a fault — whether it fired or
    /// not — can never leak into the next test sharing this worker thread.
    #[must_use]
    pub(super) struct Armed;
    impl Drop for Armed {
        fn drop(&mut self) {
            PLAN.with(|p| *p.borrow_mut() = None);
        }
    }

    /// Arm: the next durability op of kind `op` whose path contains `substr`
    /// fails once with an I/O error. The returned guard disarms on drop.
    pub(super) fn fail_next(op: FaultOp, substr: &str) -> Armed {
        PLAN.with(|p| *p.borrow_mut() = Some((op, substr.to_string())));
        Armed
    }

    /// Consulted by the `io_*` wrappers before the real syscall.
    pub(super) fn check(op: FaultOp, path: &Path) -> io::Result<()> {
        PLAN.with(|p| {
            let mut slot = p.borrow_mut();
            if let Some((want, substr)) = slot.as_ref() {
                if *want == op && path.to_string_lossy().contains(substr.as_str()) {
                    *slot = None; // fire exactly once
                    return Err(io::Error::other("injected durability failure"));
                }
            }
            Ok(())
        })
    }
}

// =====================================================================
// Plan construction (pure-ish: reads current preimages, writes nothing)
// =====================================================================

/// One ordinary target's desired postimage content, supplied by the caller
/// (the `mpd` CLI composes these from `ArchivePlan` spec updates and the
/// durable documentation copy).
#[derive(Debug, Clone)]
pub struct TargetWrite {
    /// The real repository-relative path this write targets.
    pub target: RelativePath,
    /// The exact postimage bytes.
    pub bytes: Vec<u8>,
}

/// The active → archive directory rename the caller wants planned.
#[derive(Debug, Clone)]
pub struct DirectoryMoveInput {
    /// The active change directory (source of the rename).
    pub source: RelativePath,
    /// The dated archive directory (destination of the rename).
    pub destination: RelativePath,
}

/// Build (but do not durably stage) an [`ArchiveTransactionPlan`]: capture
/// every target's real current preimage, compute postimages from `writes`
/// and `closure_ledger`, hash the source directory tree, and derive the
/// plan's id and every staged path from it. Performs no filesystem
/// mutation — symmetric with `Project::plan_archive`.
/// Build an [`ArchiveTransactionPlan`]. `closure_ledger` is a callback rather
/// than a plain value: the ledger postimage the caller wants to stage
/// legitimately *names this very transaction* (`ArchiveClosure::
/// transaction_id`), which would otherwise make the plan's `id` depend on
/// content that depends on `id` — an unresolvable cycle. Breaking it here
/// mirrors how `staged` paths are derived only after `id` is known: `id` is
/// computed from every *ordinary* target, the directory move, and
/// `final_scoped_digest` (never from the ledger's own bytes), and only then
/// is `closure_ledger(id)` invoked so the caller can embed the real,
/// now-known transaction id into the ledger content it returns.
pub fn build_plan<F>(
    root: &Path,
    change: &str,
    base_commit: OidText,
    writes: Vec<TargetWrite>,
    directory_move: DirectoryMoveInput,
    final_scoped_digest: Digest,
    closure_ledger: F,
) -> TxResult<ArchiveTransactionPlan>
where
    F: FnOnce(Digest) -> TargetWrite,
{
    if writes.len() > MAX_TARGETS {
        return Err(TransactionError::LimitExceeded(format!(
            "{} targets exceeds the {MAX_TARGETS}-target limit",
            writes.len()
        )));
    }
    let mut seen_paths: Vec<&str> = Vec::new();
    let mut total_bytes: u64 = 0;
    for w in &writes {
        if w.bytes.len() as u64 > MAX_TARGET_BYTES {
            return Err(TransactionError::LimitExceeded(format!(
                "target {:?} exceeds the {MAX_TARGET_BYTES}-byte limit",
                w.target
            )));
        }
        if seen_paths.contains(&w.target.as_str()) {
            return Err(TransactionError::Corrupt(format!(
                "duplicate transaction target {:?}",
                w.target
            )));
        }
        seen_paths.push(&w.target);
        total_bytes = total_bytes.saturating_add(w.bytes.len() as u64);
    }
    if total_bytes > MAX_STAGED_TOTAL_BYTES {
        return Err(TransactionError::LimitExceeded(format!(
            "{total_bytes} total staged bytes exceeds the {MAX_STAGED_TOTAL_BYTES}-byte limit"
        )));
    }

    let build_target = |w: &TargetWrite| -> TxResult<(RelativePath, ImageState, FileImage)> {
        let path = contained(root, &w.target)?;
        let preimage = match capture(&path)? {
            Captured::Absent => ImageState::Absent,
            Captured::File(f) => ImageState::File(f),
            Captured::Other => {
                return Err(TransactionError::Corrupt(format!(
                    "{} is a symlink or special file; refusing to plan a transaction over it",
                    w.target
                )))
            }
        };
        let postimage = FileImage {
            digest: Digest::of_bytes(&w.bytes),
            mode: 0o100644,
            length: w.bytes.len() as u64,
        };
        Ok((w.target.clone(), preimage, postimage))
    };

    let mut ordinary: Vec<(RelativePath, ImageState, FileImage)> = writes
        .iter()
        .map(build_target)
        .collect::<TxResult<Vec<_>>>()?;
    ordinary.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let source_full = contained(root, &directory_move.source)?;
    let source_md = fs::symlink_metadata(&source_full).map_err(|e| {
        TransactionError::Corrupt(format!(
            "cannot stat directory move source {:?}: {e}",
            directory_move.source
        ))
    })?;
    if source_md.file_type().is_symlink() || !source_md.is_dir() {
        return Err(TransactionError::Corrupt(format!(
            "directory move source {:?} is not a real directory",
            directory_move.source
        )));
    }
    let dest_full = contained(root, &directory_move.destination)?;
    if fs::symlink_metadata(&dest_full).is_ok() {
        return Err(TransactionError::Corrupt(format!(
            "directory move destination {:?} already exists",
            directory_move.destination
        )));
    }
    let tree_digest = tree_digest_of(&source_full)?;

    // Compute the plan id from every field except `id` itself, the closure
    // ledger (see this function's doc comment — it may legitimately embed
    // `id`), and every `staged` path (which is derived from `id` below).
    #[derive(Serialize)]
    struct IdInput<'a> {
        version: u32,
        change: &'a str,
        base_commit: &'a str,
        targets: &'a [(RelativePath, ImageState, FileImage)],
        directory_move: (&'a str, &'a str, Digest),
        final_scoped_digest: Digest,
    }
    let id_input = IdInput {
        version: TRANSACTION_SCHEMA,
        change,
        base_commit: &base_commit,
        targets: &ordinary,
        directory_move: (
            &directory_move.source,
            &directory_move.destination,
            tree_digest,
        ),
        final_scoped_digest,
    };
    let id_bytes = serde_json::to_vec(&id_input)
        .map_err(|e| TransactionError::Corrupt(format!("cannot encode plan id input: {e}")))?;
    let id = Digest::of_bytes(&id_bytes);

    // Only now, with `id` known, ask the caller for the ledger postimage
    // (which may embed `id` itself) and capture its preimage/postimage.
    let ledger_write = closure_ledger(id);
    if ledger_write.bytes.len() as u64 > MAX_TARGET_BYTES {
        return Err(TransactionError::LimitExceeded(format!(
            "closure ledger target {:?} exceeds the {MAX_TARGET_BYTES}-byte limit",
            ledger_write.target
        )));
    }
    if seen_paths.contains(&ledger_write.target.as_str()) {
        return Err(TransactionError::Corrupt(format!(
            "closure ledger target {:?} collides with an ordinary target",
            ledger_write.target
        )));
    }
    let (ledger_path, ledger_preimage, ledger_postimage) = build_target(&ledger_write)?;

    let staged_for = |target: &str| -> RelativePath {
        staged_dir(root, id)
            .join(target)
            .strip_prefix(root)
            .expect("staged path is under root by construction")
            .to_string_lossy()
            .replace('\\', "/")
    };

    let targets = ordinary
        .into_iter()
        .map(|(target, preimage, postimage)| TransactionTarget {
            staged: staged_for(&target),
            target,
            preimage,
            postimage,
        })
        .collect();
    let closure_ledger_target = TransactionTarget {
        staged: staged_for(&ledger_path),
        target: ledger_path,
        preimage: ledger_preimage,
        postimage: ledger_postimage,
    };

    Ok(ArchiveTransactionPlan {
        version: TRANSACTION_SCHEMA,
        id,
        change: change.to_string(),
        base_commit,
        targets,
        directory_move: DirectoryMove {
            source: directory_move.source,
            destination: directory_move.destination,
            tree_digest,
        },
        closure_ledger: closure_ledger_target,
        final_scoped_digest,
    })
}

// =====================================================================
// Preparation: durable staging + journal + pointer (Preparing -> Prepared)
// =====================================================================

/// Write `bytes` to an exclusive new file at `path`, `sync_all`, then
/// re-open non-following and verify the tuple matches `expect`.
fn stage_one(path: &Path, bytes: &[u8], expect: &FileImage) -> TxResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
        f.write_all(bytes)?;
        io_fsync(&f, path)?;
    }
    // Enforce a stable, non-executable mode regardless of umask (every
    // postimage in this system is spec/doc/JSON text).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    match capture(path)? {
        Captured::File(actual) if actual == *expect => Ok(()),
        other => Err(TransactionError::Corrupt(format!(
            "staged file {} did not verify after write (got {:?}, want {:?})",
            path.display(),
            other,
            expect
        ))),
    }
}

/// Durably stage every postimage and write the journal + pending pointer,
/// driving `Preparing` -> `Prepared`. `contents` must have exactly one entry
/// per target in `plan.targets` plus `plan.closure_ledger`, keyed by target
/// path, with bytes whose digest matches that target's planned postimage.
///
/// If this returns `Err`, no project target has changed — only paths under
/// this plan's own `.mpd/tmp/archive/<id>/` subtree may have been created,
/// and only those are safe to clean up.
pub fn prepare(
    root: &Path,
    plan: &ArchiveTransactionPlan,
    contents: &BTreeMap<RelativePath, Vec<u8>>,
) -> TxResult<()> {
    match fs::symlink_metadata(pointer_path(root)) {
        Ok(_) => {
            return Err(TransactionError::Refused(
                "a closure is already pending; run `mpd closure recover` or `mpd closure abandon` first".into(),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if contents.len() != plan.targets.len() + 1 {
        return Err(TransactionError::Refused(
            "staged content keys do not exactly match the transaction targets".into(),
        ));
    }
    // A crash before the pointer is durably installed may leave only this
    // content-addressed scratch subtree. No project target can have changed at
    // that stage, so an exact-id retry may discard and deterministically
    // recreate only its own ignored metadata.
    let orphan = transaction_dir(root, plan.id);
    match fs::symlink_metadata(&orphan) {
        Ok(md) if md.file_type().is_symlink() || !md.is_dir() => {
            return Err(TransactionError::Corrupt(
                "transaction scratch path is not a real directory".into(),
            ));
        }
        Ok(_) => fs::remove_dir_all(&orphan)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let all_targets: Vec<&TransactionTarget> = plan
        .targets
        .iter()
        .chain(std::iter::once(&plan.closure_ledger))
        .collect();
    for t in &all_targets {
        let bytes = contents.get(&t.target).ok_or_else(|| {
            TransactionError::Corrupt(format!(
                "no staged content supplied for target {:?}",
                t.target
            ))
        })?;
        if Digest::of_bytes(bytes) != t.postimage.digest || bytes.len() as u64 != t.postimage.length
        {
            return Err(TransactionError::Corrupt(format!(
                "supplied content for {:?} does not match its planned postimage",
                t.target
            )));
        }
        let staged_full = contained(root, &t.staged)?;
        stage_one(&staged_full, bytes, &t.postimage)?;
    }

    let dir = transaction_dir(root, plan.id);
    fs::create_dir_all(&dir)?;
    let journal_tmp = dir.join("journal.json.tmp");
    let journal_final = journal_path(root, plan.id);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&journal_tmp)?;
        let json = serde_json::to_vec_pretty(plan)
            .map_err(|e| TransactionError::Corrupt(format!("cannot encode journal: {e}")))?;
        f.write_all(&json)?;
        io_fsync(&f, &journal_tmp)?;
    }
    io_rename(&journal_tmp, &journal_final)?;
    sync_dir(&dir)?;

    let pointer = PendingClosurePointer {
        version: PENDING_POINTER_SCHEMA,
        transaction_id: plan.id,
        change: plan.change.clone(),
        stage: TransactionState::Prepared,
    };
    write_pointer(root, &pointer)?;
    Ok(())
}

/// Atomically replace `.mpd/pending-closure`: write to an exclusive sibling
/// temp file, `sync_all`, rename over the pointer, then sync the parent
/// directory.
fn write_pointer(root: &Path, pointer: &PendingClosurePointer) -> TxResult<()> {
    let dir = mpd_dir(root);
    fs::create_dir_all(&dir)?;
    let final_path = pointer_path(root);
    let tmp_path = dir.join(format!("pending-closure.tmp.{}", std::process::id()));
    {
        // Exclusive create; a leftover same-named temp from a prior crashed
        // writer is removed first (it is `mpd`-owned ignored scratch, never
        // a repository target) rather than causing a spurious failure.
        let _ = fs::remove_file(&tmp_path);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        let json = serde_json::to_vec_pretty(pointer)
            .map_err(|e| TransactionError::Corrupt(format!("cannot encode pointer: {e}")))?;
        f.write_all(&json)?;
        io_fsync(&f, &tmp_path)?;
    }
    io_rename(&tmp_path, &final_path)?;
    sync_dir(&dir)?;
    Ok(())
}

fn read_bounded_non_following(path: &Path, cap: u64, label: &str) -> TxResult<String> {
    let file = open_non_following().open(path)?;
    let md = file.metadata()?;
    if !md.is_file() || md.len() > cap {
        return Err(TransactionError::Corrupt(format!(
            "{label} is not a regular file within its safe size limit"
        )));
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(TransactionError::Corrupt(format!(
            "{label} exceeds the safe size limit"
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| TransactionError::Corrupt(format!("{label} is not valid UTF-8")))
}

fn read_pointer(root: &Path) -> TxResult<Option<PendingClosurePointer>> {
    let path = pointer_path(root);
    let md = match fs::symlink_metadata(&path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if md.file_type().is_symlink() {
        return Err(TransactionError::Corrupt(
            "pending-closure pointer is a symlink; refusing to follow it".into(),
        ));
    }
    if md.len() > MAX_POINTER_BYTES {
        return Err(TransactionError::Corrupt(
            "pending-closure pointer exceeds the safe size limit".into(),
        ));
    }
    let text = read_bounded_non_following(&path, MAX_POINTER_BYTES, "pending-closure pointer")?;
    let pointer: PendingClosurePointer = serde_json::from_str(&text)
        .map_err(|e| TransactionError::Corrupt(format!("corrupt pending-closure pointer: {e}")))?;
    if pointer.version != PENDING_POINTER_SCHEMA {
        return Err(TransactionError::Corrupt(format!(
            "unknown pending-closure pointer schema {}",
            pointer.version
        )));
    }
    Ok(Some(pointer))
}

fn read_journal(root: &Path, id: Digest) -> TxResult<ArchiveTransactionPlan> {
    let path = journal_path(root, id);
    let md = match fs::symlink_metadata(&path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(TransactionError::Corrupt(format!(
                "journal for transaction {} is missing",
                id.to_hex()
            )))
        }
        Err(e) => return Err(e.into()),
    };
    if md.file_type().is_symlink() {
        return Err(TransactionError::Corrupt(
            "journal file is a symlink; refusing to follow it".into(),
        ));
    }
    if md.len() > MAX_JOURNAL_BYTES {
        return Err(TransactionError::Corrupt(
            "journal exceeds the safe size limit".into(),
        ));
    }
    let text = read_bounded_non_following(&path, MAX_JOURNAL_BYTES, "journal")?;
    let plan: ArchiveTransactionPlan = serde_json::from_str(&text)
        .map_err(|e| TransactionError::Corrupt(format!("corrupt journal: {e}")))?;
    if plan.version != TRANSACTION_SCHEMA {
        return Err(TransactionError::Corrupt(format!(
            "unknown transaction schema {}",
            plan.version
        )));
    }
    if plan.id != id {
        return Err(TransactionError::Corrupt(
            "journal id does not match the pointer that named it".into(),
        ));
    }
    Ok(plan)
}

// =====================================================================
// Apply state machine
// =====================================================================

/// How one target classifies against its current on-disk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    AlreadyPostimage,
    ExactPreimageStagedReady,
    ThirdState,
}

fn classify_target(root: &Path, t: &TransactionTarget) -> TxResult<Step> {
    let target_full = contained_leaf(root, &t.target)?;
    let current = capture(&target_full)?;
    if captured_matches_file(current, &t.postimage) {
        return Ok(Step::AlreadyPostimage);
    }
    if !captured_matches_image(current, &t.preimage) {
        return Ok(Step::ThirdState);
    }
    let staged_full = contained_leaf(root, &t.staged)?;
    let staged_state = capture(&staged_full)?;
    if captured_matches_file(staged_state, &t.postimage) {
        Ok(Step::ExactPreimageStagedReady)
    } else {
        Ok(Step::ThirdState)
    }
}

/// Replace `target` with the already-staged, already-verified postimage at
/// `staged`: rename over the target (the staged file is itself the sibling
/// temp the protocol describes — it was already durably written+synced in
/// `prepare`), then sync the file and its parent directory.
fn replace_from_staged(root: &Path, t: &TransactionTarget) -> TxResult<()> {
    let target_full = contained(root, &t.target)?;
    let staged_full = contained(root, &t.staged)?;
    if let Some(parent) = target_full.parent() {
        fs::create_dir_all(parent)?;
    }
    io_rename(&staged_full, &target_full)?;
    let f = open_non_following().open(&target_full)?;
    io_fsync(&f, &target_full)?;
    drop(f);
    if let Some(parent) = target_full.parent() {
        sync_dir(parent)?;
    }
    // Re-verify immediately after replacement.
    match capture(&target_full)? {
        Captured::File(actual) if actual == t.postimage => Ok(()),
        other => Err(TransactionError::Corrupt(format!(
            "{} did not verify as its postimage immediately after replacement (got {:?})",
            t.target, other
        ))),
    }
}

/// Apply one target, returning `Ok(true)` if it is now (or already was) an
/// exact postimage, `Ok(false)` if it is a third state requiring manual
/// recovery (no write performed).
fn apply_one(root: &Path, t: &TransactionTarget) -> TxResult<bool> {
    match classify_target(root, t)? {
        Step::AlreadyPostimage => Ok(true),
        Step::ExactPreimageStagedReady => {
            replace_from_staged(root, t)?;
            Ok(true)
        }
        Step::ThirdState => Ok(false),
    }
}

/// The outcome of driving a pending transaction forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveOutcome {
    /// No pending closure exists.
    NothingPending,
    /// The transaction reached (or already was at) `AwaitingCommit`.
    AwaitingCommit,
    /// A third state was found; no write was performed for that step or any
    /// step after it.
    ManualRecoveryRequired {
        /// The offending target's path (or `source -> destination` for the
        /// directory move).
        path: String,
        /// A short, terminal-safe description of the third state found.
        detail: String,
    },
}

/// Load the pending pointer/journal (if any) and drive it forward along the
/// normative state machine: `Prepared`/`Applying` → `Renaming` →
/// `RecordingClosure` → `AwaitingCommit`, or stop at the first third state.
/// This is the single apply code path used by both a normal (non-crash)
/// archive and `mpd closure recover --yes`.
pub fn drive(root: &Path) -> TxResult<DriveOutcome> {
    let Some(pointer) = read_pointer(root)? else {
        return Ok(DriveOutcome::NothingPending);
    };
    let plan = read_journal(root, pointer.transaction_id)?;
    let mut stage = pointer.stage;

    if matches!(stage, TransactionState::Preparing) {
        // A crash strictly between "write journal" and "write pointer as
        // Prepared" leaves no pointer at all (read_pointer returned None
        // above), so a live pointer is never actually seen in `Preparing`.
        // Guard anyway rather than assume.
        return Err(TransactionError::Corrupt(
            "pending pointer is in an unreachable Preparing state".into(),
        ));
    }

    if matches!(
        stage,
        TransactionState::Prepared | TransactionState::Applying
    ) {
        if matches!(stage, TransactionState::Prepared) {
            stage = TransactionState::Applying;
            write_pointer(root, &pointer_with_stage(&pointer, stage))?;
        }
        for t in &plan.targets {
            if !apply_one(root, t)? {
                return Ok(DriveOutcome::ManualRecoveryRequired {
                    path: t.target.clone(),
                    detail: "neither the exact preimage nor the exact postimage was found".into(),
                });
            }
        }
        stage = TransactionState::Renaming;
        write_pointer(root, &pointer_with_stage(&pointer, stage))?;
    }

    if matches!(stage, TransactionState::Renaming) {
        match classify_directory_move(root, &plan.directory_move)? {
            DirStep::AlreadyMoved => {}
            DirStep::NeedsMove => {
                apply_directory_move(root, &plan.directory_move)?;
            }
            DirStep::ThirdState(detail) => {
                return Ok(DriveOutcome::ManualRecoveryRequired {
                    path: format!(
                        "{} -> {}",
                        plan.directory_move.source, plan.directory_move.destination
                    ),
                    detail,
                });
            }
        }
        // Re-verify every ordinary target once more before proceeding.
        for t in &plan.targets {
            if !matches!(classify_target(root, t)?, Step::AlreadyPostimage) {
                return Ok(DriveOutcome::ManualRecoveryRequired {
                    path: t.target.clone(),
                    detail: "postimage no longer verifies after the directory move".into(),
                });
            }
        }
        stage = TransactionState::RecordingClosure;
        write_pointer(root, &pointer_with_stage(&pointer, stage))?;
    }

    if matches!(stage, TransactionState::RecordingClosure) {
        if !apply_one(root, &plan.closure_ledger)? {
            return Ok(DriveOutcome::ManualRecoveryRequired {
                path: plan.closure_ledger.target.clone(),
                detail: "neither the exact preimage nor the exact postimage was found".into(),
            });
        }
        stage = TransactionState::AwaitingCommit;
        write_pointer(root, &pointer_with_stage(&pointer, stage))?;
    }

    debug_assert!(matches!(stage, TransactionState::AwaitingCommit));
    Ok(DriveOutcome::AwaitingCommit)
}

fn pointer_with_stage(p: &PendingClosurePointer, stage: TransactionState) -> PendingClosurePointer {
    PendingClosurePointer { stage, ..p.clone() }
}

enum DirStep {
    AlreadyMoved,
    NeedsMove,
    ThirdState(String),
}

fn classify_directory_move(root: &Path, mv: &DirectoryMove) -> TxResult<DirStep> {
    let source_full = contained_leaf(root, &mv.source)?;
    let dest_full = contained_leaf(root, &mv.destination)?;
    let source_exists = source_full.symlink_metadata().is_ok();
    let dest_exists = dest_full.symlink_metadata().is_ok();
    match (source_exists, dest_exists) {
        (true, false) => {
            let source_md = fs::symlink_metadata(&source_full)?;
            if !source_md.is_dir() {
                return Ok(DirStep::ThirdState(
                    "directory move source is not a directory".into(),
                ));
            }
            match tree_digest_of(&source_full) {
                Ok(d) if d == mv.tree_digest => Ok(DirStep::NeedsMove),
                Ok(_) => Ok(DirStep::ThirdState(
                    "directory move source tree no longer matches its planned identity".into(),
                )),
                Err(e) => Ok(DirStep::ThirdState(format!(
                    "cannot hash directory move source: {e}"
                ))),
            }
        }
        (false, true) => {
            let dest_md = fs::symlink_metadata(&dest_full)?;
            if !dest_md.is_dir() {
                return Ok(DirStep::ThirdState(
                    "directory move destination is not a directory".into(),
                ));
            }
            match tree_digest_of(&dest_full) {
                Ok(d) if d == mv.tree_digest => Ok(DirStep::AlreadyMoved),
                Ok(_) => Ok(DirStep::ThirdState(
                    "directory move destination tree does not match its planned identity".into(),
                )),
                Err(e) => Ok(DirStep::ThirdState(format!(
                    "cannot hash directory move destination: {e}"
                ))),
            }
        }
        (true, true) => Ok(DirStep::ThirdState(
            "both the directory move source and destination exist".into(),
        )),
        (false, false) => Ok(DirStep::ThirdState(
            "neither the directory move source nor destination exists".into(),
        )),
    }
}

fn apply_directory_move(root: &Path, mv: &DirectoryMove) -> TxResult<()> {
    let source_full = contained(root, &mv.source)?;
    let dest_full = contained(root, &mv.destination)?;
    if let Some(parent) = dest_full.parent() {
        fs::create_dir_all(parent)?;
    }
    io_rename(&source_full, &dest_full)?;
    sync_dir(&dest_full)?;
    if let Some(parent) = dest_full.parent() {
        sync_dir(parent)?;
    }
    if let Some(parent) = source_full.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

// =====================================================================
// Read-only inspection / TransactionView (recover & abandon preview)
// =====================================================================

/// How one target/directory-move classifies for a read-only preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepClass {
    /// Already the exact postimage; nothing to do.
    AlreadyComplete,
    /// Exact preimage, exact staged postimage; roll-forward would apply.
    Pending,
    /// Neither state matches; roll-forward would refuse.
    ThirdState,
}

/// One bounded, human/JSON-safe classification line in a [`TransactionView`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TargetClassification {
    /// The affected repository-relative path (or `source -> destination`
    /// for the directory move).
    pub path: String,
    /// This step's classification.
    pub class: StepClass,
    /// A short, terminal-safe description.
    pub detail: String,
}

/// The shared, non-mutating view both `mpd closure recover` and `mpd closure
/// abandon` render in human and JSON form.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TransactionView {
    /// The pending transaction's id.
    pub transaction_id: Digest,
    /// The change being archived.
    pub change: String,
    /// The transaction's current durable stage.
    pub stage: TransactionState,
    /// An honest description of the durability level actually provided —
    /// never claims filesystem-independent atomicity.
    pub durability_note: String,
    /// Total number of affected paths (targets + the directory move +
    /// the closure ledger), independent of how many are shown below.
    pub affected_path_count: usize,
    /// Bounded per-path classifications (see `truncated` for whether more
    /// exist beyond this list).
    pub classifications: Vec<TargetClassification>,
    /// Whether `classifications` was truncated to stay bounded.
    pub truncated: bool,
    /// `true` only when every pending step is exact-preimage-plus-exact-
    /// staged-postimage — i.e. `recover --yes` would converge without
    /// refusing anywhere.
    pub write_eligible: bool,
    /// Concrete reasons write_eligible is `false` (empty when `true`).
    pub blockers: Vec<String>,
    /// One safe next action.
    pub next: String,
}

/// Maximum classification rows shown in a [`TransactionView`] before
/// truncating (the total is still reported via `affected_path_count`).
pub const MAX_VIEW_ROWS: usize = 50;

const DURABILITY_NOTE: &str = "each staged file and the journal are fsync'd before the pending pointer advances, and every replacement is fsync'd (file and, where the platform supports it, parent directory) immediately after; this is not a claim of power-loss atomicity beyond what the filesystem/OS actually provides, and preimage bytes are not retained, so recovery is completion-only, never rollback.";

/// Read-only: load the pending pointer/journal (if any) and classify every
/// step without writing anything. Used for both `mpd closure recover` and
/// `mpd closure abandon` previews.
pub fn inspect(root: &Path) -> TxResult<Option<TransactionView>> {
    let Some(pointer) = read_pointer(root)? else {
        return Ok(None);
    };
    let plan = read_journal(root, pointer.transaction_id)?;

    let mut rows: Vec<TargetClassification> = Vec::new();
    let mut all_complete = true;
    let mut blockers = Vec::new();

    for t in &plan.targets {
        let class = classify_target(root, t)?;
        push_target_row(&mut rows, t, class);
        note_blocker(&mut all_complete, &mut blockers, &t.target, class);
    }

    let dir_row_path = format!(
        "{} -> {}",
        plan.directory_move.source, plan.directory_move.destination
    );
    let dir_class = match classify_directory_move(root, &plan.directory_move)? {
        DirStep::AlreadyMoved => StepClass::AlreadyComplete,
        DirStep::NeedsMove => StepClass::Pending,
        DirStep::ThirdState(detail) => {
            blockers.push(format!("directory move {dir_row_path}: {detail}"));
            all_complete = false;
            StepClass::ThirdState
        }
    };
    rows.push(TargetClassification {
        path: dir_row_path,
        class: dir_class,
        detail: dir_class_detail(dir_class),
    });

    let ledger_class = classify_target(root, &plan.closure_ledger)?;
    push_target_row(&mut rows, &plan.closure_ledger, ledger_class);
    note_blocker(
        &mut all_complete,
        &mut blockers,
        &plan.closure_ledger.target,
        ledger_class,
    );

    let affected_path_count = rows.len();
    let truncated = rows.len() > MAX_VIEW_ROWS;
    rows.truncate(MAX_VIEW_ROWS);

    let write_eligible = all_complete && !matches!(pointer.stage, TransactionState::AwaitingCommit);
    let next = if matches!(pointer.stage, TransactionState::AwaitingCommit) {
        "mpd closure abandon --yes (after committing the archived result), or commit the archived result directly".to_string()
    } else if write_eligible {
        "mpd closure recover --yes".to_string()
    } else {
        "resolve the reported third state manually, then re-run `mpd closure recover` to re-check"
            .to_string()
    };

    Ok(Some(TransactionView {
        transaction_id: pointer.transaction_id,
        change: pointer.change,
        stage: pointer.stage,
        durability_note: DURABILITY_NOTE.to_string(),
        affected_path_count,
        classifications: rows,
        truncated,
        write_eligible,
        blockers,
        next,
    }))
}

fn push_target_row(rows: &mut Vec<TargetClassification>, t: &TransactionTarget, class: Step) {
    let class = match class {
        Step::AlreadyPostimage => StepClass::AlreadyComplete,
        Step::ExactPreimageStagedReady => StepClass::Pending,
        Step::ThirdState => StepClass::ThirdState,
    };
    rows.push(TargetClassification {
        path: t.target.clone(),
        class,
        detail: dir_class_detail(class),
    });
}

fn note_blocker(all_complete: &mut bool, blockers: &mut Vec<String>, path: &str, class: Step) {
    if matches!(class, Step::ThirdState) {
        *all_complete = false;
        blockers.push(format!(
            "{path}: neither the exact preimage nor the exact postimage was found"
        ));
    }
}

fn dir_class_detail(class: StepClass) -> String {
    match class {
        StepClass::AlreadyComplete => "already the exact postimage".to_string(),
        StepClass::Pending => "exact preimage; staged postimage verified and ready".to_string(),
        StepClass::ThirdState => {
            "neither the exact preimage nor the exact postimage was found".to_string()
        }
    }
}

/// `mpd closure recover --yes`: converge an eligible pending transaction to
/// `AwaitingCommit`. Refuses **before any write** if [`inspect`] would
/// report `write_eligible: false` (a third state, corrupt journal/staging,
/// or a missing pending closure) or the pointer is already `AwaitingCommit`.
pub fn recover_apply(root: &Path) -> TxResult<TransactionView> {
    let view = inspect(root)?
        .ok_or_else(|| TransactionError::Refused("no pending closure to recover".into()))?;
    if matches!(view.stage, TransactionState::AwaitingCommit) {
        return Err(TransactionError::Refused(
            "the pending closure already reached AwaitingCommit; nothing to roll forward".into(),
        ));
    }
    if !view.write_eligible {
        return Err(TransactionError::Refused(format!(
            "cannot roll forward: {}",
            view.blockers.join("; ")
        )));
    }
    match drive(root)? {
        DriveOutcome::AwaitingCommit => {}
        DriveOutcome::NothingPending => {
            return Err(TransactionError::Refused(
                "no pending closure to recover".into(),
            ))
        }
        DriveOutcome::ManualRecoveryRequired { path, detail } => {
            return Err(TransactionError::Refused(format!(
                "roll-forward stopped at {path}: {detail} (no write was performed for this step)"
            )))
        }
    }
    inspect(root)?
        .ok_or_else(|| TransactionError::Corrupt("pending closure vanished during recovery".into()))
}

/// `mpd closure abandon --yes`: delete only this transaction's own ignored
/// metadata (pointer + journal + staged files), and only from
/// `AwaitingCommit`. Never touches a repository target, the ledger history,
/// the index, commits, or remote state.
pub fn abandon_apply(root: &Path) -> TxResult<()> {
    let pointer = read_pointer(root)?
        .ok_or_else(|| TransactionError::Refused("no pending closure to abandon".into()))?;
    if !matches!(pointer.stage, TransactionState::AwaitingCommit) {
        return Err(TransactionError::Refused(format!(
            "abandon is only permitted once the pending closure reaches AwaitingCommit (currently {:?})",
            pointer.stage
        )));
    }
    // Validate the journal still resolves/contains before deleting anything,
    // so a corrupt/foreign pointer can never trigger deletion of an
    // unrelated path.
    let _ = read_journal(root, pointer.transaction_id)?;
    let dir = transaction_dir(root, pointer.transaction_id);
    crate::project::assert_contained(root, &dir)
        .map_err(|e| TransactionError::Corrupt(e.to_string()))?;
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    let ptr_path = pointer_path(root);
    if ptr_path.exists() {
        fs::remove_file(&ptr_path)?;
    }
    sync_dir(&mpd_dir(root))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn init_project(root: &Path) {
        fs::create_dir_all(root.join("openspec/specs")).unwrap();
        fs::create_dir_all(root.join("openspec/changes/add-thing/specs/thing")).unwrap();
        fs::write(
            root.join("openspec/changes/add-thing/.openspec.yaml"),
            "schema: mpd\ncreated: 2026-01-01\n",
        )
        .unwrap();
        fs::write(
            root.join("openspec/changes/add-thing/proposal.md"),
            "# Proposal\n",
        )
        .unwrap();
        fs::create_dir_all(root.join(".mpd/state")).unwrap();
        fs::write(
            root.join(".mpd/state/add-thing.json"),
            "{\"change\":\"add-thing\"}",
        )
        .unwrap();
    }

    fn sample_writes(root: &Path) -> (Vec<TargetWrite>, TargetWrite, DirectoryMoveInput) {
        let _ = root;
        let writes = vec![TargetWrite {
            target: "openspec/specs/thing/spec.md".to_string(),
            bytes: b"# Thing\n\n## Requirements\n".to_vec(),
        }];
        let ledger = TargetWrite {
            target: ".mpd/state/add-thing.json".to_string(),
            bytes: b"{\"change\":\"add-thing\",\"archived\":true}".to_vec(),
        };
        let mv = DirectoryMoveInput {
            source: "openspec/changes/add-thing".to_string(),
            destination: "openspec/changes/archive/2026-01-01-add-thing".to_string(),
        };
        (writes, ledger, mv)
    }

    fn build_sample(root: &Path) -> ArchiveTransactionPlan {
        let (writes, ledger, mv) = sample_writes(root);
        build_plan(
            root,
            "add-thing",
            "a".repeat(40),
            writes,
            mv,
            Digest::of_bytes(b"final"),
            |_id| ledger,
        )
        .unwrap()
    }

    fn contents_for(plan: &ArchiveTransactionPlan, root: &Path) -> BTreeMap<RelativePath, Vec<u8>> {
        let _ = root;
        let mut map = BTreeMap::new();
        for t in plan
            .targets
            .iter()
            .chain(std::iter::once(&plan.closure_ledger))
        {
            // Reconstruct the exact bytes from the sample fixtures by target
            // path (tests always call this against `sample_writes`' output).
            let bytes = match t.target.as_str() {
                "openspec/specs/thing/spec.md" => b"# Thing\n\n## Requirements\n".to_vec(),
                ".mpd/state/add-thing.json" => {
                    b"{\"change\":\"add-thing\",\"archived\":true}".to_vec()
                }
                "openspec/specs/other/spec.md" => b"# Other\n\n## Requirements\n".to_vec(),
                other => panic!("unexpected target in test fixture: {other}"),
            };
            map.insert(t.target.clone(), bytes);
        }
        map
    }

    #[test]
    fn plan_round_trips_through_json() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let json = serde_json::to_string_pretty(&plan).unwrap();
        let back: ArchiveTransactionPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }

    #[test]
    fn image_state_tags_are_stable_and_distinct() {
        let absent = serde_json::to_value(ImageState::Absent).unwrap();
        assert_eq!(absent["kind"], "absent");
        let file = ImageState::File(FileImage {
            digest: Digest::of_bytes(b"x"),
            mode: 0o100644,
            length: 1,
        });
        let file_json = serde_json::to_value(&file).unwrap();
        assert_eq!(file_json["kind"], "file");
        assert_ne!(absent, file_json);
    }

    #[test]
    fn transaction_state_slugs_are_kebab_case() {
        let states = [
            (TransactionState::Preparing, "\"preparing\""),
            (TransactionState::Prepared, "\"prepared\""),
            (TransactionState::Applying, "\"applying\""),
            (TransactionState::Renaming, "\"renaming\""),
            (TransactionState::RecordingClosure, "\"recording-closure\""),
            (TransactionState::AwaitingCommit, "\"awaiting-commit\""),
        ];
        for (state, expected) in states {
            assert_eq!(serde_json::to_string(&state).unwrap(), expected);
        }
    }

    #[test]
    fn unknown_transaction_state_fails_closed_rather_than_defaulting() {
        let err = serde_json::from_str::<TransactionState>("\"mid-flight\"");
        assert!(err.is_err());
    }

    // -----------------------------------------------------------------
    // Test harness: a real, isolated temp directory per test (no shared
    // global state), cleaned up on drop.
    // -----------------------------------------------------------------
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        // `cargo test` runs tests on multiple threads concurrently; neither
        // the PID nor a timestamp alone is guaranteed unique across threads
        // sampled close together, so an explicit per-process atomic counter
        // is the only reliable uniqueness source here.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "mpd-tx-test-{}-{}-{:?}",
            std::process::id(),
            n,
            std::thread::current().id()
        ));
        fs::create_dir_all(&base).unwrap();
        TempDir(base)
    }

    // -----------------------------------------------------------------
    // build_plan
    // -----------------------------------------------------------------

    #[test]
    fn build_plan_captures_absent_preimage_for_new_spec() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].preimage, ImageState::Absent);
        assert_eq!(
            plan.targets[0].postimage.length,
            "# Thing\n\n## Requirements\n".len() as u64
        );
    }

    #[test]
    fn build_plan_captures_existing_preimage_for_ledger() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        match &plan.closure_ledger.preimage {
            ImageState::File(f) => assert_eq!(f.length, "{\"change\":\"add-thing\"}".len() as u64),
            ImageState::Absent => panic!("ledger preimage should be the existing file"),
        }
    }

    #[test]
    fn build_plan_is_deterministic_for_identical_inputs() {
        let dir = tempdir();
        init_project(dir.path());
        let a = build_sample(dir.path());
        let b = build_sample(dir.path());
        assert_eq!(a.id, b.id);
        assert_eq!(a, b);
    }

    #[test]
    fn build_plan_lets_the_closure_ledger_callback_embed_the_real_plan_id() {
        // The whole point of `closure_ledger` being a callback: the ledger
        // bytes it returns may legitimately reference `id`, and the id it
        // observes must be the exact same id the returned plan carries
        // (this is what breaks the ArchiveClosure::transaction_id
        // self-reference cycle).
        let dir = tempdir();
        init_project(dir.path());
        let (writes, base_ledger, mv) = sample_writes(dir.path());
        let observed_id = std::cell::RefCell::new(None);
        let plan = build_plan(
            dir.path(),
            "add-thing",
            "a".repeat(40),
            writes,
            mv,
            Digest::of_bytes(b"final"),
            |id| {
                *observed_id.borrow_mut() = Some(id);
                TargetWrite {
                    target: base_ledger.target,
                    bytes: format!("{{\"transaction_id\":\"{}\"}}", id.to_hex()).into_bytes(),
                }
            },
        )
        .unwrap();
        assert_eq!(observed_id.into_inner(), Some(plan.id));
        let ledger_bytes_digest =
            Digest::of_bytes(format!("{{\"transaction_id\":\"{}\"}}", plan.id.to_hex()).as_bytes());
        assert_eq!(plan.closure_ledger.postimage.digest, ledger_bytes_digest);
    }

    #[test]
    fn build_plan_id_is_independent_of_ledger_content() {
        // Changing only the ledger's bytes (as would happen when its
        // embedded transaction id legitimately differs run to run) must
        // never change the plan id — otherwise the id/ledger relationship
        // would still be circular.
        let dir = tempdir();
        init_project(dir.path());
        let (writes_a, _ledger, mv_a) = sample_writes(dir.path());
        let plan_a = build_plan(
            dir.path(),
            "add-thing",
            "a".repeat(40),
            writes_a,
            mv_a,
            Digest::of_bytes(b"final"),
            |_id| TargetWrite {
                target: ".mpd/state/add-thing.json".to_string(),
                bytes: b"ledger-variant-one".to_vec(),
            },
        )
        .unwrap();
        let (writes_b, _ledger, mv_b) = sample_writes(dir.path());
        let plan_b = build_plan(
            dir.path(),
            "add-thing",
            "a".repeat(40),
            writes_b,
            mv_b,
            Digest::of_bytes(b"final"),
            |_id| TargetWrite {
                target: ".mpd/state/add-thing.json".to_string(),
                bytes: b"a completely different ledger body".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(plan_a.id, plan_b.id);
    }

    #[test]
    fn build_plan_rejects_duplicate_target_paths() {
        let dir = tempdir();
        init_project(dir.path());
        let (mut writes, ledger, mv) = sample_writes(dir.path());
        writes.push(writes[0].clone());
        let err = build_plan(
            dir.path(),
            "add-thing",
            "a".repeat(40),
            writes,
            mv,
            Digest::of_bytes(b"x"),
            |_id| ledger,
        )
        .unwrap_err();
        assert!(matches!(err, TransactionError::Corrupt(_)));
    }

    #[test]
    fn build_plan_rejects_symlinked_target() {
        let dir = tempdir();
        init_project(dir.path());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            fs::create_dir_all(dir.path().join("openspec/specs/thing")).unwrap();
            symlink(
                "/etc/passwd",
                dir.path().join("openspec/specs/thing/spec.md"),
            )
            .unwrap();
            let (writes, ledger, mv) = sample_writes(dir.path());
            let err = build_plan(
                dir.path(),
                "add-thing",
                "a".repeat(40),
                writes,
                mv,
                Digest::of_bytes(b"x"),
                |_id| ledger,
            )
            .unwrap_err();
            assert!(matches!(err, TransactionError::Corrupt(_)));
        }
    }

    #[test]
    fn build_plan_rejects_oversized_target() {
        let dir = tempdir();
        init_project(dir.path());
        let (_, ledger, mv) = sample_writes(dir.path());
        let writes = vec![TargetWrite {
            target: "openspec/specs/thing/spec.md".to_string(),
            bytes: vec![0u8; (MAX_TARGET_BYTES + 1) as usize],
        }];
        let err = build_plan(
            dir.path(),
            "add-thing",
            "a".repeat(40),
            writes,
            mv,
            Digest::of_bytes(b"x"),
            |_id| ledger,
        )
        .unwrap_err();
        assert!(matches!(err, TransactionError::LimitExceeded(_)));
    }

    #[test]
    fn build_plan_rejects_too_many_targets() {
        let dir = tempdir();
        init_project(dir.path());
        let (_, ledger, mv) = sample_writes(dir.path());
        let writes: Vec<TargetWrite> = (0..MAX_TARGETS + 1)
            .map(|i| TargetWrite {
                target: format!("openspec/specs/thing/spec-{i}.md"),
                bytes: b"x".to_vec(),
            })
            .collect();
        let err = build_plan(
            dir.path(),
            "add-thing",
            "a".repeat(40),
            writes,
            mv,
            Digest::of_bytes(b"x"),
            |_id| ledger,
        )
        .unwrap_err();
        assert!(matches!(err, TransactionError::LimitExceeded(_)));
    }

    // -----------------------------------------------------------------
    // prepare + drive: the happy path end to end
    // -----------------------------------------------------------------

    #[test]
    fn prepare_then_drive_converges_to_awaiting_commit_and_writes_real_content() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);

        let spec = fs::read_to_string(dir.path().join("openspec/specs/thing/spec.md")).unwrap();
        assert_eq!(spec, "# Thing\n\n## Requirements\n");
        let ledger = fs::read_to_string(dir.path().join(".mpd/state/add-thing.json")).unwrap();
        assert_eq!(ledger, "{\"change\":\"add-thing\",\"archived\":true}");
        assert!(!dir.path().join("openspec/changes/add-thing").exists());
        assert!(dir
            .path()
            .join("openspec/changes/archive/2026-01-01-add-thing")
            .is_dir());

        let pointer = read_pointer(dir.path()).unwrap().unwrap();
        assert_eq!(pointer.stage, TransactionState::AwaitingCommit);
    }

    #[test]
    fn drive_is_idempotent_once_awaiting_commit() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        // Calling drive again must not error, double-write, or move state.
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        let spec = fs::read_to_string(dir.path().join("openspec/specs/thing/spec.md")).unwrap();
        assert_eq!(spec, "# Thing\n\n## Requirements\n");
    }

    #[test]
    fn drive_with_no_pointer_reports_nothing_pending() {
        let dir = tempdir();
        init_project(dir.path());
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::NothingPending);
    }

    // -----------------------------------------------------------------
    // Crash injection: after prepare, before any target replacement.
    // -----------------------------------------------------------------

    #[test]
    fn crash_after_prepare_before_any_replacement_recovers_cleanly() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        // "Crash" = we never called drive(). Simulate a fresh process by
        // just calling drive() now, exactly like `closure recover --yes`.
        let view = inspect(dir.path()).unwrap().unwrap();
        assert_eq!(view.stage, TransactionState::Prepared);
        assert!(view.write_eligible);
        assert_eq!(
            recover_apply(dir.path()).unwrap().stage,
            TransactionState::AwaitingCommit
        );
        assert!(dir
            .path()
            .join("openspec/changes/archive/2026-01-01-add-thing")
            .is_dir());
    }

    // -----------------------------------------------------------------
    // Crash injection: mid-Applying, after ONE of two targets replaced.
    // -----------------------------------------------------------------

    #[test]
    fn crash_after_one_of_two_targets_replaced_completes_only_the_remaining_one() {
        let dir = tempdir();
        init_project(dir.path());
        fs::create_dir_all(dir.path().join("openspec/specs/other")).unwrap();
        let mut writes = sample_writes(dir.path()).0;
        writes.push(TargetWrite {
            target: "openspec/specs/other/spec.md".to_string(),
            bytes: b"# Other\n\n## Requirements\n".to_vec(),
        });
        let ledger = sample_writes(dir.path()).1;
        let mv = sample_writes(dir.path()).2;
        let plan = build_plan(
            dir.path(),
            "add-thing",
            "a".repeat(40),
            writes,
            mv,
            Digest::of_bytes(b"final"),
            |_id| ledger,
        )
        .unwrap();
        let mut contents = contents_for(&plan, dir.path());
        contents.insert(
            "openspec/specs/other/spec.md".to_string(),
            b"# Other\n\n## Requirements\n".to_vec(),
        );
        prepare(dir.path(), &plan, &contents).unwrap();

        // Simulate the process dying after replacing exactly the FIRST
        // canonical-order target (apply_one is the same primitive drive()
        // uses internally for each target).
        let first = &plan.targets[0];
        apply_one(dir.path(), first).unwrap();
        assert!(fs::read(dir.path().join(&first.target)).is_ok());
        // The second target's staged sibling must still be untouched.
        let second = &plan.targets[1];
        assert!(fs::symlink_metadata(dir.path().join(&second.staged)).is_ok());

        // Recovery must complete the second target and never re-touch the
        // first (its content already matches — a re-apply would be a no-op
        // by construction, but assert content is unchanged either way).
        assert_eq!(
            recover_apply(dir.path()).unwrap().stage,
            TransactionState::AwaitingCommit
        );
        let first_content = fs::read_to_string(dir.path().join(&first.target)).unwrap();
        let second_content = fs::read_to_string(dir.path().join(&second.target)).unwrap();
        assert!(first_content.starts_with("# "));
        assert!(second_content.starts_with("# "));
    }

    // -----------------------------------------------------------------
    // Crash injection: after directory rename, before recording closure.
    // -----------------------------------------------------------------

    #[test]
    fn crash_after_directory_rename_before_closure_completes_only_the_ledger() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();

        // Manually drive through Applying + the directory rename, then stop
        // (simulating a crash) before RecordingClosure.
        for t in &plan.targets {
            apply_one(dir.path(), t).unwrap();
        }
        apply_directory_move(dir.path(), &plan.directory_move).unwrap();
        assert!(dir.path().join(&plan.directory_move.destination).is_dir());
        assert!(!dir.path().join(&plan.directory_move.source).exists());
        // The ledger has NOT been replaced yet.
        let ledger_before =
            fs::read_to_string(dir.path().join(&plan.closure_ledger.target)).unwrap();
        assert_eq!(ledger_before, "{\"change\":\"add-thing\"}");

        let view = inspect(dir.path()).unwrap().unwrap();
        assert!(view.write_eligible);
        assert_eq!(
            recover_apply(dir.path()).unwrap().stage,
            TransactionState::AwaitingCommit
        );
        let ledger_after =
            fs::read_to_string(dir.path().join(&plan.closure_ledger.target)).unwrap();
        assert_eq!(ledger_after, "{\"change\":\"add-thing\",\"archived\":true}");
    }

    #[test]
    fn crash_after_closure_ledger_replaced_is_idempotent_on_recovery() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        for t in &plan.targets {
            apply_one(dir.path(), t).unwrap();
        }
        apply_directory_move(dir.path(), &plan.directory_move).unwrap();
        apply_one(dir.path(), &plan.closure_ledger).unwrap();
        // Pointer is still stuck at an earlier stage on disk (we never
        // called drive/write_pointer past Applying in this manual
        // sequence) — recovery must still converge without double-applying
        // (the ledger file is already exact; re-applying would be a no-op).
        let ledger_content =
            fs::read_to_string(dir.path().join(&plan.closure_ledger.target)).unwrap();
        assert_eq!(
            ledger_content,
            "{\"change\":\"add-thing\",\"archived\":true}"
        );
        assert_eq!(
            recover_apply(dir.path()).unwrap().stage,
            TransactionState::AwaitingCommit
        );
        let ledger_content =
            fs::read_to_string(dir.path().join(&plan.closure_ledger.target)).unwrap();
        assert_eq!(
            ledger_content,
            "{\"change\":\"add-thing\",\"archived\":true}"
        );
    }

    // -----------------------------------------------------------------
    // Third-state refusal: never double-applies, never writes on refusal.
    // -----------------------------------------------------------------

    #[test]
    fn third_state_target_refuses_without_writing_and_reports_manual_recovery() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();

        // Plant a third state: something other than Absent or the exact
        // postimage now sits at the target (simulating unrelated concurrent
        // interference after prepare, before recovery).
        let target_full = dir.path().join(&plan.targets[0].target);
        fs::create_dir_all(target_full.parent().unwrap()).unwrap();
        fs::write(&target_full, "unexpected concurrent content").unwrap();

        match drive(dir.path()).unwrap() {
            DriveOutcome::ManualRecoveryRequired { path, .. } => {
                assert_eq!(path, plan.targets[0].target);
            }
            other => panic!("expected ManualRecoveryRequired, got {other:?}"),
        }
        // No write beyond the plant: directory move must NOT have happened.
        assert!(dir.path().join(&plan.directory_move.source).exists());
        assert!(!dir.path().join(&plan.directory_move.destination).exists());
        // The pointer must still report a non-terminal stage, never
        // AwaitingCommit.
        let pointer = read_pointer(dir.path()).unwrap().unwrap();
        assert_ne!(pointer.stage, TransactionState::AwaitingCommit);
    }

    #[test]
    fn third_state_disables_write_eligibility_and_recover_yes_refuses_before_any_write() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let target_full = dir.path().join(&plan.targets[0].target);
        fs::create_dir_all(target_full.parent().unwrap()).unwrap();
        fs::write(&target_full, "unexpected concurrent content").unwrap();

        let view = inspect(dir.path()).unwrap().unwrap();
        assert!(!view.write_eligible);
        assert!(!view.blockers.is_empty());

        let err = recover_apply(dir.path()).unwrap_err();
        assert!(matches!(err, TransactionError::Refused(_)));
        // Still refused before any write: directory move untouched.
        assert!(dir.path().join(&plan.directory_move.source).exists());
        assert!(!dir.path().join(&plan.directory_move.destination).exists());
    }

    #[test]
    fn symlink_swapped_into_target_after_prepare_is_a_third_state() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target_full = dir.path().join(&plan.targets[0].target);
            fs::create_dir_all(target_full.parent().unwrap()).unwrap();
            symlink("/etc/passwd", &target_full).unwrap();
            match drive(dir.path()).unwrap() {
                DriveOutcome::ManualRecoveryRequired { .. } => {}
                other => {
                    panic!("expected ManualRecoveryRequired for a symlink swap, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn corrupt_staged_file_after_prepare_refuses_without_replacing() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let staged_full = dir.path().join(&plan.targets[0].staged);
        fs::write(&staged_full, "corrupted staged content").unwrap();
        match drive(dir.path()).unwrap() {
            DriveOutcome::ManualRecoveryRequired { path, .. } => {
                assert_eq!(path, plan.targets[0].target)
            }
            other => panic!("expected ManualRecoveryRequired, got {other:?}"),
        }
        assert!(!dir.path().join(&plan.targets[0].target).exists());
    }

    #[test]
    fn truncated_journal_is_refused_as_corrupt() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let jpath = journal_path(dir.path(), plan.id);
        let mut text = fs::read_to_string(&jpath).unwrap();
        text.truncate(text.len() / 2);
        fs::write(&jpath, text).unwrap();
        let err = drive(dir.path()).unwrap_err();
        assert!(matches!(err, TransactionError::Corrupt(_)));
    }

    #[test]
    fn oversized_journal_is_refused_without_reading_it_as_valid() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let jpath = journal_path(dir.path(), plan.id);
        let mut bytes = fs::read(&jpath).unwrap();
        bytes.extend(std::iter::repeat_n(b' ', (MAX_JOURNAL_BYTES as usize) + 1));
        fs::write(&jpath, bytes).unwrap();
        let err = drive(dir.path()).unwrap_err();
        assert!(matches!(err, TransactionError::Corrupt(_)));
    }

    #[test]
    fn symlinked_pointer_is_refused_fail_closed() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let ptr = pointer_path(dir.path());
        fs::remove_file(&ptr).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink("/etc/passwd", &ptr).unwrap();
            let err = drive(dir.path()).unwrap_err();
            assert!(matches!(err, TransactionError::Corrupt(_)));
            // Fail-closed: never deleted or overwritten the symlink.
            assert!(fs::symlink_metadata(&ptr).unwrap().file_type().is_symlink());
        }
    }

    // -----------------------------------------------------------------
    // prepare(): a second concurrent prepare is refused; nothing changes.
    // -----------------------------------------------------------------

    #[test]
    fn prepare_refuses_when_a_closure_is_already_pending() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let err = prepare(dir.path(), &plan, &contents).unwrap_err();
        assert!(matches!(err, TransactionError::Refused(_)));
    }

    // -----------------------------------------------------------------
    // recover preview is byte-for-byte non-mutating.
    // -----------------------------------------------------------------

    #[test]
    fn inspect_never_mutates_the_repository_or_the_pointer() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let pointer_before = fs::read(pointer_path(dir.path())).unwrap();
        let journal_before = fs::read(journal_path(dir.path(), plan.id)).unwrap();
        assert!(!dir.path().join(&plan.targets[0].target).exists());

        let _ = inspect(dir.path()).unwrap();
        let _ = inspect(dir.path()).unwrap();

        assert_eq!(fs::read(pointer_path(dir.path())).unwrap(), pointer_before);
        assert_eq!(
            fs::read(journal_path(dir.path(), plan.id)).unwrap(),
            journal_before
        );
        assert!(!dir.path().join(&plan.targets[0].target).exists());
    }

    // -----------------------------------------------------------------
    // abandon: only from AwaitingCommit, metadata-only.
    // -----------------------------------------------------------------

    #[test]
    fn abandon_refuses_before_awaiting_commit() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let err = abandon_apply(dir.path()).unwrap_err();
        assert!(matches!(err, TransactionError::Refused(_)));
        assert!(pointer_path(dir.path()).exists());
    }

    #[test]
    fn abandon_yes_removes_only_owned_metadata_from_awaiting_commit() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);

        // Repository targets must survive abandon untouched.
        let spec_before =
            fs::read_to_string(dir.path().join("openspec/specs/thing/spec.md")).unwrap();
        abandon_apply(dir.path()).unwrap();
        let spec_after =
            fs::read_to_string(dir.path().join("openspec/specs/thing/spec.md")).unwrap();
        assert_eq!(spec_before, spec_after);
        assert!(dir
            .path()
            .join("openspec/changes/archive/2026-01-01-add-thing")
            .is_dir());

        // Only the pointer + journal/staging subtree are gone.
        assert!(!pointer_path(dir.path()).exists());
        assert!(!transaction_dir(dir.path(), plan.id).exists());
    }

    #[test]
    fn abandon_with_no_pending_closure_refuses() {
        let dir = tempdir();
        init_project(dir.path());
        let err = abandon_apply(dir.path()).unwrap_err();
        assert!(matches!(err, TransactionError::Refused(_)));
    }

    // -----------------------------------------------------------------
    // Human/JSON parity: TransactionView serializes with the same fields
    // the text renderer would read.
    // -----------------------------------------------------------------

    #[test]
    fn transaction_view_serializes_with_stable_stage_and_class_slugs() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let view = inspect(dir.path()).unwrap().unwrap();
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["stage"], "prepared");
        assert_eq!(json["write-eligible"], serde_json::Value::Bool(true));
        assert!(json["classifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["class"] == "pending"));
    }

    // -----------------------------------------------------------------
    // Crash injection (3.7 gap a): MID-STAGING — some staged postimages
    // are already durable on disk, but the journal was never written and
    // no pointer exists yet. Nothing is pending, recovery is a safe
    // no-op, and no repository target was touched. A same-id retry then
    // discards the orphan scratch subtree and converges.
    // -----------------------------------------------------------------
    #[test]
    fn crash_mid_staging_before_journal_leaves_nothing_pending_and_no_target_touched() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());

        // Simulate a crash after staging ONLY the first target's
        // postimage, before the journal/pointer are written. `stage_one`
        // is the exact primitive `prepare` uses for each target.
        let first = &plan.targets[0];
        let staged_full = contained(dir.path(), &first.staged).unwrap();
        stage_one(
            &staged_full,
            b"# Thing\n\n## Requirements\n",
            &first.postimage,
        )
        .unwrap();

        // The durable "pending" markers never appeared.
        assert!(!journal_path(dir.path(), plan.id).exists());
        assert!(!pointer_path(dir.path()).exists());

        // Recovery never invents work from a bare staged file.
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::NothingPending);
        assert!(inspect(dir.path()).unwrap().is_none());

        // No repository target was touched: the new spec is still absent,
        // the ledger still holds its original preimage, and the directory
        // move never happened.
        assert!(!dir.path().join(&first.target).exists());
        let ledger = fs::read_to_string(dir.path().join(".mpd/state/add-thing.json")).unwrap();
        assert_eq!(ledger, "{\"change\":\"add-thing\"}");
        assert!(dir.path().join(&plan.directory_move.source).exists());
        assert!(!dir.path().join(&plan.directory_move.destination).exists());

        // A same-id retry discards the orphan scratch subtree and converges.
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        assert!(dir.path().join(&first.target).exists());
    }

    // -----------------------------------------------------------------
    // Crash injection (3.7 gap b): STRICTLY BETWEEN the journal
    // sync/rename and the pointer install — the journal and every staged
    // file are durable, but `.mpd/pending-closure` never appeared. With
    // no pointer there is nothing to resolve; recovery must never guess
    // from a bare journal, and no repository target may be touched.
    // -----------------------------------------------------------------
    #[test]
    fn crash_between_journal_and_pointer_leaves_nothing_pending_and_no_target_touched() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();

        // Reproduce the exact on-disk state of a crash between journal
        // rename+sync (step 3) and pointer install (step 4): remove only
        // the pointer, leaving the fully-written journal and staged files.
        fs::remove_file(pointer_path(dir.path())).unwrap();
        assert!(journal_path(dir.path(), plan.id).exists());
        assert!(!pointer_path(dir.path()).exists());

        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::NothingPending);
        assert!(inspect(dir.path()).unwrap().is_none());

        // No repository target touched.
        assert!(!dir.path().join(&plan.targets[0].target).exists());
        assert!(dir.path().join(&plan.directory_move.source).exists());
        assert!(!dir.path().join(&plan.directory_move.destination).exists());

        // A same-id retry cleans the orphan scratch and converges.
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
    }

    // -----------------------------------------------------------------
    // Crash injection (3.7 gap b, half-written variant): a leftover
    // pointer *temp* file from a crashed writer (with the final pointer
    // still absent) must never be mistaken for an installed pointer.
    // Only `.mpd/pending-closure` (the atomically renamed final path) is
    // authoritative.
    // -----------------------------------------------------------------
    #[test]
    fn a_half_written_pointer_temp_without_the_final_pointer_is_ignored() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        fs::remove_file(pointer_path(dir.path())).unwrap();

        // A truncated pointer temp from some crashed writer (any pid).
        let tmp = mpd_dir(dir.path()).join("pending-closure.tmp.999999");
        fs::write(&tmp, b"{\"version\":1,\"transaction_id\":").unwrap();

        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::NothingPending);
        assert!(inspect(dir.path()).unwrap().is_none());
        assert!(!dir.path().join(&plan.targets[0].target).exists());
        assert!(dir.path().join(&plan.directory_move.source).exists());
    }

    // -----------------------------------------------------------------
    // Crash injection (3.7 gap c): the FINAL AwaitingCommit pointer-sync.
    // Every ordinary target, the directory move, and the closure ledger
    // are already exact on disk, and the durable pointer sits at
    // `RecordingClosure` — precisely a crash in the last
    // `write_pointer(AwaitingCommit)`. Recovery only needs to advance the
    // durable stage; no target may be written a second time. Distinct
    // from `crash_after_closure_ledger_replaced_is_idempotent_on_recovery`
    // (whose pointer is stuck at `Prepared`).
    // -----------------------------------------------------------------
    #[test]
    fn crash_at_final_pointer_sync_from_recording_closure_converges_idempotently() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();

        // Apply the full mutation on disk, then leave the pointer durably
        // at RecordingClosure (the stage written immediately before the
        // final AwaitingCommit pointer sync).
        for t in &plan.targets {
            apply_one(dir.path(), t).unwrap();
        }
        apply_directory_move(dir.path(), &plan.directory_move).unwrap();
        apply_one(dir.path(), &plan.closure_ledger).unwrap();
        let pointer = read_pointer(dir.path()).unwrap().unwrap();
        write_pointer(
            dir.path(),
            &pointer_with_stage(&pointer, TransactionState::RecordingClosure),
        )
        .unwrap();

        // Everything is already exact, so recovery only advances the
        // durable stage — every step classifies as already-complete.
        let view = inspect(dir.path()).unwrap().unwrap();
        assert_eq!(view.stage, TransactionState::RecordingClosure);
        assert!(view.write_eligible);
        assert_eq!(
            recover_apply(dir.path()).unwrap().stage,
            TransactionState::AwaitingCommit
        );
        let ledger = fs::read_to_string(dir.path().join(&plan.closure_ledger.target)).unwrap();
        assert_eq!(ledger, "{\"change\":\"add-thing\",\"archived\":true}");

        // Idempotent: a second drive stays put and never rewrites.
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        let ledger_again =
            fs::read_to_string(dir.path().join(&plan.closure_ledger.target)).unwrap();
        assert_eq!(ledger_again, "{\"change\":\"add-thing\",\"archived\":true}");
    }

    // -----------------------------------------------------------------
    // Codec fail-closed (deterministic fuzz): the durable state-machine
    // slug is never silently coerced. Every canonical slug round-trips
    // and re-serializes to a fixed point; any other string is a hard
    // parse error, so a corrupt or foreign pointer can never deserialize
    // into a valid stage. The negative cases are driven by a fixed-seed
    // xorshift so the test is fully reproducible with no wall-clock or
    // external randomness.
    // -----------------------------------------------------------------
    #[test]
    fn transaction_state_slugs_round_trip_and_reject_all_non_canonical_strings() {
        let all = [
            TransactionState::Preparing,
            TransactionState::Prepared,
            TransactionState::Applying,
            TransactionState::Renaming,
            TransactionState::RecordingClosure,
            TransactionState::AwaitingCommit,
        ];
        let mut canonical_slugs = Vec::new();
        for s in all {
            let json = serde_json::to_string(&s).unwrap();
            let back: TransactionState = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back, "{json} must round-trip exactly");
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                json,
                "re-serialization must be a fixed point"
            );
            canonical_slugs.push(json.trim_matches('"').to_string());
        }

        // Fixed-seed xorshift64 → arbitrary near-miss strings.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Alphabet includes every character the real slugs use plus noise,
        // but no `"` or `\`, so `"{s}"` is always a valid JSON string body.
        let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz-ABCDEZ_ 0129";
        for _ in 0..4000 {
            let len = (next() % 20) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() as usize) % alphabet.len()] as char)
                .collect();
            let parsed = serde_json::from_str::<TransactionState>(&format!("\"{s}\""));
            if canonical_slugs.iter().any(|c| c == &s) {
                assert!(parsed.is_ok(), "canonical slug {s:?} must parse");
            } else {
                assert!(
                    parsed.is_err(),
                    "non-canonical stage string {s:?} must fail closed, not coerce onto a stage"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // Forced durability-I/O failure (via the io_* seam; tasks.md 3.7
    // "forced sync/rename failures"). Distinct from the process-restart
    // crash tests above: these arm a thread-local fault so a real
    // sync_all/rename returns Err mid-transaction, then assert the executor
    // propagated the error, left NO partial/incorrect write, and that a clean
    // re-run converges with no double-apply. The fault fires exactly once and
    // its guard disarms on drop.
    // -----------------------------------------------------------------
    use faults::{fail_next, FaultOp};

    #[test]
    fn journal_fsync_failure_in_prepare_leaves_nothing_pending() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        {
            let _g = fail_next(FaultOp::Fsync, "journal");
            assert!(prepare(dir.path(), &plan, &contents).is_err());
        }
        // No durable pointer installed -> nothing to drive, no target touched.
        assert!(!pointer_path(dir.path()).exists());
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::NothingPending);
        assert!(!dir.path().join(&plan.targets[0].target).exists());
        assert!(dir.path().join(&plan.directory_move.source).exists());
        // A clean retry discards the orphan scratch and converges.
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
    }

    #[test]
    fn journal_rename_failure_in_prepare_leaves_nothing_pending() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        {
            let _g = fail_next(FaultOp::Rename, "journal");
            assert!(prepare(dir.path(), &plan, &contents).is_err());
        }
        assert!(!pointer_path(dir.path()).exists());
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::NothingPending);
        assert!(!dir.path().join(&plan.targets[0].target).exists());
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
    }

    #[test]
    fn pointer_fsync_failure_in_prepare_installs_no_pointer_and_recovers() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        {
            let _g = fail_next(FaultOp::Fsync, "pending-closure");
            assert!(prepare(dir.path(), &plan, &contents).is_err());
        }
        // The journal may be durable, but with no installed pointer recovery
        // must never guess: fail closed, no target touched.
        assert!(!pointer_path(dir.path()).exists());
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::NothingPending);
        assert!(!dir.path().join(&plan.targets[0].target).exists());
        prepare(dir.path(), &plan, &contents).unwrap();
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
    }

    #[test]
    fn target_rename_failure_during_drive_reapplies_cleanly() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let target = plan.targets[0].target.clone();
        {
            let _g = fail_next(FaultOp::Rename, &target);
            assert!(drive(dir.path()).is_err());
        }
        // The rename never took effect: the target is still absent (its
        // preimage) and the staged postimage is intact.
        assert!(!dir.path().join(&target).exists());
        assert!(dir.path().join(&plan.targets[0].staged).exists());
        // A clean re-drive applies from the exact preimage+staged and converges.
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        assert_eq!(
            fs::read_to_string(dir.path().join(&target)).unwrap(),
            "# Thing\n\n## Requirements\n"
        );
    }

    #[test]
    fn target_fsync_failure_after_rename_is_already_postimage_on_redrive() {
        // The crown-jewel case: the rename SUCCEEDED but its following sync_all
        // FAILED. The target is now its postimage (renamed, just not fsynced)
        // and the staged file was consumed. A re-drive must classify the target
        // AlreadyPostimage and never attempt a second rename (which would fail,
        // the staged source being gone) nor double-apply.
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let target = plan.targets[0].target.clone();
        {
            let _g = fail_next(FaultOp::Fsync, &target);
            assert!(drive(dir.path()).is_err());
        }
        // Rename applied; staged consumed.
        assert_eq!(
            fs::read_to_string(dir.path().join(&target)).unwrap(),
            "# Thing\n\n## Requirements\n"
        );
        assert!(!dir.path().join(&plan.targets[0].staged).exists());
        // Re-drive is AlreadyPostimage (no second rename) and idempotent.
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        assert_eq!(
            fs::read_to_string(dir.path().join(&target)).unwrap(),
            "# Thing\n\n## Requirements\n"
        );
    }

    #[test]
    fn directory_move_rename_failure_during_drive_reapplies_cleanly() {
        let dir = tempdir();
        init_project(dir.path());
        let plan = build_sample(dir.path());
        let contents = contents_for(&plan, dir.path());
        prepare(dir.path(), &plan, &contents).unwrap();
        let dest = plan.directory_move.destination.clone();
        {
            let _g = fail_next(FaultOp::Rename, &dest);
            assert!(drive(dir.path()).is_err());
        }
        // The move never took effect: source dir intact, destination absent.
        assert!(dir.path().join(&plan.directory_move.source).exists());
        assert!(!dir.path().join(&dest).exists());
        // Re-drive completes the move (NeedsMove) and converges.
        assert_eq!(drive(dir.path()).unwrap(), DriveOutcome::AwaitingCommit);
        assert!(dir.path().join(&dest).exists());
        assert!(!dir.path().join(&plan.directory_move.source).exists());
    }
}
