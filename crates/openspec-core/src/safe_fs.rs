//! Small, deliberately conservative primitives for state files owned by OpenSpec.
//!
//! These helpers are not a capability filesystem: a same-UID attacker can still race
//! a path between checks.  They do, however, reject symlink components, cap reads,
//! and make the normal state-file update path crash-safe on the supported local
//! filesystems.  Callers must pass a project root and a repository-contained target.

use crate::{assert_contained, CoreError, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Conservative upper bound for state and policy documents read by this crate.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn io_error(error: io::Error) -> CoreError {
    CoreError::Io(error.to_string())
}

/// Read a UTF-8 regular file below `root`, refusing every symlink component and
/// rejecting a file whose size changes beyond `cap` while it is being read.
pub fn read_contained_capped(root: &Path, path: &Path, cap: u64) -> Result<String> {
    assert_contained(root, path)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CoreError::Io(format!(
            "refusing to read non-regular state file {}",
            path.display()
        )));
    }
    if metadata.len() > cap {
        return Err(CoreError::Io(format!(
            "{} exceeds the {cap}-byte limit",
            path.display()
        )));
    }

    let mut file = File::open(path).map_err(io_error)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > cap {
        return Err(CoreError::Io(format!(
            "{} exceeded the {cap}-byte limit while reading",
            path.display()
        )));
    }
    // Recheck after the read so a replacement/symlink cannot be accepted as a
    // successful state read simply because the first metadata lookup was benign.
    assert_contained(root, path)?;
    let after = fs::symlink_metadata(path).map_err(io_error)?;
    if after.file_type().is_symlink() || !after.file_type().is_file() || after.len() > cap {
        return Err(CoreError::Io(format!(
            "state file {} changed unsafely while reading",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| CoreError::Io(format!("{} is not UTF-8", path.display())))
}

/// Atomically replace a regular repository-contained state file.
///
/// The temporary sibling is created exclusively, synced, and renamed only after a
/// second containment check.  The parent directory is synced after rename.  A failed
/// update leaves the previous target untouched; a stranded temporary is uniquely
/// named and remains inside the resolved parent for later bounded cleanup.
pub fn atomic_write_contained(root: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write_contained_classified(root, path, bytes).into_result()
}

/// The commit boundary reached by a contained atomic write.
///
/// A failure after rename is deliberately distinct: the requested bytes won
/// the namespace replacement, but the caller did not receive normal durable
/// success (for example, because parent-directory sync failed). Callers that
/// transfer ownership after publication can read the target back and decide
/// against the exact expected bytes.
#[derive(Debug)]
pub enum AtomicWriteOutcome {
    /// The replacement and parent-directory sync both completed.
    Committed,
    /// The target namespace was not replaced by this invocation.
    FailedBeforeRename(CoreError),
    /// Rename completed, but a subsequent operation failed.
    FailedAfterRename(CoreError),
}

impl AtomicWriteOutcome {
    fn into_result(self) -> Result<()> {
        match self {
            Self::Committed => Ok(()),
            Self::FailedBeforeRename(error) | Self::FailedAfterRename(error) => Err(error),
        }
    }
}

/// Atomically replace a contained file while preserving the exact commit
/// boundary in the result.
pub fn atomic_write_contained_classified(
    root: &Path,
    path: &Path,
    bytes: &[u8],
) -> AtomicWriteOutcome {
    atomic_write_contained_classified_with(root, path, bytes, |_| Ok(()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStep {
    Write,
    FileSync,
    Rename,
    DirectorySync,
}

#[cfg(test)]
fn atomic_write_contained_with(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    mut before: impl FnMut(WriteStep) -> io::Result<()>,
) -> Result<()> {
    atomic_write_contained_classified_with(root, path, bytes, &mut before).into_result()
}

fn atomic_write_contained_classified_with(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    mut before: impl FnMut(WriteStep) -> io::Result<()>,
) -> AtomicWriteOutcome {
    let mut renamed = false;
    let mut temporary = None;
    let write_result = (|| -> Result<()> {
        if bytes.len() as u64 > DEFAULT_MAX_BYTES {
            return Err(CoreError::Io(format!(
                "refusing to write {} bytes to {} (limit {})",
                bytes.len(),
                path.display(),
                DEFAULT_MAX_BYTES
            )));
        }
        assert_contained(root, path)?;
        let parent = path
            .parent()
            .ok_or_else(|| CoreError::Io("state target has no parent".into()))?;
        assert_contained(root, parent)?;
        fs::create_dir_all(parent).map_err(io_error)?;
        assert_contained(root, parent)?;

        // Existing state must be a regular file. Do not replace a planted symlink.
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(CoreError::Io(format!(
                    "refusing to replace non-regular state target {}",
                    path.display()
                )));
            }
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| CoreError::Io("state target has no UTF-8 file name".into()))?;
        let temp = temporary_sibling(parent, name);
        temporary = Some(temp.clone());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(io_error)?;
        before(WriteStep::Write).map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        before(WriteStep::FileSync).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);

        assert_contained(root, path)?;
        assert_contained(root, &temp)?;
        let tmp_metadata = fs::symlink_metadata(&temp).map_err(io_error)?;
        if tmp_metadata.file_type().is_symlink() || !tmp_metadata.file_type().is_file() {
            return Err(CoreError::Io(
                "temporary state file changed unsafely".into(),
            ));
        }
        before(WriteStep::Rename).map_err(io_error)?;
        fs::rename(&temp, path).map_err(io_error)?;
        renamed = true;
        before(WriteStep::DirectorySync).map_err(io_error)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if write_result.is_err() {
        // Never follow a symlink while cleaning up. A failed cleanup is
        // intentionally ignored: the owned filename is unique and the original
        // error is more useful.
        if let Some(temp) = temporary.as_ref() {
            if let Ok(metadata) = fs::symlink_metadata(temp) {
                if metadata.file_type().is_file() {
                    let _ = fs::remove_file(temp);
                }
            }
        }
    }
    match write_result {
        Ok(()) => AtomicWriteOutcome::Committed,
        Err(error) if renamed => AtomicWriteOutcome::FailedAfterRename(error),
        Err(error) => AtomicWriteOutcome::FailedBeforeRename(error),
    }
}

fn temporary_sibling(parent: &Path, leaf: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".{leaf}.mpd-tmp-{}-{sequence}", std::process::id()))
}

fn sync_directory(path: &Path) -> Result<()> {
    // Directory fsync is supported by the local Unix filesystems we support.  On a
    // platform where opening a directory is not available, fail closed rather than
    // claiming durable success.
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "openspec-safe-fs-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn atomically_replaces_a_regular_contained_file() {
        let root = root("replace");
        let file = root.join(".mpd/state/change.json");
        atomic_write_contained(&root, &file, b"before").unwrap();
        atomic_write_contained(&root, &file, b"after").unwrap();
        assert_eq!(read_contained_capped(&root, &file, 32).unwrap(), "after");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_read_is_refused() {
        let root = root("oversized");
        let file = root.join("state.json");
        fs::write(&file, b"12345").unwrap();
        assert!(read_contained_capped(&root, &file, 4).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn injected_write_sync_and_rename_failures_are_never_accepted() {
        for fault in [WriteStep::Write, WriteStep::FileSync, WriteStep::Rename] {
            let root = root(&format!("fault-{fault:?}"));
            let file = root.join("state.json");
            atomic_write_contained(&root, &file, b"before").unwrap();
            let result = atomic_write_contained_with(&root, &file, b"after", |step| {
                if step == fault {
                    Err(io::Error::other("injected failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            assert_eq!(read_contained_capped(&root, &file, 32).unwrap(), "before");
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn directory_sync_failure_reports_error_without_truncated_target() {
        let root = root("directory-sync-fault");
        let file = root.join("state.json");
        atomic_write_contained(&root, &file, b"before").unwrap();
        let result =
            atomic_write_contained_classified_with(&root, &file, b"complete-after", |step| {
                if step == WriteStep::DirectorySync {
                    Err(io::Error::other("injected directory sync failure"))
                } else {
                    Ok(())
                }
            });
        assert!(matches!(result, AtomicWriteOutcome::FailedAfterRename(_)));
        assert_eq!(
            read_contained_capped(&root, &file, 32).unwrap(),
            "complete-after"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_intermediate_and_leaf_symlinks() {
        use std::os::unix::fs::symlink;
        let root = root("symlink");
        let outside = root.with_extension("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("target"), b"secret").unwrap();
        symlink(&outside, root.join(".mpd")).unwrap();
        assert!(atomic_write_contained(&root, &root.join(".mpd/state"), b"x").is_err());
        fs::remove_file(root.join(".mpd")).unwrap();
        symlink(outside.join("target"), root.join("leaf")).unwrap();
        assert!(read_contained_capped(&root, &root.join("leaf"), 32).is_err());
        assert!(atomic_write_contained(&root, &root.join("leaf"), b"x").is_err());
        assert_eq!(fs::read(outside.join("target")).unwrap(), b"secret");
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}
