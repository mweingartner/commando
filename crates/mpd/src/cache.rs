//! Read-only candidate-cache inspection and explicit, identity-bound pruning.
//!
//! This module deliberately owns no CLI parsing and no reference discovery.
//! Callers supply the union of live, pending, build-output, receipt, and
//! archived candidate IDs.  That makes the policy boundary explicit and keeps
//! `inspect`/preview read-only.  The only writable operation is [`prune`],
//! which repeats the reference and inode checks, moves both objects into
//! private same-parent quarantine directories, then verifies them again.

use nix::dir::Dir;
use nix::fcntl::{openat, renameat, AtFlags, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 10_000;
const MAX_JOURNAL_BYTES: u64 = 4096;
const QUARANTINE_DIR: &str = "candidate-cache-quarantine";
const JOURNAL_SCHEMA: u32 = 1;

/// References collected by the integration layer.  A cache inspection never
/// guesses from paths: any ID in this set is retained even when its sidecar is
/// otherwise malformed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CacheReferences {
    pub candidate_ids: BTreeSet<String>,
}

/// Stable device/inode identity, used only for retry-safe prune confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum CacheDisposition {
    RetainedReference,
    Prunable,
    Blocked { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheEntry {
    pub id: String,
    pub root: Option<FileIdentity>,
    pub sidecar: Option<FileIdentity>,
    pub disposition: CacheDisposition,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CacheInspection {
    pub entries: Vec<CacheEntry>,
    pub truncated: bool,
    pub scan_blocker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum PruneOutcome {
    Pruned { id: String },
    Retained { id: String, reason: String },
    Blocked { id: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PruneJournal {
    schema: u32,
    id: String,
    root: FileIdentity,
    sidecar: FileIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectLocation {
    Canonical,
    Quarantine,
    Absent,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailurePoint {
    RootMoved,
    SidecarMoved,
    RootDeleted,
}

#[cfg(test)]
thread_local! {
    static INJECT_FAILURE: std::cell::Cell<Option<FailurePoint>> = const { std::cell::Cell::new(None) };
}

fn maybe_fail(#[cfg_attr(not(test), allow(unused_variables))] point: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        let expected = match point {
            "after-root-move" => FailurePoint::RootMoved,
            "after-sidecar-move" => FailurePoint::SidecarMoved,
            "after-root-delete" => FailurePoint::RootDeleted,
            _ => return Ok(()),
        };
        if INJECT_FAILURE.with(|slot| slot.get() == Some(expected)) {
            INJECT_FAILURE.with(|slot| slot.set(None));
            return Err(format!("injected cache interruption {point}"));
        }
    }
    Ok(())
}

/// Inspect the fixed clone-private cache parents.  This is read-only and
/// refuses to create missing cache state.
pub fn inspect(root: &Path, references: &CacheReferences) -> CacheInspection {
    let dirs = match cache_dirs(root) {
        Ok(dirs) => dirs,
        Err(reason) => {
            return CacheInspection {
                scan_blocker: Some(reason),
                ..CacheInspection::default()
            }
        }
    };
    inspect_at(&dirs.candidates, &dirs.records, references)
}

/// Confirm deletion for an entry produced by [`inspect`].  Re-running this
/// function after interruption is safe: vanished or replaced objects are
/// retained/blocked rather than treated as successful deletion.
pub fn prune(root: &Path, entry: &CacheEntry, references: &CacheReferences) -> PruneOutcome {
    let dirs = match cache_dirs(root) {
        Ok(dirs) => dirs,
        Err(reason) => {
            return PruneOutcome::Blocked {
                id: entry.id.clone(),
                reason,
            }
        }
    };
    prune_at(&dirs.candidates, &dirs.records, entry, references)
}

/// Resume every bounded quarantine transaction left by an interrupted
/// confirmed prune. This is a mutation and therefore belongs only on the
/// explicit `cache prune --yes` path; inspect/preview never calls it.
pub fn recover(root: &Path, references: &CacheReferences) -> Vec<PruneOutcome> {
    let dirs = match cache_dirs(root) {
        Ok(dirs) => dirs,
        Err(reason) => {
            return vec![PruneOutcome::Blocked {
                id: "cache".into(),
                reason,
            }]
        }
    };
    recover_at(&dirs.candidates, &dirs.records, references)
}

struct CacheDirs {
    candidates: PathBuf,
    records: PathBuf,
}

fn cache_dirs(root: &Path) -> Result<CacheDirs, String> {
    let common = crate::local_validation::git_common_dir(root)?;
    let mpd = common.join("mpd");
    validate_private_dir(&mpd, "clone-private MPD directory")?;
    let candidates = mpd.join("candidates");
    let records = mpd.join("candidate-records");
    validate_private_dir(&candidates, "candidate cache directory")?;
    validate_private_dir(&records, "candidate record directory")?;
    Ok(CacheDirs {
        candidates,
        records,
    })
}

fn validate_private_dir(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{label} unavailable: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} is not a regular directory"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!("{label} is not owner-only"));
    }
    Ok(())
}

fn open_dir(path: &Path) -> Result<Dir, String> {
    Dir::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot open cache directory: {e}"))
}

fn id_is_valid(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn identity(stat: &nix::sys::stat::FileStat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino,
    }
}

fn inspect_at(candidates: &Path, records: &Path, references: &CacheReferences) -> CacheInspection {
    let mut candidate_dir = match open_dir(candidates) {
        Ok(dir) => dir,
        Err(reason) => {
            return CacheInspection {
                scan_blocker: Some(reason),
                ..CacheInspection::default()
            }
        }
    };
    let mut record_dir = match open_dir(records) {
        Ok(dir) => dir,
        Err(reason) => {
            return CacheInspection {
                scan_blocker: Some(reason),
                ..CacheInspection::default()
            }
        }
    };
    let candidate_names = match directory_names(&mut candidate_dir, "candidate root") {
        Ok(names) => names,
        Err(reason) => {
            return CacheInspection {
                scan_blocker: Some(reason),
                ..CacheInspection::default()
            }
        }
    };
    let record_names = match directory_names(&mut record_dir, "candidate sidecar") {
        Ok(names) => names,
        Err(reason) => {
            return CacheInspection {
                scan_blocker: Some(reason),
                ..CacheInspection::default()
            }
        }
    };
    let mut ids = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut sidecars = BTreeSet::new();
    let mut entries = Vec::new();
    for name in candidate_names {
        if id_is_valid(&name) {
            roots.insert(name.clone());
            ids.insert(name);
        } else {
            entries.push(blocked_entry(
                &name,
                "candidate root has a noncanonical name",
            ));
        }
    }
    for name in record_names {
        match name.strip_suffix(".json") {
            Some(id) if id_is_valid(id) => {
                sidecars.insert(id.to_string());
                ids.insert(id.to_string());
            }
            _ => entries.push(blocked_entry(
                &name,
                "candidate sidecar has a noncanonical name",
            )),
        }
    }
    let truncated = ids.len().saturating_add(entries.len()) > MAX_ENTRIES;
    if truncated {
        return CacheInspection {
            entries,
            truncated: true,
            scan_blocker: Some("candidate cache inventory exceeds its cap".into()),
        };
    }
    for id in ids {
        let root = if roots.contains(&id) {
            match observe_root(&candidate_dir, &id) {
                Ok(identity) => Some(identity),
                Err(reason) => {
                    entries.push(blocked_entry(&id, &reason));
                    continue;
                }
            }
        } else {
            None
        };
        let sidecar = if sidecars.contains(&id) {
            match observe_sidecar(&record_dir, &id) {
                Ok(identity) => Some(identity),
                Err(reason) => {
                    entries.push(CacheEntry {
                        id,
                        root,
                        sidecar: None,
                        disposition: CacheDisposition::Blocked { reason },
                    });
                    continue;
                }
            }
        } else {
            None
        };
        let disposition = match (root, sidecar) {
            (Some(_), Some(_)) if references.candidate_ids.contains(&id) => {
                CacheDisposition::RetainedReference
            }
            (Some(_), Some(_)) => CacheDisposition::Prunable,
            (None, Some(_)) => CacheDisposition::Blocked {
                reason: "sidecar-only orphan; candidate root is missing".into(),
            },
            (Some(_), None) => CacheDisposition::Blocked {
                reason: "candidate-root-only orphan; sidecar is missing".into(),
            },
            (None, None) => CacheDisposition::Blocked {
                reason: "candidate pair disappeared during inspection".into(),
            },
        };
        entries.push(CacheEntry {
            id,
            root,
            sidecar,
            disposition,
        });
    }
    CacheInspection {
        entries,
        truncated,
        scan_blocker: None,
    }
}

fn directory_names(dir: &mut Dir, label: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for listed in dir.iter() {
        let listed = listed.map_err(|error| format!("{label} enumeration failed: {error}"))?;
        let name = listed
            .file_name()
            .to_str()
            .map_err(|_| format!("{label} has a non-UTF-8 name"))?;
        if name != "." && name != ".." {
            names.push(name.to_string());
            if names.len() > MAX_ENTRIES {
                return Err(format!("{label} inventory exceeds its cap"));
            }
        }
    }
    Ok(names)
}

fn blocked_entry(id: &str, reason: &str) -> CacheEntry {
    CacheEntry {
        id: id.to_string(),
        root: None,
        sidecar: None,
        disposition: CacheDisposition::Blocked {
            reason: reason.into(),
        },
    }
}

fn observe_root(candidate_dir: &Dir, id: &str) -> Result<FileIdentity, String> {
    match Dir::openat(
        candidate_dir,
        id,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(dir) => match fstat(&dir) {
            Ok(stat) if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR) => {
                Ok(identity(&stat))
            }
            Ok(_) => Err("candidate root is not a directory".into()),
            Err(error) => Err(format!("cannot stat candidate root: {error}")),
        },
        Err(error) => Err(format!(
            "cannot open candidate root without following links: {error}"
        )),
    }
}

fn observe_sidecar(record_dir: &Dir, id: &str) -> Result<FileIdentity, String> {
    let sidecar_name = format!("{id}.json");
    match openat(
        record_dir,
        sidecar_name.as_str(),
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => match fstat(&fd) {
            Ok(stat) if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFREG) => {
                Ok(identity(&stat))
            }
            Ok(_) => Err("candidate sidecar is not a regular file".into()),
            Err(error) => Err(format!("cannot stat candidate sidecar: {error}")),
        },
        Err(error) => Err(format!("candidate sidecar is unavailable: {error}")),
    }
}

fn prune_at(
    candidates: &Path,
    records: &Path,
    entry: &CacheEntry,
    references: &CacheReferences,
) -> PruneOutcome {
    if !matches!(entry.disposition, CacheDisposition::Prunable) {
        return PruneOutcome::Retained {
            id: entry.id.clone(),
            reason: "entry was not previewed as prunable".into(),
        };
    }
    if !id_is_valid(&entry.id) {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason: "candidate ID is noncanonical".into(),
        };
    }
    if references.candidate_ids.contains(&entry.id) {
        return PruneOutcome::Retained {
            id: entry.id.clone(),
            reason: "candidate became referenced after preview".into(),
        };
    }
    let Some(root_identity) = entry.root else {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason: "previewed candidate root identity is absent".into(),
        };
    };
    let Some(sidecar_identity) = entry.sidecar else {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason: "previewed candidate sidecar identity is absent".into(),
        };
    };
    let current = inspect_at(candidates, records, references);
    if current.truncated || current.scan_blocker.is_some() {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason: "cache reinspection was incomplete".into(),
        };
    }
    let Some(observed) = current
        .entries
        .into_iter()
        .find(|candidate| candidate.id == entry.id)
    else {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason: "candidate vanished before confirmed prune".into(),
        };
    };
    if observed.root != entry.root
        || observed.sidecar != entry.sidecar
        || !matches!(observed.disposition, CacheDisposition::Prunable)
    {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason: "candidate identity or eligibility drifted after preview".into(),
        };
    }
    let Some(mpd) = candidates.parent() else {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason: "candidate parent is unavailable".into(),
        };
    };
    let quarantine = mpd.join(QUARANTINE_DIR);
    if let Err(reason) = ensure_quarantine(&quarantine) {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason,
        };
    }
    let journal = PruneJournal {
        schema: JOURNAL_SCHEMA,
        id: entry.id.clone(),
        root: root_identity,
        sidecar: sidecar_identity,
    };
    let quarantine_dir = match open_dir(&quarantine) {
        Ok(value) => value,
        Err(reason) => {
            return PruneOutcome::Blocked {
                id: entry.id.clone(),
                reason,
            }
        }
    };
    if let Err(reason) = ensure_journal(&quarantine_dir, &prepared_name(&entry.id), &journal) {
        return PruneOutcome::Blocked {
            id: entry.id.clone(),
            reason,
        };
    }
    drive_transaction(candidates, records, &quarantine, &journal, references)
}

fn recover_at(
    candidates: &Path,
    records: &Path,
    references: &CacheReferences,
) -> Vec<PruneOutcome> {
    let Some(mpd) = candidates.parent() else {
        return vec![PruneOutcome::Blocked {
            id: "cache".into(),
            reason: "candidate parent is unavailable".into(),
        }];
    };
    let quarantine = mpd.join(QUARANTINE_DIR);
    match fs::symlink_metadata(&quarantine) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            return vec![PruneOutcome::Blocked {
                id: "cache".into(),
                reason: format!("cannot inspect cache quarantine: {error}"),
            }]
        }
        Ok(_) => {}
    }
    if let Err(reason) = validate_private_dir(&quarantine, "candidate cache quarantine") {
        return vec![PruneOutcome::Blocked {
            id: "cache".into(),
            reason,
        }];
    }
    let mut quarantine_dir = match open_dir(&quarantine) {
        Ok(value) => value,
        Err(reason) => {
            return vec![PruneOutcome::Blocked {
                id: "cache".into(),
                reason,
            }]
        }
    };
    let names = match directory_names(&mut quarantine_dir, "candidate cache quarantine") {
        Ok(value) => value,
        Err(reason) => {
            return vec![PruneOutcome::Blocked {
                id: "cache".into(),
                reason,
            }]
        }
    };
    let mut ids = BTreeSet::new();
    let mut ambiguous = Vec::new();
    for name in names {
        if let Some(id) = journal_id(&name) {
            ids.insert(id.to_string());
        } else if let Some(id) = quarantined_object_id(&name) {
            ids.insert(id.to_string());
        } else {
            ambiguous.push(PruneOutcome::Blocked {
                id: name,
                reason: "unrecognized quarantine entry retained".into(),
            });
        }
    }
    for id in ids {
        match load_transaction(&quarantine_dir, &id) {
            Ok(Some(journal)) => ambiguous.push(drive_transaction(
                candidates,
                records,
                &quarantine,
                &journal,
                references,
            )),
            Ok(None) => ambiguous.push(PruneOutcome::Blocked {
                id,
                reason: "quarantined object has no identity journal".into(),
            }),
            Err(reason) => ambiguous.push(PruneOutcome::Blocked { id, reason }),
        }
    }
    ambiguous
}

fn drive_transaction(
    candidates: &Path,
    records: &Path,
    quarantine: &Path,
    journal: &PruneJournal,
    references: &CacheReferences,
) -> PruneOutcome {
    let id = journal.id.clone();
    let candidate_dir = match open_dir(candidates) {
        Ok(value) => value,
        Err(reason) => return PruneOutcome::Blocked { id, reason },
    };
    let record_dir = match open_dir(records) {
        Ok(value) => value,
        Err(reason) => return PruneOutcome::Blocked { id, reason },
    };
    let quarantine_dir = match open_dir(quarantine) {
        Ok(value) => value,
        Err(reason) => return PruneOutcome::Blocked { id, reason },
    };
    let deleting = match read_journal(&quarantine_dir, &deleting_name(&journal.id)) {
        Ok(value) => value,
        Err(reason) => return PruneOutcome::Blocked { id, reason },
    };
    if let Some(ref deleting_journal) = deleting {
        if deleting_journal != journal {
            return PruneOutcome::Blocked {
                id,
                reason: "prepared and deleting cache journals disagree".into(),
            };
        }
        if references.candidate_ids.contains(&journal.id) {
            return PruneOutcome::Blocked {
                id,
                reason:
                    "candidate became referenced after deletion began; retained for manual recovery"
                        .into(),
            };
        }
        return finish_deletion(&candidate_dir, &record_dir, &quarantine_dir, journal);
    }
    let root_location = match locate_root(&candidate_dir, &quarantine_dir, journal) {
        Ok(value) => value,
        Err(reason) => return PruneOutcome::Blocked { id, reason },
    };
    let sidecar_location = match locate_sidecar(&record_dir, &quarantine_dir, journal) {
        Ok(value) => value,
        Err(reason) => return PruneOutcome::Blocked { id, reason },
    };
    if references.candidate_ids.contains(&journal.id) {
        if root_location == ObjectLocation::Absent || sidecar_location == ObjectLocation::Absent {
            return PruneOutcome::Blocked {
                id,
                reason: "referenced interrupted prune is missing an object".into(),
            };
        }
        if root_location == ObjectLocation::Quarantine {
            if let Err(error) = renameat(
                &quarantine_dir,
                root_name(&journal.id).as_str(),
                &candidate_dir,
                journal.id.as_str(),
            ) {
                return PruneOutcome::Blocked {
                    id,
                    reason: format!("cannot restore referenced candidate root: {error}"),
                };
            }
        }
        if sidecar_location == ObjectLocation::Quarantine {
            if let Err(error) = renameat(
                &quarantine_dir,
                sidecar_quarantine_name(&journal.id).as_str(),
                &record_dir,
                format!("{}.json", journal.id).as_str(),
            ) {
                return PruneOutcome::Blocked {
                    id,
                    reason: format!("cannot restore referenced candidate sidecar: {error}"),
                };
            }
        }
        if let Err(reason) = verify_canonical_pair(&candidate_dir, &record_dir, journal) {
            return PruneOutcome::Blocked { id, reason };
        }
        if let Err(reason) = remove_if_present(&quarantine_dir, &prepared_name(&journal.id)) {
            return PruneOutcome::Blocked { id, reason };
        }
        return PruneOutcome::Retained {
            id,
            reason: "candidate became referenced and was restored from quarantine".into(),
        };
    }
    if root_location == ObjectLocation::Absent || sidecar_location == ObjectLocation::Absent {
        return PruneOutcome::Blocked {
            id,
            reason: "prepared cache transaction lost an object before deletion authorization"
                .into(),
        };
    }
    if root_location == ObjectLocation::Canonical {
        if let Err(error) = renameat(
            &candidate_dir,
            journal.id.as_str(),
            &quarantine_dir,
            root_name(&journal.id).as_str(),
        ) {
            return PruneOutcome::Blocked {
                id,
                reason: format!("candidate quarantine move refused: {error}"),
            };
        }
        if let Err(reason) = maybe_fail("after-root-move") {
            return PruneOutcome::Blocked { id, reason };
        }
    }
    if sidecar_location == ObjectLocation::Canonical {
        if let Err(error) = renameat(
            &record_dir,
            format!("{}.json", journal.id).as_str(),
            &quarantine_dir,
            sidecar_quarantine_name(&journal.id).as_str(),
        ) {
            return PruneOutcome::Blocked {
                id,
                reason: format!("sidecar quarantine move refused: {error}"),
            };
        }
        if let Err(reason) = maybe_fail("after-sidecar-move") {
            return PruneOutcome::Blocked { id, reason };
        }
    }
    if let Err(reason) = verify_quarantined_pair(&quarantine_dir, journal) {
        return PruneOutcome::Blocked { id, reason };
    }
    if let Err(reason) = ensure_journal(&quarantine_dir, &deleting_name(&journal.id), journal) {
        return PruneOutcome::Blocked { id, reason };
    }
    if let Err(reason) = remove_if_present(&quarantine_dir, &prepared_name(&journal.id)) {
        return PruneOutcome::Blocked { id, reason };
    }
    finish_deletion(&candidate_dir, &record_dir, &quarantine_dir, journal)
}

fn finish_deletion(
    candidate_dir: &Dir,
    record_dir: &Dir,
    quarantine_dir: &Dir,
    journal: &PruneJournal,
) -> PruneOutcome {
    let id = journal.id.clone();
    if optional_root_identity(candidate_dir, &journal.id).is_some()
        || optional_sidecar_identity(record_dir, &journal.id).is_some()
    {
        return PruneOutcome::Blocked {
            id,
            reason: "canonical cache object reappeared after deletion authorization".into(),
        };
    }
    match optional_root_identity(quarantine_dir, &root_name(&journal.id)) {
        Some(Ok(observed)) if observed == journal.root => {
            if let Err(reason) = remove_tree_at(quarantine_dir, &root_name(&journal.id)) {
                return PruneOutcome::Blocked { id, reason };
            }
            if let Err(reason) = maybe_fail("after-root-delete") {
                return PruneOutcome::Blocked { id, reason };
            }
        }
        Some(Ok(_)) => {
            return PruneOutcome::Blocked {
                id,
                reason: "quarantined candidate root identity drifted".into(),
            }
        }
        Some(Err(reason)) => return PruneOutcome::Blocked { id, reason },
        None => {}
    }
    match optional_file_identity(quarantine_dir, &sidecar_quarantine_name(&journal.id)) {
        Some(Ok(observed)) if observed == journal.sidecar => {
            if let Err(error) = unlinkat(
                quarantine_dir,
                sidecar_quarantine_name(&journal.id).as_str(),
                UnlinkatFlags::NoRemoveDir,
            ) {
                return PruneOutcome::Blocked {
                    id,
                    reason: format!("cannot remove quarantined sidecar: {error}"),
                };
            }
        }
        Some(Ok(_)) => {
            return PruneOutcome::Blocked {
                id,
                reason: "quarantined sidecar identity drifted".into(),
            }
        }
        Some(Err(reason)) => return PruneOutcome::Blocked { id, reason },
        None => {}
    }
    if let Err(reason) = remove_if_present(quarantine_dir, &deleting_name(&journal.id)) {
        return PruneOutcome::Blocked { id, reason };
    }
    PruneOutcome::Pruned { id }
}

fn prepared_name(id: &str) -> String {
    format!("prepared-{id}.json")
}

fn deleting_name(id: &str) -> String {
    format!("deleting-{id}.json")
}

fn root_name(id: &str) -> String {
    format!("root-{id}")
}

fn sidecar_quarantine_name(id: &str) -> String {
    format!("record-{id}.json")
}

fn journal_id(name: &str) -> Option<&str> {
    let id = name
        .strip_prefix("prepared-")
        .or_else(|| name.strip_prefix("deleting-"))?
        .strip_suffix(".json")?;
    id_is_valid(id).then_some(id)
}

fn quarantined_object_id(name: &str) -> Option<&str> {
    if let Some(id) = name.strip_prefix("root-") {
        return id_is_valid(id).then_some(id);
    }
    let id = name.strip_prefix("record-")?.strip_suffix(".json")?;
    id_is_valid(id).then_some(id)
}

fn ensure_journal(dir: &Dir, name: &str, journal: &PruneJournal) -> Result<(), String> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| format!("cannot encode cache journal: {error}"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err("cache journal exceeds its byte cap".into());
    }
    match openat(
        dir,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(fd) => {
            let mut file = File::from(fd);
            file.write_all(&bytes)
                .map_err(|error| format!("cannot write cache journal: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("cannot sync cache journal: {error}"))
        }
        Err(nix::errno::Errno::EEXIST) => match read_journal(dir, name)? {
            Some(existing) if existing == *journal => Ok(()),
            Some(_) => Err("existing cache journal has different identity".into()),
            None => Err("cache journal disappeared after create collision".into()),
        },
        Err(error) => Err(format!("cannot create cache journal: {error}")),
    }
}

fn read_journal(dir: &Dir, name: &str) -> Result<Option<PruneJournal>, String> {
    let fd = match openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(format!("cannot open cache journal: {error}")),
    };
    let before = fstat(&fd).map_err(|error| format!("cannot stat cache journal: {error}"))?;
    if !SFlag::from_bits_truncate(before.st_mode).contains(SFlag::S_IFREG)
        || before.st_size <= 0
        || before.st_size as u64 > MAX_JOURNAL_BYTES
    {
        return Err("cache journal is not a bounded regular file".into());
    }
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read cache journal: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("cannot restat cache journal: {error}"))?;
    if identity(&before)
        != (FileIdentity {
            device: after.dev(),
            inode: after.ino(),
        })
        || bytes.len() as u64 > MAX_JOURNAL_BYTES
    {
        return Err("cache journal identity changed while reading".into());
    }
    let journal: PruneJournal =
        serde_json::from_slice(&bytes).map_err(|_| "cache journal is malformed")?;
    if journal.schema != JOURNAL_SCHEMA || !id_is_valid(&journal.id) {
        return Err("cache journal schema or ID is invalid".into());
    }
    Ok(Some(journal))
}

fn load_transaction(dir: &Dir, id: &str) -> Result<Option<PruneJournal>, String> {
    let prepared = read_journal(dir, &prepared_name(id))?;
    let deleting = read_journal(dir, &deleting_name(id))?;
    let selected = match (prepared, deleting) {
        (Some(left), Some(right)) if left == right => Some(right),
        (Some(_), Some(_)) => return Err("prepared and deleting cache journals disagree".into()),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    };
    if selected.as_ref().is_some_and(|journal| journal.id != id) {
        return Err("cache journal filename does not match its bound ID".into());
    }
    Ok(selected)
}

fn optional_root_identity(dir: &Dir, name: &str) -> Option<Result<FileIdentity, String>> {
    match Dir::openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(opened) => Some(
            fstat(&opened)
                .map(|stat| identity(&stat))
                .map_err(|error| format!("cannot stat cache root: {error}")),
        ),
        Err(nix::errno::Errno::ENOENT) => None,
        Err(error) => Some(Err(format!(
            "cannot open cache root without following links: {error}"
        ))),
    }
}

fn optional_file_identity(dir: &Dir, name: &str) -> Option<Result<FileIdentity, String>> {
    match openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Some(
            fstat(&fd)
                .and_then(|stat| {
                    if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFREG) {
                        Ok(stat)
                    } else {
                        Err(nix::errno::Errno::EINVAL)
                    }
                })
                .map(|stat| identity(&stat))
                .map_err(|error| format!("cannot inspect cache file: {error}")),
        ),
        Err(nix::errno::Errno::ENOENT) => None,
        Err(error) => Some(Err(format!(
            "cannot open cache file without following links: {error}"
        ))),
    }
}

fn optional_sidecar_identity(dir: &Dir, id: &str) -> Option<Result<FileIdentity, String>> {
    optional_file_identity(dir, &format!("{id}.json"))
}

fn locate_root(
    canonical: &Dir,
    quarantine: &Dir,
    journal: &PruneJournal,
) -> Result<ObjectLocation, String> {
    locate_object(
        optional_root_identity(canonical, &journal.id),
        optional_root_identity(quarantine, &root_name(&journal.id)),
        journal.root,
        "candidate root",
    )
}

fn locate_sidecar(
    canonical: &Dir,
    quarantine: &Dir,
    journal: &PruneJournal,
) -> Result<ObjectLocation, String> {
    locate_object(
        optional_sidecar_identity(canonical, &journal.id),
        optional_file_identity(quarantine, &sidecar_quarantine_name(&journal.id)),
        journal.sidecar,
        "candidate sidecar",
    )
}

fn locate_object(
    canonical: Option<Result<FileIdentity, String>>,
    quarantine: Option<Result<FileIdentity, String>>,
    expected: FileIdentity,
    label: &str,
) -> Result<ObjectLocation, String> {
    let canonical = canonical.transpose()?;
    let quarantine = quarantine.transpose()?;
    match (canonical, quarantine) {
        (Some(_), Some(_)) => Err(format!(
            "{label} exists in canonical and quarantine locations"
        )),
        (Some(observed), None) if observed == expected => Ok(ObjectLocation::Canonical),
        (None, Some(observed)) if observed == expected => Ok(ObjectLocation::Quarantine),
        (Some(_), None) | (None, Some(_)) => Err(format!("{label} identity drifted")),
        (None, None) => Ok(ObjectLocation::Absent),
    }
}

fn verify_canonical_pair(
    candidate_dir: &Dir,
    record_dir: &Dir,
    journal: &PruneJournal,
) -> Result<(), String> {
    match optional_root_identity(candidate_dir, &journal.id).transpose()? {
        Some(identity) if identity == journal.root => {}
        _ => return Err("restored candidate root identity differs".into()),
    }
    match optional_sidecar_identity(record_dir, &journal.id).transpose()? {
        Some(identity) if identity == journal.sidecar => Ok(()),
        _ => Err("restored candidate sidecar identity differs".into()),
    }
}

fn verify_quarantined_pair(quarantine_dir: &Dir, journal: &PruneJournal) -> Result<(), String> {
    match optional_root_identity(quarantine_dir, &root_name(&journal.id)).transpose()? {
        Some(identity) if identity == journal.root => {}
        _ => return Err("quarantined candidate root identity differs".into()),
    }
    match optional_file_identity(quarantine_dir, &sidecar_quarantine_name(&journal.id))
        .transpose()?
    {
        Some(identity) if identity == journal.sidecar => Ok(()),
        _ => Err("quarantined candidate sidecar identity differs".into()),
    }
}

fn remove_if_present(dir: &Dir, name: &str) -> Result<(), String> {
    match unlinkat(dir, name, UnlinkatFlags::NoRemoveDir) {
        Ok(()) | Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(error) => Err(format!("cannot remove cache transaction marker: {error}")),
    }
}

fn ensure_quarantine(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot secure cache quarantine: {e}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("cannot create cache quarantine: {error}")),
    }
    validate_private_dir(path, "candidate cache quarantine")
}

fn remove_tree_at(parent: &Dir, name: &str) -> Result<(), String> {
    let mut dir = Dir::openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot reopen quarantined candidate: {e}"))?;
    let mut children = Vec::new();
    for entry in dir.iter() {
        let entry = entry.map_err(|e| format!("cannot enumerate quarantined candidate: {e}"))?;
        let Ok(child) = entry.file_name().to_str() else {
            return Err("quarantined candidate has a non-UTF-8 child".into());
        };
        if child != "." && child != ".." {
            children.push(child.to_string());
        }
    }
    for child in children {
        let stat = nix::sys::stat::fstatat(&dir, child.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|e| format!("cannot restat quarantined child: {e}"))?;
        match SFlag::from_bits_truncate(stat.st_mode) {
            flag if flag.contains(SFlag::S_IFDIR) => remove_tree_at(&dir, child.as_str())?,
            flag if flag.contains(SFlag::S_IFREG) => {
                unlinkat(&dir, child.as_str(), UnlinkatFlags::NoRemoveDir)
                    .map_err(|e| format!("cannot remove quarantined candidate file: {e}"))?
            }
            _ => return Err("quarantined candidate contains a non-regular entry".into()),
        }
    }
    unlinkat(parent, name, UnlinkatFlags::RemoveDir)
        .map_err(|e| format!("cannot remove quarantined candidate root: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("mpd-cache-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let candidates = base.join("candidates");
        let records = base.join("candidate-records");
        fs::create_dir_all(&candidates).unwrap();
        fs::create_dir_all(&records).unwrap();
        (base, candidates, records)
    }

    fn candidate(candidates: &Path, records: &Path, id: &str) {
        fs::create_dir(candidates.join(id)).unwrap();
        fs::write(candidates.join(id).join("payload"), b"x").unwrap();
        fs::write(records.join(format!("{id}.json")), b"{}").unwrap();
    }

    #[test]
    fn inspection_retains_references_and_blocks_missing_sidecars() {
        let (base, candidates, records) = fixture("inspect");
        let live = "a".repeat(64);
        let orphan = "b".repeat(64);
        candidate(&candidates, &records, &live);
        candidate(&candidates, &records, &orphan);
        fs::remove_file(records.join(format!("{orphan}.json"))).unwrap();
        let inspection = inspect_at(
            &candidates,
            &records,
            &CacheReferences {
                candidate_ids: [live.clone()].into_iter().collect(),
            },
        );
        assert!(matches!(
            inspection
                .entries
                .iter()
                .find(|entry| entry.id == live)
                .unwrap()
                .disposition,
            CacheDisposition::RetainedReference
        ));
        assert!(matches!(
            inspection
                .entries
                .iter()
                .find(|entry| entry.id == orphan)
                .unwrap()
                .disposition,
            CacheDisposition::Blocked { .. }
        ));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn prune_rechecks_identity_and_removes_only_quarantined_pair() {
        let (base, candidates, records) = fixture("prune");
        let id = "c".repeat(64);
        candidate(&candidates, &records, &id);
        let preview = inspect_at(&candidates, &records, &CacheReferences::default());
        let entry = preview.entries.into_iter().next().unwrap();
        assert_eq!(
            prune_at(&candidates, &records, &entry, &CacheReferences::default()),
            PruneOutcome::Pruned { id: id.clone() }
        );
        assert!(!candidates.join(&id).exists());
        assert!(!records.join(format!("{id}.json")).exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn prune_refuses_reference_added_after_preview() {
        let (base, candidates, records) = fixture("race");
        let id = "d".repeat(64);
        candidate(&candidates, &records, &id);
        let entry = inspect_at(&candidates, &records, &CacheReferences::default())
            .entries
            .remove(0);
        let references = CacheReferences {
            candidate_ids: [id.clone()].into_iter().collect(),
        };
        assert!(matches!(
            prune_at(&candidates, &records, &entry, &references),
            PruneOutcome::Retained { .. }
        ));
        assert!(candidates.join(id).is_dir());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn inspection_enumerates_sidecar_only_orphan() {
        let (base, candidates, records) = fixture("sidecar-only");
        let id = "e".repeat(64);
        fs::write(records.join(format!("{id}.json")), b"{}").unwrap();

        let inspection = inspect_at(&candidates, &records, &CacheReferences::default());
        assert!(!inspection.truncated);
        assert!(inspection.scan_blocker.is_none());
        let entry = inspection
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .unwrap();
        assert_eq!(entry.root, None);
        assert!(entry.sidecar.is_some());
        assert!(matches!(
            &entry.disposition,
            CacheDisposition::Blocked { reason } if reason.contains("sidecar-only orphan")
        ));
        assert!(records.join(format!("{id}.json")).is_file());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn interruption_after_first_rename_is_retryable() {
        let (base, candidates, records) = fixture("rename-retry");
        let id = "f".repeat(64);
        candidate(&candidates, &records, &id);
        let entry = inspect_at(&candidates, &records, &CacheReferences::default())
            .entries
            .remove(0);
        INJECT_FAILURE.with(|slot| slot.set(Some(FailurePoint::RootMoved)));
        assert!(matches!(
            prune_at(&candidates, &records, &entry, &CacheReferences::default()),
            PruneOutcome::Blocked { reason, .. } if reason.contains("injected cache interruption")
        ));
        assert!(!candidates.join(&id).exists());
        assert!(records.join(format!("{id}.json")).is_file());

        assert_eq!(
            recover_at(&candidates, &records, &CacheReferences::default()),
            vec![PruneOutcome::Pruned { id: id.clone() }]
        );
        assert!(!candidates.join(&id).exists());
        assert!(!records.join(format!("{id}.json")).exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn retry_after_partial_deletion_is_idempotent() {
        let (base, candidates, records) = fixture("delete-retry");
        let id = "1".repeat(64);
        candidate(&candidates, &records, &id);
        let entry = inspect_at(&candidates, &records, &CacheReferences::default())
            .entries
            .remove(0);
        INJECT_FAILURE.with(|slot| slot.set(Some(FailurePoint::RootDeleted)));
        assert!(matches!(
            prune_at(&candidates, &records, &entry, &CacheReferences::default()),
            PruneOutcome::Blocked { reason, .. } if reason.contains("injected cache interruption")
        ));

        assert_eq!(
            recover_at(&candidates, &records, &CacheReferences::default()),
            vec![PruneOutcome::Pruned { id: id.clone() }]
        );
        assert!(recover_at(&candidates, &records, &CacheReferences::default()).is_empty());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn reference_added_during_interruption_restores_both_objects() {
        let (base, candidates, records) = fixture("restore-retry");
        let id = "2".repeat(64);
        candidate(&candidates, &records, &id);
        let entry = inspect_at(&candidates, &records, &CacheReferences::default())
            .entries
            .remove(0);
        INJECT_FAILURE.with(|slot| slot.set(Some(FailurePoint::SidecarMoved)));
        assert!(matches!(
            prune_at(&candidates, &records, &entry, &CacheReferences::default()),
            PruneOutcome::Blocked { .. }
        ));
        let references = CacheReferences {
            candidate_ids: [id.clone()].into_iter().collect(),
        };
        assert!(matches!(
            recover_at(&candidates, &records, &references).as_slice(),
            [PruneOutcome::Retained { id: restored, .. }] if restored == &id
        ));
        assert!(candidates.join(&id).is_dir());
        assert!(records.join(format!("{id}.json")).is_file());
        assert!(recover_at(&candidates, &records, &references).is_empty());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn inspection_blocks_when_inventory_exceeds_fixed_cap() {
        let (base, candidates, records) = fixture("cap");
        for index in 0..=MAX_ENTRIES {
            let id = format!("{index:064x}");
            fs::create_dir(candidates.join(id)).unwrap();
        }
        let inspection = inspect_at(&candidates, &records, &CacheReferences::default());
        assert!(inspection.entries.is_empty());
        assert!(inspection
            .scan_blocker
            .as_deref()
            .is_some_and(|reason| reason.contains("cap")));
        fs::remove_dir_all(base).unwrap();
    }
}
