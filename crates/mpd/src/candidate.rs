//! Immutable candidate projection over `HEAD` plus the declared dirty union.
//!
//! This module is intentionally capture-only. It does not execute validation,
//! create Git objects or refs, install hooks, archive, commit, or push.

use crate::closure::{self, ChangeManifest};
use crate::digest::Digest;
use crate::git::{self, StatusEntry};
use crate::local_validation::{self, MaterializedSubject};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub const CANDIDATE_SCHEMA: u32 = 1;
const CANDIDATE_RECORD_SCHEMA: u32 = 1;
const MAX_CANDIDATE_ENTRIES: usize = 100_000;
const MAX_CANDIDATE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CANDIDATE_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CANDIDATE_PATH_BYTES: usize = 4096;
const MAX_CANDIDATE_RECORD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXCLUDED_DIRTY_SAMPLE: usize = 16;

/// The canonical state of one declared candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidatePathState {
    Present,
    Deleted,
}

/// Git's only supported regular-file modes for a candidate projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateMode {
    #[serde(rename = "100644")]
    Regular,
    #[serde(rename = "100755")]
    Executable,
}

impl CandidateMode {
    fn from_git_mode(mode: u32) -> Result<Self, String> {
        match mode {
            0o100644 => Ok(Self::Regular),
            0o100755 => Ok(Self::Executable),
            _ => Err(format!("candidate path has unsupported Git mode {mode:o}")),
        }
    }

    fn permission_mode(self) -> u32 {
        match self {
            Self::Regular => 0o400,
            Self::Executable => 0o500,
        }
    }
}

/// One sorted, raw-path candidate inventory entry. Deleted entries use no
/// mode/digest and length zero; present entries always carry all three.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEntry {
    pub path_bytes: Vec<u8>,
    pub state: CandidatePathState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<CandidateMode>,
    pub byte_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl CandidateEntry {
    fn deleted(path: &str) -> Self {
        Self {
            path_bytes: path.as_bytes().to_vec(),
            state: CandidatePathState::Deleted,
            mode: None,
            byte_len: 0,
            sha256: None,
        }
    }
}

/// A dirty path deliberately retained from base HEAD because it is outside
/// the declared candidate scope or is mutable MPD process state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedDirtyPath {
    pub path_bytes: Vec<u8>,
    pub status: String,
}

/// Stable content identity for one retained clone-private projection. Storage
/// location and capture-time display metadata are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSubject {
    pub version: u32,
    pub change: String,
    pub base_commit: String,
    pub base_tree: String,
    pub manifest_digest: String,
    pub entries_digest: String,
    pub policy_digest: String,
    pub source_digest: String,
    pub id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCounts {
    pub entries: usize,
    pub included_dirty: usize,
    pub deleted: usize,
    pub untracked: usize,
    pub executable: usize,
    pub excluded_dirty: usize,
}

/// Durable capture metadata. The clone-private path is display/reopen state,
/// never cleanup authority and never part of the candidate ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCapture {
    pub subject: CandidateSubject,
    pub clone_private_root: String,
    pub storage: CandidateStorageBinding,
    pub counts: CandidateCounts,
    pub excluded_dirty_digest: String,
    pub excluded_dirty_sample: Vec<ExcludedDirtyPath>,
    pub declared_status_digest: String,
    pub captured_at_epoch_secs: u64,
}

/// Compact durable authority for reopening the clone-private inventory
/// sidecar and the retained projection without placing the full path manifest
/// in the gate ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateStorageBinding {
    pub record_path: String,
    pub record_sha256: String,
    pub root_device: u64,
    pub root_inode: u64,
    pub record_device: u64,
    pub record_inode: u64,
}

/// Durable exact projected inventory paired with its capture metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProjection {
    pub capture: CandidateCapture,
    pub entries: Vec<CandidateEntry>,
    pub excluded_dirty_paths: Vec<ExcludedDirtyPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateProjectionRecordV1 {
    schema: u32,
    subject: CandidateSubject,
    entries: Vec<CandidateEntry>,
    excluded_dirty_paths: Vec<ExcludedDirtyPath>,
    counts: CandidateCounts,
    excluded_dirty_digest: String,
    declared_status_digest: String,
    root_device: u64,
    root_inode: u64,
    payload_digest: String,
}

#[derive(Debug)]
struct ObservedCandidateRecord {
    record: CandidateProjectionRecordV1,
    sha256: String,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct CandidateRecordPublishError {
    message: String,
    /// A published retained root may be removed only when the canonical
    /// sidecar path was positively observed absent after any owned unlink was
    /// made durable. `false` deliberately conflates present and uncertain.
    final_sidecar_absent_confirmed: bool,
}

impl From<String> for CandidateRecordPublishError {
    fn from(message: String) -> Self {
        Self {
            message,
            final_sidecar_absent_confirmed: false,
        }
    }
}

impl From<&str> for CandidateRecordPublishError {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

/// Runtime ownership for one published projection. Only this non-serializable
/// wrapper can invoke identity-bound cleanup.
#[derive(Debug)]
pub struct CapturedCandidate {
    pub projection: CandidateProjection,
    materialized: MaterializedSubject,
    source_root: PathBuf,
}

impl CapturedCandidate {
    pub fn root(&self) -> &Path {
        &self.materialized.root
    }

    /// Rehash the immutable tree and compare the complete declared inventory.
    /// Gate integration will use this in task 2.2; task 2.1 exposes and tests
    /// the primitive without connecting it to phase execution.
    pub fn rehash(&self, root: &Path) -> Result<(), String> {
        let manifest = load_ready_manifest(root, &self.projection.capture.subject.change)?;
        if manifest_digest(&manifest)? != self.projection.capture.subject.manifest_digest {
            return Err("candidate manifest drifted".into());
        }
        let base = local_validation::capture_subject(root, Some("HEAD"))?;
        if base.commit != self.projection.capture.subject.base_commit
            || base.tree != self.projection.capture.subject.base_tree
        {
            return Err("candidate base HEAD drifted".into());
        }
        let statuses = git::status_v2(root).map_err(|e| e.to_string())?;
        let (plan, _) = overlay_plan(&manifest, &statuses)?;
        if overlay_digest(&plan)? != self.projection.capture.declared_status_digest {
            return Err("candidate declared status drifted".into());
        }
        let inventory_by_path: BTreeMap<&[u8], &CandidateEntry> = self
            .projection
            .entries
            .iter()
            .map(|entry| (entry.path_bytes.as_slice(), entry))
            .collect();
        let mut noop = |_: CaptureHookPoint, _: &Path| {};
        for item in &plan {
            let expected = inventory_by_path.get(item.path.as_bytes()).copied();
            match item.source {
                OverlaySource::Index => {
                    if expected != Some(&read_index_entry(root, &item.path)?) {
                        return Err("candidate index postimage drifted".into());
                    }
                }
                OverlaySource::Worktree | OverlaySource::Untracked => {
                    let (entry, _) = read_worktree_entry(root, &item.path, &mut noop)?;
                    if expected != Some(&entry) {
                        return Err("candidate worktree postimage drifted".into());
                    }
                }
                OverlaySource::Deleted => {
                    if expected.is_none_or(|entry| entry.state != CandidatePathState::Deleted) {
                        return Err("candidate deletion drifted".into());
                    }
                }
            }
        }
        let observed = inventory_read_only_projection(
            self.root(),
            &manifest,
            &deleted_paths(&self.projection.entries)?,
        )?;
        if observed != self.projection.entries {
            return Err("candidate projection inventory drifted".into());
        }
        if entries_digest(&observed)? != self.projection.capture.subject.entries_digest
            || source_digest(&observed)? != self.projection.capture.subject.source_digest
        {
            return Err("candidate projection digest drifted".into());
        }
        Ok(())
    }

    pub fn cleanup(self) -> Result<(), String> {
        self.cleanup_inner(|| Ok(()))
    }

    fn cleanup_inner<F>(self, after_record_removed: F) -> Result<(), String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        let CapturedCandidate {
            projection,
            materialized,
            source_root,
        } = self;
        // Validate both authorities before deleting either. Then remove the
        // sidecar first: if tree cleanup fails, same-ID retry can re-inventory
        // the retained root and recreate the record. The reverse order could
        // strand an authoritative record with no recoverable projection.
        reopen_candidate(&source_root, &projection.capture)?;
        materialized.verify_identity()?;
        remove_candidate_record(&projection.capture.storage)?;
        after_record_removed()?;
        materialized.cleanup()
    }
}

/// Reopen one compact ledger capture through its canonical clone-private
/// sidecar, revalidating both file identities and the complete retained tree.
pub fn reopen_candidate(
    root: &Path,
    capture: &CandidateCapture,
) -> Result<CandidateProjection, String> {
    if capture.subject.version != CANDIDATE_SCHEMA {
        return Err("unsupported candidate subject version".into());
    }
    Digest::from_hex(&capture.subject.id).map_err(|_| "candidate ID is invalid")?;
    let candidates = candidate_parent_read_only(root)?;
    let expected_root = candidates.join(&capture.subject.id);
    if expected_root.to_str() != Some(capture.clone_private_root.as_str()) {
        return Err("candidate root binding is non-canonical".into());
    }
    let expected_record_path = candidate_record_path_read_only(root, &capture.subject.id)?;
    if expected_record_path.to_str() != Some(capture.storage.record_path.as_str()) {
        return Err("candidate record binding is non-canonical".into());
    }
    let first = read_candidate_record(&expected_record_path)?;
    verify_record_binding(capture, &first)?;
    validate_inventory(&first.record.entries)?;
    if entries_digest(&first.record.entries)? != capture.subject.entries_digest
        || source_digest(&first.record.entries)? != capture.subject.source_digest
        || candidate_id(
            &capture.subject.base_tree,
            &capture.subject.manifest_digest,
            &capture.subject.entries_digest,
            &capture.subject.policy_digest,
            &capture.subject.source_digest,
        )? != capture.subject.id
    {
        return Err("candidate projection record does not match its subject ID".into());
    }
    let manifest = load_ready_manifest(root, &capture.subject.change)?;
    if manifest_digest(&manifest)? != capture.subject.manifest_digest {
        return Err("candidate manifest drifted before reopen".into());
    }
    let deletions = deleted_paths(&first.record.entries)?;
    let (root_device, root_inode) = verify_retained_projection(
        &expected_root,
        &candidates,
        &capture.subject.id,
        &manifest,
        &deletions,
        &first.record.entries,
    )?;
    if root_device != capture.storage.root_device || root_inode != capture.storage.root_inode {
        return Err("candidate retained root identity does not match its binding".into());
    }
    let second = read_candidate_record(&expected_record_path)?;
    verify_record_binding(capture, &second)?;
    if first.record != second.record
        || first.sha256 != second.sha256
        || first.device != second.device
        || first.inode != second.inode
    {
        return Err("candidate projection record changed during reopen".into());
    }
    Ok(CandidateProjection {
        capture: capture.clone(),
        entries: first.record.entries,
        excluded_dirty_paths: first.record.excluded_dirty_paths,
    })
}

fn verify_record_binding(
    capture: &CandidateCapture,
    observed: &ObservedCandidateRecord,
) -> Result<(), String> {
    let record = &observed.record;
    if observed.sha256 != capture.storage.record_sha256
        || observed.device != capture.storage.record_device
        || observed.inode != capture.storage.record_inode
        || record.subject != capture.subject
        || record.counts != capture.counts
        || record.excluded_dirty_digest != capture.excluded_dirty_digest
        || record.declared_status_digest != capture.declared_status_digest
        || record.root_device != capture.storage.root_device
        || record.root_inode != capture.storage.root_inode
        || record.excluded_dirty_paths.len() != capture.counts.excluded_dirty
        || record
            .excluded_dirty_paths
            .iter()
            .take(MAX_EXCLUDED_DIRTY_SAMPLE)
            .ne(capture.excluded_dirty_sample.iter())
        || domain_digest(
            b"mpd:candidate:excluded-dirty:v1",
            &record.excluded_dirty_paths,
        )? != capture.excluded_dirty_digest
    {
        return Err("candidate projection record does not match its compact binding".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlaySource {
    Index,
    Worktree,
    Untracked,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OverlayPlanEntry {
    path: String,
    source: OverlaySource,
    status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureHookPoint {
    AfterWorktreeOpen,
    BeforeGitReobserve,
    BeforePublication,
    AfterPublication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordPublishFailurePoint {
    LinkPublished,
    TemporaryUnlinked,
    ParentSynced,
}

struct ReobserveExpectation<'a> {
    change: &'a str,
    base: &'a local_validation::Subject,
    manifest_digest: &'a str,
    index: &'a Digest,
    status: &'a [StatusEntry],
    plan: &'a [OverlayPlanEntry],
    overlays: &'a BTreeMap<String, CandidateEntry>,
}

#[cfg(test)]
thread_local! {
    static RECORD_PUBLISH_FAILURE: std::cell::Cell<Option<RecordPublishFailurePoint>> = const {
        std::cell::Cell::new(None)
    };
    static RECORD_READ_REPLACEMENT_COUNTDOWN: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static RECORD_FINAL_CLEANUP_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

fn maybe_inject_record_publish_failure(
    #[cfg_attr(not(test), allow(unused_variables))] point: RecordPublishFailurePoint,
) -> Result<(), String> {
    #[cfg(test)]
    {
        let inject = RECORD_PUBLISH_FAILURE.with(|slot| slot.get() == Some(point));
        if inject {
            RECORD_PUBLISH_FAILURE.with(|slot| slot.set(None));
            return Err(format!("injected candidate record failure after {point:?}"));
        }
    }
    Ok(())
}

/// Capture and atomically publish one read-only candidate below the clone's
/// common `.git/mpd/candidates` directory.
pub fn capture_candidate(
    root: &Path,
    change: &str,
    policy_digest: &str,
) -> Result<CapturedCandidate, String> {
    capture_candidate_with_hook(root, change, policy_digest, &mut |_, _| {})
}

fn capture_candidate_with_hook<F>(
    root: &Path,
    change: &str,
    policy_digest: &str,
    hook: &mut F,
) -> Result<CapturedCandidate, String>
where
    F: FnMut(CaptureHookPoint, &Path),
{
    Digest::from_hex(policy_digest).map_err(|_| "candidate policy digest is invalid")?;
    let manifest = load_ready_manifest(root, change)?;
    let manifest_digest = manifest_digest(&manifest)?;
    let base = local_validation::capture_subject(root, Some("HEAD"))?;
    let index_before = git::index_identity(root).map_err(|e| e.to_string())?;
    let status_before = git::status_v2(root).map_err(|e| e.to_string())?;
    let (plan, mut excluded) = overlay_plan(&manifest, &status_before)?;
    validate_plan_collisions(&plan)?;
    validate_worktree_surface(root, &manifest, &plan)?;

    let candidates = candidate_parent(root)?;
    let mut materialized =
        local_validation::materialize_subject_in(root, &base, &candidates, ".candidate-stage-")?;
    let mut preserve_published_root_on_error = false;
    let capture_result = (|| {
        prune_mutable_process_paths(&materialized.root)?;
        let mut observed_overlays = BTreeMap::new();
        for item in &plan {
            let observed = apply_overlay(root, &materialized.root, item, hook)?;
            if let Some(entry) = observed {
                observed_overlays.insert(item.path.clone(), entry);
            }
        }

        let deletion_set: BTreeSet<String> = plan
            .iter()
            .filter(|item| item.source == OverlaySource::Deleted)
            .map(|item| item.path.clone())
            .collect();
        let entries = inventory_projection(&materialized.root, &manifest, &deletion_set)?;
        validate_inventory(&entries)?;

        hook(CaptureHookPoint::BeforeGitReobserve, root);
        let expected = ReobserveExpectation {
            change,
            base: &base,
            manifest_digest: &manifest_digest,
            index: &index_before,
            status: &status_before,
            plan: &plan,
            overlays: &observed_overlays,
        };
        reobserve_inputs(root, &expected, hook)?;
        let second_inventory = inventory_projection(&materialized.root, &manifest, &deletion_set)?;
        if second_inventory != entries {
            return Err("candidate projection changed during capture".into());
        }

        let entries_digest = entries_digest(&entries)?;
        let source_digest = source_digest(&entries)?;
        let id = candidate_id(
            &base.tree,
            &manifest_digest,
            &entries_digest,
            policy_digest,
            &source_digest,
        )?;
        let final_root = candidates.join(&id);
        excluded.sort_by(|a, b| {
            a.path_bytes
                .cmp(&b.path_bytes)
                .then(a.status.cmp(&b.status))
        });
        let counts = CandidateCounts {
            entries: entries.len(),
            included_dirty: plan.len(),
            deleted: deletion_set.len(),
            untracked: plan
                .iter()
                .filter(|item| item.source == OverlaySource::Untracked)
                .count(),
            executable: entries
                .iter()
                .filter(|entry| entry.mode == Some(CandidateMode::Executable))
                .count(),
            excluded_dirty: excluded.len(),
        };
        let clone_private_root = final_root
            .to_str()
            .ok_or("candidate root is not UTF-8")?
            .to_string();
        let subject = CandidateSubject {
            version: CANDIDATE_SCHEMA,
            change: change.to_string(),
            base_commit: base.commit,
            base_tree: base.tree,
            manifest_digest,
            entries_digest,
            policy_digest: policy_digest.to_string(),
            source_digest,
            id,
        };
        let declared_status_digest = overlay_digest(&plan)?;
        let excluded_dirty_digest = domain_digest(b"mpd:candidate:excluded-dirty:v1", &excluded)?;
        let excluded_dirty_sample = excluded
            .iter()
            .take(MAX_EXCLUDED_DIRTY_SAMPLE)
            .cloned()
            .collect::<Vec<_>>();
        let records = candidate_record_parent(root)?;
        let record_path = records.join(format!("{}.json", subject.id));
        let build_record =
            |root_device: u64, root_inode: u64| -> Result<CandidateProjectionRecordV1, String> {
                finalize_candidate_record(CandidateProjectionRecordV1 {
                    schema: CANDIDATE_RECORD_SCHEMA,
                    subject: subject.clone(),
                    entries: entries.clone(),
                    excluded_dirty_paths: excluded.clone(),
                    counts: counts.clone(),
                    excluded_dirty_digest: excluded_dirty_digest.clone(),
                    declared_status_digest: declared_status_digest.clone(),
                    root_device,
                    root_inode,
                    payload_digest: String::new(),
                })
            };

        let (root_device, root_inode, observed_record) = match fs::symlink_metadata(&final_root) {
            Ok(_) => {
                let (device, inode) = verify_retained_projection(
                    &final_root,
                    &candidates,
                    &subject.id,
                    &manifest,
                    &deletion_set,
                    &entries,
                )?;
                let expected_record = build_record(device, inode)?;
                let observed_record = match fs::symlink_metadata(&record_path) {
                    Ok(_) => {
                        recover_candidate_record_publication(&record_path)?;
                        let observed = read_candidate_record(&record_path)?;
                        if observed.record != expected_record {
                            return Err(
                                "existing candidate projection record does not match its ID".into(),
                            );
                        }
                        observed
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        publish_candidate_record(&record_path, &expected_record).map_err(
                            |failure| {
                                preserve_published_root_on_error |= materialized.root == final_root
                                    && !failure.final_sidecar_absent_confirmed;
                                failure.message
                            },
                        )?
                    }
                    Err(error) => {
                        return Err(format!(
                            "cannot inspect candidate projection record: {error}"
                        ));
                    }
                };
                materialized.replace_with_existing(
                    &final_root,
                    &candidates,
                    &subject.id,
                    device,
                    inode,
                )?;
                materialized.verify_identity()?;
                (device, inode, observed_record)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if fs::symlink_metadata(&record_path).is_ok() {
                    return Err(
                        "candidate projection record exists without its retained root".into(),
                    );
                }
                make_projection_read_only(&materialized.root)?;
                sync_tree(&materialized.root)?;
                hook(CaptureHookPoint::BeforePublication, &materialized.root);
                materialized.publish_within_parent(&final_root, &subject.id)?;
                sync_directory(&candidates)?;
                hook(CaptureHookPoint::AfterPublication, &materialized.root);
                materialized.verify_identity()?;
                let (device, inode) = verify_retained_projection(
                    &materialized.root,
                    &candidates,
                    &subject.id,
                    &manifest,
                    &deletion_set,
                    &entries,
                )?;
                materialized.verify_identity()?;
                let expected_record = build_record(device, inode)?;
                let observed_record = publish_candidate_record(&record_path, &expected_record)
                    .map_err(|failure| {
                        preserve_published_root_on_error |= materialized.root == final_root
                            && !failure.final_sidecar_absent_confirmed;
                        failure.message
                    })?;
                (device, inode, observed_record)
            }
            Err(error) => return Err(format!("cannot inspect retained candidate: {error}")),
        };

        let record_path = record_path
            .to_str()
            .ok_or("candidate projection record path is not UTF-8")?
            .to_string();
        Ok(CandidateProjection {
            capture: CandidateCapture {
                subject,
                clone_private_root,
                storage: CandidateStorageBinding {
                    record_path,
                    record_sha256: observed_record.sha256,
                    root_device,
                    root_inode,
                    record_device: observed_record.device,
                    record_inode: observed_record.inode,
                },
                counts,
                excluded_dirty_digest,
                excluded_dirty_sample,
                declared_status_digest,
                captured_at_epoch_secs: crate::ledger::now_epoch_secs(),
            },
            entries,
            excluded_dirty_paths: excluded,
        })
    })();

    match capture_result {
        Ok(projection) => Ok(CapturedCandidate {
            projection,
            materialized,
            source_root: root.to_path_buf(),
        }),
        Err(error) => {
            if preserve_published_root_on_error {
                return Err(format!(
                    "{error}; retained candidate root preserved because final sidecar absence was not confirmed"
                ));
            }
            let cleanup = materialized.cleanup();
            match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!(
                    "{error}; candidate cleanup also failed: {cleanup_error}"
                )),
            }
        }
    }
}

fn load_ready_manifest(root: &Path, change: &str) -> Result<ChangeManifest, String> {
    let manifest = closure::load_manifest(root, change).map_err(|e| e.to_string())?;
    let issues = manifest.validate();
    if !issues.is_empty() {
        return Err(format!(
            "candidate manifest is not ready: {}",
            issues
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    Ok(manifest)
}

fn manifest_digest(manifest: &ChangeManifest) -> Result<String, String> {
    domain_digest(b"mpd:candidate:manifest:v1", manifest)
}

fn declared(manifest: &ChangeManifest, path: &str) -> bool {
    manifest
        .paths
        .iter()
        .chain(manifest.shared_paths.iter())
        .any(|pattern| crate::pathmatch::glob_match(pattern, path))
}

fn may_contain_declared_descendant(manifest: &ChangeManifest, directory: &str) -> bool {
    manifest
        .paths
        .iter()
        .chain(manifest.shared_paths.iter())
        .any(|pattern| crate::pathmatch::glob_may_match_descendant(pattern, directory))
}

fn mutable_process_path(path: &str) -> bool {
    path == ".mpd/state"
        || path.starts_with(".mpd/state/")
        || path == ".mpd/current"
        || path == ".mpd/pending-closure"
        || path == ".mpd/parity-observations.json"
        || path == ".mpd/build-output"
        || path.starts_with(".mpd/build-output/")
        || path == ".mpd/local"
        || path.starts_with(".mpd/local/")
        || path == ".mpd/validation"
        || path.starts_with(".mpd/validation/")
        || path == ".mpd/logs"
        || path.starts_with(".mpd/logs/")
        || path == ".mpd/cache"
        || path.starts_with(".mpd/cache/")
        || path.starts_with(".git/mpd/")
}

fn validate_candidate_path(path: &str) -> Result<(), String> {
    if path.len() > MAX_CANDIDATE_PATH_BYTES {
        return Err("candidate path exceeds its byte cap".into());
    }
    crate::digest::validate_canonical_path(path).map_err(|e| e.to_string())
}

fn status_choice(xy: &str) -> Result<OverlaySource, String> {
    let bytes = xy.as_bytes();
    if bytes.len() != 2 {
        return Err("candidate status has malformed XY state".into());
    }
    let (index, worktree) = (bytes[0], bytes[1]);
    if worktree != b'.' {
        if worktree == b'D' {
            Ok(OverlaySource::Deleted)
        } else {
            Ok(OverlaySource::Worktree)
        }
    } else if index == b'D' {
        Ok(OverlaySource::Deleted)
    } else if index != b'.' {
        Ok(OverlaySource::Index)
    } else {
        Err("candidate status contains no change".into())
    }
}

fn overlay_plan(
    manifest: &ChangeManifest,
    statuses: &[StatusEntry],
) -> Result<(Vec<OverlayPlanEntry>, Vec<ExcludedDirtyPath>), String> {
    let mut plan = BTreeMap::<String, OverlayPlanEntry>::new();
    let mut excluded = Vec::new();
    let mut add = |path: &str, source: OverlaySource, status: String| -> Result<(), String> {
        validate_candidate_path(path)?;
        if mutable_process_path(path) || !declared(manifest, path) {
            excluded.push(ExcludedDirtyPath {
                path_bytes: path.as_bytes().to_vec(),
                status: if mutable_process_path(path) {
                    format!("process-state-excluded:{status}")
                } else {
                    status
                },
            });
            return Ok(());
        }
        let entry = OverlayPlanEntry {
            path: path.to_string(),
            source,
            status,
        };
        if plan.insert(path.to_string(), entry).is_some() {
            return Err(format!("candidate path collision at {path:?}"));
        }
        Ok(())
    };

    for status in statuses {
        match status {
            StatusEntry::Ordinary { xy, path } => {
                add(path, status_choice(xy)?, format!("tracked:{xy}"))?;
            }
            StatusEntry::RenamedOrCopied {
                xy,
                score,
                path,
                orig_path,
            } => {
                add(path, status_choice(xy)?, format!("tracked:{xy}:{score}"))?;
                if score.starts_with('R') {
                    add(
                        orig_path,
                        OverlaySource::Deleted,
                        format!("tracked-rename-source:{xy}:{score}"),
                    )?;
                }
            }
            StatusEntry::Unmerged { path, .. } => {
                return Err(format!("unmerged path blocks candidate capture: {path:?}"));
            }
            StatusEntry::Untracked { path } => {
                add(path, OverlaySource::Untracked, "untracked".into())?;
            }
            StatusEntry::Ignored { path } if mutable_process_path(path) => {
                add(
                    path,
                    OverlaySource::Untracked,
                    "ignored-process-state".into(),
                )?;
            }
            StatusEntry::Ignored { path } if declared(manifest, path) => {
                return Err(format!(
                    "declared ignored path blocks candidate capture: {path:?}"
                ));
            }
            StatusEntry::Ignored { .. } => {}
        }
    }
    if plan.len() > MAX_CANDIDATE_ENTRIES || excluded.len() > MAX_CANDIDATE_ENTRIES {
        return Err("candidate dirty-path count exceeds its cap".into());
    }
    Ok((plan.into_values().collect(), excluded))
}

fn validate_plan_collisions(plan: &[OverlayPlanEntry]) -> Result<(), String> {
    for pair in plan.windows(2) {
        let a = &pair[0].path;
        let b = &pair[1].path;
        if b.starts_with(&format!("{a}/")) {
            return Err(format!(
                "candidate file/directory collision: {a:?} and {b:?}"
            ));
        }
    }
    Ok(())
}

/// Git status intentionally omits some filesystem objects (notably FIFOs).
/// Independently enumerate the cooperative owner's worktree without following
/// links so no declared special/symlink/omitted regular path can disappear
/// from the overlay union.
fn validate_worktree_surface(
    root: &Path,
    manifest: &ChangeManifest,
    plan: &[OverlayPlanEntry],
) -> Result<(), String> {
    let tracked: BTreeSet<String> = git::ls_files(root)
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect();
    let planned: BTreeSet<&str> = plan.iter().map(|entry| entry.path.as_str()).collect();
    let mut remaining = MAX_CANDIDATE_ENTRIES;
    validate_worktree_directory(root, root, manifest, &tracked, &planned, &mut remaining)
}

fn validate_worktree_directory(
    root: &Path,
    directory: &Path,
    manifest: &ChangeManifest,
    tracked: &BTreeSet<String>,
    planned: &BTreeSet<&str>,
    remaining: &mut usize,
) -> Result<(), String> {
    let mut children = fs::read_dir(directory)
        .map_err(|e| format!("cannot enumerate candidate worktree: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot enumerate candidate worktree entry: {e}"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let relative_path = path
            .strip_prefix(root)
            .map_err(|_| "candidate worktree path escaped its root")?;
        let relative = path_to_utf8(relative_path)?;
        validate_candidate_path(&relative)?;
        if relative == ".git" || relative.starts_with(".git/") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot inspect candidate worktree entry: {e}"))?;
        if mutable_process_path(&relative) {
            continue;
        }
        let relevant = declared(manifest, &relative)
            || (metadata.is_dir() && may_contain_declared_descendant(manifest, &relative));
        if !relevant {
            continue;
        }
        if *remaining == 0 {
            return Err("candidate worktree entry count exceeds its cap".into());
        }
        *remaining -= 1;
        if metadata.file_type().is_symlink() {
            if declared(manifest, &relative) {
                return Err(format!(
                    "declared candidate path is a symlink: {relative:?}"
                ));
            }
            continue;
        }
        if metadata.is_dir() {
            validate_worktree_directory(root, &path, manifest, tracked, planned, remaining)?;
        } else if metadata.is_file() {
            if declared(manifest, &relative)
                && !tracked.contains(&relative)
                && !planned.contains(relative.as_str())
            {
                return Err(format!(
                    "declared untracked path was omitted from normalized status: {relative:?}"
                ));
            }
        } else if declared(manifest, &relative) {
            return Err(format!(
                "declared candidate path is a special file: {relative:?}"
            ));
        }
    }
    Ok(())
}

fn overlay_digest(plan: &[OverlayPlanEntry]) -> Result<String, String> {
    let stable: Vec<(&str, &str, &str)> = plan
        .iter()
        .map(|entry| {
            let source = match entry.source {
                OverlaySource::Index => "index",
                OverlaySource::Worktree => "worktree",
                OverlaySource::Untracked => "untracked",
                OverlaySource::Deleted => "deleted",
            };
            (entry.path.as_str(), source, entry.status.as_str())
        })
        .collect();
    domain_digest(b"mpd:candidate:declared-status:v1", &stable)
}

fn candidate_parent(root: &Path) -> Result<PathBuf, String> {
    let common = local_validation::git_common_dir(root)?;
    ensure_owner_private_dir(&common)?;
    let mpd = common.join("mpd");
    create_or_validate_private_dir(&mpd)?;
    let candidates = mpd.join("candidates");
    create_or_validate_private_dir(&candidates)?;
    Ok(candidates)
}

fn candidate_record_parent(root: &Path) -> Result<PathBuf, String> {
    let common = local_validation::git_common_dir(root)?;
    ensure_owner_private_dir(&common)?;
    let mpd = common.join("mpd");
    create_or_validate_private_dir(&mpd)?;
    let records = mpd.join("candidate-records");
    create_or_validate_private_dir(&records)?;
    Ok(records)
}

fn candidate_parent_read_only(root: &Path) -> Result<PathBuf, String> {
    let common = local_validation::git_common_dir(root)?;
    ensure_owner_private_dir(&common)?;
    let mpd = common.join("mpd");
    validate_existing_private_dir(&mpd, "clone-private MPD directory")?;
    let candidates = mpd.join("candidates");
    validate_existing_private_dir(&candidates, "candidate directory")?;
    Ok(candidates)
}

fn candidate_record_parent_read_only(root: &Path) -> Result<PathBuf, String> {
    let common = local_validation::git_common_dir(root)?;
    ensure_owner_private_dir(&common)?;
    let mpd = common.join("mpd");
    validate_existing_private_dir(&mpd, "clone-private MPD directory")?;
    let records = mpd.join("candidate-records");
    validate_existing_private_dir(&records, "candidate record directory")?;
    Ok(records)
}

fn candidate_record_path_read_only(root: &Path, id: &str) -> Result<PathBuf, String> {
    Digest::from_hex(id).map_err(|_| "candidate record ID is invalid")?;
    Ok(candidate_record_parent_read_only(root)?.join(format!("{id}.json")))
}

fn validate_existing_private_dir(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("{label} is unavailable: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} is unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!("{label} is not owner-only"));
        }
    }
    Ok(())
}

fn candidate_record_payload_digest(record: &CandidateProjectionRecordV1) -> Result<String, String> {
    let mut payload = record.clone();
    payload.payload_digest.clear();
    domain_digest(b"mpd:candidate:projection-record:v1", &payload)
}

fn finalize_candidate_record(
    mut record: CandidateProjectionRecordV1,
) -> Result<CandidateProjectionRecordV1, String> {
    record.payload_digest = candidate_record_payload_digest(&record)?;
    Ok(record)
}

fn read_candidate_record(path: &Path) -> Result<ObservedCandidateRecord, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|e| format!("candidate projection record is unavailable: {e}"))?;
    validate_candidate_record_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot open candidate projection record: {e}"))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("cannot stat candidate projection record: {e}"))?;
    if !same_metadata(&before, &opened) {
        return Err("candidate projection record changed while opening".into());
    }
    let mut bytes = Vec::with_capacity((opened.len() as usize).min(1024 * 1024));
    std::io::Read::by_ref(&mut file)
        .take(MAX_CANDIDATE_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read candidate projection record: {e}"))?;
    let after = file
        .metadata()
        .map_err(|e| format!("cannot restat candidate projection record: {e}"))?;
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_CANDIDATE_RECORD_BYTES
        || bytes.len() as u64 != after.len()
        || !same_metadata(&opened, &after)
    {
        return Err("candidate projection record drifted during read".into());
    }
    validate_candidate_record_metadata(&after)?;
    #[cfg(test)]
    maybe_inject_record_read_replacement(path, &bytes)?;
    let final_path = fs::symlink_metadata(path)
        .map_err(|_| "candidate projection record path disappeared after read")?;
    validate_candidate_record_metadata(&final_path)?;
    if !same_metadata(&after, &final_path) {
        return Err("candidate projection record path changed after descriptor read".into());
    }
    let record: CandidateProjectionRecordV1 = serde_json::from_slice(&bytes)
        .map_err(|e| format!("candidate projection record is malformed: {e}"))?;
    if record.schema != CANDIDATE_RECORD_SCHEMA
        || record.payload_digest != candidate_record_payload_digest(&record)?
    {
        return Err("candidate projection record digest is invalid".into());
    }
    let canonical = serde_json::to_vec(&record)
        .map_err(|e| format!("cannot canonicalize candidate projection record: {e}"))?;
    if canonical != bytes {
        return Err("candidate projection record is not canonical".into());
    }
    let (device, inode) = directory_identity(&after);
    Ok(ObservedCandidateRecord {
        record,
        sha256: Digest::of_bytes(&bytes).to_hex(),
        device,
        inode,
    })
}

#[cfg(test)]
fn maybe_inject_record_read_replacement(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let replace = RECORD_READ_REPLACEMENT_COUNTDOWN.with(|slot| {
        let remaining = slot.get();
        if remaining == 0 {
            false
        } else {
            slot.set(remaining - 1);
            remaining == 1
        }
    });
    if !replace {
        return Ok(());
    }
    let old = path.with_extension("record-read-hook-old");
    fs::rename(path, &old).map_err(|e| format!("cannot inject record replacement: {e}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut replacement = options
        .open(path)
        .map_err(|e| format!("cannot inject replacement record: {e}"))?;
    replacement
        .write_all(bytes)
        .map_err(|e| format!("cannot write replacement record: {e}"))?;
    replacement
        .sync_all()
        .map_err(|e| format!("cannot sync replacement record: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .map_err(|e| format!("cannot protect replacement record: {e}"))?;
    }
    Ok(())
}

/// Recover the only interrupted hard-link publication state: `final` and one
/// or more owned staging names are the same inode because the process stopped
/// between link(final) and unlink(temp). Foreign links or mismatched staging
/// identities block; only exact owned staging links are removed.
fn recover_candidate_record_publication(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| format!("candidate projection record is unavailable: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() <= 1 {
            return Ok(());
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("candidate projection record name is not UTF-8")?;
        let id = file_name
            .strip_suffix(".json")
            .ok_or("candidate projection record name is non-canonical")?;
        Digest::from_hex(id).map_err(|_| "candidate projection record name is invalid")?;
        let prefix = format!(".candidate-record-stage-{id}-");
        let parent = path
            .parent()
            .ok_or("candidate projection record has no parent")?;
        let mut entries = fs::read_dir(parent)
            .map_err(|e| format!("cannot enumerate candidate record recovery: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("cannot enumerate candidate record recovery entry: {e}"))?;
        if entries.len() > MAX_CANDIDATE_ENTRIES {
            return Err("candidate record recovery entry count exceeds its cap".into());
        }
        entries.sort_by_key(|entry| entry.file_name());
        let mut removed = 0_u64;
        for entry in entries {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(&prefix) {
                continue;
            }
            let staging = entry.path();
            let observed = fs::symlink_metadata(&staging)
                .map_err(|_| "candidate record staging link disappeared")?;
            if observed.file_type().is_symlink()
                || !observed.is_file()
                || observed.dev() != metadata.dev()
                || observed.ino() != metadata.ino()
                || observed.permissions().mode() & 0o777 != 0o400
            {
                return Err("candidate record recovery found a mismatched staging link".into());
            }
            fs::remove_file(&staging)
                .map_err(|e| format!("cannot remove recovered candidate staging link: {e}"))?;
            removed = removed.saturating_add(1);
        }
        let after = fs::symlink_metadata(path)
            .map_err(|_| "candidate projection record disappeared during recovery")?;
        if removed == 0
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.nlink() != 1
        {
            return Err("candidate record publication has unrecoverable extra links".into());
        }
        sync_directory(parent)?;
    }
    Ok(())
}

fn validate_candidate_record_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CANDIDATE_RECORD_BYTES
    {
        return Err("candidate projection record is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != 0o400 || metadata.nlink() != 1 {
            return Err(
                "candidate projection record is not owner-only, read-only, and single-link".into(),
            );
        }
    }
    #[cfg(not(unix))]
    if !metadata.permissions().readonly() {
        return Err("candidate projection record is writable".into());
    }
    Ok(())
}

fn publish_candidate_record(
    path: &Path,
    expected: &CandidateProjectionRecordV1,
) -> Result<ObservedCandidateRecord, CandidateRecordPublishError> {
    let expected_name = format!("{}.json", expected.subject.id);
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err("candidate projection record path is non-canonical".into());
    }
    let parent = path
        .parent()
        .ok_or("candidate projection record has no parent")?;
    let bytes = serde_json::to_vec(expected)
        .map_err(|e| format!("cannot encode candidate projection record: {e}"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CANDIDATE_RECORD_BYTES {
        return Err("candidate projection record exceeds its cap".into());
    }
    let temporary = parent.join(format!(
        ".candidate-record-stage-{}-{}-{}",
        expected.subject.id,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    let expected_sha256 = Digest::of_bytes(&bytes).to_hex();
    let mut owned_identity = None;
    let mut temporary_exists = false;
    let mut owns_final = false;
    let result = (|| -> Result<ObservedCandidateRecord, String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|e| format!("cannot create candidate projection record: {e}"))?;
        file.write_all(&bytes)
            .map_err(|e| format!("cannot write candidate projection record: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot sync candidate projection record: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o400))
                .map_err(|e| format!("cannot protect candidate projection record: {e}"))?;
        }
        let protected = fs::symlink_metadata(&temporary)
            .map_err(|_| "candidate record staging file disappeared")?;
        let (temporary_device, temporary_inode) = directory_identity(&protected);
        owned_identity = Some((temporary_device, temporary_inode));
        temporary_exists = true;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                owns_final = true;
                maybe_inject_record_publish_failure(RecordPublishFailurePoint::LinkPublished)?;
                remove_owned_record_path(
                    &temporary,
                    temporary_device,
                    temporary_inode,
                    &expected_sha256,
                )?;
                temporary_exists = false;
                maybe_inject_record_publish_failure(RecordPublishFailurePoint::TemporaryUnlinked)?;
                sync_directory(parent)?;
                maybe_inject_record_publish_failure(RecordPublishFailurePoint::ParentSynced)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                remove_owned_record_path(
                    &temporary,
                    temporary_device,
                    temporary_inode,
                    &expected_sha256,
                )?;
                temporary_exists = false;
            }
            Err(error) => {
                return Err(format!(
                    "cannot atomically publish candidate projection record: {error}"
                ));
            }
        }
        // Publication and capture retry are explicitly mutating contexts. A
        // pure reopen never invokes this repair path.
        recover_candidate_record_publication(path)?;
        let observed = read_candidate_record(path)?;
        if observed.record != *expected {
            return Err("existing candidate projection record does not match its ID".into());
        }
        Ok(observed)
    })();
    match result {
        Ok(observed) => Ok(observed),
        Err(error) => {
            let mut cleanup_errors = Vec::new();
            let mut owned_final_removed = false;
            if owns_final {
                if let Some((device, inode)) = owned_identity {
                    match remove_owned_record_path(path, device, inode, &expected_sha256) {
                        Ok(()) => owned_final_removed = true,
                        Err(cleanup) => cleanup_errors.push(cleanup),
                    }
                }
            }
            if temporary_exists {
                if let Some((device, inode)) = owned_identity {
                    if let Err(cleanup) =
                        remove_owned_record_path(&temporary, device, inode, &expected_sha256)
                    {
                        cleanup_errors.push(cleanup);
                    }
                }
            }
            let mut owned_final_removal_durable = !owns_final;
            if owned_final_removed {
                match sync_directory(parent) {
                    Ok(()) => owned_final_removal_durable = true,
                    Err(cleanup) => cleanup_errors.push(cleanup),
                }
            }
            let final_path_absent = matches!(
                fs::symlink_metadata(path),
                Err(ref error) if error.kind() == std::io::ErrorKind::NotFound
            );
            let final_sidecar_absent_confirmed = final_path_absent && owned_final_removal_durable;
            let message = if cleanup_errors.is_empty() {
                error
            } else {
                format!(
                    "{error}; candidate record cleanup also failed: {}",
                    cleanup_errors.join("; ")
                )
            };
            Err(CandidateRecordPublishError {
                message,
                final_sidecar_absent_confirmed,
            })
        }
    }
}

fn remove_owned_record_path(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    #[cfg(test)]
    if path.extension().and_then(|extension| extension.to_str()) == Some("json")
        && RECORD_FINAL_CLEANUP_FAILURE.with(|slot| slot.replace(false))
    {
        return Err("injected candidate final-sidecar cleanup failure".into());
    }
    let before = fs::symlink_metadata(path)
        .map_err(|_| "owned candidate record cleanup target disappeared")?;
    let (device, inode) = directory_identity(&before);
    if before.file_type().is_symlink()
        || !before.is_file()
        || device != expected_device
        || inode != expected_inode
        || before.len() == 0
        || before.len() > MAX_CANDIDATE_RECORD_BYTES
    {
        return Err("owned candidate record cleanup blocked by identity drift".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot reopen owned candidate record: {e}"))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("cannot stat owned candidate record: {e}"))?;
    if directory_identity(&opened) != (expected_device, expected_inode) {
        return Err("owned candidate record changed while opening".into());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_CANDIDATE_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot hash owned candidate record: {e}"))?;
    let after_descriptor = file
        .metadata()
        .map_err(|e| format!("cannot restat owned candidate record: {e}"))?;
    let after_path =
        fs::symlink_metadata(path).map_err(|_| "owned candidate record path disappeared")?;
    if directory_identity(&after_descriptor) != (expected_device, expected_inode)
        || directory_identity(&after_path) != (expected_device, expected_inode)
        || after_descriptor.len() != bytes.len() as u64
        || Digest::of_bytes(&bytes).to_hex() != expected_sha256
    {
        return Err("owned candidate record cleanup blocked by content drift".into());
    }
    fs::remove_file(path).map_err(|e| format!("cannot remove owned candidate record: {e}"))
}

fn remove_candidate_record(binding: &CandidateStorageBinding) -> Result<(), String> {
    let path = Path::new(&binding.record_path);
    let observed = read_candidate_record(path)?;
    if observed.sha256 != binding.record_sha256
        || observed.device != binding.record_device
        || observed.inode != binding.record_inode
    {
        return Err("candidate record cleanup blocked by identity drift".into());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "candidate record cleanup target disappeared")?;
    let (device, inode) = directory_identity(&metadata);
    if device != binding.record_device || inode != binding.record_inode {
        return Err("candidate record cleanup blocked by replacement".into());
    }
    fs::remove_file(path).map_err(|e| format!("cannot remove candidate projection record: {e}"))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn ensure_owner_private_dir(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("clone-private parent is unavailable: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("clone-private parent is unsafe".into());
    }
    Ok(())
}

fn create_or_validate_private_dir(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("clone-private candidate directory is unsafe".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|e| format!("cannot create clone-private candidate directory: {e}"))?;
        }
        Err(error) => return Err(format!("cannot inspect candidate directory: {error}")),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot protect candidate directory: {e}"))?;
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("clone-private candidate directory is not owner-only".into());
        }
    }
    Ok(())
}

fn apply_overlay<F>(
    source_root: &Path,
    projection_root: &Path,
    item: &OverlayPlanEntry,
    hook: &mut F,
) -> Result<Option<CandidateEntry>, String>
where
    F: FnMut(CaptureHookPoint, &Path),
{
    let target = projection_root.join(&item.path);
    match item.source {
        OverlaySource::Deleted => {
            remove_projected_file(&target)?;
            Ok(None)
        }
        OverlaySource::Index => {
            let entry = read_index_entry(source_root, &item.path)?;
            write_projected_file(
                projection_root,
                &target,
                &entry,
                &git::staged_blob(source_root, &item.path).map_err(|e| e.to_string())?,
            )?;
            Ok(Some(entry))
        }
        OverlaySource::Worktree | OverlaySource::Untracked => {
            let (entry, bytes) = read_worktree_entry(source_root, &item.path, hook)?;
            write_projected_file(projection_root, &target, &entry, &bytes)?;
            Ok(Some(entry))
        }
    }
}

fn remove_projected_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("candidate deletion collided with a non-file path".into())
        }
        Ok(_) => fs::remove_file(path).map_err(|e| format!("cannot apply candidate deletion: {e}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect candidate deletion: {error}")),
    }
}

fn read_index_entry(root: &Path, path: &str) -> Result<CandidateEntry, String> {
    let mode = git::staged_mode(root, path)
        .map_err(|e| e.to_string())?
        .ok_or("candidate index postimage disappeared")?;
    let mode = CandidateMode::from_git_mode(mode)?;
    let bytes = git::staged_blob(root, path).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_CANDIDATE_FILE_BYTES {
        return Err("candidate index postimage exceeds its file cap".into());
    }
    Ok(present_entry(path, mode, &bytes))
}

fn read_worktree_entry<F>(
    root: &Path,
    path: &str,
    hook: &mut F,
) -> Result<(CandidateEntry, Vec<u8>), String>
where
    F: FnMut(CaptureHookPoint, &Path),
{
    validate_candidate_path(path)?;
    let full = root.join(path);
    let before = fs::symlink_metadata(&full)
        .map_err(|_| format!("candidate worktree path disappeared: {path:?}"))?;
    validate_regular_metadata(&before)?;
    if before.len() > MAX_CANDIDATE_FILE_BYTES {
        return Err("candidate worktree file exceeds its cap".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&full)
        .map_err(|e| format!("cannot open candidate worktree file: {e}"))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("cannot inspect candidate descriptor: {e}"))?;
    if !same_metadata(&before, &opened) {
        return Err("candidate worktree file changed while opening".into());
    }
    hook(CaptureHookPoint::AfterWorktreeOpen, &full);
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_CANDIDATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read candidate worktree file: {e}"))?;
    if bytes.len() as u64 > MAX_CANDIDATE_FILE_BYTES {
        return Err("candidate worktree file exceeds its cap".into());
    }
    let after_descriptor = file
        .metadata()
        .map_err(|e| format!("cannot recheck candidate descriptor: {e}"))?;
    let after_path = fs::symlink_metadata(&full)
        .map_err(|_| "candidate worktree path disappeared during read")?;
    if !same_metadata(&opened, &after_descriptor)
        || !same_metadata(&after_descriptor, &after_path)
        || after_descriptor.len() != bytes.len() as u64
    {
        return Err("candidate worktree metadata drifted during read".into());
    }
    let mode = mode_from_metadata(&after_descriptor)?;
    Ok((present_entry(path, mode, &bytes), bytes))
}

fn validate_regular_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("candidate overlay is not a no-follow regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("candidate projection file has multiple links".into());
        }
    }
    Ok(())
}

fn mode_from_metadata(metadata: &fs::Metadata) -> Result<CandidateMode, String> {
    validate_regular_metadata(metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(if metadata.permissions().mode() & 0o111 != 0 {
            CandidateMode::Executable
        } else {
            CandidateMode::Regular
        })
    }
    #[cfg(not(unix))]
    Ok(CandidateMode::Regular)
}

fn same_metadata(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mode() == b.mode()
            && a.nlink() == b.nlink()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}

fn present_entry(path: &str, mode: CandidateMode, bytes: &[u8]) -> CandidateEntry {
    CandidateEntry {
        path_bytes: path.as_bytes().to_vec(),
        state: CandidatePathState::Present,
        mode: Some(mode),
        byte_len: bytes.len() as u64,
        sha256: Some(Digest::of_bytes(bytes).to_hex()),
    }
}

fn write_projected_file(
    projection_root: &Path,
    target: &Path,
    entry: &CandidateEntry,
    bytes: &[u8],
) -> Result<(), String> {
    if entry.byte_len != bytes.len() as u64
        || entry.sha256.as_deref() != Some(&Digest::of_bytes(bytes).to_hex())
    {
        return Err("candidate overlay bytes do not match their inventory".into());
    }
    ensure_safe_projected_parent(projection_root, target)?;
    match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("candidate overlay collided with a non-file path".into());
        }
        Ok(_) => {
            fs::remove_file(target).map_err(|e| format!("cannot replace candidate file: {e}"))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect candidate target: {error}")),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .mode(0o600);
    }
    let mut file = options
        .open(target)
        .map_err(|e| format!("cannot create candidate overlay: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("cannot write candidate overlay: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("cannot sync candidate overlay: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = entry.mode.ok_or("present candidate entry has no mode")?;
        fs::set_permissions(target, fs::Permissions::from_mode(mode.permission_mode()))
            .map_err(|e| format!("cannot protect candidate overlay: {e}"))?;
    }
    let observed = hash_projection_file(target, path_bytes_to_string(&entry.path_bytes)?)?;
    if &observed != entry {
        return Err("candidate overlay changed after copy".into());
    }
    Ok(())
}

fn ensure_safe_projected_parent(projection_root: &Path, target: &Path) -> Result<(), String> {
    if !target.starts_with(projection_root) {
        return Err("candidate overlay target escaped its projection".into());
    }
    let parent = target.parent().ok_or("candidate path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create candidate parent: {e}"))?;
    let mut cursor = parent;
    loop {
        let metadata = fs::symlink_metadata(cursor)
            .map_err(|e| format!("cannot inspect candidate parent: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "candidate path collided with a non-directory parent: {}",
                cursor.display()
            ));
        }
        if cursor == projection_root {
            break;
        }
        match cursor.parent() {
            Some(next) if next.starts_with(projection_root) => cursor = next,
            _ => return Err("candidate parent escaped its projection".into()),
        }
    }
    Ok(())
}

fn reobserve_inputs<F>(
    root: &Path,
    expected: &ReobserveExpectation<'_>,
    hook: &mut F,
) -> Result<(), String>
where
    F: FnMut(CaptureHookPoint, &Path),
{
    let current = local_validation::capture_subject(root, Some("HEAD"))?;
    if current.commit != expected.base.commit || current.tree != expected.base.tree {
        return Err("candidate base HEAD changed during capture".into());
    }
    if git::index_identity(root).map_err(|e| e.to_string())? != *expected.index {
        return Err("candidate index changed during capture".into());
    }
    if git::status_v2(root).map_err(|e| e.to_string())? != expected.status {
        return Err("candidate normalized status changed during capture".into());
    }
    if manifest_digest(&load_ready_manifest(root, expected.change)?)? != expected.manifest_digest {
        return Err("candidate manifest changed during capture".into());
    }
    for item in expected.plan {
        match item.source {
            OverlaySource::Index => {
                let observed = read_index_entry(root, &item.path)?;
                if expected.overlays.get(&item.path) != Some(&observed) {
                    return Err("candidate index postimage drifted during capture".into());
                }
            }
            OverlaySource::Worktree | OverlaySource::Untracked => {
                let (observed, _) = read_worktree_entry(root, &item.path, hook)?;
                if expected.overlays.get(&item.path) != Some(&observed) {
                    return Err("candidate worktree postimage drifted during capture".into());
                }
            }
            OverlaySource::Deleted => {
                if fs::symlink_metadata(root.join(&item.path)).is_ok() {
                    return Err("candidate deleted path reappeared during capture".into());
                }
            }
        }
    }
    Ok(())
}

fn inventory_projection(
    root: &Path,
    manifest: &ChangeManifest,
    deletions: &BTreeSet<String>,
) -> Result<Vec<CandidateEntry>, String> {
    let mut entries = Vec::new();
    let mut remaining_entries = MAX_CANDIDATE_ENTRIES;
    let mut remaining_bytes = MAX_CANDIDATE_TOTAL_BYTES;
    inventory_directory(
        root,
        root,
        manifest,
        &mut entries,
        &mut remaining_entries,
        &mut remaining_bytes,
    )?;
    for path in deletions {
        if declared(manifest, path) && !mutable_process_path(path) {
            entries.push(CandidateEntry::deleted(path));
        }
    }
    entries.sort_by(|a, b| a.path_bytes.cmp(&b.path_bytes));
    validate_inventory(&entries)?;
    Ok(entries)
}

/// Inventory a published candidate only while every descendant retains the
/// exact immutable permission contract. No-follow metadata snapshots before
/// and after the content inventory close chmod/replacement races that preserve
/// bytes and the coarse Git executable bit.
fn inventory_read_only_projection(
    root: &Path,
    manifest: &ChangeManifest,
    deletions: &BTreeSet<String>,
) -> Result<Vec<CandidateEntry>, String> {
    let before = projection_metadata_snapshot(root)?;
    let inventory = inventory_projection(root, manifest, deletions)?;
    let after = projection_metadata_snapshot(root)?;
    if before != after {
        return Err("candidate projection metadata drifted during inventory".into());
    }
    Ok(inventory)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionMetadata {
    path: String,
    directory: bool,
    len: u64,
    mode: u32,
    device: u64,
    inode: u64,
    links: u64,
    modified_secs: i64,
    modified_nanos: i64,
    changed_secs: i64,
    changed_nanos: i64,
}

fn projection_metadata_snapshot(root: &Path) -> Result<Vec<ProjectionMetadata>, String> {
    let mut snapshot = Vec::new();
    // The candidate entry cap counts descendants; reserve one additional slot
    // for the published root metadata record itself.
    let mut remaining = MAX_CANDIDATE_ENTRIES.saturating_add(1);
    snapshot_projection_directory(root, root, &mut snapshot, &mut remaining)?;
    snapshot.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(snapshot)
}

fn snapshot_projection_directory(
    projection_root: &Path,
    directory: &Path,
    snapshot: &mut Vec<ProjectionMetadata>,
    remaining: &mut usize,
) -> Result<(), String> {
    if *remaining == 0 {
        return Err("candidate metadata entry count exceeds its cap".into());
    }
    *remaining -= 1;
    let before = fs::symlink_metadata(directory)
        .map_err(|e| format!("cannot inspect candidate directory metadata: {e}"))?;
    validate_projection_permissions(&before, true)?;
    let relative = directory
        .strip_prefix(projection_root)
        .map_err(|_| "candidate metadata path escaped its root")?;
    let relative = if relative.as_os_str().is_empty() {
        String::new()
    } else {
        path_to_utf8(relative)?
    };
    snapshot.push(projection_metadata(&relative, true, &before));

    let mut children = fs::read_dir(directory)
        .map_err(|e| format!("cannot enumerate candidate metadata: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot enumerate candidate metadata entry: {e}"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot inspect candidate descendant metadata: {e}"))?;
        if metadata.file_type().is_symlink() {
            return Err("candidate projection contains a symlink".into());
        }
        if metadata.is_dir() {
            snapshot_projection_directory(projection_root, &path, snapshot, remaining)?;
        } else if metadata.is_file() {
            if *remaining == 0 {
                return Err("candidate metadata entry count exceeds its cap".into());
            }
            *remaining -= 1;
            validate_projection_permissions(&metadata, false)?;
            let relative = path
                .strip_prefix(projection_root)
                .map_err(|_| "candidate metadata path escaped its root")?;
            let relative = path_to_utf8(relative)?;
            let after = fs::symlink_metadata(&path)
                .map_err(|_| "candidate descendant disappeared during metadata capture")?;
            if projection_metadata(&relative, false, &metadata)
                != projection_metadata(&relative, false, &after)
            {
                return Err("candidate file metadata drifted during capture".into());
            }
            snapshot.push(projection_metadata(&relative, false, &after));
        } else {
            return Err("candidate projection contains a special file".into());
        }
    }
    let after = fs::symlink_metadata(directory)
        .map_err(|_| "candidate directory disappeared during metadata capture")?;
    if projection_metadata(&relative, true, &before) != projection_metadata(&relative, true, &after)
    {
        return Err("candidate directory metadata drifted during capture".into());
    }
    Ok(())
}

fn validate_projection_permissions(metadata: &fs::Metadata, directory: bool) -> Result<(), String> {
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err("candidate projection descendant has an unsupported type".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode() & 0o777;
        if (directory && mode != 0o500) || (!directory && !matches!(mode, 0o400 | 0o500)) {
            return Err(format!(
                "candidate projection descendant has mutable permissions {mode:o}"
            ));
        }
        if !directory && metadata.nlink() != 1 {
            return Err("candidate projection file has multiple links".into());
        }
    }
    #[cfg(not(unix))]
    if !metadata.permissions().readonly() {
        return Err("candidate projection descendant is writable".into());
    }
    Ok(())
}

fn projection_metadata(path: &str, directory: bool, metadata: &fs::Metadata) -> ProjectionMetadata {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ProjectionMetadata {
            path: path.to_string(),
            directory,
            len: metadata.len(),
            mode: metadata.mode(),
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            modified_secs: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_secs: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        }
    }
    #[cfg(not(unix))]
    {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
        ProjectionMetadata {
            path: path.to_string(),
            directory,
            len: metadata.len(),
            mode: u32::from(metadata.permissions().readonly()),
            device: 0,
            inode: 0,
            links: 0,
            modified_secs: modified.map_or(0, |value| value.as_secs() as i64),
            modified_nanos: modified.map_or(0, |value| value.subsec_nanos() as i64),
            changed_secs: 0,
            changed_nanos: 0,
        }
    }
}

/// Verify a same-ID retained publication without trusting its pathname alone.
/// Two complete no-follow inventories surround stable root identity checks so
/// retry can adopt only the exact deterministic projection left by a prior
/// invocation that lost its result after rename.
fn verify_retained_projection(
    root: &Path,
    parent: &Path,
    id: &str,
    manifest: &ChangeManifest,
    deletions: &BTreeSet<String>,
    expected: &[CandidateEntry],
) -> Result<(u64, u64), String> {
    if root.parent() != Some(parent) || root.file_name().and_then(|name| name.to_str()) != Some(id)
    {
        return Err("retained candidate has a non-canonical path".into());
    }
    let before = fs::symlink_metadata(root)
        .map_err(|e| format!("cannot inspect retained candidate: {e}"))?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err("retained candidate is not a no-follow directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = before.permissions().mode();
        if mode & 0o077 != 0 || mode & 0o222 != 0 {
            return Err("retained candidate is not owner-only and read-only".into());
        }
    }
    if inventory_read_only_projection(root, manifest, deletions)? != expected {
        return Err("retained candidate inventory does not match its ID".into());
    }
    let middle = fs::symlink_metadata(root)
        .map_err(|_| "retained candidate disappeared during inventory")?;
    if !same_directory_identity(&before, &middle) {
        return Err("retained candidate changed identity during inventory".into());
    }
    if inventory_read_only_projection(root, manifest, deletions)? != expected {
        return Err("retained candidate inventory changed during retry".into());
    }
    let after =
        fs::symlink_metadata(root).map_err(|_| "retained candidate disappeared after inventory")?;
    if !same_directory_identity(&middle, &after) {
        return Err("retained candidate changed identity after inventory".into());
    }
    Ok(directory_identity(&after))
}

fn same_directory_identity(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    if a.file_type().is_symlink() || b.file_type().is_symlink() || !a.is_dir() || !b.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino() && a.mode() == b.mode()
    }
    #[cfg(not(unix))]
    {
        a.permissions() == b.permissions()
    }
}

fn directory_identity(metadata: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        (0, 0)
    }
}

fn inventory_directory(
    projection_root: &Path,
    directory: &Path,
    manifest: &ChangeManifest,
    out: &mut Vec<CandidateEntry>,
    remaining_entries: &mut usize,
    remaining_bytes: &mut u64,
) -> Result<(), String> {
    let mut children = fs::read_dir(directory)
        .map_err(|e| format!("cannot enumerate candidate projection: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot enumerate candidate entry: {e}"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if *remaining_entries == 0 {
            return Err("candidate entry count exceeds its cap".into());
        }
        *remaining_entries -= 1;
        let path = child.path();
        let relative = path
            .strip_prefix(projection_root)
            .map_err(|_| "candidate inventory escaped its root")?;
        let relative = path_to_utf8(relative)?;
        validate_candidate_path(&relative)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot inspect candidate projection: {e}"))?;
        if metadata.file_type().is_symlink() {
            return Err("candidate projection contains a symlink".into());
        }
        if metadata.is_dir() {
            inventory_directory(
                projection_root,
                &path,
                manifest,
                out,
                remaining_entries,
                remaining_bytes,
            )?;
        } else if metadata.is_file() {
            *remaining_bytes = remaining_bytes
                .checked_sub(metadata.len())
                .ok_or("candidate aggregate bytes exceed their cap")?;
            if declared(manifest, &relative) && !mutable_process_path(&relative) {
                out.push(hash_projection_file(&path, &relative)?);
            }
        } else {
            return Err("candidate projection contains a special file".into());
        }
    }
    Ok(())
}

fn hash_projection_file(path: &Path, relative: &str) -> Result<CandidateEntry, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    validate_regular_metadata(&metadata)?;
    if metadata.len() > MAX_CANDIDATE_FILE_BYTES {
        return Err("candidate projected file exceeds its cap".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !same_metadata(&metadata, &opened) {
        return Err("candidate projected file changed while opening".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_CANDIDATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_CANDIDATE_FILE_BYTES
        || !same_metadata(&opened, &after)
        || after.len() != bytes.len() as u64
    {
        return Err("candidate projected file drifted while hashing".into());
    }
    Ok(present_entry(relative, mode_from_metadata(&after)?, &bytes))
}

fn validate_inventory(entries: &[CandidateEntry]) -> Result<(), String> {
    if entries.len() > MAX_CANDIDATE_ENTRIES {
        return Err("candidate inventory exceeds its entry cap".into());
    }
    let mut previous: Option<&[u8]> = None;
    for entry in entries {
        let path = path_bytes_to_string(&entry.path_bytes)?;
        validate_candidate_path(path)?;
        if previous.is_some_and(|prior| prior >= entry.path_bytes.as_slice()) {
            return Err("candidate inventory is not strictly path-sorted".into());
        }
        previous = Some(&entry.path_bytes);
        match entry.state {
            CandidatePathState::Present => {
                if entry.mode.is_none()
                    || entry
                        .sha256
                        .as_deref()
                        .is_none_or(|value| Digest::from_hex(value).is_err())
                {
                    return Err("present candidate inventory entry is incomplete".into());
                }
            }
            CandidatePathState::Deleted => {
                if entry.mode.is_some() || entry.byte_len != 0 || entry.sha256.is_some() {
                    return Err("deleted candidate inventory entry is malformed".into());
                }
            }
        }
    }
    Ok(())
}

fn deleted_paths(entries: &[CandidateEntry]) -> Result<BTreeSet<String>, String> {
    entries
        .iter()
        .filter(|entry| entry.state == CandidatePathState::Deleted)
        .map(|entry| path_bytes_to_string(&entry.path_bytes).map(str::to_string))
        .collect()
}

fn path_bytes_to_string(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "candidate path is not UTF-8".into())
}

fn path_to_utf8(path: &Path) -> Result<String, String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("candidate path is not canonical".into());
    }
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| "candidate path is not UTF-8".into())
}

fn prune_mutable_process_paths(root: &Path) -> Result<(), String> {
    for relative in [
        ".mpd/current",
        ".mpd/pending-closure",
        ".mpd/parity-observations.json",
        ".mpd/build-output",
        ".mpd/local",
        ".mpd/validation",
        ".mpd/logs",
        ".mpd/cache",
    ] {
        remove_projection_path(&root.join(relative))?;
    }
    Ok(())
}

fn remove_projection_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("mutable process path is a symlink in base tree".into())
        }
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(path).map_err(|e| format!("cannot prune process file: {e}"))
        }
        Ok(metadata) if metadata.is_dir() => {
            let mut children = fs::read_dir(path)
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                remove_projection_path(&child.path())?;
            }
            fs::remove_dir(path).map_err(|e| format!("cannot prune process directory: {e}"))
        }
        Ok(_) => Err("mutable process path is special in base tree".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect mutable process path: {error}")),
    }
}

fn make_projection_read_only(root: &Path) -> Result<(), String> {
    let mut directories = Vec::new();
    collect_projection_paths(root, &mut directories)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in directories.into_iter().rev() {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))
                .map_err(|e| format!("cannot make candidate directory read-only: {e}"))?;
        }
    }
    Ok(())
}

fn collect_projection_paths(
    directory: &Path,
    directories: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("candidate projection root is unsafe".into());
    }
    directories.push(directory.to_path_buf());
    for child in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let path = child.map_err(|e| e.to_string())?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("candidate projection contains a symlink".into());
        }
        if metadata.is_dir() {
            collect_projection_paths(&path, directories)?;
        } else if !metadata.is_file() {
            return Err("candidate projection contains a special file".into());
        }
    }
    Ok(())
}

fn sync_tree(root: &Path) -> Result<(), String> {
    for child in fs::read_dir(root).map_err(|e| e.to_string())? {
        let path = child.map_err(|e| e.to_string())?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.is_dir() {
            sync_tree(&path)?;
        } else if metadata.is_file() {
            File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|e| format!("cannot sync candidate file: {e}"))?;
        } else {
            return Err("candidate projection contains an unsupported entry".into());
        }
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("cannot sync candidate directory: {e}"))
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, String> {
    let payload = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let mut preimage = Vec::with_capacity(domain.len() + 1 + payload.len());
    preimage.extend_from_slice(domain);
    preimage.push(0);
    preimage.extend_from_slice(&payload);
    Ok(Digest::of_bytes(&preimage).to_hex())
}

fn entries_digest(entries: &[CandidateEntry]) -> Result<String, String> {
    domain_digest(b"mpd:candidate:entries:v1", &entries)
}

fn source_digest(entries: &[CandidateEntry]) -> Result<String, String> {
    let present: Vec<&CandidateEntry> = entries
        .iter()
        .filter(|entry| entry.state == CandidatePathState::Present)
        .collect();
    domain_digest(b"mpd:candidate:source:v1", &present)
}

fn candidate_id(
    base_tree: &str,
    manifest_digest: &str,
    entries_digest: &str,
    policy_digest: &str,
    source_digest: &str,
) -> Result<String, String> {
    domain_digest(
        b"mpd:candidate:id:v1",
        &(
            CANDIDATE_SCHEMA,
            base_tree,
            manifest_digest,
            entries_digest,
            policy_digest,
            source_digest,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct Repo {
        root: PathBuf,
    }

    impl Repo {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("mpd-candidate-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            git_ok(&root, &["init", "-q"]);
            git_ok(
                &root,
                &["config", "user.email", "candidate@example.invalid"],
            );
            git_ok(&root, &["config", "user.name", "Candidate Test"]);
            Self { root }
        }

        fn write(&self, relative: &str, bytes: &[u8]) {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }

        fn manifest(&self, change: &str, paths: &[&str]) {
            self.write(
                &format!("openspec/changes/{change}/manifest.json"),
                serde_json::to_string_pretty(&serde_json::json!({
                    "version": 1,
                    "paths": paths,
                    "shared_paths": []
                }))
                .unwrap()
                .as_bytes(),
            );
        }

        fn commit_all(&self, message: &str) {
            git_ok(&self.root, &["add", "-A"]);
            git_ok(&self.root, &["commit", "-q", "-m", message]);
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn git_ok(root: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn object_inventory(root: &Path) -> Vec<(PathBuf, u64, String)> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<(PathBuf, u64, String)>) {
            let mut entries = fs::read_dir(dir)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    walk(base, &path, out);
                } else if metadata.is_file() {
                    let bytes = fs::read(&path).unwrap();
                    out.push((
                        path.strip_prefix(base).unwrap().to_path_buf(),
                        metadata.len(),
                        Digest::of_bytes(&bytes).to_hex(),
                    ));
                }
            }
        }
        let objects = repo_git_dir(root).join("objects");
        let mut out = Vec::new();
        walk(&objects, &objects, &mut out);
        out
    }

    fn repo_git_dir(root: &Path) -> PathBuf {
        let raw = String::from_utf8(git_ok(root, &["rev-parse", "--git-dir"]))
            .unwrap()
            .trim()
            .to_string();
        if Path::new(&raw).is_absolute() {
            PathBuf::from(raw)
        } else {
            root.join(raw)
        }
    }

    fn no_staging_directories(root: &Path) -> bool {
        let candidates = repo_git_dir(root).join("mpd/candidates");
        !candidates.exists()
            || fs::read_dir(candidates).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".candidate-stage-")
            })
    }

    fn entry(path: &[u8], bytes: &[u8]) -> CandidateEntry {
        CandidateEntry {
            path_bytes: path.to_vec(),
            state: CandidatePathState::Present,
            mode: Some(CandidateMode::Regular),
            byte_len: bytes.len() as u64,
            sha256: Some(Digest::of_bytes(bytes).to_hex()),
        }
    }

    #[test]
    fn candidate_identity_is_deterministic_domain_separated_and_order_sensitive() {
        let entries = vec![entry(b"a", b"one"), entry(b"b", b"two")];
        let ed = entries_digest(&entries).unwrap();
        let source = source_digest(&entries).unwrap();
        let id = candidate_id(
            &"a".repeat(40),
            &"b".repeat(64),
            &ed,
            &"c".repeat(64),
            &source,
        )
        .unwrap();
        assert_eq!(
            id,
            candidate_id(
                &"a".repeat(40),
                &"b".repeat(64),
                &ed,
                &"c".repeat(64),
                &source,
            )
            .unwrap()
        );
        let reversed = entries.into_iter().rev().collect::<Vec<_>>();
        assert_ne!(ed, entries_digest(&reversed).unwrap());
        assert_ne!(ed, source_digest(&reversed).unwrap());
    }

    #[test]
    fn candidate_mode_serializes_as_canonical_git_mode() {
        assert_eq!(
            serde_json::to_string(&CandidateMode::Regular).unwrap(),
            "\"100644\""
        );
        assert_eq!(CandidateMode::Executable.permission_mode(), 0o500);
    }

    #[test]
    fn capture_projects_head_then_worktree_wins_index_with_untracked_delete_and_mode() {
        let repo = Repo::new("happy");
        let change = "candidate-happy";
        repo.write("src/staged.txt", b"head\n");
        repo.write("src/staged-only.txt", b"head staged only\n");
        repo.write("src/deleted.txt", b"remove me\n");
        repo.write("src/mode.sh", b"#!/bin/sh\nexit 0\n");
        repo.write("outside.txt", b"base outside\n");
        repo.manifest(change, &["src/**"]);
        repo.commit_all("base");

        repo.write("src/staged.txt", b"staged\n");
        git_ok(&repo.root, &["add", "src/staged.txt"]);
        repo.write("src/staged.txt", b"worktree wins\n");
        repo.write("src/staged-only.txt", b"index postimage\n");
        git_ok(&repo.root, &["add", "src/staged-only.txt"]);
        repo.write("src/untracked.txt", b"new\n");
        fs::remove_file(repo.root.join("src/deleted.txt")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                repo.root.join("src/mode.sh"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        repo.write("outside.txt", b"dirty but excluded\n");

        let head_before = git_ok(&repo.root, &["rev-parse", "HEAD"]);
        let index_before = git::index_identity(&repo.root).unwrap();
        let status_before = git::status_v2(&repo.root).unwrap();
        let refs_before = git_ok(
            &repo.root,
            &["for-each-ref", "--format=%(refname)%00%(objectname)"],
        );
        let objects_before = object_inventory(&repo.root);

        let captured = capture_candidate(&repo.root, change, &"a".repeat(64)).unwrap();
        assert_eq!(
            fs::read(captured.root().join("src/staged.txt")).unwrap(),
            b"worktree wins\n"
        );
        assert_eq!(
            fs::read(captured.root().join("src/untracked.txt")).unwrap(),
            b"new\n"
        );
        assert_eq!(
            fs::read(captured.root().join("src/staged-only.txt")).unwrap(),
            b"index postimage\n"
        );
        assert!(!captured.root().join("src/deleted.txt").exists());
        assert_eq!(
            fs::read(captured.root().join("outside.txt")).unwrap(),
            b"base outside\n"
        );
        let deleted = captured
            .projection
            .entries
            .iter()
            .find(|entry| entry.path_bytes == b"src/deleted.txt")
            .unwrap();
        assert_eq!(deleted.state, CandidatePathState::Deleted);
        let mode = captured
            .projection
            .entries
            .iter()
            .find(|entry| entry.path_bytes == b"src/mode.sh")
            .unwrap();
        assert_eq!(mode.mode, Some(CandidateMode::Executable));
        assert_eq!(captured.projection.capture.counts.untracked, 1);
        assert!(captured
            .projection
            .excluded_dirty_paths
            .iter()
            .any(|path| path.path_bytes == b"outside.txt"));
        assert_eq!(
            captured.root().file_name().unwrap().to_str().unwrap(),
            captured.projection.capture.subject.id
        );
        assert_eq!(git_ok(&repo.root, &["rev-parse", "HEAD"]), head_before);
        assert_eq!(git::index_identity(&repo.root).unwrap(), index_before);
        assert_eq!(git::status_v2(&repo.root).unwrap(), status_before);
        assert_eq!(
            git_ok(
                &repo.root,
                &["for-each-ref", "--format=%(refname)%00%(objectname)"]
            ),
            refs_before
        );
        assert_eq!(object_inventory(&repo.root), objects_before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::symlink_metadata(captured.root())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o500
            );
        }
        captured.rehash(&repo.root).unwrap();
        let retained = captured.root().to_path_buf();
        captured.cleanup().unwrap();
        assert!(!retained.exists());
        assert!(no_staging_directories(&repo.root));
    }

    #[test]
    fn staged_only_worktree_overlay_and_head_images_have_distinct_deterministic_ids() {
        let repo = Repo::new("precedence-ids");
        let change = "precedence";
        repo.write("src/value", b"head");
        repo.manifest(change, &["src/**"]);
        repo.commit_all("base");

        repo.write("src/value", b"staged");
        git_ok(&repo.root, &["add", "src/value"]);
        let staged = capture_candidate(&repo.root, change, &"f".repeat(64)).unwrap();
        let staged_id = staged.projection.capture.subject.id.clone();
        assert_eq!(
            fs::read(staged.root().join("src/value")).unwrap(),
            b"staged"
        );
        staged.cleanup().unwrap();

        repo.write("src/value", b"worktree");
        let worktree = capture_candidate(&repo.root, change, &"f".repeat(64)).unwrap();
        let worktree_id = worktree.projection.capture.subject.id.clone();
        assert_eq!(
            fs::read(worktree.root().join("src/value")).unwrap(),
            b"worktree"
        );
        assert_ne!(worktree_id, staged_id);
        worktree.cleanup().unwrap();

        git_ok(&repo.root, &["reset", "--hard", "-q", "HEAD"]);
        let head = capture_candidate(&repo.root, change, &"f".repeat(64)).unwrap();
        assert_ne!(head.projection.capture.subject.id, staged_id);
        assert_ne!(head.projection.capture.subject.id, worktree_id);
        head.cleanup().unwrap();
    }

    #[test]
    fn same_id_publication_is_reinventoried_and_adopted_after_lost_return() {
        let repo = Repo::new("same-id-recovery");
        repo.write("src/value", b"base");
        repo.manifest("recover", &["src/**"]);
        repo.commit_all("base");
        repo.write("src/value", b"candidate");

        let first = capture_candidate(&repo.root, "recover", &"e".repeat(64)).unwrap();
        let retained = first.root().to_path_buf();
        let expected = first.projection.clone();
        // Simulate a process that completed the atomic rename but lost its
        // in-memory return value before it could persist downstream state.
        std::mem::forget(first);

        let retry = capture_candidate(&repo.root, "recover", &"e".repeat(64)).unwrap();
        assert_eq!(retry.root(), retained);
        assert_eq!(retry.projection.capture.subject, expected.capture.subject);
        assert_eq!(retry.projection.entries, expected.entries);
        assert_eq!(retry.projection.capture.storage, expected.capture.storage);
        retry.rehash(&repo.root).unwrap();
        retry.cleanup().unwrap();
        assert!(!retained.exists());
        assert!(no_staging_directories(&repo.root));

        let mismatch_repo = Repo::new("same-id-mismatch");
        mismatch_repo.write("src/value", b"base");
        mismatch_repo.manifest("recover", &["src/**"]);
        mismatch_repo.commit_all("base");
        mismatch_repo.write("src/value", b"candidate");
        let retained = capture_candidate(&mismatch_repo.root, "recover", &"e".repeat(64)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                retained.root().join("src/value"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        fs::write(retained.root().join("src/value"), b"tampered").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                retained.root().join("src/value"),
                fs::Permissions::from_mode(0o400),
            )
            .unwrap();
        }
        let error = capture_candidate(&mismatch_repo.root, "recover", &"e".repeat(64)).unwrap_err();
        assert!(error.contains("inventory does not match"), "{error}");
        assert!(
            retained.root().exists(),
            "mismatch must preserve prior root"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                retained.root().join("src/value"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        fs::write(retained.root().join("src/value"), b"candidate").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                retained.root().join("src/value"),
                fs::Permissions::from_mode(0o400),
            )
            .unwrap();
        }
        retained.cleanup().unwrap();
        assert!(no_staging_directories(&mismatch_repo.root));

        // A crash after root publication but before sidecar durability leaves
        // a complete read-only root. Retry re-inventories that root and
        // recreates the missing canonical record without recapturing bytes.
        let record_loss_repo = Repo::new("same-id-record-loss");
        record_loss_repo.write("src/value", b"base");
        record_loss_repo.manifest("recover", &["src/**"]);
        record_loss_repo.commit_all("base");
        record_loss_repo.write("src/value", b"candidate");
        let lost = capture_candidate(&record_loss_repo.root, "recover", &"e".repeat(64)).unwrap();
        let retained_root = lost.root().to_path_buf();
        let record_path = PathBuf::from(&lost.projection.capture.storage.record_path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::remove_file(&record_path).unwrap();
        std::mem::forget(lost);
        let recovered =
            capture_candidate(&record_loss_repo.root, "recover", &"e".repeat(64)).unwrap();
        assert_eq!(recovered.root(), retained_root);
        assert!(record_path.is_file());
        reopen_candidate(&record_loss_repo.root, &recovered.projection.capture).unwrap();
        recovered.cleanup().unwrap();

        #[cfg(unix)]
        for (label, target, mode) in [
            ("writable-file", "src/nested/value", 0o600),
            ("writable-directory", "src/nested", 0o700),
        ] {
            use std::os::unix::fs::PermissionsExt;
            let repo = Repo::new(&format!("same-id-{label}"));
            repo.write("src/nested/value", b"base");
            repo.manifest("recover", &["src/**"]);
            repo.commit_all("base");
            repo.write("src/nested/value", b"candidate");
            let retained = capture_candidate(&repo.root, "recover", &"e".repeat(64)).unwrap();
            fs::set_permissions(
                retained.root().join(target),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();

            let error = capture_candidate(&repo.root, "recover", &"e".repeat(64)).unwrap_err();
            assert!(error.contains("mutable permissions"), "{label}: {error}");
            assert!(
                retained.root().exists(),
                "{label}: retry must preserve the pre-existing root"
            );
            fs::set_permissions(
                retained.root().join(target),
                fs::Permissions::from_mode(if label == "writable-file" {
                    0o400
                } else {
                    0o500
                }),
            )
            .unwrap();
            retained.cleanup().unwrap();
            assert!(no_staging_directories(&repo.root));
        }
    }

    #[test]
    fn projection_record_codec_reopen_and_tamper_checks_are_closed() {
        let repo = Repo::new("projection-record");
        repo.write("src/nested/value", b"base");
        repo.manifest("record", &["src/**"]);
        repo.commit_all("base");
        repo.write("src/nested/value", b"candidate");
        repo.write("outside", b"excluded");
        let captured = capture_candidate(&repo.root, "record", &"a".repeat(64)).unwrap();
        let capture = captured.projection.capture.clone();

        let encoded = serde_json::to_vec(&capture).unwrap();
        let decoded: CandidateCapture = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, capture);
        let encoded_value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert!(encoded_value.get("entries").is_none());
        assert!(capture.excluded_dirty_sample.len() <= MAX_EXCLUDED_DIRTY_SAMPLE);

        let reopened = reopen_candidate(&repo.root, &capture).unwrap();
        assert_eq!(reopened.entries, captured.projection.entries);
        assert_eq!(
            reopened.excluded_dirty_paths,
            captured.projection.excluded_dirty_paths
        );
        let record_path = PathBuf::from(&capture.storage.record_path);
        assert!(!record_path.starts_with(captured.root()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::symlink_metadata(&record_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }

        let mut wrong_id = capture.clone();
        wrong_id.subject.id = "f".repeat(64);
        assert!(reopen_candidate(&repo.root, &wrong_id)
            .unwrap_err()
            .contains("non-canonical"));
        let mut wrong_digest = capture.clone();
        wrong_digest.storage.record_sha256 = "0".repeat(64);
        assert!(reopen_candidate(&repo.root, &wrong_digest)
            .unwrap_err()
            .contains("compact binding"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(reopen_candidate(&repo.root, &capture)
                .unwrap_err()
                .contains("read-only"));
            fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();

            let bytes = fs::read(&record_path).unwrap();
            fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&record_path, b"{}").unwrap();
            fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();
            assert!(reopen_candidate(&repo.root, &capture).is_err());
            fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&record_path, bytes).unwrap();
            fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();

            let projected = captured.root().join("src/nested/value");
            fs::set_permissions(&projected, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(reopen_candidate(&repo.root, &capture)
                .unwrap_err()
                .contains("mutable permissions"));
            fs::set_permissions(&projected, fs::Permissions::from_mode(0o400)).unwrap();
        }
        reopen_candidate(&repo.root, &capture).unwrap();
        captured.cleanup().unwrap();
    }

    #[test]
    fn projection_record_link_and_cleanup_failure_seams_are_idempotent() {
        let link_repo = Repo::new("record-link-loss");
        link_repo.write("src/value", b"base");
        link_repo.manifest("record", &["src/**"]);
        link_repo.commit_all("base");
        link_repo.write("src/value", b"candidate");
        let linked = capture_candidate(&link_repo.root, "record", &"a".repeat(64)).unwrap();
        let record = PathBuf::from(&linked.projection.capture.storage.record_path);
        let id = &linked.projection.capture.subject.id;
        let staging = record
            .parent()
            .unwrap()
            .join(format!(".candidate-record-stage-{id}-injected"));
        fs::hard_link(&record, &staging).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let snapshot = |directory: &Path| {
                let mut entries = directory
                    .read_dir()
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let metadata = fs::symlink_metadata(entry.path()).unwrap();
                        (
                            entry.file_name().to_string_lossy().into_owned(),
                            metadata.dev(),
                            metadata.ino(),
                            metadata.nlink(),
                            metadata.len(),
                            metadata.permissions().mode() & 0o777,
                        )
                    })
                    .collect::<Vec<_>>();
                entries.sort();
                entries
            };
            let before = snapshot(record.parent().unwrap());
            assert_eq!(fs::symlink_metadata(&record).unwrap().nlink(), 2);
            let error = reopen_candidate(&link_repo.root, &linked.projection.capture).unwrap_err();
            assert!(error.contains("single-link"));
            assert_eq!(snapshot(record.parent().unwrap()), before);
            assert!(staging.is_file());
            assert_eq!(fs::symlink_metadata(&record).unwrap().nlink(), 2);
        }
        drop(linked);
        let recovered = capture_candidate(&link_repo.root, "record", &"a".repeat(64)).unwrap();
        reopen_candidate(&link_repo.root, &recovered.projection.capture).unwrap();
        assert!(!staging.exists());
        recovered.cleanup().unwrap();

        let cleanup_repo = Repo::new("record-cleanup-loss");
        cleanup_repo.write("src/value", b"base");
        cleanup_repo.manifest("record", &["src/**"]);
        cleanup_repo.commit_all("base");
        cleanup_repo.write("src/value", b"candidate");
        let interrupted = capture_candidate(&cleanup_repo.root, "record", &"a".repeat(64)).unwrap();
        let retained_root = interrupted.root().to_path_buf();
        let record = PathBuf::from(&interrupted.projection.capture.storage.record_path);
        let error = interrupted
            .cleanup_inner(|| Err("injected failure after record removal".into()))
            .unwrap_err();
        assert!(error.contains("injected failure"));
        assert!(retained_root.is_dir());
        assert!(!record.exists());
        let recovered = capture_candidate(&cleanup_repo.root, "record", &"a".repeat(64)).unwrap();
        assert_eq!(recovered.root(), retained_root);
        assert!(record.is_file());
        recovered.cleanup().unwrap();

        let mismatch_repo = Repo::new("record-cleanup-mismatch");
        mismatch_repo.write("src/value", b"base");
        mismatch_repo.manifest("record", &["src/**"]);
        mismatch_repo.commit_all("base");
        mismatch_repo.write("src/value", b"candidate");
        let mismatched = capture_candidate(&mismatch_repo.root, "record", &"a".repeat(64)).unwrap();
        let retained_root = mismatched.root().to_path_buf();
        let record = PathBuf::from(&mismatched.projection.capture.storage.record_path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(mismatched.cleanup().is_err());
        assert!(retained_root.is_dir());
        assert!(record.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o400)).unwrap();
        }
        let recovered = capture_candidate(&mismatch_repo.root, "record", &"a".repeat(64)).unwrap();
        recovered.cleanup().unwrap();
    }

    #[test]
    fn projection_record_publication_failures_remove_only_owned_artifacts_and_retry() {
        for (tag, failure) in [
            ("after-link", RecordPublishFailurePoint::LinkPublished),
            (
                "after-temp-unlink",
                RecordPublishFailurePoint::TemporaryUnlinked,
            ),
            ("after-parent-sync", RecordPublishFailurePoint::ParentSynced),
        ] {
            let repo = Repo::new(&format!("record-publish-{tag}"));
            repo.write("src/value", b"base");
            repo.manifest("record", &["src/**"]);
            repo.commit_all("base");
            repo.write("src/value", b"candidate");

            RECORD_PUBLISH_FAILURE.with(|slot| slot.set(Some(failure)));
            let error = capture_candidate(&repo.root, "record", &"a".repeat(64)).unwrap_err();
            assert!(error.contains("injected candidate record failure"));

            let common = local_validation::git_common_dir(&repo.root).unwrap();
            let candidates = common.join("mpd/candidates");
            let records = common.join("mpd/candidate-records");
            assert!(candidates.read_dir().unwrap().next().is_none());
            assert!(records.read_dir().unwrap().next().is_none());

            let retried = capture_candidate(&repo.root, "record", &"a".repeat(64)).unwrap();
            reopen_candidate(&repo.root, &retried.projection.capture).unwrap();
            retried.cleanup().unwrap();
            assert!(candidates.read_dir().unwrap().next().is_none());
            assert!(records.read_dir().unwrap().next().is_none());
        }

        let foreign_repo = Repo::new("record-publish-foreign");
        foreign_repo.write("src/value", b"base");
        foreign_repo.manifest("record", &["src/**"]);
        foreign_repo.commit_all("base");
        foreign_repo.write("src/value", b"candidate");
        let captured = capture_candidate(&foreign_repo.root, "record", &"a".repeat(64)).unwrap();
        let record = PathBuf::from(&captured.projection.capture.storage.record_path);
        captured.cleanup().unwrap();
        fs::write(&record, b"foreign record").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o400)).unwrap();
        }
        let error = capture_candidate(&foreign_repo.root, "record", &"a".repeat(64)).unwrap_err();
        assert!(error.contains("record exists without its retained root"));
        assert_eq!(fs::read(&record).unwrap(), b"foreign record");
        let candidates = local_validation::git_common_dir(&foreign_repo.root)
            .unwrap()
            .join("mpd/candidates");
        assert!(candidates.read_dir().unwrap().next().is_none());
        fs::remove_file(record).unwrap();
    }

    #[test]
    fn failed_final_sidecar_cleanup_preserves_root_and_record_for_safe_retry() {
        let repo = Repo::new("record-final-cleanup-failure");
        repo.write("src/value", b"base");
        repo.manifest("record", &["src/**"]);
        repo.commit_all("base");
        repo.write("src/value", b"candidate");

        RECORD_PUBLISH_FAILURE
            .with(|slot| slot.set(Some(RecordPublishFailurePoint::TemporaryUnlinked)));
        RECORD_FINAL_CLEANUP_FAILURE.with(|slot| slot.set(true));
        let error = capture_candidate(&repo.root, "record", &"a".repeat(64)).unwrap_err();
        assert!(error.contains("injected candidate record failure"));
        assert!(error.contains("injected candidate final-sidecar cleanup failure"));
        assert!(error.contains("retained candidate root preserved"));

        let common = local_validation::git_common_dir(&repo.root).unwrap();
        let candidates = common.join("mpd/candidates");
        let records = common.join("mpd/candidate-records");
        let retained_roots = candidates
            .read_dir()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let retained_records = records
            .read_dir()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(retained_roots.len(), 1);
        assert_eq!(retained_records.len(), 1);
        let retained_root = retained_roots[0].path();
        let retained_record = retained_records[0].path();
        assert!(retained_root.is_dir());
        assert_eq!(
            retained_record.extension().and_then(|value| value.to_str()),
            Some("json")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::symlink_metadata(&retained_record).unwrap().nlink(), 1);
        }

        let retried = capture_candidate(&repo.root, "record", &"a".repeat(64)).unwrap();
        assert_eq!(retried.root(), retained_root);
        assert_eq!(
            Path::new(&retried.projection.capture.storage.record_path),
            retained_record
        );
        reopen_candidate(&repo.root, &retried.projection.capture).unwrap();
        retried.cleanup().unwrap();
        assert!(candidates.read_dir().unwrap().next().is_none());
        assert!(records.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn projection_record_replacement_after_second_descriptor_read_blocks_reopen() {
        let repo = Repo::new("record-second-read-replacement");
        repo.write("src/value", b"base");
        repo.manifest("record", &["src/**"]);
        repo.commit_all("base");
        repo.write("src/value", b"candidate");
        let captured = capture_candidate(&repo.root, "record", &"a".repeat(64)).unwrap();
        let capture = captured.projection.capture.clone();
        let record = PathBuf::from(&capture.storage.record_path);
        let displaced = record.with_extension("record-read-hook-old");

        RECORD_READ_REPLACEMENT_COUNTDOWN.with(|slot| slot.set(2));
        let error = reopen_candidate(&repo.root, &capture).unwrap_err();
        assert!(error.contains("path changed after descriptor read"));
        assert!(record.is_file());
        assert!(displaced.is_file());
        assert_eq!(fs::read(&record).unwrap(), fs::read(&displaced).unwrap());
        assert!(captured.root().is_dir());

        fs::remove_file(&record).unwrap();
        fs::rename(&displaced, &record).unwrap();
        reopen_candidate(&repo.root, &capture).unwrap();
        captured.cleanup().unwrap();
    }

    #[test]
    fn reopen_missing_private_parents_is_strictly_read_only() {
        let repo = Repo::new("reopen-read-only");
        repo.write("src/value", b"base");
        repo.manifest("record", &["src/**"]);
        repo.commit_all("base");
        let common = local_validation::git_common_dir(&repo.root).unwrap();
        let private = common.join("mpd");
        let id = "1".repeat(64);
        let capture = CandidateCapture {
            subject: CandidateSubject {
                version: CANDIDATE_SCHEMA,
                change: "record".into(),
                base_commit: "a".repeat(40),
                base_tree: "b".repeat(40),
                manifest_digest: "c".repeat(64),
                entries_digest: "d".repeat(64),
                policy_digest: "e".repeat(64),
                source_digest: "f".repeat(64),
                id: id.clone(),
            },
            clone_private_root: common
                .join("mpd/candidates")
                .join(&id)
                .to_string_lossy()
                .into_owned(),
            storage: CandidateStorageBinding {
                record_path: common
                    .join("mpd/candidate-records")
                    .join(format!("{id}.json"))
                    .to_string_lossy()
                    .into_owned(),
                record_sha256: "2".repeat(64),
                root_device: 1,
                root_inode: 2,
                record_device: 1,
                record_inode: 3,
            },
            counts: CandidateCounts::default(),
            excluded_dirty_digest: "3".repeat(64),
            excluded_dirty_sample: Vec::new(),
            declared_status_digest: "4".repeat(64),
            captured_at_epoch_secs: 1,
        };

        assert!(!private.exists());
        assert!(reopen_candidate(&repo.root, &capture).is_err());
        assert!(!private.exists(), "reopen must not create .git/mpd");

        fs::create_dir(&private).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(reopen_candidate(&repo.root, &capture).is_err());
        assert!(!private.join("candidates").exists());
        assert!(!private.join("candidate-records").exists());

        fs::create_dir(private.join("candidates")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                private.join("candidates"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        assert!(reopen_candidate(&repo.root, &capture).is_err());
        assert!(!private.join("candidate-records").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = repo.root.join("outside-private");
            fs::create_dir(&outside).unwrap();
            fs::remove_dir(private.join("candidates")).unwrap();
            symlink(&outside, private.join("candidates")).unwrap();
            assert!(reopen_candidate(&repo.root, &capture).is_err());
            assert!(outside.read_dir().unwrap().next().is_none());
            assert!(!private.join("candidate-records").exists());
        }
    }

    #[test]
    fn mutable_process_state_is_absent_and_stable_but_declared_governance_inputs_move_id() {
        let repo = Repo::new("process-state");
        let change = "process-state";
        let declared = [
            (".mpd/config.json", b"config-v1\n".as_slice()),
            (
                ".mpd/directives/security.md",
                b"security-directive-v1\n".as_slice(),
            ),
            (".githooks/pre-push", b"hook-v1\n".as_slice()),
            ("security/policy/local.json", b"policy-v1\n".as_slice()),
            ("security/tool-lock.json", b"tools-v1\n".as_slice()),
        ];
        for (path, bytes) in declared {
            repo.write(path, bytes);
        }
        repo.write(".mpd/current", b"historical-selection\n");
        repo.write(".mpd/state/historical.json", b"historical-ledger\n");
        repo.write("src/lib.rs", b"pub fn stable() {}\n");
        repo.manifest(
            change,
            &["src/**", ".mpd/**", ".githooks/**", "security/**"],
        );
        repo.commit_all("base with durable governance");

        for (path, bytes) in [
            (".mpd/current", b"live-selection".as_slice()),
            (".mpd/state/live.json", b"live-ledger".as_slice()),
            (".mpd/pending-closure", b"pending".as_slice()),
            (".mpd/parity-observations.json", b"parity".as_slice()),
            (".mpd/build-output/mpd", b"output".as_slice()),
            (".mpd/local/logs/run", b"log".as_slice()),
        ] {
            repo.write(path, bytes);
        }

        let first = capture_candidate(&repo.root, change, &"b".repeat(64)).unwrap();
        let stable_id = first.projection.capture.subject.id.clone();
        assert!(!first.root().join(".mpd/current").exists());
        assert!(!first.root().join(".mpd/build-output").exists());
        assert!(!first.root().join(".mpd/local").exists());
        assert!(!first.root().join(".git").exists());
        assert_eq!(
            fs::read(first.root().join(".mpd/state/historical.json")).unwrap(),
            b"historical-ledger\n"
        );
        repo.write(".mpd/state/live.json", b"live-ledger-v2");
        repo.write(".mpd/current", b"live-selection-v2");
        first.rehash(&repo.root).unwrap();
        first.cleanup().unwrap();

        let second = capture_candidate(&repo.root, change, &"b".repeat(64)).unwrap();
        assert_eq!(second.projection.capture.subject.id, stable_id);
        let config_original = fs::read(repo.root.join(".mpd/config.json")).unwrap();
        repo.write(".mpd/config.json", b"config-stale\n");
        assert!(second
            .rehash(&repo.root)
            .unwrap_err()
            .contains("status drifted"));
        repo.write(".mpd/config.json", &config_original);
        second.rehash(&repo.root).unwrap();
        second.cleanup().unwrap();

        let governed = [
            (".mpd/config.json", b"config-v2\n".as_slice()),
            (
                ".mpd/directives/security.md",
                b"security-directive-v2\n".as_slice(),
            ),
            (".githooks/pre-push", b"hook-v2\n".as_slice()),
            ("security/policy/local.json", b"policy-v2\n".as_slice()),
            ("security/tool-lock.json", b"tools-v2\n".as_slice()),
        ];
        for (path, changed) in governed {
            let original = fs::read(repo.root.join(path)).unwrap();
            repo.write(path, changed);
            let moved = capture_candidate(&repo.root, change, &"b".repeat(64)).unwrap();
            assert_ne!(moved.projection.capture.subject.id, stable_id, "{path}");
            moved.cleanup().unwrap();
            repo.write(path, &original);
        }
        assert!(no_staging_directories(&repo.root));
    }

    #[test]
    fn mutable_process_root_aliases_and_descendants_do_not_move_candidate_identity() {
        let repo = Repo::new("process-root-aliases");
        let change = "process-roots";
        repo.write("src/lib.rs", b"pub fn stable() {}\n");
        repo.manifest(change, &["src/**", ".mpd/**"]);
        repo.commit_all("base");

        let baseline = capture_candidate(&repo.root, change, &"b".repeat(64)).unwrap();
        let stable_id = baseline.projection.capture.subject.id.clone();
        baseline.cleanup().unwrap();

        for relative in [
            ".mpd/state",
            ".mpd/current",
            ".mpd/pending-closure",
            ".mpd/parity-observations.json",
            ".mpd/build-output",
            ".mpd/local",
            ".mpd/validation",
            ".mpd/logs",
            ".mpd/cache",
        ] {
            repo.write(relative, b"process-root-v1\n");
            let captured = capture_candidate(&repo.root, change, &"b".repeat(64)).unwrap();
            assert_eq!(
                captured.projection.capture.subject.id, stable_id,
                "{relative}"
            );
            repo.write(relative, b"process-root-v2\n");
            captured.rehash(&repo.root).unwrap();
            captured.cleanup().unwrap();
            fs::remove_file(repo.root.join(relative)).unwrap();
        }

        for relative in [
            ".mpd/state/run.json",
            ".mpd/build-output/mpd",
            ".mpd/local/run.json",
            ".mpd/validation/run.json",
            ".mpd/logs/run.log",
            ".mpd/cache/item",
        ] {
            repo.write(relative, b"process-child-v1\n");
            let captured = capture_candidate(&repo.root, change, &"b".repeat(64)).unwrap();
            assert_eq!(
                captured.projection.capture.subject.id, stable_id,
                "{relative}"
            );
            repo.write(relative, b"process-child-v2\n");
            captured.rehash(&repo.root).unwrap();
            captured.cleanup().unwrap();
            fs::remove_file(repo.root.join(relative)).unwrap();
        }
        assert!(no_staging_directories(&repo.root));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_gitlink_special_collision_and_caps_fail_closed_with_cleanup() {
        use std::os::unix::fs::symlink;

        // Untracked symlink.
        let symlink_repo = Repo::new("reject-symlink");
        symlink_repo.write("src/base", b"base");
        symlink_repo.manifest("reject", &["src/**"]);
        symlink_repo.commit_all("base");
        symlink("base", symlink_repo.root.join("src/link")).unwrap();
        let error = capture_candidate(&symlink_repo.root, "reject", &"c".repeat(64)).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(no_staging_directories(&symlink_repo.root));

        // Staged gitlink in base HEAD is rejected by the reused commit materializer.
        let gitlink_repo = Repo::new("reject-gitlink");
        gitlink_repo.write("src/base", b"base");
        gitlink_repo.manifest("reject", &["src/**"]);
        gitlink_repo.commit_all("base");
        let head = String::from_utf8(git_ok(&gitlink_repo.root, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_string();
        git_ok(
            &gitlink_repo.root,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{head},src/submodule"),
            ],
        );
        git_ok(&gitlink_repo.root, &["commit", "-q", "-m", "gitlink"]);
        let error = capture_candidate(&gitlink_repo.root, "reject", &"c".repeat(64)).unwrap_err();
        assert!(error.contains("unsupported entry"), "{error}");
        assert!(no_staging_directories(&gitlink_repo.root));

        // FIFO special file.
        let fifo_repo = Repo::new("reject-fifo");
        fifo_repo.write("src/base", b"base");
        fifo_repo.manifest("reject", &["src/**"]);
        fifo_repo.commit_all("base");
        let fifo = fifo_repo.root.join("src/fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let error = capture_candidate(&fifo_repo.root, "reject", &"c".repeat(64)).unwrap_err();
        assert!(error.contains("special file"), "{error}");
        assert!(no_staging_directories(&fifo_repo.root));

        // File/directory collision in the overlay union.
        let collision_repo = Repo::new("reject-collision");
        collision_repo.write("src/tree/child", b"child");
        collision_repo.manifest("reject", &["src/**"]);
        collision_repo.commit_all("base");
        fs::remove_file(collision_repo.root.join("src/tree/child")).unwrap();
        fs::remove_dir(collision_repo.root.join("src/tree")).unwrap();
        collision_repo.write("src/tree", b"now a file");
        let error = capture_candidate(&collision_repo.root, "reject", &"c".repeat(64)).unwrap_err();
        assert!(error.contains("collision"), "{error}");
        assert!(no_staging_directories(&collision_repo.root));

        // Per-file cap blocks from metadata without reading a sparse payload.
        let cap_repo = Repo::new("reject-cap");
        cap_repo.write("src/base", b"base");
        cap_repo.manifest("reject", &["src/**"]);
        cap_repo.commit_all("base");
        let oversized = File::create(cap_repo.root.join("src/oversized")).unwrap();
        oversized.set_len(MAX_CANDIDATE_FILE_BYTES + 1).unwrap();
        let error = capture_candidate(&cap_repo.root, "reject", &"c".repeat(64)).unwrap_err();
        assert!(error.contains("exceeds its cap"), "{error}");
        assert!(no_staging_directories(&cap_repo.root));
    }

    #[test]
    fn unmerged_ignored_and_inventory_caps_are_rejected() {
        let manifest = ChangeManifest {
            version: 1,
            paths: vec!["src/**".into()],
            shared_paths: Vec::new(),
            publish: None,
        };
        assert!(overlay_plan(
            &manifest,
            &[StatusEntry::Unmerged {
                xy: "UU".into(),
                path: "src/conflict".into()
            }]
        )
        .unwrap_err()
        .contains("unmerged"));
        assert!(overlay_plan(
            &manifest,
            &[StatusEntry::Ignored {
                path: "src/ignored".into()
            }]
        )
        .unwrap_err()
        .contains("ignored"));
        let over_cap = (0..=MAX_CANDIDATE_ENTRIES)
            .map(|index| CandidateEntry::deleted(&format!("src/{index:06}")))
            .collect::<Vec<_>>();
        assert!(validate_inventory(&over_cap)
            .unwrap_err()
            .contains("entry cap"));
        let too_long = format!("src/{}", "x".repeat(MAX_CANDIDATE_PATH_BYTES));
        assert!(
            overlay_plan(&manifest, &[StatusEntry::Untracked { path: too_long }])
                .unwrap_err()
                .contains("path exceeds")
        );

        let ignored_repo = Repo::new("reject-ignored");
        ignored_repo.write(".gitignore", b"src/ignored\n");
        ignored_repo.write("src/base", b"base");
        ignored_repo.manifest("reject", &["src/**"]);
        ignored_repo.commit_all("base");
        ignored_repo.write("src/ignored", b"ignored but declared");
        let error = capture_candidate(&ignored_repo.root, "reject", &"d".repeat(64)).unwrap_err();
        assert!(error.contains("ignored"), "{error}");
        assert!(no_staging_directories(&ignored_repo.root));
    }

    #[test]
    fn worktree_surface_prunes_undeclared_subtrees_before_the_entry_cap() {
        let repo = Repo::new("surface-pruning");
        repo.write("src/kept", b"kept");
        repo.write("target/deep/nested/ignored", b"ignored");
        let manifest = ChangeManifest {
            version: 1,
            paths: vec!["src/**".into()],
            shared_paths: Vec::new(),
            publish: None,
        };
        let tracked = BTreeSet::from(["src/kept".to_string()]);
        let planned = BTreeSet::new();
        let mut remaining = 2;

        validate_worktree_directory(
            &repo.root,
            &repo.root,
            &manifest,
            &tracked,
            &planned,
            &mut remaining,
        )
        .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn descriptor_and_git_state_races_block_and_remove_only_staging() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let repo = Repo::new("races");
        repo.write("src/race", b"original");
        repo.manifest("race", &["src/**"]);
        repo.commit_all("base");
        repo.write("src/race", b"changed1");

        let mut replaced = false;
        let error =
            capture_candidate_with_hook(&repo.root, "race", &"d".repeat(64), &mut |point, path| {
                if point == CaptureHookPoint::AfterWorktreeOpen && !replaced {
                    replaced = true;
                    let old = path.with_extension("old");
                    fs::rename(path, &old).unwrap();
                    fs::write(path, b"changed2").unwrap();
                }
            })
            .unwrap_err();
        assert!(error.contains("metadata drifted"), "{error}");
        assert!(no_staging_directories(&repo.root));

        // Restore a simple dirty state, then mutate only the index at the
        // explicit pre-reobserve seam. Capture observes and rejects it.
        let _ = fs::remove_file(repo.root.join("src/race.old"));
        repo.write("src/race", b"changed3");
        let mut indexed = false;
        let error =
            capture_candidate_with_hook(&repo.root, "race", &"d".repeat(64), &mut |point, _| {
                if point == CaptureHookPoint::BeforeGitReobserve && !indexed {
                    indexed = true;
                    git_ok(&repo.root, &["add", "src/race"]);
                }
            })
            .unwrap_err();
        assert!(error.contains("index changed"), "{error}");
        assert!(no_staging_directories(&repo.root));

        let head_repo = Repo::new("head-race");
        head_repo.write("src/race", b"base");
        head_repo.manifest("race", &["src/**"]);
        head_repo.commit_all("base");
        head_repo.write("src/race", b"dirty");
        let mut committed = false;
        let error = capture_candidate_with_hook(
            &head_repo.root,
            "race",
            &"d".repeat(64),
            &mut |point, _| {
                if point == CaptureHookPoint::BeforeGitReobserve && !committed {
                    committed = true;
                    git_ok(
                        &head_repo.root,
                        &["commit", "--allow-empty", "-q", "-m", "concurrent head"],
                    );
                }
            },
        )
        .unwrap_err();
        assert!(error.contains("base HEAD changed"), "{error}");
        assert!(no_staging_directories(&head_repo.root));

        // The final ID is not authority until a complete post-publication
        // inventory succeeds. An owner-side content mutation at that seam is
        // detected and the exact published root is removed.
        let published_repo = Repo::new("post-publication-content-race");
        published_repo.write("src/race", b"base");
        published_repo.manifest("race", &["src/**"]);
        published_repo.commit_all("base");
        published_repo.write("src/race", b"candidate");
        let mut mutated = false;
        let error = capture_candidate_with_hook(
            &published_repo.root,
            "race",
            &"d".repeat(64),
            &mut |point, root| {
                if point == CaptureHookPoint::AfterPublication && !mutated {
                    mutated = true;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(
                            root.join("src/race"),
                            fs::Permissions::from_mode(0o600),
                        )
                        .unwrap();
                    }
                    fs::write(root.join("src/race"), b"mutated").unwrap();
                    #[cfg(unix)]
                    fs::set_permissions(root.join("src/race"), fs::Permissions::from_mode(0o400))
                        .unwrap();
                    #[cfg(unix)]
                    fs::set_permissions(root.join("src"), fs::Permissions::from_mode(0o500))
                        .unwrap();
                }
            },
        )
        .unwrap_err();
        assert!(error.contains("inventory"), "{error}");
        assert!(candidate_parent(&published_repo.root)
            .unwrap()
            .read_dir()
            .unwrap()
            .next()
            .is_none());

        // Replacing a projected leaf at the same seam is equally rejected;
        // cleanup remains bound to the unchanged published root inode.
        let replacement_repo = Repo::new("post-publication-replacement-race");
        replacement_repo.write("src/race", b"base");
        replacement_repo.manifest("race", &["src/**"]);
        replacement_repo.commit_all("base");
        replacement_repo.write("src/race", b"candidate");
        let mut replaced = false;
        let error = capture_candidate_with_hook(
            &replacement_repo.root,
            "race",
            &"d".repeat(64),
            &mut |point, root| {
                if point == CaptureHookPoint::AfterPublication && !replaced {
                    replaced = true;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(root.join("src"), fs::Permissions::from_mode(0o700))
                            .unwrap();
                    }
                    fs::rename(root.join("src/race"), root.join("src/race.old")).unwrap();
                    fs::write(root.join("src/race"), b"replacement").unwrap();
                    #[cfg(unix)]
                    fs::set_permissions(root.join("src/race"), fs::Permissions::from_mode(0o400))
                        .unwrap();
                    #[cfg(unix)]
                    fs::set_permissions(root.join("src"), fs::Permissions::from_mode(0o500))
                        .unwrap();
                }
            },
        )
        .unwrap_err();
        assert!(error.contains("inventory"), "{error}");
        assert!(candidate_parent(&replacement_repo.root)
            .unwrap()
            .read_dir()
            .unwrap()
            .next()
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn permission_only_post_publication_races_block_and_clean_the_new_root() {
        use std::os::unix::fs::PermissionsExt;

        for (label, target, mode) in [
            ("file", "src/nested/value", 0o600),
            ("directory", "src/nested", 0o700),
        ] {
            let repo = Repo::new(&format!("post-publication-mode-{label}"));
            repo.write("src/nested/value", b"base");
            repo.manifest("race", &["src/**"]);
            repo.commit_all("base");
            repo.write("src/nested/value", b"candidate");
            let mut changed = false;
            let error = capture_candidate_with_hook(
                &repo.root,
                "race",
                &"d".repeat(64),
                &mut |point, root| {
                    if point == CaptureHookPoint::AfterPublication && !changed {
                        changed = true;
                        fs::set_permissions(root.join(target), fs::Permissions::from_mode(mode))
                            .unwrap();
                    }
                },
            )
            .unwrap_err();
            assert!(error.contains("mutable permissions"), "{label}: {error}");
            assert!(candidate_parent(&repo.root)
                .unwrap()
                .read_dir()
                .unwrap()
                .next()
                .is_none());
            assert!(no_staging_directories(&repo.root));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_dirty_path_is_rejected_before_projection() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let repo = Repo::new("non-utf8");
        repo.write("src/base", b"base");
        repo.manifest("reject", &["src/**"]);
        repo.commit_all("base");
        let name = OsString::from_vec(vec![b's', b'r', b'c', b'/', 0xff]);
        match fs::write(repo.root.join(name), b"bad") {
            Ok(()) => {
                let error = capture_candidate(&repo.root, "reject", &"e".repeat(64)).unwrap_err();
                assert!(error.contains("UTF-8"), "{error}");
                assert!(no_staging_directories(&repo.root));
            }
            // Some current Apple filesystems reject non-UTF-8 names before
            // MPD can observe them. Exercise the same durable inventory
            // boundary directly on those hosts.
            Err(_) => {
                let invalid = vec![CandidateEntry {
                    path_bytes: vec![b's', b'r', b'c', b'/', 0xff],
                    state: CandidatePathState::Deleted,
                    mode: None,
                    byte_len: 0,
                    sha256: None,
                }];
                assert!(validate_inventory(&invalid).unwrap_err().contains("UTF-8"));
            }
        }
    }
}
