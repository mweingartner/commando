//! Local-only validation preflight and immutable Git subject handling.
//!
//! This module deliberately separates *capturing* a subject from executing a
//! profile.  Until a clone has an approved trusted-policy ref, callers receive a
//! deterministic blocker and no candidate-defined command is launched.

use crate::config::{BuildOutputConfig, DeployOutputConfig, LocalValidationConfig};
use crate::digest::Digest;
use crate::ledger::{BuildOutputV1, DeployResultV1};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TRUSTED_POLICY_REF: &str = "refs/mpd/trusted-validation-policy";
const OID_MAX: usize = 64;
const MAX_POLICY_BYTES: usize = 1024 * 1024;
#[allow(dead_code)] // activated by the clone-private pre-push coordinator slice
const MAX_PUSH_RECORDS: usize = 10_000;
#[allow(dead_code)] // activated by the clone-private pre-push coordinator slice
const MAX_PUSH_BYTES: usize = 1024 * 1024;
const MAX_PUSH_AUTHORIZATION_AUDIT_BYTES: u64 = 4 * 1024 * 1024;
/// The hook deliberately keeps tighter caps than the design maximum while the
/// clone-private streaming coordinator is being introduced.  A cap is an
/// authorization boundary, never a reason to inspect only a prefix.
const MAX_PUSH_OBJECTS: usize = 250_000;
const MAX_PUSH_OBJECT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PUSH_BLOB_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PUSH_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_PUSH_METADATA_TOTAL: u64 = 16 * 1024 * 1024;
const MAX_PUSH_ENUM_BYTES: usize = 64 * 1024 * 1024;
/// The complete pre-push batch shares this enumeration budget. A per-ref cap
/// alone would let a large multi-ref push force repeated 64 MiB traversals.
const MAX_PUSH_ENUM_TOTAL_BYTES: usize = MAX_PUSH_ENUM_BYTES;
/// Cap on the number of distinct (blob oid, path) bindings the D1 path-mapping
/// pass may accumulate across the whole outgoing batch — same order of
/// magnitude as the outgoing object cap, since the pass only ever widens a
/// blob already counted against that cap into one-or-more paths.
const MAX_PUSH_PATH_MAPPINGS: usize = MAX_PUSH_OBJECTS;
const MAX_DELETION_APPROVALS: usize = 64;
const MAX_DELETION_APPROVAL_BYTES: u64 = 64 * 1024;
const MAX_MATERIALIZED_TREE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MATERIALIZED_BLOB_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MATERIALIZED_ENTRIES: usize = 100_000;
const MAX_MATERIALIZED_PATH_BYTES: usize = 4096;
const MAX_MATERIALIZED_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const VALIDATION_NOTES_REF: &str = "refs/notes/mpd-validation";
const MAX_NOTE_BYTES: usize = 1024 * 1024;
const MAX_TAG_DEPTH: usize = 16;
const MAX_TAG_OBJECT_BYTES: u64 = 1024 * 1024;
const MAX_TAG_HEADER_BYTES: usize = 64 * 1024;
const MAX_TAG_CHAIN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GIT_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;
const VALIDATION_SCHEMA: u32 = 1;
const BUILD_OUTPUT_SCHEMA: u32 = 1;
const MAX_BUILD_OUTPUT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
#[cfg(test)]
const PRETRUST_PROOF_SCHEMA: u32 = 1;
const ACTIVATION_JOURNAL_SCHEMA: u32 = 1;
const POLICY_ASSET_SCHEMA: u32 = 1;
const MAX_POLICY_ASSET_BYTES: usize = 4 * 1024 * 1024;
const MAX_POLICY_ASSET_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const POLICY_STATE_DIR: &str = "mpd/policy";
#[cfg(test)]
const FIRST_ADOPTION_DIR: &str = "mpd/first-adoption";
#[cfg(test)]
const BOOTSTRAP_NONCE_DOMAIN: &[u8] = b"mpd:first-adoption:bootstrap-nonce:v1\0";

#[derive(Debug)]
struct CanonicalGitOutput {
    success: bool,
    code: Option<i32>,
    stdout: Vec<u8>,
}

fn canonical_git_path() -> Result<&'static Path, String> {
    for candidate in ["/usr/bin/git", "/bin/git"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err("canonical local Git executable is unavailable".into())
}

fn read_capped<R: Read>(reader: R, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    reader
        .take((cap as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let exceeded = bytes.len() > cap;
    if exceeded {
        bytes.truncate(cap);
    }
    Ok((bytes, exceeded))
}

/// The sole production boundary for local Git plumbing in this module.
/// Ambient Git/config/identity/pager/hook/filter state is never inherited and
/// child output is drained concurrently into hard caps. Callers receive only
/// stable errors; child stderr is deliberately never rendered or persisted.
fn canonical_git_run(
    root: &Path,
    args: &[&str],
    input: &[u8],
    extra_env: &[(OsString, OsString)],
    stdout_cap: usize,
) -> Result<CanonicalGitOutput, String> {
    let mut command = Command::new(canonical_git_path()?);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        // /usr/bin/git is a developer-tool shim on macOS; without a pinned
        // DEVELOPER_DIR it resolves through xcode-select, whose target may be
        // outside any sandbox read root (e.g. an Xcode beta).
        .env("DEVELOPER_DIR", "/Library/Developer/CommandLineTools")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("LC_ALL", "C")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.pager=cat",
            "-c",
            "pager.branch=false",
            "-c",
            "pager.log=false",
            "-c",
            "pager.show=false",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "core.attributesFile=/dev/null",
        ])
        .args(args)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let mut child = command
        .spawn()
        .map_err(|_| "cannot start canonical local Git".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or("canonical local Git stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("canonical local Git stderr is unavailable")?;
    let stdout_thread = std::thread::spawn(move || read_capped(stdout, stdout_cap));
    let stderr_thread = std::thread::spawn(move || read_capped(stderr, MAX_GIT_STDERR_BYTES));
    child
        .stdin
        .take()
        .ok_or("canonical local Git stdin is unavailable")?
        .write_all(input)
        .map_err(|_| "cannot write canonical local Git input".to_string())?;
    let status = child
        .wait()
        .map_err(|_| "cannot finish canonical local Git".to_string())?;
    let (stdout, stdout_exceeded) = stdout_thread
        .join()
        .map_err(|_| "canonical local Git stdout reader failed".to_string())?
        .map_err(|_| "cannot read canonical local Git stdout".to_string())?;
    let (_, stderr_exceeded) = stderr_thread
        .join()
        .map_err(|_| "canonical local Git stderr reader failed".to_string())?
        .map_err(|_| "cannot read canonical local Git stderr".to_string())?;
    if stdout_exceeded || stderr_exceeded {
        return Err("canonical local Git output exceeded its cap".into());
    }
    Ok(CanonicalGitOutput {
        success: status.success(),
        code: status.code(),
        stdout,
    })
}

fn canonical_git(
    root: &Path,
    args: &[&str],
    stdout_cap: usize,
) -> Result<CanonicalGitOutput, String> {
    canonical_git_run(root, args, b"", &[], stdout_cap)
}

fn git_env_pair(key: &str, value: impl AsRef<OsStr>) -> (OsString, OsString) {
    (OsString::from(key), value.as_ref().to_os_string())
}

#[derive(Debug, Clone, Copy)]
struct PolicyAssetSpec {
    path: &'static str,
    mode: u32,
}

const POLICY_ASSET_SPECS: &[PolicyAssetSpec] = &[
    PolicyAssetSpec {
        path: ".githooks/pre-commit",
        mode: 0o100755,
    },
    PolicyAssetSpec {
        path: ".githooks/pre-push",
        mode: 0o100755,
    },
    PolicyAssetSpec {
        path: "security/advisory-db.lock.json",
        mode: 0o100644,
    },
    PolicyAssetSpec {
        path: "security/policy/local-ci-policy.json",
        mode: 0o100644,
    },
    PolicyAssetSpec {
        path: "security/sandbox/validation.bwrap",
        mode: 0o100644,
    },
    PolicyAssetSpec {
        path: "security/sandbox/validation.sb",
        mode: 0o100644,
    },
    PolicyAssetSpec {
        path: "security/semgrep/local-ci.yml",
        mode: 0o100644,
    },
    PolicyAssetSpec {
        path: "security/tool-lock.json",
        mode: 0o100644,
    },
];

#[cfg(test)]
type NoteCasBarrier = std::sync::Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>;
#[cfg(test)]
struct NoteCasHook {
    root: PathBuf,
    barrier: NoteCasBarrier,
}
#[cfg(test)]
static NOTE_CAS_BARRIER: std::sync::Mutex<Option<NoteCasHook>> = std::sync::Mutex::new(None);
#[cfg(test)]
static INSTALL_RACE_MODES: std::sync::LazyLock<std::sync::Mutex<BTreeMap<PathBuf, usize>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));
#[cfg(test)]
static CANDIDATE_OUTPUT_RACE_MODES: std::sync::LazyLock<
    std::sync::Mutex<BTreeMap<PathBuf, usize>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));
#[cfg(test)]
static DEPLOY_CALLS: std::sync::LazyLock<std::sync::Mutex<BTreeMap<PathBuf, (usize, usize)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));

#[cfg(test)]
fn set_candidate_output_failure(root: &Path, mode: usize) {
    CANDIDATE_OUTPUT_RACE_MODES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(root.to_path_buf(), mode);
}

#[cfg(test)]
fn take_candidate_output_failure(root: &Path, mode: usize) -> bool {
    let mut modes = CANDIDATE_OUTPUT_RACE_MODES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if modes.get(root) == Some(&mode) {
        modes.remove(root);
        true
    } else {
        false
    }
}

pub(crate) fn maybe_crash_candidate_output(
    #[cfg_attr(not(test), allow(unused_variables))] stage: &str,
) {
    #[cfg(test)]
    if std::env::var("MPD_TEST_CANDIDATE_OUTPUT_CRASH").as_deref() == Ok(stage) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::SIGKILL);
        std::process::abort();
    }
}

/// The one deliberately untrusted result produced before the first policy CAS.
/// Its nonce is public challenge material; the digest, rather than the preimage,
/// is subsequently carried in the trusted policy object and reconciliation event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
pub struct PretrustCheckpointProofV1 {
    pub schema: u32,
    pub change: String,
    pub checkpoint_oid: String,
    pub checkpoint_tree_oid: String,
    pub checkpoint_scope: CheckpointScopeV1,
    pub checkpoint_chain_digest: String,
    pub security_evidence: String,
    pub security_evidence_digest: String,
    pub candidate_policy_digest: String,
    pub tool_lock_digest: String,
    pub sandbox_digest: String,
    pub hook_digest: String,
    pub coordinator_digest: String,
    pub sandbox_contract: String,
    pub allowed_effect_digest: String,
    pub observed_effect_digest: String,
    pub protected_before_digest: String,
    pub protected_after_digest: String,
    pub private_state_before_digest: String,
    pub private_state_after_without_proof_digest: String,
    pub proof_relative_path: String,
    pub configured_checks_executed: u32,
    pub nonce_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct PretrustProtectedStateV1 {
    head_oid: String,
    head_ref: String,
    index_digest: String,
    refs_digest: String,
    local_config_digest: String,
    hooks_digest: String,
    source_status_digest: String,
    configured_graph_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct PretrustEffectObservationV1 {
    schema: u32,
    protected_before_digest: String,
    protected_after_digest: String,
    private_state_before_digest: String,
    private_state_after_without_proof_digest: String,
    exclusive_write: String,
    configured_checks_executed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationStageV1 {
    Prepared,
    TrustedInactive,
    LauncherStaged,
    CoordinatorInstalled,
    HooksInstalled,
    HooksPathSet,
    VerifiedActive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationJournalV1 {
    pub schema: u32,
    pub trusted_policy_oid: String,
    pub trusted_policy_digest: String,
    pub reviewed_coordinator_digest: String,
    pub stage: ActivationStageV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_hooks_path: Option<String>,
    #[serde(default)]
    pub installed_path_digests: BTreeMap<String, String>,
    pub actor: String,
    pub updated_at_epoch_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedPolicyObjectV1 {
    schema: u32,
    local_validation: LocalValidationConfig,
    asset_schema: u32,
    assets: Vec<TrustedPolicyAssetV1>,
    /// The direct trusted ref value that this object supersedes.  Bootstrap has
    /// no predecessor; every normal promotion binds its exact prior floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_trusted_policy_oid: Option<String>,
    checkpoint_oid: String,
    pretrust_proof_digest: String,
    bootstrap_nonce_digest: String,
    coordinator_digest: String,
    hook_digest: String,
    tool_lock_digest: String,
    sandbox_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedPolicyAssetV1 {
    path: String,
    mode: u32,
    size: u64,
    sha256: String,
    blob_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedPolicyAssetBytes {
    metadata: TrustedPolicyAssetV1,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedPolicyBundleV1 {
    object: TrustedPolicyObjectV1,
    assets: BTreeMap<String, TrustedPolicyAssetBytes>,
}

/// The owner-visible result of an explicit policy promotion.  It deliberately
/// contains only policy/object identities and a semantic summary: promotion is
/// not a validation receipt and never records a gate PASS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(test)]
pub struct PolicyPromotionReport {
    pub subject_commit: String,
    pub trusted_before_oid: String,
    pub trusted_before_digest: String,
    pub candidate_policy_digest: String,
    pub candidate_tool_lock_digest: String,
    pub candidate_sandbox_digest: String,
    pub candidate_hook_digest: String,
    pub semantic_diff: Vec<String>,
    pub promoted_policy_oid: String,
}

#[derive(Debug, Clone)]
#[cfg(test)]
pub struct BootstrapRequest<'a> {
    pub checkpoint_oid: &'a str,
    pub reviewed_policy_digest: &'a str,
    pub pretrust_proof_digest: &'a str,
    pub nonce: &'a str,
}

/// Read one contained release artifact through an opened descriptor, rejecting
/// symlinks, directories, special files and multiply-linked files.  The
/// descriptor metadata is rechecked after open so a path replacement cannot
/// turn a reviewed pre-open path into the bytes that are recorded.
pub fn capture_build_output(root: &Path, relative: &str) -> Result<BuildOutputV1, String> {
    let path = contained_regular_path(root, relative)?;
    let before =
        fs::symlink_metadata(&path).map_err(|e| format!("build artifact is unavailable: {e}"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err("build artifact must be a non-symlink regular file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options
        .open(&path)
        .map_err(|e| format!("cannot open build artifact: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat opened build artifact: {e}"))?;
    if !metadata.is_file() || metadata.len() > MAX_BUILD_OUTPUT_BYTES {
        return Err("build artifact is not a bounded regular file".into());
    }
    if !same_file_identity(&before, &metadata) {
        return Err("build artifact changed while it was opened".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("build artifact must have exactly one link".into());
        }
    }
    let digest = hash_open_file(file)?;
    let mode = mode_of(&metadata);
    Ok(BuildOutputV1 {
        schema: BUILD_OUTPUT_SCHEMA,
        name: String::new(),
        path: relative.to_string(),
        max_bytes: 0,
        required_mode: 0,
        size: metadata.len(),
        mode,
        device: device_of(&metadata),
        inode: inode_of(&metadata),
        sha256: digest,
        candidate_id: None,
    })
}

/// Apply the Build policy contract when recording an artifact. This is kept
/// separate from the generic identity reader because an installed path has a
/// different name/path contract but must still be hashable by the leaf probe.
pub fn capture_configured_build_output(
    root: &Path,
    contract: &BuildOutputConfig,
) -> Result<BuildOutputV1, String> {
    let mut output = capture_build_output(root, &contract.path)?;
    if output.size > contract.max_bytes {
        return Err("build artifact exceeds configured max_bytes".into());
    }
    if output.mode != contract.required_mode {
        return Err(format!(
            "build artifact mode {:o} differs from required_mode {:o}",
            output.mode, contract.required_mode
        ));
    }
    output.name = contract.name.clone();
    output.max_bytes = contract.max_bytes;
    output.required_mode = contract.required_mode;
    Ok(output)
}

fn capture_recorded_build_output(
    root: &Path,
    output: &BuildOutputV1,
) -> Result<BuildOutputV1, String> {
    validate_build_output_candidate_id(output.candidate_id.as_deref())?;
    if output.name.is_empty()
        || output.max_bytes == 0
        || output.required_mode == 0
        || output.max_bytes > MAX_BUILD_OUTPUT_BYTES
    {
        return Err("Build output lacks a strict named size/mode contract".into());
    }
    let mut observed = capture_build_output(root, &output.path)?;
    if observed.size > output.max_bytes || observed.mode != output.required_mode {
        return Err("build artifact no longer satisfies its recorded size/mode contract".into());
    }
    observed.name = output.name.clone();
    observed.max_bytes = output.max_bytes;
    observed.required_mode = output.required_mode;
    observed.candidate_id = output.candidate_id.clone();
    Ok(observed)
}

fn validate_build_output_candidate_id(candidate_id: Option<&str>) -> Result<(), String> {
    if let Some(candidate_id) = candidate_id {
        Digest::from_hex(candidate_id)
            .map_err(|_| "Build output candidate_id is not a canonical SHA-256 digest")?;
    }
    Ok(())
}

/// Reopen and recheck a previously recorded Build file before atomically
/// copying it. There is intentionally no command/rebuild hook here.
pub fn install_build_output(
    root: &Path,
    output: &BuildOutputV1,
    installed_relative: &str,
) -> Result<BuildOutputV1, String> {
    #[cfg(test)]
    {
        DEPLOY_CALLS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(root.to_path_buf())
            .or_default()
            .0 += 1;
    }
    if output.schema != BUILD_OUTPUT_SCHEMA {
        return Err("unsupported BuildOutput schema".into());
    }
    let observed = capture_recorded_build_output(root, output)?;
    if &observed != output {
        return Err("build artifact identity changed after Build".into());
    }
    let destination = contained_regular_path(root, installed_relative)?;
    let destination_before = safe_replaceable_file_identity(&destination)?;
    let parent = destination
        .parent()
        .ok_or("installed target has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create install directory: {e}"))?;
    let temp = parent.join(format!(
        ".mpd-install-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    let mut source_options = OpenOptions::new();
    source_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source_options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut source = source_options
        .open(root.join(&output.path))
        .map_err(|e| format!("cannot reopen verified build artifact: {e}"))?;
    let mut target_options = OpenOptions::new();
    target_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        target_options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        target_options.mode(0o600);
    }
    let mut target = target_options
        .open(&temp)
        .map_err(|e| format!("cannot create atomic install file: {e}"))?;
    let mut temp_guard = OwnedTempFile::capture(&temp, &target)?;
    std::io::copy(&mut source, &mut target)
        .map_err(|e| format!("cannot copy build artifact: {e}"))?;
    target
        .sync_all()
        .map_err(|e| format!("cannot sync installed artifact: {e}"))?;
    drop(target);
    #[cfg(test)]
    inject_install_race(root, output, &destination, &temp)?;
    temp_guard.verify()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(output.mode))
            .map_err(|e| format!("cannot set installed artifact mode: {e}"))?;
    }
    let staged = capture_absolute_build_output(&temp, output)?;
    if staged.size != output.size
        || staged.mode != output.mode
        || staged.sha256 != output.sha256
        || staged.candidate_id != output.candidate_id
    {
        return Err("staged installed artifact differs from Build output".into());
    }
    if capture_recorded_build_output(root, output)? != *output {
        return Err("build artifact changed while Deploy copied it".into());
    }
    if safe_replaceable_file_identity(&destination)? != destination_before {
        return Err("installed target changed before atomic replacement".into());
    }
    fs::rename(&temp, &destination)
        .map_err(|e| format!("cannot atomically install artifact: {e}"))?;
    temp_guard.disarm();
    sync_parent_directory(parent)?;
    if capture_recorded_build_output(root, output)? != *output {
        return Err("build artifact changed after Deploy replacement".into());
    }
    let mut installed = capture_build_output(root, installed_relative)?;
    installed.candidate_id = output.candidate_id.clone();
    if installed.size != output.size
        || installed.mode != output.mode
        || installed.sha256 != output.sha256
    {
        return Err("installed artifact identity does not match Build output".into());
    }
    Ok(installed)
}

fn safe_replaceable_file_identity(path: &Path) -> Result<Option<(u64, u64)>, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("cannot inspect atomic replacement target".into()),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("atomic replacement target must be a non-symlink regular file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err("atomic replacement target must have exactly one link".into());
                }
            }
            Ok(Some((device_of(&metadata), inode_of(&metadata))))
        }
    }
}

fn capture_absolute_build_output(
    path: &Path,
    contract: &BuildOutputV1,
) -> Result<BuildOutputV1, String> {
    let parent = path.parent().ok_or("staged artifact has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("staged artifact has no UTF-8 filename")?;
    let mut captured = capture_build_output(parent, name)?;
    captured.name = contract.name.clone();
    captured.max_bytes = contract.max_bytes;
    captured.required_mode = contract.required_mode;
    captured.candidate_id = contract.candidate_id.clone();
    Ok(captured)
}

struct OwnedTempFile {
    path: PathBuf,
    device: u64,
    inode: u64,
    armed: bool,
}

impl OwnedTempFile {
    fn capture(path: &Path, file: &fs::File) -> Result<Self, String> {
        let metadata = file
            .metadata()
            .map_err(|_| "cannot capture temporary file identity")?;
        if !metadata.is_file() {
            return Err("temporary artifact is not a regular file".into());
        }
        Ok(Self {
            path: path.to_path_buf(),
            device: device_of(&metadata),
            inode: inode_of(&metadata),
            armed: true,
        })
    }

    fn verify(&self) -> Result<(), String> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|_| "temporary artifact disappeared before replacement")?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || device_of(&metadata) != self.device
            || inode_of(&metadata) != self.inode
        {
            return Err("temporary artifact changed before replacement".into());
        }
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OwnedTempFile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_symlink() || metadata.is_file() {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(test)]
fn inject_install_race(
    root: &Path,
    output: &BuildOutputV1,
    destination: &Path,
    temporary: &Path,
) -> Result<(), String> {
    let mode = INSTALL_RACE_MODES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(root)
        .unwrap_or_default();
    match mode {
        1 => {
            let source = root.join(&output.path);
            fs::rename(&source, source.with_extension("race-old"))
                .map_err(|e| format!("test source replacement failed: {e}"))?;
            fs::write(&source, b"replacement")
                .map_err(|e| format!("test source replacement failed: {e}"))?;
        }
        2 => {
            fs::write(destination, b"replacement")
                .map_err(|e| format!("test destination replacement failed: {e}"))?;
        }
        3 => {
            fs::remove_file(temporary)
                .map_err(|e| format!("test temporary replacement failed: {e}"))?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(root.join(&output.path), temporary)
                .map_err(|e| format!("test temporary replacement failed: {e}"))?;
            #[cfg(not(unix))]
            fs::write(temporary, b"replacement")
                .map_err(|e| format!("test temporary replacement failed: {e}"))?;
        }
        _ => {}
    }
    Ok(())
}

/// A pure leaf identity probe. It opens and hashes one named file only; it
/// never consults doctor, validation, deployment, policy, or configuration.
pub fn identity(root: &Path, relative: &str) -> Result<BuildOutputV1, String> {
    capture_build_output(root, relative)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReportV1 {
    pub schema: u32,
    pub crate_name: String,
    pub crate_version: String,
    pub validation_contract_version: u32,
    pub ledger_schema_version: u32,
    pub receipt_schema_version: u32,
    pub artifact: BuildOutputV1,
}

pub fn identity_report(root: &Path, relative: Option<&str>) -> Result<IdentityReportV1, String> {
    let relative = match relative {
        Some(relative) => relative.to_string(),
        None => {
            let root = fs::canonicalize(root)
                .map_err(|e| format!("cannot canonicalize identity root: {e}"))?;
            let executable = fs::canonicalize(
                std::env::current_exe()
                    .map_err(|e| format!("cannot resolve identity executable: {e}"))?,
            )
            .map_err(|e| format!("cannot canonicalize identity executable: {e}"))?;
            executable
                .strip_prefix(&root)
                .map_err(|_| "identity executable is outside the repository root")?
                .to_str()
                .ok_or("identity executable path is non-UTF-8")?
                .to_string()
        }
    };
    Ok(IdentityReportV1 {
        schema: 1,
        crate_name: env!("CARGO_PKG_NAME").into(),
        crate_version: env!("CARGO_PKG_VERSION").into(),
        validation_contract_version: 1,
        ledger_schema_version: 1,
        receipt_schema_version: VALIDATION_SCHEMA,
        artifact: identity(root, &relative)?,
    })
}

/// Execute the closed, typed Deploy graph. There is no command/rebuild branch:
/// `exact-copy` can only copy the Build descriptor verified above. The installed
/// executable is never invoked; the parent reopens and verifies the resulting
/// bytes. The returned record is safe to persist in a GateRecord because it
#[cfg(test)]
mod recorded_output_path_tests {
    use super::recorded_output_path_matches_contract;

    #[test]
    fn deploy_contract_accepts_only_candidate_scoped_export_paths() {
        let contract = ".mpd/build-output/mpd";
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(recorded_output_path_matches_contract(
            &format!(".mpd/build-output/{digest}/mpd"),
            contract
        ));
        // The literal contract path is the atomic in-place exporter's shape.
        assert!(recorded_output_path_matches_contract(contract, contract));
        // Wrong file, wrong base dir, malformed or nested digests all fail.
        assert!(!recorded_output_path_matches_contract(
            &format!(".mpd/build-output/{digest}/other"),
            contract
        ));
        assert!(!recorded_output_path_matches_contract(
            &format!(".mpd/elsewhere/{digest}/mpd"),
            contract
        ));
        assert!(!recorded_output_path_matches_contract(
            ".mpd/build-output/NOTHEX/mpd",
            contract
        ));
        assert!(!recorded_output_path_matches_contract(
            ".mpd/build-output/0123abc/mpd",
            contract
        ));
        assert!(!recorded_output_path_matches_contract(
            &format!(".mpd/build-output/{digest}/extra/mpd"),
            contract
        ));
        // Uppercase hex is not the exporter's alphabet.
        assert!(!recorded_output_path_matches_contract(
            &format!(".mpd/build-output/{}/mpd", digest.to_uppercase()),
            contract
        ));
    }
}

/// A recorded Build output path is legitimate in exactly two exporter
/// shapes: the literal contract path (`capture_configured_build_output`
/// after an atomic in-place publish) or the candidate-scoped runtime export
/// (`<contract-dir>/<64-hex-candidate-digest>/<contract-file>`, written by
/// the sandboxed profile so concurrent captures can never alias one
/// another's bytes). Anything else is rejected. Byte identity is separately
/// enforced by the no-follow re-capture and post-install re-hash below.
fn recorded_output_path_matches_contract(recorded: &str, contract: &str) -> bool {
    if recorded == contract {
        return true;
    }
    let contract = Path::new(contract);
    let recorded = Path::new(recorded);
    let (Some(dir), Some(file)) = (contract.parent(), contract.file_name()) else {
        return false;
    };
    if recorded.file_name() != Some(file) {
        return false;
    }
    let Some(scoped) = recorded.parent() else {
        return false;
    };
    if scoped.parent() != Some(dir) {
        return false;
    }
    scoped.file_name().is_some_and(|digest| {
        digest.to_str().is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    })
}

/// contains digests and booleans, never child output.
pub fn execute_typed_deploy(
    root: &Path,
    build_contract: Option<&BuildOutputConfig>,
    deploy: &DeployOutputConfig,
    build: Option<&BuildOutputV1>,
) -> Result<DeployResultV1, String> {
    let definition =
        serde_json::to_vec(deploy).map_err(|e| format!("cannot encode Deploy definition: {e}"))?;
    let definition_digest = Digest::of_bytes(&definition).to_hex();
    match deploy {
        DeployOutputConfig::Execute {
            artifact,
            installed_path,
            target,
            ..
        } => {
            let build_contract = build_contract
                .ok_or("typed execute Deploy is missing its Build output contract")?;
            let build = build.ok_or("typed execute Deploy is missing its Build receipt")?;
            if build.name != *artifact
                || build.name != build_contract.name
                || build.max_bytes != build_contract.max_bytes
                || build.required_mode != build_contract.required_mode
                || !recorded_output_path_matches_contract(&build.path, &build_contract.path)
            {
                return Err(
                    "Build receipt does not match the current typed artifact contract".into(),
                );
            }
            // This check opens the source no-follow and rejects stale/replaced,
            // symlinked, or hard-linked input before `install_build_output` can
            // create any destination bytes.
            let observed = capture_recorded_build_output(root, build)?;
            if observed != *build {
                return Err("Build receipt artifact is stale or replaced before Deploy".into());
            }
            let installed = install_build_output(root, build, installed_path)?;
            if installed.size != build.size
                || installed.mode != build.mode
                || installed.sha256 != build.sha256
            {
                return Err("installed bytes differ from typed Deploy expectation".into());
            }
            let result = serde_json::to_vec(&serde_json::json!({
                "build_sha256": build.sha256,
                "installed_sha256": installed.sha256,
                "installed_size": installed.size,
                "installed_mode": installed.mode,
            }))
            .map_err(|e| format!("cannot encode Deploy result: {e}"))?;
            Ok(DeployResultV1 {
                schema: 1,
                mode: "execute".into(),
                target: target.clone(),
                definition_digest,
                result_digest: Digest::of_bytes(&result).to_hex(),
                install_executed: true,
                probe_executed: false,
                verified: true,
            })
        }
        DeployOutputConfig::Readiness { evidence, target } => {
            let path = contained_regular_path(root, evidence)?;
            let bytes = openspec_core::read_contained_capped(root, &path, 1024 * 1024)
                .map_err(|e| format!("readiness evidence is unavailable: {e}"))?;
            Ok(DeployResultV1 {
                schema: 1,
                mode: "readiness".into(),
                target: target.clone(),
                definition_digest,
                result_digest: Digest::of_bytes(bytes.as_bytes()).to_hex(),
                install_executed: false,
                probe_executed: false,
                verified: true,
            })
        }
    }
}

#[derive(Debug)]
struct OwnedCandidateOutputPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl OwnedCandidateOutputPath {
    fn capture(path: &Path, metadata: &fs::Metadata) -> Self {
        Self {
            path: path.to_path_buf(),
            device: device_of(metadata),
            inode: inode_of(metadata),
        }
    }

    fn remove_if_owned(&self) -> Result<(), String> {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("cannot inspect owned Build output: {error}")),
            Ok(metadata)
                if !metadata.file_type().is_symlink()
                    && metadata.is_file()
                    && device_of(&metadata) == self.device
                    && inode_of(&metadata) == self.inode =>
            {
                fs::remove_file(&self.path)
                    .map_err(|error| format!("cannot remove owned Build output: {error}"))
            }
            Ok(_) => Err("owned Build output path was concurrently replaced; preserving it".into()),
        }
    }
}

/// Runtime ownership of one candidate-ID-versioned Build artifact. The file is
/// deleted on an uncommitted transaction only when its exact device/inode still
/// occupy the owned path; a replacement is always preserved.
#[derive(Debug)]
pub struct OwnedCandidateBuildOutput {
    output: BuildOutputV1,
    directory: PathBuf,
    directory_device: u64,
    directory_inode: u64,
    directory_file: File,
    temporary: Option<OwnedCandidateOutputPath>,
    published: Option<OwnedCandidateOutputPath>,
    armed: bool,
    lock: CandidateOutputLock,
}

impl OwnedCandidateBuildOutput {
    /// Exact typed descriptor recorded by the candidate profile.
    pub fn output(&self) -> &BuildOutputV1 {
        &self.output
    }

    /// Descriptor-reopen the exact versioned path and require every recorded
    /// identity/contract field to remain unchanged.
    pub fn revalidate(&self, root: &Path) -> Result<(), String> {
        self.lock.revalidate(root)?;
        let descriptor = self
            .directory_file
            .metadata()
            .map_err(|error| format!("cannot recheck candidate output directory fd: {error}"))?;
        let named = fs::symlink_metadata(&self.directory)
            .map_err(|error| format!("cannot recheck candidate output directory: {error}"))?;
        if device_of(&descriptor) != self.directory_device
            || inode_of(&descriptor) != self.directory_inode
            || device_of(&named) != self.directory_device
            || inode_of(&named) != self.directory_inode
        {
            return Err("candidate output directory identity changed".into());
        }
        let observed = capture_recorded_build_output(root, &self.output)?;
        if observed != self.output {
            return Err("candidate-bound Build output changed after export".into());
        }
        Ok(())
    }

    /// Whether any directory entry currently occupies the versioned artifact
    /// name. Used to keep candidate/output preservation symmetric when cleanup
    /// cannot prove that entry is still ours.
    pub fn destination_exists(&self) -> bool {
        Path::new(&self.output.path)
            .file_name()
            .is_some_and(|leaf| fs::symlink_metadata(self.directory.join(leaf)).is_ok())
    }

    /// Remove only the exact owned file and then the exact now-empty candidate
    /// directory. Concurrent replacements or additions are preserved.
    pub fn cleanup(&mut self) -> Result<(), String> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        let mut errors = Vec::new();
        if let Some(path) = self.published.take() {
            if let Err(error) = path.remove_if_owned() {
                errors.push(error);
            }
        }
        if let Some(path) = self.temporary.take() {
            if let Err(error) = path.remove_if_owned() {
                errors.push(error);
            }
        }
        match fs::symlink_metadata(&self.directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!(
                "cannot inspect candidate output directory: {error}"
            )),
            Ok(metadata)
                if !metadata.file_type().is_symlink()
                    && metadata.is_dir()
                    && device_of(&metadata) == self.directory_device
                    && inode_of(&metadata) == self.directory_inode =>
            {
                match fs::remove_dir(&self.directory) {
                    Ok(()) => {
                        if let Some(parent) = self.directory.parent() {
                            if let Err(error) = sync_parent_directory(parent) {
                                errors.push(error);
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                    Err(error) => errors.push(format!(
                        "cannot remove owned candidate output directory: {error}"
                    )),
                }
            }
            Ok(_) => errors
                .push("candidate output directory was concurrently replaced; preserving it".into()),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Transfer file/directory lifetime to the durable ledger binding.
    pub fn retain(&mut self) {
        self.armed = false;
        self.temporary = None;
        self.published = None;
    }
}

impl Drop for OwnedCandidateBuildOutput {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("candidate-output-cleanup-blocked: {error}");
        }
    }
}

/// Candidate profile result plus runtime ownership of any exported artifact.
#[derive(Debug)]
pub struct CandidateProfileValidation {
    pub report: ValidationReport,
    pub build_output: Option<OwnedCandidateBuildOutput>,
}

#[derive(Debug)]
struct CandidateOutputLock {
    file: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    base_file: File,
    base_path: PathBuf,
    base_device: u64,
    base_inode: u64,
    locks_file: File,
    locks_path: PathBuf,
    locks_device: u64,
    locks_inode: u64,
}

impl CandidateOutputLock {
    fn revalidate(&self, root: &Path) -> Result<(), String> {
        for (file, path, device, inode, label) in [
            (
                &self.base_file,
                &self.base_path,
                self.base_device,
                self.base_inode,
                "base",
            ),
            (
                &self.locks_file,
                &self.locks_path,
                self.locks_device,
                self.locks_inode,
                "lock directory",
            ),
            (&self.file, &self.path, self.device, self.inode, "lock file"),
        ] {
            let descriptor = file
                .metadata()
                .map_err(|error| format!("cannot recheck candidate output {label}: {error}"))?;
            let named = fs::symlink_metadata(path)
                .map_err(|error| format!("cannot recheck candidate output {label}: {error}"))?;
            if device_of(&descriptor) != device
                || inode_of(&descriptor) != inode
                || device_of(&named) != device
                || inode_of(&named) != inode
            {
                return Err(format!("candidate output {label} identity changed"));
            }
        }
        #[cfg(unix)]
        {
            let owner = fs::metadata(root)
                .map_err(|error| format!("cannot inspect repository owner: {error}"))?
                .uid();
            for (directory, label) in [
                (&self.base_file, "base"),
                (&self.locks_file, "lock directory"),
            ] {
                let metadata = directory
                    .metadata()
                    .map_err(|error| format!("cannot inspect candidate output {label}: {error}"))?;
                if metadata.uid() != owner
                    || metadata.mode() & 0o777 != 0o700
                    || metadata.nlink() == 0
                {
                    return Err(format!(
                        "candidate output {label} owner/mode/link count changed"
                    ));
                }
            }
            let lock = self
                .file
                .metadata()
                .map_err(|error| format!("cannot inspect candidate output lock: {error}"))?;
            if lock.uid() != owner || lock.mode() & 0o777 != 0o600 || lock.nlink() != 1 {
                return Err("candidate output lock owner/mode/link count changed".into());
            }
        }
        Ok(())
    }
}

fn open_private_output_directory(
    root: &Path,
    path: &Path,
    crash_after_create: bool,
) -> Result<(File, fs::Metadata, bool), String> {
    #[cfg(unix)]
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(format!("cannot create private output directory: {error}")),
    };
    if created && crash_after_create {
        maybe_crash_candidate_output("directory-created");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|error| format!("cannot open private output directory: {error}"))?;
    let descriptor = file
        .metadata()
        .map_err(|error| format!("cannot inspect private output directory: {error}"))?;
    let named = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot recheck private output directory: {error}"))?;
    if descriptor.file_type().is_symlink()
        || !descriptor.is_dir()
        || named.file_type().is_symlink()
        || !named.is_dir()
        || device_of(&descriptor) != device_of(&named)
        || inode_of(&descriptor) != inode_of(&named)
    {
        return Err("private output directory identity is invalid".into());
    }
    #[cfg(unix)]
    {
        let owner = fs::metadata(root)
            .map_err(|error| format!("cannot inspect repository owner: {error}"))?
            .uid();
        if descriptor.uid() != owner
            || descriptor.mode() & 0o777 != 0o700
            || descriptor.nlink() == 0
            || descriptor.nlink() != named.nlink()
        {
            return Err("private output directory owner/mode/link count is invalid".into());
        }
    }
    Ok((file, descriptor, created))
}

fn acquire_candidate_output_lock(
    root: &Path,
    candidate_id: &str,
) -> Result<CandidateOutputLock, String> {
    let base = root.join(".mpd/build-output");
    let (base_file, base_metadata, _) = open_private_output_directory(root, &base, false)?;
    let locks = base.join(".locks");
    let (locks_file, locks_metadata, _) = open_private_output_directory(root, &locks, false)?;
    let path = locks.join(format!("{candidate_id}.lock"));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options
        .open(&path)
        .map_err(|error| format!("cannot open candidate output lock: {error}"))?;
    file.lock()
        .map_err(|error| format!("cannot lock candidate output: {error}"))?;
    let descriptor = file
        .metadata()
        .map_err(|error| format!("cannot inspect candidate output lock: {error}"))?;
    let named = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot recheck candidate output lock: {error}"))?;
    if descriptor.file_type().is_symlink()
        || !descriptor.is_file()
        || named.file_type().is_symlink()
        || !named.is_file()
        || device_of(&descriptor) != device_of(&named)
        || inode_of(&descriptor) != inode_of(&named)
    {
        return Err("candidate output lock identity changed".into());
    }
    #[cfg(unix)]
    {
        let owner = fs::metadata(root)
            .map_err(|error| format!("cannot inspect repository owner: {error}"))?
            .uid();
        if descriptor.uid() != owner
            || descriptor.nlink() != 1
            || descriptor.mode() & 0o777 != 0o600
        {
            return Err("candidate output lock owner/mode/link count is invalid".into());
        }
    }
    Ok(CandidateOutputLock {
        file,
        path,
        device: device_of(&descriptor),
        inode: inode_of(&descriptor),
        base_file,
        base_path: base,
        base_device: device_of(&base_metadata),
        base_inode: inode_of(&base_metadata),
        locks_file,
        locks_path: locks,
        locks_device: device_of(&locks_metadata),
        locks_inode: inode_of(&locks_metadata),
    })
}

fn candidate_output_ledger_bound(
    root: &Path,
    change: &str,
    candidate_id: &str,
    relative: &str,
) -> Result<bool, String> {
    let state = crate::ledger::state_path(root, change);
    match fs::symlink_metadata(&state) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect candidate ledger binding: {error}")),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("candidate ledger binding is not a regular file".into())
        }
        Ok(_) => {}
    }
    let ledger = crate::ledger::load(root, change)
        .map_err(|error| format!("cannot verify candidate ledger binding: {error}"))?;
    // D2: only the authoritative `gates` map (latest verdict per phase) can
    // bind an output. `history` is an append-only audit trail — a phase that
    // has been rewound by `invalidate_for_freshness` leaves its superseded
    // records in `history` only, and those records legitimately carry
    // `candidate` (every candidate gate attaches it) without `build_output`
    // (only a passing Build ever attaches that). Treating a candidate-
    // carrying-but-output-less record as a binding — or consulting `history`
    // at all — is exactly what permanently poisoned re-export after a
    // freshness rewind; see design.md D2.
    let mut bound = false;
    for record in ledger.gates.values() {
        let Some(output) = record.build_output.as_ref() else {
            continue;
        };
        if output.candidate_id.as_deref() != Some(candidate_id) {
            continue;
        }
        if output.path != relative {
            return Err("candidate ledger binding points at a different output path".into());
        }
        bound = true;
    }
    Ok(bound)
}

fn candidate_output_matches_source(
    root: &Path,
    relative: &str,
    source_size: u64,
    source_sha256: &str,
    contract: &BuildOutputConfig,
    candidate_id: &str,
) -> Result<BuildOutputV1, String> {
    let mut output = capture_build_output(root, relative)?;
    if output.size != source_size
        || output.mode != contract.required_mode
        || output.sha256 != source_sha256
        || output.size > contract.max_bytes
    {
        return Err("existing candidate output differs from the exact runtime artifact".into());
    }
    output.name = contract.name.clone();
    output.max_bytes = contract.max_bytes;
    output.required_mode = contract.required_mode;
    output.candidate_id = Some(candidate_id.to_string());
    Ok(output)
}

fn verify_preexisting_candidate_output(
    path: &Path,
    source_size: u64,
    source_sha256: &str,
    contract: &BuildOutputConfig,
) -> Result<(File, fs::Metadata), String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect preexisting candidate output: {error}"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err("preexisting candidate output is not a regular file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|error| format!("cannot open preexisting candidate output: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened candidate output: {error}"))?;
    let digest = hash_open_file(
        file.try_clone()
            .map_err(|error| format!("cannot retain proven candidate output: {error}"))?,
    )?;
    if !same_file_identity(&before, &opened)
        || opened.len() != source_size
        || mode_of(&opened) != contract.required_mode
        || opened.len() > contract.max_bytes
        || digest != source_sha256
    {
        return Err("preexisting candidate output differs from the opened runtime artifact".into());
    }
    Ok((file, opened))
}

fn same_file_identity_strict(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    if !same_file_identity(before, after) {
        return false;
    }
    #[cfg(unix)]
    {
        before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
fn inject_candidate_proof_to_arm_race(root: &Path, destination: &Path) -> Result<(), String> {
    if take_candidate_output_failure(root, 5) {
        let displaced = destination.with_extension("proof-original");
        fs::rename(destination, &displaced)
            .map_err(|error| format!("test destination replacement failed: {error}"))?;
        fs::write(destination, b"proof-to-arm replacement\n")
            .map_err(|error| format!("test destination replacement failed: {error}"))?;
    } else if take_candidate_output_failure(root, 6) {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let displaced = destination.with_extension("aba-original");
        fs::rename(destination, &displaced)
            .map_err(|error| format!("test destination ABA failed: {error}"))?;
        fs::write(destination, b"transient ABA replacement\n")
            .map_err(|error| format!("test destination ABA failed: {error}"))?;
        fs::remove_file(destination)
            .map_err(|error| format!("test destination ABA failed: {error}"))?;
        fs::rename(&displaced, destination)
            .map_err(|error| format!("test destination ABA failed: {error}"))?;
        #[cfg(unix)]
        {
            fs::set_permissions(destination, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("test destination ABA failed: {error}"))?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o644))
                .map_err(|error| format!("test destination ABA failed: {error}"))?;
        }
    }
    Ok(())
}

fn export_candidate_runtime_build_output(
    root: &Path,
    source: &Path,
    contract: &BuildOutputConfig,
    candidate_id: &str,
    change: &str,
) -> Result<OwnedCandidateBuildOutput, String> {
    Digest::from_hex(candidate_id)
        .map_err(|_| "candidate Build output requires a canonical candidate ID")?;
    let leaf = Path::new(&contract.path)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or("candidate Build output contract has no UTF-8 artifact name")?;
    let relative = format!(".mpd/build-output/{candidate_id}/{leaf}");
    let destination = contained_regular_path(root, &relative)?;
    let base = root.join(".mpd/build-output");
    let output_lock = acquire_candidate_output_lock(root, candidate_id)?;
    let base_metadata = fs::symlink_metadata(&base)
        .map_err(|error| format!("cannot inspect candidate Build output base: {error}"))?;
    if base_metadata.file_type().is_symlink() || !base_metadata.is_dir() {
        return Err("candidate Build output base is not a no-follow directory".into());
    }
    let directory = destination
        .parent()
        .ok_or("candidate Build output has no parent")?;
    if candidate_output_ledger_bound(root, change, candidate_id, &relative)? {
        return Err("candidate Build output is already bound by a durable ledger event".into());
    }
    let (directory_file, directory_metadata, _directory_created) =
        open_private_output_directory(root, directory, true)?;
    let temporary = directory.join(format!(".{leaf}.mpd-stage-v1"));
    let placeholder = BuildOutputV1 {
        schema: BUILD_OUTPUT_SCHEMA,
        name: contract.name.clone(),
        path: relative.clone(),
        max_bytes: contract.max_bytes,
        required_mode: contract.required_mode,
        size: 0,
        mode: 0,
        device: 0,
        inode: 0,
        sha256: String::new(),
        candidate_id: Some(candidate_id.to_string()),
    };
    let mut owned = OwnedCandidateBuildOutput {
        output: placeholder,
        directory: directory.to_path_buf(),
        directory_device: device_of(&directory_metadata),
        directory_inode: inode_of(&directory_metadata),
        directory_file,
        temporary: None,
        published: None,
        armed: true,
        lock: output_lock,
    };
    // The mode-0700 mkdir and no-follow descriptor binding are complete before
    // any subsequent fallible work. A crash immediately after mkdir is safely
    // inventoried by the next lock holder.
    #[cfg(test)]
    if take_candidate_output_failure(root, 2) {
        return Err("injected candidate output failure after directory creation".into());
    }
    let source_before = fs::symlink_metadata(source)
        .map_err(|error| format!("release build produced no typed artifact: {error}"))?;
    if source_before.file_type().is_symlink() || !source_before.is_file() {
        return Err("release build artifact is not a regular file".into());
    }
    #[cfg(unix)]
    if source_before.nlink() != 1 {
        return Err("release build artifact must have exactly one link".into());
    }
    let mut input_options = OpenOptions::new();
    input_options.read(true);
    #[cfg(unix)]
    input_options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let mut input = input_options
        .open(source)
        .map_err(|error| format!("cannot reopen release Build artifact: {error}"))?;
    let opened = input
        .metadata()
        .map_err(|error| format!("cannot inspect opened release Build artifact: {error}"))?;
    if !same_file_identity(&source_before, &opened) {
        return Err("release Build artifact changed while it was opened".into());
    }
    let source_sha256 =
        hash_open_file(input.try_clone().map_err(|error| {
            format!("cannot clone candidate Build source descriptor: {error}")
        })?)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind candidate Build source descriptor: {error}"))?;
    let source_size = opened.len();
    #[cfg(test)]
    if take_candidate_output_failure(root, 4) {
        let displaced = source.with_extension("descriptor-observed");
        fs::rename(source, &displaced)
            .map_err(|error| format!("test source replacement failed: {error}"))?;
        fs::write(source, b"replacement-after-source-open\n")
            .map_err(|error| format!("test source replacement failed: {error}"))?;
    }
    let temporary_relative = format!(".mpd/build-output/{candidate_id}/.{leaf}.mpd-stage-v1");
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot inventory candidate Build output directory: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inventory candidate Build output entry: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    let preexisting_entries = !entries.is_empty();
    for entry in &entries {
        let path = entry.path();
        if path != destination && path != temporary {
            return Err("candidate Build output directory contains a foreign entry".into());
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect candidate Build output entry: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("candidate Build output directory contains a non-regular entry".into());
        }
    }
    if destination.exists() {
        let published_before = fs::symlink_metadata(&destination)
            .map_err(|error| format!("cannot inspect adoptable candidate output: {error}"))?;
        let staged_before = if temporary.exists() {
            let metadata = fs::symlink_metadata(&temporary)
                .map_err(|error| format!("cannot inspect adoptable staging output: {error}"))?;
            if device_of(&metadata) != device_of(&published_before)
                || inode_of(&metadata) != inode_of(&published_before)
            {
                return Err("candidate output and staging orphan have different identities".into());
            }
            Some(metadata)
        } else {
            None
        };
        let (_proven_file, proven_metadata) = verify_preexisting_candidate_output(
            &destination,
            source_size,
            &source_sha256,
            contract,
        )?;
        #[cfg(test)]
        inject_candidate_proof_to_arm_race(root, &destination)?;
        let published_after = fs::symlink_metadata(&destination)
            .map_err(|_| "candidate output pathname changed after content proof")?;
        if !same_file_identity_strict(&proven_metadata, &published_after)
            || !same_file_identity_strict(&published_before, &published_after)
        {
            return Err("candidate output pathname identity changed after content proof".into());
        }
        if let Some(staged_before) = staged_before {
            let staged_after = fs::symlink_metadata(&temporary)
                .map_err(|_| "candidate staging pathname changed after content proof")?;
            if !same_file_identity_strict(&staged_before, &staged_after)
                || device_of(&staged_after) != device_of(&published_after)
                || inode_of(&staged_after) != inode_of(&published_after)
            {
                return Err(
                    "candidate output and staging identities changed after content proof".into(),
                );
            }
            // The destination descriptor remains open through the final path
            // checks. Cleanup authority is armed only from its proven identity.
            owned.published = Some(OwnedCandidateOutputPath::capture(
                &destination,
                &proven_metadata,
            ));
            owned.temporary = Some(OwnedCandidateOutputPath::capture(
                &temporary,
                &proven_metadata,
            ));
            owned
                .temporary
                .as_ref()
                .expect("adoptable staging output is armed")
                .remove_if_owned()?;
            owned.temporary = None;
            sync_parent_directory(directory)?;
        } else {
            owned.published = Some(OwnedCandidateOutputPath::capture(
                &destination,
                &proven_metadata,
            ));
        }
        owned.output = candidate_output_matches_source(
            root,
            &relative,
            source_size,
            &source_sha256,
            contract,
            candidate_id,
        )?;
        let source_after = fs::symlink_metadata(source)
            .map_err(|_| "release Build artifact disappeared during adoption")?;
        if !same_file_identity(&source_before, &source_after) {
            owned.retain();
            return Err("release Build artifact changed during adoption".into());
        }
        owned.revalidate(root)?;
        return Ok(owned);
    }
    if temporary.exists() {
        let _ = candidate_output_matches_source(
            root,
            &temporary_relative,
            source_size,
            &source_sha256,
            contract,
            candidate_id,
        )?;
        let staged_metadata = fs::symlink_metadata(&temporary)
            .map_err(|error| format!("cannot inspect adoptable candidate staging: {error}"))?;
        owned.temporary = Some(OwnedCandidateOutputPath::capture(
            &temporary,
            &staged_metadata,
        ));
        fs::hard_link(&temporary, &destination).map_err(|error| {
            format!("cannot finish candidate Build artifact publication: {error}")
        })?;
        // Arm from the already-opened/proven staged inode immediately after
        // link, before any fallible path metadata or identity operation.
        owned.published = Some(OwnedCandidateOutputPath {
            path: destination.clone(),
            device: device_of(&staged_metadata),
            inode: inode_of(&staged_metadata),
        });
    }
    if owned.temporary.is_none() {
        let mut target_options = OpenOptions::new();
        target_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            target_options.mode(0o600);
            target_options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        }
        let mut target = target_options
            .open(&temporary)
            .map_err(|error| format!("cannot create candidate Build staging file: {error}"))?;
        let temporary_metadata = target
            .metadata()
            .map_err(|error| format!("cannot inspect candidate Build staging file: {error}"))?;
        owned.temporary = Some(OwnedCandidateOutputPath::capture(
            &temporary,
            &temporary_metadata,
        ));
        let copied = std::io::copy(
            &mut input.take(contract.max_bytes.saturating_add(1)),
            &mut target,
        )
        .map_err(|error| format!("cannot copy candidate Build artifact: {error}"))?;
        if copied > contract.max_bytes {
            return Err("candidate Build artifact exceeds configured max_bytes".into());
        }
        #[cfg(unix)]
        target
            .set_permissions(fs::Permissions::from_mode(contract.required_mode))
            .map_err(|error| format!("cannot set candidate Build artifact mode: {error}"))?;
        target
            .sync_all()
            .map_err(|error| format!("cannot sync candidate Build artifact: {error}"))?;
        drop(target);
    }
    let source_after = fs::symlink_metadata(source)
        .map_err(|_| "release Build artifact disappeared during export")?;
    if !same_file_identity(&source_before, &source_after) {
        return Err("release Build artifact changed during export".into());
    }
    if owned.published.is_none() && fs::symlink_metadata(&destination).is_ok() {
        return Err("candidate Build output destination already exists".into());
    }
    let staged_metadata = fs::symlink_metadata(&temporary)
        .map_err(|error| format!("cannot recheck candidate Build staging file: {error}"))?;
    if owned.published.is_none() {
        fs::hard_link(&temporary, &destination).map_err(|error| {
            format!("cannot publish candidate Build artifact no-clobber: {error}")
        })?;
        // The staged inode is already proven; arm cleanup immediately after
        // the namespace mutation, before any fallible destination lookup.
        owned.published = Some(OwnedCandidateOutputPath {
            path: destination.clone(),
            device: device_of(&staged_metadata),
            inode: inode_of(&staged_metadata),
        });
    }
    maybe_crash_candidate_output("hard-link-published");
    #[cfg(test)]
    if take_candidate_output_failure(root, 1) {
        return Err("injected candidate output failure after link before staging unlink".into());
    }
    let published_metadata = fs::symlink_metadata(&destination)
        .map_err(|error| format!("cannot inspect published candidate Build artifact: {error}"))?;
    if device_of(&staged_metadata) != device_of(&published_metadata)
        || inode_of(&staged_metadata) != inode_of(&published_metadata)
        || staged_metadata.len() != published_metadata.len()
        || mode_of(&staged_metadata) != mode_of(&published_metadata)
    {
        return Err("published candidate Build artifact differs from staging identity".into());
    }
    owned
        .temporary
        .as_ref()
        .expect("candidate staging ownership is armed")
        .remove_if_owned()?;
    owned.temporary = None;
    maybe_crash_candidate_output("staging-unlinked");
    #[cfg(test)]
    if take_candidate_output_failure(root, 3) {
        return Err("injected candidate output failure after staging unlink".into());
    }
    sync_parent_directory(directory)?;
    let mut output = capture_build_output(root, &relative)?;
    if output.size > contract.max_bytes || output.mode != contract.required_mode {
        return Err("candidate Build output violates its size/mode contract".into());
    }
    output.name = contract.name.clone();
    output.max_bytes = contract.max_bytes;
    output.required_mode = contract.required_mode;
    output.candidate_id = Some(candidate_id.to_string());
    owned.output = output;
    owned.revalidate(root)?;
    let source_final = fs::symlink_metadata(source)
        .map_err(|_| "release Build artifact disappeared before export completion")?;
    if !same_file_identity(&source_before, &source_final) {
        if preexisting_entries {
            owned.retain();
        }
        return Err("release Build artifact changed before export completion".into());
    }
    Ok(owned)
}

fn export_runtime_build_output(
    root: &Path,
    source: &Path,
    contract: &BuildOutputConfig,
) -> Result<BuildOutputV1, String> {
    let source_meta = fs::symlink_metadata(source)
        .map_err(|e| format!("release build produced no typed artifact: {e}"))?;
    if source_meta.file_type().is_symlink() || !source_meta.is_file() {
        return Err("release build artifact is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if source_meta.nlink() != 1 {
            return Err("release build artifact must have exactly one link".into());
        }
    }
    let destination = contained_regular_path(root, &contract.path)?;
    let parent = destination
        .parent()
        .ok_or("typed Build destination has no parent")?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create typed Build destination: {e}"))?;
    let destination_before = safe_replaceable_file_identity(&destination)?;
    let temporary = parent.join(format!(
        ".mpd-build-output-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut target = options
        .open(&temporary)
        .map_err(|e| format!("cannot create typed Build temporary: {e}"))?;
    let mut temp_guard = OwnedTempFile::capture(&temporary, &target)?;
    let mut input_options = OpenOptions::new();
    input_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        input_options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut input = input_options
        .open(source)
        .map_err(|e| format!("cannot reopen release Build artifact: {e}"))?;
    let opened_meta = input
        .metadata()
        .map_err(|e| format!("cannot inspect opened release Build artifact: {e}"))?;
    if !same_file_identity(&source_meta, &opened_meta) {
        return Err("release Build artifact changed while it was opened".into());
    }
    std::io::copy(&mut input, &mut target)
        .map_err(|e| format!("cannot copy release Build artifact: {e}"))?;
    target
        .sync_all()
        .map_err(|e| format!("cannot sync release Build artifact: {e}"))?;
    drop(target);
    temp_guard.verify()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &temporary,
            fs::Permissions::from_mode(source_meta.permissions().mode() & 0o7777),
        )
        .map_err(|e| format!("cannot set typed Build artifact mode: {e}"))?;
    }
    let source_parent = source
        .parent()
        .ok_or("release Build artifact has no parent")?;
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("release Build artifact has no UTF-8 filename")?;
    let staged_name = temporary
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("typed Build temporary has no UTF-8 filename")?;
    let source_identity = capture_build_output(source_parent, source_name)?;
    let staged_identity = capture_build_output(parent, staged_name)?;
    if source_identity.size != staged_identity.size
        || source_identity.mode != staged_identity.mode
        || source_identity.sha256 != staged_identity.sha256
    {
        return Err("typed Build temporary differs from release artifact".into());
    }
    let after = fs::symlink_metadata(source)
        .map_err(|e| format!("cannot recheck release Build artifact: {e}"))?;
    if !same_file_identity(&source_meta, &after) {
        return Err("release Build artifact changed during export".into());
    }
    if safe_replaceable_file_identity(&destination)? != destination_before {
        return Err("typed Build destination changed before atomic replacement".into());
    }
    fs::rename(&temporary, &destination)
        .map_err(|e| format!("cannot publish typed Build artifact atomically: {e}"))?;
    temp_guard.disarm();
    sync_parent_directory(parent)?;
    let after = fs::symlink_metadata(source)
        .map_err(|e| format!("cannot recheck release Build artifact: {e}"))?;
    if !same_file_identity(&source_meta, &after) {
        return Err("release Build artifact changed during export".into());
    }
    capture_configured_build_output(root, contract)
}

fn sync_parent_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("cannot sync artifact parent directory: {e}"))
}

fn same_file_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mode() == after.mode()
            && before.nlink() == after.nlink()
    }
    #[cfg(not(unix))]
    {
        before.len() == after.len() && before.permissions() == after.permissions()
    }
}

fn contained_regular_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("artifact path must be a contained relative file path".into());
    }
    let joined = root.join(path);
    openspec_core::assert_contained(root, &joined)
        .map_err(|e| format!("unsafe artifact path: {e}"))?;
    Ok(joined)
}

fn hash_open_file(mut file: fs::File) -> Result<String, String> {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    let mut remaining = MAX_BUILD_OUTPUT_BYTES;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot read opened artifact: {e}"))?;
        if read == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(read as u64)
            .ok_or("build artifact exceeds cap")?;
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn mode_of(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

fn device_of(metadata: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.dev()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

fn inode_of(metadata: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

/// Exact, reviewable first-adoption checkpoint inventory. The enum is closed
/// so a missing target is distinguishable from a reviewed deletion tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
pub struct CheckpointScopeV1 {
    pub schema: u32,
    pub change: String,
    pub manifest_digest: String,
    pub recorded_base_oid: String,
    pub recorded_branch_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_upstream_oid: Option<String>,
    pub entries: Vec<CheckpointEntryV1>,
    pub aggregate_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
#[cfg(test)]
pub enum CheckpointEntryV1 {
    Present {
        path: String,
        mode: u32,
        blob_oid: String,
    },
    Deleted {
        path: String,
        base_mode: u32,
        base_blob_oid: String,
    },
}

#[cfg(test)]
impl CheckpointEntryV1 {
    fn path(&self) -> &str {
        match self {
            Self::Present { path, .. } | Self::Deleted { path, .. } => path,
        }
    }
}

/// Resolve only the bounded first-adoption union. It is read-only: it does not
/// stage, run validation checks, invoke a candidate command, or write Git
/// state. The caller may display the returned exact argv path vector for an
/// owner to stage with direct `git add --` later.
#[cfg(test)]
pub fn prepare_checkpoint_scope(
    root: &Path,
    change: &str,
    base: &str,
    branch: &str,
    upstream: Option<&str>,
) -> Result<CheckpointScopeV1, String> {
    prepare_checkpoint_scope_at_head(root, change, base, branch, upstream, base)
}

#[cfg(test)]
fn prepare_checkpoint_scope_at_head(
    root: &Path,
    change: &str,
    base: &str,
    branch: &str,
    upstream: Option<&str>,
    expected_head: &str,
) -> Result<CheckpointScopeV1, String> {
    openspec_core::validate_change_name(change)?;
    validate_oid(base)?;
    if branch.is_empty() || branch.len() > 512 || branch.chars().any(char::is_control) {
        return Err("unsafe checkpoint branch ref".into());
    }
    let observed_head = git_output(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if observed_head != expected_head {
        return Err("first-adoption-base-moved".into());
    }
    let observed_branch = git_optional(root, &["symbolic-ref", "--quiet", "HEAD"])?
        .ok_or("first-adoption requires a symbolic branch HEAD")?;
    if observed_branch != branch {
        return Err("first-adoption-branch-moved".into());
    }
    let observed_upstream = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", "@{upstream}^{commit}"],
    )?;
    match (upstream, observed_upstream.as_deref()) {
        (Some(expected), Some(observed)) => {
            validate_oid(expected)?;
            if expected != observed {
                return Err("first-adoption-upstream-moved".into());
            }
        }
        (None, None) => {}
        _ => return Err("first-adoption-upstream-state-changed".into()),
    }
    if git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?
    .is_some()
    {
        return Err("first-adoption-already-initialized".into());
    }
    let staged = canonical_git(root, &["diff", "--cached", "--quiet", "--exit-code"], 0)?;
    if !staged.success {
        return Err("first-adoption-index-not-empty".into());
    }
    let manifest = crate::closure::load_manifest(root, change).map_err(|e| e.to_string())?;
    if !manifest.is_ready() {
        return Err("first-adoption checkpoint requires a ready manifest".into());
    }
    let manifest_path = crate::closure::manifest_path(root, change).map_err(|e| e.to_string())?;
    let manifest_digest = Digest::of_bytes(
        &fs::read(&manifest_path).map_err(|e| format!("cannot read manifest: {e}"))?,
    )
    .to_hex();
    let mut paths = BTreeSet::new();
    collect_regular_files(root, &format!("openspec/changes/{change}"), &mut paths)?;
    paths.insert(format!(".mpd/state/{change}.json"));
    let mut changed_paths = git_name_list(root, &["diff", "--name-only", "-z", base, "--"])?;
    changed_paths.extend(git_name_list(
        root,
        &["ls-files", "--others", "--exclude-standard", "-z", "--"],
    )?);
    for path in changed_paths {
        // System paths are always in the exact union; every other changed path
        // must be explicitly declared in the reviewed manifest.
        let system = crate::closure::SystemScope {
            change_dir: format!("openspec/changes/{change}"),
            ledger_path: format!(".mpd/state/{change}.json"),
            merged_spec_targets: vec![],
            doc_target: None,
            archive_target: String::new(),
        };
        if !manifest.covers(&path, &system) {
            return Err(format!("first-adoption-surprise-path: {path}"));
        }
        paths.insert(path);
    }
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let target = root.join(&path);
        if target.exists() {
            let meta = fs::symlink_metadata(&target)
                .map_err(|e| format!("cannot inspect checkpoint path {path}: {e}"))?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(format!("checkpoint path is not a regular file: {path}"));
            }
            let oid = git_hash_file(root, &target)?;
            entries.push(CheckpointEntryV1::Present {
                path,
                mode: mode_of(&meta),
                blob_oid: oid,
            });
        } else {
            let (mode, oid) = base_tree_entry(root, base, &path)?.ok_or_else(|| {
                format!("declared Present is absent or deletion has no base entry: {path}")
            })?;
            entries.push(CheckpointEntryV1::Deleted {
                path,
                base_mode: mode,
                base_blob_oid: oid,
            });
        }
    }
    entries.sort_by(|a, b| a.path().as_bytes().cmp(b.path().as_bytes()));
    let scope = CheckpointScopeV1 {
        schema: 1,
        change: change.to_string(),
        manifest_digest,
        recorded_base_oid: base.to_string(),
        recorded_branch_ref: branch.to_string(),
        recorded_upstream_oid: upstream.map(str::to_string),
        entries,
        aggregate_digest: String::new(),
    };
    let mut digestable = scope.clone();
    digestable.aggregate_digest.clear();
    let mut result = scope;
    result.aggregate_digest =
        Digest::of_bytes(&serde_json::to_vec(&digestable).map_err(|e| e.to_string())?).to_hex();
    Ok(result)
}

#[cfg(test)]
fn collect_regular_files(
    root: &Path,
    relative: &str,
    paths: &mut BTreeSet<String>,
) -> Result<(), String> {
    let dir = root.join(relative);
    let meta = fs::symlink_metadata(&dir)
        .map_err(|e| format!("missing protected change directory: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("protected change directory is unsafe".into());
    }
    for entry in fs::read_dir(&dir)
        .map_err(|e| format!("cannot enumerate protected change directory: {e}"))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF-8 protected path")?;
        let child = format!("{relative}/{name}");
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("symlink in checkpoint scope: {child}"));
        }
        if meta.is_dir() {
            collect_regular_files(root, &child, paths)?;
        } else if meta.is_file() {
            paths.insert(child);
        } else {
            return Err(format!("unsupported checkpoint entry: {child}"));
        }
    }
    Ok(())
}

#[cfg(test)]
fn git_name_list(root: &Path, args: &[&str]) -> Result<Vec<String>, String> {
    let result = canonical_git(root, args, 16 * 1024 * 1024)?;
    if !result.success {
        return Err("cannot enumerate checkpoint diff".into());
    }
    let paths = result
        .stdout
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .map(|v| {
            std::str::from_utf8(v)
                .map(str::to_string)
                .map_err(|_| "non-UTF-8 checkpoint path".into())
        })
        .collect::<Result<Vec<_>, String>>()?;
    if paths.len() > 100_000 {
        return Err("checkpoint path enumeration exceeds its cap".into());
    }
    Ok(paths)
}

#[cfg(test)]
fn git_hash_file(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "checkpoint path escaped root")?
        .to_str()
        .ok_or("non-UTF-8 checkpoint path")?;
    let output = canonical_git(root, &["hash-object", "--no-filters", "--", relative], 1024)?;
    if !output.success {
        return Err("cannot hash checkpoint path".into());
    }
    let oid = String::from_utf8(output.stdout)
        .map_err(|_| "non-UTF-8 blob oid")?
        .trim()
        .to_string();
    validate_oid(&oid)?;
    Ok(oid)
}

#[cfg(test)]
fn base_tree_entry(root: &Path, base: &str, path: &str) -> Result<Option<(u32, String)>, String> {
    let output = canonical_git(root, &["ls-tree", base, "--", path], 4096)?;
    if !output.success {
        return Err("cannot inspect checkpoint base tree".into());
    }
    if output.stdout.is_empty() {
        return Ok(None);
    }
    let line = String::from_utf8(output.stdout).map_err(|_| "non-UTF-8 base tree entry")?;
    let mut fields = line.split_whitespace();
    let mode = u32::from_str_radix(fields.next().ok_or("malformed base tree mode")?, 8)
        .map_err(|_| "malformed base tree mode")?;
    let kind = fields.next().ok_or("malformed base tree kind")?;
    let oid = fields.next().ok_or("malformed base tree oid")?.to_string();
    if kind != "blob" || !matches!(mode, 0o100644 | 0o100755) {
        return Err("checkpoint base entry is not a regular blob".into());
    }
    validate_oid(&oid)?;
    Ok(Some((mode & 0o7777, oid)))
}

/// A closed, clone-local receipt.  The intentionally compact foundation binds
/// the values that make an execution reusable; raw output is private evidence,
/// never note content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReceiptV1 {
    pub schema: u32,
    pub id: String,
    pub subject: Subject,
    pub profile: String,
    pub config_digest: String,
    pub checks_digest: String,
    pub trusted_policy_oid: String,
    pub trusted_before_policy_digest: String,
    pub candidate_policy_digest: String,
    pub effective_policy_digest: String,
    pub sandbox: SandboxReceiptBindingV1,
    pub validation_contract_version: u32,
    pub validator_version: String,
    pub validator_digest: String,
    pub platform: PlatformReceiptBindingV1,
    pub toolchain: ToolchainReceiptBindingV1,
    pub cargo_lock_digest: String,
    pub advisory: AdvisoryReceiptBindingV1,
    pub tool_policy_digest: String,
    pub tool_digests: std::collections::BTreeMap<String, String>,
    pub results: Vec<ValidationCheckResult>,
    pub started_epoch_secs: u64,
    pub completed_epoch_secs: u64,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_output: Option<BuildOutputV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformReceiptBindingV1 {
    pub operating_system: String,
    pub architecture: String,
    pub cargo_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainReceiptBindingV1 {
    pub rust_release: String,
    pub host: Option<String>,
    pub components: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryReceiptBindingV1 {
    pub revision: String,
    pub tree: String,
    pub lock_digest: String,
    pub max_age_days: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxReceiptBindingV1 {
    pub contract_version: u32,
    pub adapter_digest: String,
    pub profile_digest: String,
    pub environment_keys: Vec<String>,
    pub certified_host: String,
    pub adapter_abi_digest: String,
    pub canary_contract_digest: String,
    pub residual_limitations: Vec<String>,
    pub run_request_digests: Vec<String>,
    pub run_authority_digests: Vec<String>,
    pub run_root_inventory_digests: Vec<String>,
    pub run_canary_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationCheckResult {
    pub name: String,
    pub kind: String,
    pub outcome: String,
    pub exit: Option<i32>,
    pub count: Option<u64>,
    pub duration_millis: u64,
    pub log_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationNoteEnvelopeV1 {
    schema: u32,
    receipts: std::collections::BTreeMap<String, ValidationReceiptV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateLogEntryV1 {
    file: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateRunManifestV1 {
    schema: u32,
    profile: String,
    subject: Subject,
    completed_epoch_secs: u64,
    logs: Vec<PrivateLogEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateRunInventoryEntryV1 {
    directory: String,
    manifest_sha256: String,
    log_count: usize,
    log_bytes: u64,
    completed_epoch_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateLogInventoryV1 {
    schema: u32,
    runs: Vec<PrivateRunInventoryEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub schema: u32,
    pub subject: Subject,
    pub profile: String,
    pub status: String,
    pub receipt: Option<ValidationReceiptV1>,
    pub blocker: Option<String>,
    pub counts: ValidationCountsV1,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationCountsV1 {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub blocked: usize,
    pub not_run: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub requested: String,
    pub pushed_oid: String,
    pub pushed_kind: String,
    pub tag_chain: Vec<TagChainEntryV1>,
    pub commit: String,
    pub tree: String,
}

impl Subject {
    fn attached_object_oid(&self) -> &str {
        &self.pushed_oid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagChainEntryV1 {
    pub oid: String,
    pub target_oid: String,
    pub target_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptState {
    Current,
    Stale,
    Missing,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptClassification {
    pub state: ReceiptState,
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ValidationReceiptV1>,
}

/// The read-only receipt observation used by `mpd doctor --scope runtime-health`.
/// It deliberately carries no process output and is produced only after the
/// current exact-HEAD policy, tool, cache, sandbox, and note bindings have been
/// rechecked.  In particular, it never starts a validation lane, installation,
/// Deploy, or identity child process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReceiptHealth {
    pub subject: Subject,
    pub receipt_id: String,
    pub profile: String,
    pub sandbox: SandboxReceiptBindingV1,
    pub results: Vec<ValidationCheckResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyPreflight {
    pub subject: Subject,
    pub candidate_policy_digest: String,
    pub trusted_policy_oid: Option<String>,
    pub trusted_policy_digest: Option<String>,
    pub blocker: Option<String>,
}

/// Parse-only self-check used inside an immutable materialized subject. It has
/// no Git/profile/tool entry point and therefore cannot recurse into validation.
pub fn static_policy_check(root: &Path) -> Result<(), String> {
    let config = crate::config::Config::load_strict(root)?;
    let local = config
        .local_validation
        .ok_or("structured local_validation is absent")?;
    local.validate()?;
    let tool_lock = openspec_core::read_contained_capped(
        root,
        &root.join("security/tool-lock.json"),
        4 * 1024 * 1024,
    )
    .map_err(|e| format!("tool lock is unavailable: {e}"))?;
    let tool_lock: serde_json::Value =
        serde_json::from_str(&tool_lock).map_err(|e| format!("tool lock is malformed: {e}"))?;
    if tool_lock["schema_version"] != 1
        || tool_lock["tools"]
            .as_array()
            .is_none_or(|tools| tools.is_empty())
    {
        return Err("tool lock schema or tool set is invalid".into());
    }
    let advisory = openspec_core::read_contained_capped(
        root,
        &root.join("security/advisory-db.lock.json"),
        1024 * 1024,
    )
    .map_err(|e| format!("advisory lock is unavailable: {e}"))?;
    let advisory: serde_json::Value =
        serde_json::from_str(&advisory).map_err(|e| format!("advisory lock is malformed: {e}"))?;
    let commit = advisory["commit"]
        .as_str()
        .ok_or("advisory lock commit is missing")?;
    let tree = advisory["git_tree_oid"]
        .as_str()
        .ok_or("advisory lock tree is missing")?;
    validate_oid(commit)?;
    validate_oid(tree)?;
    if commit != local.offline.advisory_revision || tree != local.offline.advisory_tree {
        return Err("advisory lock differs from typed offline revision/tree".into());
    }
    if advisory["max_age_days"].as_u64() != Some(local.offline.advisory_max_age_days) {
        return Err("advisory lock differs from typed offline freshness".into());
    }
    crate::digest::Digest::from_hex(
        advisory["tree_listing_sha256"]
            .as_str()
            .ok_or("advisory lock listing digest is missing")?,
    )?;
    let _ = digest_validation_assets(root)?;
    Ok(())
}

/// Verify the clone-private post-promotion activation state without modifying
/// refs, configuration, hooks, or the worktree.  This is intentionally a
/// smaller observation than first-adoption reconciliation: doctor needs to
/// prove the currently trusted direct object and active launcher bytes, not
/// replay an adoption transaction or execute candidate policy.
pub fn doctor_activation_health(root: &Path) -> Result<(), String> {
    let trusted_oid = trusted_policy_ref(root)?;
    let trusted = read_trusted_policy_bundle(root, &trusted_oid)?;
    let policy = trusted.object;
    let policy_digest =
        Digest::of_bytes(&serde_json::to_vec(&policy).map_err(|e| e.to_string())?).to_hex();
    let active_policy = crate::config::Config::load_strict(root)?
        .local_validation
        .ok_or("active structured local_validation is absent")?;
    if canonical_policy_bytes(&active_policy)? != canonical_policy_bytes(&policy.local_validation)?
    {
        return Err("active policy differs from the immutable reviewed policy config".into());
    }
    let active_assets = capture_candidate_policy_assets(root, root)?;
    if active_assets != trusted.assets {
        return Err(
            "active hook/tool/profile assets differ from the immutable reviewed policy".into(),
        );
    }
    let _ = sandbox_adapter(root)?;
    // Doctor remains read-only: absence is an activation blocker, never
    // permission to create clone-private state while reporting.
    let policy_dir = git_common_dir(root)?.join(POLICY_STATE_DIR);
    if let Ok(metadata) = fs::symlink_metadata(&policy_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("policy state directory is unsafe".into());
        }
    }
    let journal_path = policy_dir.join("activation-journal.json");
    let journal = read_activation_journal(&journal_path)?
        .ok_or("trusted policy is inactive: activation journal missing")?;
    if journal.stage != ActivationStageV1::VerifiedActive
        || journal.trusted_policy_oid != trusted_oid
        || journal.trusted_policy_digest != policy_digest
        || journal.reviewed_coordinator_digest != policy.coordinator_digest
    {
        return Err("trusted policy activation is incomplete or stale".into());
    }

    let hooks = fs::canonicalize(git_common_dir(root)?.join("mpd/trusted-hooks"))
        .map_err(|e| format!("trusted hook directory is unavailable: {e}"))?;
    let configured = git_optional(root, &["config", "--local", "--get", "core.hooksPath"])?
        .ok_or("trusted core.hooksPath is absent")?;
    if Path::new(&configured) != hooks {
        return Err(
            "trusted core.hooksPath does not name the clone-private hooks directory".into(),
        );
    }
    for name in ["mpd-coordinator", "pre-commit", "pre-push"] {
        let path = hooks.join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("active {name} is unavailable: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("active {name} is not a regular clone-private file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0
                || metadata.permissions().mode() & 0o100 == 0
            {
                return Err(format!("active {name} lacks owner-only executable mode"));
            }
        }
        let expected = journal
            .installed_path_digests
            .get(name)
            .ok_or_else(|| format!("activation journal omits active {name}"))?;
        if Digest::of_bytes(&fs::read(&path).map_err(|e| e.to_string())?).to_hex() != *expected {
            return Err(format!("active {name} bytes drifted"));
        }
    }
    if Digest::of_bytes(&fs::read(hooks.join("mpd-coordinator")).map_err(|e| e.to_string())?)
        .to_hex()
        != policy.coordinator_digest
    {
        return Err("active coordinator differs from the trusted policy digest".into());
    }
    Ok(())
}

/// Recheck the exact current required-profile receipt without running that
/// profile.  The same pure input-preflight helpers used by validation derive
/// the expected bindings, then `classify_receipt` checks the clone-local note.
pub fn doctor_runtime_receipt_health(
    root: &Path,
    config: &LocalValidationConfig,
    profile_name: &str,
) -> Result<DoctorReceiptHealth, String> {
    let preflight = preflight(root, Some("HEAD"), config)?;
    if let Some(blocker) = preflight.blocker {
        return Err(blocker);
    }
    let trusted_oid = preflight
        .trusted_policy_oid
        .ok_or("trusted-policy-missing")?;
    let trusted_digest = preflight
        .trusted_policy_digest
        .ok_or("trusted-policy-invalid")?;
    let exact = subject_local_validation(root, &preflight.subject)?;
    exact.validate()?;
    if profile_name != exact.gates.test && profile_name != exact.gates.high_risk_test {
        return Err("runtime-health profile is not a configured Test gate profile".into());
    }
    let checks = exact.effective_checks(profile_name)?;
    let supervisor = std::env::current_exe()
        .map_err(|e| format!("cannot resolve active MPD coordinator: {e}"))?;
    let cargo_home = git_common_dir(root)?.join("mpd/cargo-home");
    let inputs = preflight_profile_inputs(root, root, &checks, &exact, &supervisor, &cargo_home)?;
    let adapter = sandbox_adapter(root)?;
    let sandbox_inputs = sandbox_receipt_inputs(&adapter, &exact)?;
    let checks = serde_json::to_vec(&checks)
        .map_err(|e| format!("cannot encode required profile checks: {e}"))?;
    let policy_digest = Digest::of_bytes(&canonical_policy_bytes(&exact)?).to_hex();
    let expected = ValidationReceiptV1 {
        schema: VALIDATION_SCHEMA,
        id: String::new(),
        subject: preflight.subject.clone(),
        profile: profile_name.to_string(),
        config_digest: policy_digest.clone(),
        checks_digest: Digest::of_bytes(&checks).to_hex(),
        trusted_policy_oid: trusted_oid,
        trusted_before_policy_digest: trusted_digest,
        candidate_policy_digest: policy_digest.clone(),
        effective_policy_digest: policy_digest,
        sandbox: SandboxReceiptBindingV1 {
            contract_version: exact.sandbox.contract_version,
            adapter_digest: sandbox_identity(&adapter)?,
            profile_digest: sandbox_inputs.profile_digest,
            environment_keys: sandbox_inputs.environment_keys,
            certified_host: sandbox_inputs.certified_host,
            adapter_abi_digest: sandbox_inputs.adapter_abi_digest,
            canary_contract_digest: sandbox_inputs.canary_contract_digest,
            residual_limitations: sandbox_inputs.residual_limitations,
            run_request_digests: Vec::new(),
            run_authority_digests: Vec::new(),
            run_root_inventory_digests: Vec::new(),
            run_canary_digests: Vec::new(),
        },
        validation_contract_version: 1,
        validator_version: env!("CARGO_PKG_VERSION").into(),
        validator_digest: digest_file(&supervisor)?,
        platform: platform_receipt_binding(&exact),
        toolchain: toolchain_receipt_binding(&exact),
        cargo_lock_digest: inputs
            .digests
            .get("cargo-lock")
            .cloned()
            .ok_or("preflight omitted Cargo.lock digest")?,
        advisory: advisory_receipt_binding(
            &exact,
            inputs
                .digests
                .get("advisory-db")
                .cloned()
                .ok_or("preflight omitted advisory digest")?,
        ),
        tool_policy_digest: digest_json(&exact.tools)?,
        tool_digests: inputs.digests,
        results: Vec::new(),
        started_epoch_secs: 0,
        completed_epoch_secs: 0,
        outcome: "passed".into(),
        build_output: None,
    };
    let classified = classify_receipt(root, &expected);
    let receipt = match classified {
        ReceiptClassification {
            state: ReceiptState::Current,
            receipt: Some(receipt),
            ..
        } if receipt.outcome == "passed" => receipt,
        ReceiptClassification { state, reasons, .. } => {
            return Err(format!(
                "required exact-HEAD receipt is {state:?}: {}",
                reasons.join(", ")
            ))
        }
    };
    Ok(DoctorReceiptHealth {
        subject: preflight.subject,
        receipt_id: receipt.id.clone(),
        profile: profile_name.to_string(),
        sandbox: receipt.sandbox,
        results: receipt.results,
    })
}

/// Inspect every input the required profile would consume, but stop before the
/// first sandboxed child is created.  This proves locked tool paths/digests,
/// the clone-private offline Cargo cache, advisory checkout freshness, and the
/// mandatory sandbox contract without treating an executable command as a
/// doctor check.
pub fn doctor_static_validation_inputs(
    root: &Path,
    config: &LocalValidationConfig,
) -> Result<(), String> {
    config.validate()?;
    let checks = config.effective_checks(&config.gates.test)?;
    let supervisor = std::env::current_exe()
        .map_err(|e| format!("cannot resolve active MPD coordinator: {e}"))?;
    let cargo_home = git_common_dir(root)?.join("mpd/cargo-home");
    let _ = preflight_profile_inputs(root, root, &checks, config, &supervisor, &cargo_home)?;
    let adapter = sandbox_adapter(root)?;
    let _ = sandbox_receipt_inputs(&adapter, config)?;
    Ok(())
}

/// Ensure the validation notes ref remains a direct, readable, bounded codec.
/// Missing evidence is deliberately healthy for this static check: receipt
/// presence/freshness belongs only to runtime-health.
pub fn doctor_note_store_health(root: &Path, subject: &Subject) -> Result<(), String> {
    let _ = read_note_envelope(root, subject)?;
    Ok(())
}

/// Validate the owner-only private state layout without deleting stale files or
/// activating anything.  A doctor report must make leftover/log problems
/// visible while staying completely read-only.
pub fn doctor_private_state_health(root: &Path) -> Result<(), String> {
    let common = git_common_dir(root)?;
    let private = common.join("mpd");
    if !private.exists() {
        return Ok(());
    }
    let meta = fs::symlink_metadata(&private)
        .map_err(|e| format!("clone-private MPD state is unavailable: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("clone-private MPD state is unsafe".into());
    }
    for relative in ["validation", "validation/logs", "first-adoption"] {
        let path = private.join(relative);
        if !path.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("clone-private {relative} is unavailable: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("clone-private {relative} is unsafe"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(format!("clone-private {relative} is not owner-only"));
            }
        }
    }
    Ok(())
}

/// A no-checkout, blob-materialized view of one exact commit. The caller owns
/// removal; this function never invokes checkout, hooks, filters, submodules,
/// or a shell.
#[derive(Debug)]
pub struct MaterializedSubject {
    pub root: std::path::PathBuf,
    identity: OwnedTreeIdentity,
}

impl MaterializedSubject {
    /// Remove only the exact private tree created by `materialize_subject`.
    /// Candidate projection reuses this identity-bound cleanup rather than
    /// accepting an arbitrary serialized path as deletion authority.
    pub(crate) fn cleanup(self) -> Result<(), String> {
        remove_owned_tree(&self.root, &self.identity)
    }

    /// Reobserve the published pathname without following links and require
    /// that it still names the exact directory inode created by MPD.
    pub(crate) fn verify_identity(&self) -> Result<(), String> {
        self.identity.verify(&self.root)
    }

    /// Discard this invocation's staging tree and adopt a previously published
    /// candidate only after the caller has twice reinventoried that exact
    /// directory identity. This is the crash-retry seam; the pre-existing root
    /// is never removed when validation or identity comparison fails.
    pub(crate) fn replace_with_existing(
        &mut self,
        existing: &Path,
        parent: &Path,
        prefix: &str,
        expected_device: u64,
        expected_inode: u64,
    ) -> Result<(), String> {
        let existing_identity = OwnedTreeIdentity::capture(existing, parent, prefix)?;
        if existing_identity.device != expected_device || existing_identity.inode != expected_inode
        {
            return Err("retained candidate changed identity before adoption".into());
        }
        existing_identity.verify(existing)?;
        remove_owned_tree(&self.root, &self.identity)?;
        self.root = existing.to_path_buf();
        self.identity = existing_identity;
        Ok(())
    }

    /// Atomically rename a completed staging tree within its existing private
    /// parent and retarget its identity-bound cleanup authority. The inode and
    /// device must remain unchanged across publication.
    pub(crate) fn publish_within_parent(
        &mut self,
        destination: &Path,
        published_prefix: &str,
    ) -> Result<(), String> {
        if destination.parent() != self.root.parent()
            || !destination
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(published_prefix))
        {
            return Err("candidate publication target is outside its private parent".into());
        }
        fs::rename(&self.root, destination)
            .map_err(|e| format!("cannot atomically publish candidate: {e}"))?;
        // Retarget cleanup immediately after the only mutation. If an
        // adversarial replacement is observed below, the caller still owns
        // cleanup authority for the published pathname rather than the now
        // nonexistent staging name.
        self.root = destination.to_path_buf();
        self.identity.parent = destination
            .parent()
            .ok_or("published candidate has no parent")?
            .to_path_buf();
        self.identity.prefix = published_prefix.to_string();
        let observed =
            fs::symlink_metadata(destination).map_err(|_| "published candidate disappeared")?;
        if observed.file_type().is_symlink()
            || !observed.is_dir()
            || device_of(&observed) != self.identity.device
            || inode_of(&observed) != self.identity.inode
        {
            return Err("published candidate changed identity".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct OwnedTreeIdentity {
    parent: PathBuf,
    prefix: String,
    device: u64,
    inode: u64,
}

impl OwnedTreeIdentity {
    fn capture(path: &Path, parent: &Path, prefix: &str) -> Result<Self, String> {
        if path.parent() != Some(parent)
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        {
            return Err("owned cleanup target is outside its fixed parent/prefix".into());
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "cannot capture owned cleanup target identity")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("owned cleanup target is not a no-follow directory".into());
        }
        Ok(Self {
            parent: parent.to_path_buf(),
            prefix: prefix.into(),
            device: device_of(&metadata),
            inode: inode_of(&metadata),
        })
    }

    fn verify(&self, path: &Path) -> Result<(), String> {
        if path.parent() != Some(self.parent.as_path())
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&self.prefix))
        {
            return Err("owned tree has an unexpected parent or prefix".into());
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "owned tree disappeared after publication")?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || device_of(&metadata) != self.device
            || inode_of(&metadata) != self.inode
        {
            return Err("owned tree changed identity after publication".into());
        }
        Ok(())
    }
}

fn remove_owned_tree(path: &Path, identity: &OwnedTreeIdentity) -> Result<(), String> {
    if path.parent() != Some(identity.parent.as_path())
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(&identity.prefix))
    {
        return Err(format!(
            "owned-tree-cleanup-blocked: {} has an unexpected parent or prefix",
            path.display()
        ));
    }
    let root_metadata = fs::symlink_metadata(path).map_err(|_| {
        format!(
            "owned-tree-cleanup-blocked: {} is unavailable",
            path.display()
        )
    })?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || device_of(&root_metadata) != identity.device
        || inode_of(&root_metadata) != identity.inode
    {
        return Err(format!(
            "owned-tree-cleanup-blocked: {} changed identity",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            format!(
                "owned-tree-cleanup-blocked: {} could not be made writable",
                path.display()
            )
        })?;
    }
    let mut remaining_entries = 100_000usize;
    let mut remaining_bytes = 8_u64 * 1024 * 1024 * 1024;
    remove_owned_tree_contents(
        path,
        identity.device,
        &mut remaining_entries,
        &mut remaining_bytes,
    )?;
    fs::remove_dir(path).map_err(|_| {
        format!(
            "owned-tree-cleanup-blocked: {} could not be removed",
            path.display()
        )
    })
}

fn remove_owned_tree_contents(
    directory: &Path,
    device: u64,
    remaining_entries: &mut usize,
    remaining_bytes: &mut u64,
) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|_| {
        format!(
            "owned-tree-cleanup-blocked: cannot enumerate {}",
            directory.display()
        )
    })?;
    for entry in entries {
        if *remaining_entries == 0 {
            return Err("owned-tree-cleanup-blocked: entry cap exceeded".into());
        }
        *remaining_entries -= 1;
        let entry = entry.map_err(|_| "owned-tree-cleanup-blocked: invalid entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "owned-tree-cleanup-blocked: entry disappeared")?;
        if metadata.file_type().is_symlink() || device_of(&metadata) != device {
            return Err(format!(
                "owned-tree-cleanup-blocked: unsafe entry {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                    format!(
                        "owned-tree-cleanup-blocked: cannot make {} writable",
                        path.display()
                    )
                })?;
            }
            remove_owned_tree_contents(&path, device, remaining_entries, remaining_bytes)?;
            fs::remove_dir(&path).map_err(|_| {
                format!(
                    "owned-tree-cleanup-blocked: cannot remove {}",
                    path.display()
                )
            })?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(format!(
                        "owned-tree-cleanup-blocked: multiply-linked file {}",
                        path.display()
                    ));
                }
            }
            *remaining_bytes = remaining_bytes
                .checked_sub(metadata.len())
                .ok_or("owned-tree-cleanup-blocked: byte cap exceeded")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|_| {
                    format!(
                        "owned-tree-cleanup-blocked: cannot make {} writable",
                        path.display()
                    )
                })?;
            }
            fs::remove_file(&path).map_err(|_| {
                format!(
                    "owned-tree-cleanup-blocked: cannot remove {}",
                    path.display()
                )
            })?;
        } else {
            return Err(format!(
                "owned-tree-cleanup-blocked: unsupported entry {}",
                path.display()
            ));
        }
    }
    Ok(())
}

struct PendingMaterialization {
    root: PathBuf,
    identity: OwnedTreeIdentity,
    keep: bool,
}

impl Drop for PendingMaterialization {
    fn drop(&mut self) {
        if !self.keep {
            let _ = remove_owned_tree(&self.root, &self.identity);
        }
    }
}

/// Materialize only ordinary regular blobs from `subject` into a fresh private
/// directory. Unsupported tree entries fail closed rather than letting a
/// validation command observe a symlink, gitlink, or checkout filter effect.
pub fn materialize_subject(root: &Path, subject: &Subject) -> Result<MaterializedSubject, String> {
    materialize_subject_in(root, subject, &std::env::temp_dir(), "mpd-exact-subject-")
}

/// Variant of [`materialize_subject`] whose exclusive destination is created
/// below a caller-validated owner-only clone-private parent. Candidate capture
/// uses this to keep staging and atomic publication on one filesystem.
pub(crate) fn materialize_subject_in(
    root: &Path,
    subject: &Subject,
    parent: &Path,
    prefix: &str,
) -> Result<MaterializedSubject, String> {
    materialize_subject_in_with_limits(
        root,
        subject,
        parent,
        prefix,
        MaterializationLimits::PRODUCTION,
    )
}

#[derive(Debug, Clone, Copy)]
struct MaterializationLimits {
    entries: usize,
    path_bytes: usize,
    blob_bytes: u64,
    total_bytes: u64,
}

impl MaterializationLimits {
    const PRODUCTION: Self = Self {
        entries: MAX_MATERIALIZED_ENTRIES,
        path_bytes: MAX_MATERIALIZED_PATH_BYTES,
        blob_bytes: MAX_MATERIALIZED_BLOB_BYTES,
        total_bytes: MAX_MATERIALIZED_TOTAL_BYTES,
    };
}

#[derive(Debug)]
struct MaterializationEntry {
    mode: String,
    oid: String,
    path: String,
    size: u64,
}

fn materialize_subject_in_with_limits(
    root: &Path,
    subject: &Subject,
    parent: &Path,
    prefix: &str,
    limits: MaterializationLimits,
) -> Result<MaterializedSubject, String> {
    let output = canonical_git(
        root,
        &["ls-tree", "-r", "-z", "--full-tree", &subject.commit],
        MAX_MATERIALIZED_TREE_BYTES,
    )?;
    if !output.success {
        return Err("exact-subject tree enumeration failed or exceeded its cap".into());
    }
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("unsafe materialization prefix".into());
    }

    // Parse and budget the entire base tree before reading any blob or
    // creating any projected path. `ls-tree` metadata is untrusted structured
    // input; a huge tree must not turn into partial filesystem effects.
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if entries.len() == limits.entries {
            return Err("exact-subject tree entry count exceeds its cap".into());
        }
        let tab = raw
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("malformed exact-subject tree record")?;
        let (header, path) = (&raw[..tab], &raw[tab + 1..]);
        if path.len() > limits.path_bytes {
            return Err("exact-subject path exceeds its byte cap".into());
        }
        let header =
            std::str::from_utf8(header).map_err(|_| "non-UTF-8 exact-subject tree header")?;
        let mut fields = header.split(' ');
        let mode = fields.next().ok_or("missing exact-subject mode")?;
        let kind = fields.next().ok_or("missing exact-subject type")?;
        let oid = fields.next().ok_or("missing exact-subject oid")?;
        if fields.next().is_some() || kind != "blob" || !matches!(mode, "100644" | "100755") {
            return Err("exact-subject tree contains an unsupported entry".into());
        }
        validate_oid(oid)?;
        let path = std::str::from_utf8(path).map_err(|_| "non-UTF-8 exact-subject path")?;
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("exact-subject tree contains an unsafe path".into());
        }
        let size = git_output(root, &["cat-file", "-s", "--", oid])?
            .parse::<u64>()
            .map_err(|_| "invalid exact-subject blob size")?;
        if size > limits.blob_bytes {
            return Err("exact-subject blob exceeds its cap".into());
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or("exact-subject aggregate bytes overflow")?;
        if total_bytes > limits.total_bytes {
            return Err("exact-subject aggregate bytes exceed their cap".into());
        }
        entries.push(MaterializationEntry {
            mode: mode.to_string(),
            oid: oid.to_string(),
            path: path.to_string(),
            size,
        });
    }

    let parent_meta = fs::symlink_metadata(parent)
        .map_err(|e| format!("candidate staging parent is unavailable: {e}"))?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err("candidate staging parent is unsafe".into());
    }
    let destination = parent.join(format!(
        "{prefix}{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    fs::create_dir(&destination)
        .map_err(|e| format!("cannot create owned validation tree: {e}"))?;
    let identity = OwnedTreeIdentity::capture(&destination, parent, prefix)?;
    let mut pending = PendingMaterialization {
        root: destination.clone(),
        identity: identity.clone(),
        keep: false,
    };
    protect_dir(&destination)?;
    for entry in entries {
        let bytes = canonical_git(
            root,
            &["cat-file", "blob", "--", &entry.oid],
            entry.size as usize,
        )?;
        if !bytes.success || bytes.stdout.len() as u64 != entry.size {
            return Err("cannot read exact-subject blob exactly".into());
        }
        let target = destination.join(&entry.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create exact-subject path: {e}"))?;
            protect_dir(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|e| format!("cannot create exact-subject file: {e}"))?;
        file.write_all(&bytes.stdout)
            .map_err(|e| format!("cannot write exact-subject file: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(if entry.mode == "100755" { 0o500 } else { 0o400 }),
            )
            .map_err(|e| format!("cannot protect exact-subject file: {e}"))?;
        }
    }
    pending.keep = true;
    Ok(MaterializedSubject {
        root: destination,
        identity,
    })
}

fn canonical_policy_bytes(config: &LocalValidationConfig) -> Result<Vec<u8>, String> {
    serde_json::to_vec(config).map_err(|e| format!("cannot encode local validation policy: {e}"))
}

fn git_hash_blob(root: &Path, bytes: &[u8]) -> Result<String, String> {
    let output = canonical_git_run(root, &["hash-object", "-w", "--stdin"], bytes, &[], 1024)?;
    if !output.success {
        return Err("Git refused to create trusted policy object".into());
    }
    let oid = String::from_utf8(output.stdout)
        .map_err(|_| "Git returned non-UTF-8 trusted policy oid")?
        .trim()
        .to_string();
    validate_oid(&oid)?;
    Ok(oid)
}

fn capture_subject_policy_assets(
    root: &Path,
    subject: &Subject,
) -> Result<BTreeMap<String, TrustedPolicyAssetBytes>, String> {
    let mut assets = BTreeMap::new();
    let mut total = 0usize;
    for spec in POLICY_ASSET_SPECS {
        let listing = git_output(root, &["ls-tree", &subject.commit, "--", spec.path])?;
        let (header, listed_path) = listing
            .split_once('\t')
            .ok_or_else(|| format!("trusted-policy asset is missing: {}", spec.path))?;
        if listed_path != spec.path {
            return Err(format!(
                "trusted-policy asset path is non-canonical: {}",
                spec.path
            ));
        }
        let mut fields = header.split(' ');
        let mode = u32::from_str_radix(
            fields
                .next()
                .ok_or("trusted-policy asset mode is missing")?,
            8,
        )
        .map_err(|_| "trusted-policy asset mode is malformed")?;
        let kind = fields
            .next()
            .ok_or("trusted-policy asset kind is missing")?;
        let blob_oid = fields
            .next()
            .ok_or("trusted-policy asset oid is missing")?
            .to_string();
        if fields.next().is_some() || kind != "blob" || mode != spec.mode {
            return Err(format!(
                "trusted-policy asset has unsupported kind or mode: {}",
                spec.path
            ));
        }
        validate_oid(&blob_oid)?;
        let bytes = subject_file_bytes(root, subject, spec.path, MAX_POLICY_ASSET_BYTES)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("trusted-policy asset total overflow")?;
        if total > MAX_POLICY_ASSET_TOTAL_BYTES {
            return Err("trusted-policy assets exceed aggregate size cap".into());
        }
        let metadata = TrustedPolicyAssetV1 {
            path: spec.path.into(),
            mode,
            size: bytes.len() as u64,
            sha256: Digest::of_bytes(&bytes).to_hex(),
            blob_oid,
        };
        assets.insert(
            spec.path.into(),
            TrustedPolicyAssetBytes { metadata, bytes },
        );
    }
    validate_policy_asset_inventory(&assets)?;
    Ok(assets)
}

fn capture_candidate_policy_assets(
    root: &Path,
    candidate_root: &Path,
) -> Result<BTreeMap<String, TrustedPolicyAssetBytes>, String> {
    let mut assets = BTreeMap::new();
    let mut total = 0usize;
    for spec in POLICY_ASSET_SPECS {
        let path = candidate_root.join(spec.path);
        let before = fs::symlink_metadata(&path)
            .map_err(|e| format!("candidate policy asset is unavailable: {e}"))?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(format!(
                "candidate policy asset is not a regular file: {}",
                spec.path
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let observed_mode = if before.permissions().mode() & 0o111 == 0 {
                0o100644
            } else {
                0o100755
            };
            if before.nlink() != 1 || observed_mode != spec.mode {
                return Err(format!(
                    "candidate policy asset mode or link count is invalid: {}",
                    spec.path
                ));
            }
        }
        let text = openspec_core::read_contained_capped(
            candidate_root,
            &path,
            MAX_POLICY_ASSET_BYTES as u64,
        )
        .map_err(|e| format!("candidate policy asset cannot be read safely: {e}"))?;
        let bytes = text.into_bytes();
        let after = fs::symlink_metadata(&path)
            .map_err(|_| "candidate policy asset disappeared during read")?;
        if bytes.is_empty()
            || bytes.len() > MAX_POLICY_ASSET_BYTES
            || !same_file_identity(&before, &after)
            || after.len() != bytes.len() as u64
        {
            return Err(format!(
                "candidate policy asset drifted or exceeded its cap: {}",
                spec.path
            ));
        }
        total = total
            .checked_add(bytes.len())
            .ok_or("candidate policy asset total overflow")?;
        if total > MAX_POLICY_ASSET_TOTAL_BYTES {
            return Err("candidate policy assets exceed aggregate size cap".into());
        }
        let blob_oid = git_hash_blob_read_only(root, &bytes)?;
        let metadata = TrustedPolicyAssetV1 {
            path: spec.path.into(),
            mode: spec.mode,
            size: bytes.len() as u64,
            sha256: Digest::of_bytes(&bytes).to_hex(),
            blob_oid,
        };
        assets.insert(
            spec.path.into(),
            TrustedPolicyAssetBytes { metadata, bytes },
        );
    }
    validate_policy_asset_inventory(&assets)?;
    Ok(assets)
}

fn git_hash_blob_read_only(root: &Path, bytes: &[u8]) -> Result<String, String> {
    let output = canonical_git_run(root, &["hash-object", "--stdin"], bytes, &[], 1024)?;
    if !output.success {
        return Err("Git refused to identify candidate policy bytes".into());
    }
    let oid = String::from_utf8(output.stdout)
        .map_err(|_| "Git returned non-UTF-8 candidate policy blob identity")?
        .trim()
        .to_string();
    validate_oid(&oid)?;
    Ok(oid)
}

fn trusted_candidate_policy_bindings(
    root: &Path,
    candidate_root: &Path,
    candidate: &LocalValidationConfig,
) -> Result<(String, String), String> {
    let trusted_oid = trusted_policy_ref(root)?;
    let trusted = read_trusted_policy_bundle(root, &trusted_oid)?;
    if canonical_policy_bytes(&trusted.object.local_validation)?
        != canonical_policy_bytes(candidate)?
    {
        return Err(
            "policy-approval-required: candidate local_validation differs from the clone-local trusted policy"
                .into(),
        );
    }
    let candidate_assets = capture_candidate_policy_assets(root, candidate_root)?;
    if policy_asset_metadata(&candidate_assets) != trusted.object.assets {
        return Err(
            "policy-approval-required: candidate policy assets differ from the clone-local trusted policy"
                .into(),
        );
    }
    let trusted_digest =
        Digest::of_bytes(&serde_json::to_vec(&trusted.object).map_err(|e| e.to_string())?).to_hex();
    Ok((trusted_oid, trusted_digest))
}

fn validate_policy_asset_inventory(
    assets: &BTreeMap<String, TrustedPolicyAssetBytes>,
) -> Result<(), String> {
    if assets.len() != POLICY_ASSET_SPECS.len() {
        return Err("trusted-policy asset inventory is missing or has extra entries".into());
    }
    let mut total = 0usize;
    for spec in POLICY_ASSET_SPECS {
        let asset = assets
            .get(spec.path)
            .ok_or_else(|| format!("trusted-policy asset is missing: {}", spec.path))?;
        if asset.metadata.path != spec.path
            || asset.metadata.mode != spec.mode
            || asset.metadata.size != asset.bytes.len() as u64
            || asset.bytes.is_empty()
            || asset.bytes.len() > MAX_POLICY_ASSET_BYTES
            || Digest::of_bytes(&asset.bytes).to_hex() != asset.metadata.sha256
        {
            return Err(format!(
                "trusted-policy asset metadata is invalid: {}",
                spec.path
            ));
        }
        Digest::from_hex(&asset.metadata.sha256)
            .map_err(|_| format!("trusted-policy asset digest is invalid: {}", spec.path))?;
        validate_oid(&asset.metadata.blob_oid)?;
        total = total
            .checked_add(asset.bytes.len())
            .ok_or("trusted-policy asset total overflow")?;
    }
    if total > MAX_POLICY_ASSET_TOTAL_BYTES {
        return Err("trusted-policy assets exceed aggregate size cap".into());
    }
    Ok(())
}

fn policy_asset_metadata(
    assets: &BTreeMap<String, TrustedPolicyAssetBytes>,
) -> Vec<TrustedPolicyAssetV1> {
    POLICY_ASSET_SPECS
        .iter()
        .filter_map(|spec| assets.get(spec.path))
        .map(|asset| asset.metadata.clone())
        .collect()
}

fn policy_asset_group_digest(
    assets: &BTreeMap<String, TrustedPolicyAssetBytes>,
    paths: &[&str],
) -> Result<String, String> {
    let mut bytes = Vec::new();
    for path in paths {
        let asset = assets
            .get(*path)
            .ok_or_else(|| format!("trusted-policy asset is missing: {path}"))?;
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&asset.bytes);
        bytes.push(0);
    }
    Ok(Digest::of_bytes(&bytes).to_hex())
}

fn policy_asset_digests(
    assets: &BTreeMap<String, TrustedPolicyAssetBytes>,
) -> Result<(String, String, String), String> {
    validate_policy_asset_inventory(assets)?;
    let tool_lock = assets
        .get("security/tool-lock.json")
        .ok_or("trusted-policy tool lock is missing")?
        .metadata
        .sha256
        .clone();
    let sandbox = policy_asset_group_digest(
        assets,
        &[
            "security/policy/local-ci-policy.json",
            "security/sandbox/validation.bwrap",
            "security/sandbox/validation.sb",
            "security/semgrep/local-ci.yml",
        ],
    )?;
    let hooks = policy_asset_group_digest(assets, &[".githooks/pre-commit", ".githooks/pre-push"])?;
    Ok((tool_lock, sandbox, hooks))
}

/// Verify an immutable checkpoint and create the sole clone-private pretrust
/// proof. This deliberately has no runner/profile entry point: the observed
/// effect contract is data and the implementation invokes only Git plumbing and
/// descriptor reads needed to bind the reviewed bytes.
#[cfg(test)]
pub fn verify_first_adoption_checkpoint(
    root: &Path,
    change: &str,
    checkpoint: &str,
    security_evidence: &str,
    config: &LocalValidationConfig,
    confirmed_policy_digest: &str,
    confirmed_coordinator_digest: &str,
) -> Result<(PretrustCheckpointProofV1, String, String), String> {
    if git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?
    .is_some()
    {
        return Err("first-adoption-already-initialized".into());
    }
    validate_oid(checkpoint)?;
    config.validate()?;
    let candidate_policy = canonical_policy_bytes(config)?;
    let candidate_policy_digest = Digest::of_bytes(&candidate_policy).to_hex();
    if candidate_policy_digest != confirmed_policy_digest {
        return Err("confirmed policy digest does not match current candidate policy".into());
    }
    crate::digest::Digest::from_hex(confirmed_coordinator_digest)?;
    let checkpoint_oid = git_output(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{checkpoint}^{{commit}}"),
        ],
    )?;
    validate_oid(&checkpoint_oid)?;
    let base = git_output(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{checkpoint_oid}^"),
        ],
    )?;
    validate_oid(&base)?;
    let branch = git_optional(root, &["symbolic-ref", "--quiet", "HEAD"])?
        .ok_or("first-adoption requires a symbolic branch HEAD")?;
    let upstream = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", "@{upstream}^{commit}"],
    )?;
    let scope = prepare_checkpoint_scope_at_head(
        root,
        change,
        &base,
        &branch,
        upstream.as_deref(),
        &checkpoint_oid,
    )?;
    verify_scope_against_checkpoint(root, &scope, &checkpoint_oid)?;
    let evidence_path = openspec_core::Project::new(root)
        .change_dir(change)
        .join(security_evidence);
    let security = openspec_core::read_contained_capped(root, &evidence_path, 1024 * 1024)
        .map_err(|e| format!("invalid first-adoption security evidence: {e}"))?;
    if !security.contains("PASS") || security.contains("## Verdict\n\nFAIL") {
        return Err(
            "first-adoption requires current provisional Security(code) PASS evidence".into(),
        );
    }
    let security_evidence_digest = Digest::of_bytes(security.as_bytes()).to_hex();
    let tool_lock_digest = digest_required_file(root, "security/tool-lock.json")?;
    let sandbox_digest = digest_validation_assets(root)?;
    let hook_digest = digest_hook_sources(root)?;
    let checkpoint_tree_oid = git_output(
        root,
        &[
            "show",
            "-s",
            "--format=%T",
            "--end-of-options",
            &checkpoint_oid,
        ],
    )?;
    validate_oid(&checkpoint_tree_oid)?;
    let checkpoint_chain_digest = Digest::of_bytes(
        format!("{base}\0{checkpoint_oid}\0{}", scope.aggregate_digest).as_bytes(),
    )
    .to_hex();
    let allowed_effect_digest = pretrust_allowed_effect_digest();
    let nonce = public_nonce()?;
    let nonce_digest = bootstrap_nonce_digest(&nonce);
    let state = first_adoption_dir(root)?;
    let proofs = state.join("proofs");
    let proofs_meta =
        fs::symlink_metadata(&proofs).map_err(|_| "pretrust proof directory is not prepared")?;
    if proofs_meta.file_type().is_symlink() || !proofs_meta.is_dir() {
        return Err("pretrust proof directory is unsafe".into());
    }
    protect_dir(&proofs)?;
    let proof_relative_path = format!("proofs/{nonce_digest}.json");
    let proof_path = state.join(&proof_relative_path);
    if fs::symlink_metadata(&proof_path).is_ok() {
        return Err("first-adoption proof path already exists".into());
    }
    let protected_before = capture_pretrust_protected_state(root, config)?;
    let protected_before_digest = digest_json(&protected_before)?;
    let private_before = inventory_private_state(&state)?;
    let private_state_before_digest = digest_json(&private_before)?;
    let observation = PretrustEffectObservationV1 {
        schema: 1,
        protected_before_digest: protected_before_digest.clone(),
        protected_after_digest: protected_before_digest.clone(),
        private_state_before_digest: private_state_before_digest.clone(),
        private_state_after_without_proof_digest: private_state_before_digest.clone(),
        exclusive_write: proof_relative_path.clone(),
        configured_checks_executed: 0,
    };
    let observed_effect_digest = digest_json(&observation)?;
    let proof = PretrustCheckpointProofV1 {
        schema: PRETRUST_PROOF_SCHEMA,
        change: change.to_string(),
        checkpoint_oid,
        checkpoint_tree_oid,
        checkpoint_scope: scope,
        checkpoint_chain_digest,
        security_evidence: security_evidence.to_string(),
        security_evidence_digest,
        candidate_policy_digest,
        tool_lock_digest,
        sandbox_digest,
        hook_digest,
        coordinator_digest: confirmed_coordinator_digest.to_string(),
        sandbox_contract: "pretrust-control-plane-v1/env-clear/network-denied/read-only-repository"
            .into(),
        allowed_effect_digest,
        observed_effect_digest,
        protected_before_digest: protected_before_digest.clone(),
        protected_after_digest: protected_before_digest,
        private_state_before_digest: private_state_before_digest.clone(),
        private_state_after_without_proof_digest: private_state_before_digest,
        proof_relative_path,
        configured_checks_executed: 0,
        nonce_digest: nonce_digest.clone(),
    };
    let bytes = serde_json::to_vec(&proof).map_err(|e| e.to_string())?;
    let digest = Digest::of_bytes(&bytes).to_hex();
    write_owner_private(&proof_path, &bytes)?;
    let measured = (|| -> Result<(), String> {
        let protected_after = capture_pretrust_protected_state(root, config)?;
        let protected_after_digest = digest_json(&protected_after)?;
        if protected_after_digest != proof.protected_after_digest
            || protected_after_digest != proof.protected_before_digest
        {
            return Err("pretrust-protected-state-mutated".into());
        }
        verify_exclusive_proof_effect(&state, &private_before, &proof_path, &bytes)?;
        Ok(())
    })();
    if let Err(error) = measured {
        remove_owned_proof(&proof_path)?;
        return Err(error);
    }
    // The public nonce preimage is returned only to the bootstrap caller.  It
    // is deliberately absent from the durable proof: every interface after
    // bootstrap consumes the domain-separated digest, never the preimage.
    Ok((proof, digest, nonce))
}

/// Bootstrap a commit/tree policy object bound to the reviewed pretrust proof.
/// A retry observes and reparses the all-zero-CAS winner, so response loss never
/// produces a second root or silently accepts different proof/nonce inputs.
#[cfg(test)]
pub fn bootstrap_first_adoption_policy(
    root: &Path,
    config: &LocalValidationConfig,
    request: BootstrapRequest<'_>,
) -> Result<(String, bool), String> {
    config.validate()?;
    validate_oid(request.checkpoint_oid)?;
    let policy_digest = Digest::of_bytes(&canonical_policy_bytes(config)?).to_hex();
    if policy_digest != request.reviewed_policy_digest {
        return Err("reviewed policy digest does not match the current candidate policy".into());
    }
    let proof = read_proof_by_digest(root, request.pretrust_proof_digest)?;
    if proof.checkpoint_oid != request.checkpoint_oid
        || proof.candidate_policy_digest != policy_digest
    {
        return Err("pretrust proof does not bind the requested checkpoint/policy".into());
    }
    let nonce_digest = bootstrap_nonce_digest(request.nonce);
    if nonce_digest != proof.nonce_digest {
        return Err("pretrust proof nonce is missing, stale, or replayed".into());
    }
    let checkpoint = capture_subject(root, Some(request.checkpoint_oid))?;
    if checkpoint.pushed_oid != request.checkpoint_oid || checkpoint.pushed_kind != "commit" {
        return Err("bootstrap checkpoint must be a direct immutable commit object id".into());
    }
    let committed = subject_local_validation(root, &checkpoint)?;
    if canonical_policy_bytes(&committed)? != canonical_policy_bytes(config)? {
        return Err("bootstrap policy differs from the immutable reviewed checkpoint".into());
    }
    let assets = capture_subject_policy_assets(root, &checkpoint)?;
    let (tool_lock_digest, sandbox_digest, hook_digest) = policy_asset_digests(&assets)?;
    if tool_lock_digest != proof.tool_lock_digest
        || sandbox_digest != proof.sandbox_digest
        || hook_digest != proof.hook_digest
    {
        return Err("bootstrap assets differ from the immutable reviewed proof".into());
    }
    let object = TrustedPolicyObjectV1 {
        schema: 1,
        local_validation: config.clone(),
        asset_schema: POLICY_ASSET_SCHEMA,
        assets: policy_asset_metadata(&assets),
        previous_trusted_policy_oid: None,
        checkpoint_oid: request.checkpoint_oid.to_string(),
        pretrust_proof_digest: request.pretrust_proof_digest.to_string(),
        bootstrap_nonce_digest: nonce_digest,
        coordinator_digest: proof.coordinator_digest,
        hook_digest,
        tool_lock_digest,
        sandbox_digest,
    };
    let oid = write_policy_commit(root, &object, &assets)?;
    let zero = "0".repeat(oid.len());
    let status = canonical_git(
        root,
        &["update-ref", "--no-deref", TRUSTED_POLICY_REF, &oid, &zero],
        0,
    )?;
    if status.success {
        return Ok((oid, false));
    }
    let existing = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?
    .ok_or("trusted-policy bootstrap CAS failed without a winner")?;
    let winner = read_trusted_policy_bundle(root, &existing)?;
    if winner.object == object && winner.assets == assets {
        Ok((existing, true))
    } else {
        Err("trusted-policy bootstrap CAS lost to a different policy object".into())
    }
}

/// Promote an already initialized clone-local policy root.  This intentionally
/// has no receipt/publication path: the two profile runs are owner review
/// evidence only, and promotion itself must never manufacture a validation or
/// gate success.
#[cfg(test)]
pub fn promote_trusted_policy(
    root: &Path,
    commit: &str,
    confirmed_policy_digest: &str,
) -> Result<PolicyPromotionReport, String> {
    validate_oid(commit)?;
    let subject = capture_subject(root, Some(commit))?;
    if subject.pushed_oid != commit
        || subject.pushed_kind != "commit"
        || !subject.tag_chain.is_empty()
    {
        return Err("policy promotion requires a direct immutable commit object id".into());
    }
    let candidate = subject_local_validation(root, &subject)?;
    candidate.validate()?;
    let candidate_policy_digest = Digest::of_bytes(&canonical_policy_bytes(&candidate)?).to_hex();
    if candidate_policy_digest != confirmed_policy_digest {
        return Err("reviewed policy digest does not match the immutable candidate commit".into());
    }

    let expected_old = trusted_policy_ref(root)?;
    let trusted = read_trusted_policy_bundle(root, &expected_old)?;
    let trusted_before_digest = trusted_policy_object_digest(root, &expected_old)?;
    let semantic_diff = policy_semantic_diff(&trusted.object.local_validation, &candidate)?;
    let candidate_assets = capture_subject_policy_assets(root, &subject)?;
    let (candidate_tool_lock_digest, candidate_sandbox_digest, candidate_hook_digest) =
        policy_asset_digests(&candidate_assets)?;

    // The prior floor always completes first.  Do not even materialize or run
    // the candidate definition until that sandboxed execution succeeds.
    run_promotion_profile(
        root,
        &subject,
        &trusted.object.local_validation,
        &trusted.object.local_validation.gates.test,
        Some(&trusted.assets),
        &expected_old,
        &trusted_before_digest,
    )?;
    // Candidate definitions run in a second, fresh sandboxed materialization;
    // same-named checks cannot replace the already-completed trusted floor.
    run_promotion_profile(
        root,
        &subject,
        &candidate,
        &candidate.gates.test,
        None,
        &expected_old,
        &trusted_before_digest,
    )?;

    // Re-read the literal direct ref before object construction so a movement
    // cannot be mistaken for an expected-old value later in the flow.
    if trusted_policy_ref(root)? != expected_old {
        return Err("trusted-policy promotion blocked: trusted ref moved before CAS".into());
    }
    let promoted = TrustedPolicyObjectV1 {
        schema: 1,
        local_validation: candidate,
        asset_schema: POLICY_ASSET_SCHEMA,
        assets: policy_asset_metadata(&candidate_assets),
        previous_trusted_policy_oid: Some(expected_old.clone()),
        checkpoint_oid: subject.commit.clone(),
        // These values describe the original root rather than pretending that
        // promotion is a second first-adoption proof.
        pretrust_proof_digest: trusted.object.pretrust_proof_digest,
        bootstrap_nonce_digest: trusted.object.bootstrap_nonce_digest,
        coordinator_digest: trusted.object.coordinator_digest,
        hook_digest: candidate_hook_digest.clone(),
        tool_lock_digest: candidate_tool_lock_digest.clone(),
        sandbox_digest: candidate_sandbox_digest.clone(),
    };
    let new_oid = write_policy_commit(root, &promoted, &candidate_assets)?;
    let winner = publish_promoted_policy(root, &expected_old, &new_oid, &promoted)?;
    Ok(PolicyPromotionReport {
        subject_commit: subject.commit,
        trusted_before_oid: expected_old,
        trusted_before_digest,
        candidate_policy_digest,
        candidate_tool_lock_digest,
        candidate_sandbox_digest,
        candidate_hook_digest,
        semantic_diff,
        promoted_policy_oid: winner,
    })
}

fn trusted_policy_ref(root: &Path) -> Result<String, String> {
    let symbolic = canonical_git(root, &["symbolic-ref", "-q", TRUSTED_POLICY_REF], 1024)?;
    if symbolic.success {
        return Err("trusted-policy-invalid: trusted policy ref must be literal and direct".into());
    }
    let oid = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?
    .ok_or("trusted-policy-missing: activate an explicitly reviewed immutable policy")?;
    validate_oid(&oid)?;
    if git_output(root, &["cat-file", "-t", "--", &oid])? != "commit" {
        return Err("trusted-policy-invalid: trusted policy ref must name a direct commit".into());
    }
    Ok(oid)
}

#[cfg(test)]
fn publish_promoted_policy(
    root: &Path,
    expected_old: &str,
    new_oid: &str,
    expected_object: &TrustedPolicyObjectV1,
) -> Result<String, String> {
    if trusted_policy_ref(root)? != expected_old {
        return Err("trusted-policy promotion blocked: trusted ref moved before CAS".into());
    }
    let status = canonical_git(
        root,
        &[
            "update-ref",
            "--no-deref",
            TRUSTED_POLICY_REF,
            new_oid,
            expected_old,
        ],
        0,
    )?;
    if !status.success {
        return Err("trusted-policy promotion CAS lost; the trusted ref was not changed".into());
    }
    let winner = trusted_policy_ref(root)?;
    if winner != new_oid || read_trusted_policy_object(root, &winner)? != *expected_object {
        return Err("trusted-policy promotion winner failed post-CAS reparse".into());
    }
    Ok(winner)
}

#[cfg(test)]
fn policy_semantic_diff(
    trusted: &LocalValidationConfig,
    candidate: &LocalValidationConfig,
) -> Result<Vec<String>, String> {
    trusted.validate()?;
    candidate.validate()?;
    let mut changes = Vec::new();
    named_policy_diff("tool", &trusted.tools, &candidate.tools, &mut changes);
    named_policy_diff("check", &trusted.checks, &candidate.checks, &mut changes);
    named_policy_diff(
        "profile",
        &trusted.profiles,
        &candidate.profiles,
        &mut changes,
    );
    for (label, changed) in [
        ("gates", trusted.gates != candidate.gates),
        ("receipts", trusted.receipts != candidate.receipts),
        (
            "build-output",
            trusted.build_output != candidate.build_output,
        ),
        (
            "deploy-output",
            trusted.deploy_output != candidate.deploy_output,
        ),
    ] {
        if changed {
            changes.push(format!(
                "{label} definition changed; trusted definition remains a required prior floor"
            ));
        }
    }
    if changes.is_empty() {
        changes.push(
            "no local-validation semantic change; promotion refreshes reviewed assets only".into(),
        );
    }
    Ok(changes)
}

#[cfg(test)]
fn named_policy_diff<T: PartialEq>(
    label: &str,
    trusted: &BTreeMap<String, T>,
    candidate: &BTreeMap<String, T>,
    changes: &mut Vec<String>,
) {
    for (name, prior) in trusted {
        match candidate.get(name) {
            None => changes.push(format!(
                "{label} {name:?} is absent from the candidate; the trusted definition remains in the prior floor"
            )),
            Some(proposed) if proposed != prior => changes.push(format!(
                "{label} {name:?} changed; candidate definition runs separately after the trusted definition"
            )),
            Some(_) => {}
        }
    }
    for name in candidate.keys().filter(|name| !trusted.contains_key(*name)) {
        changes.push(format!("{label} {name:?} added to the candidate proposal"));
    }
}

#[cfg(test)]
fn run_promotion_profile(
    root: &Path,
    subject: &Subject,
    policy: &LocalValidationConfig,
    profile: &str,
    trusted_assets: Option<&BTreeMap<String, TrustedPolicyAssetBytes>>,
    trusted_oid: &str,
    trusted_digest: &str,
) -> Result<(), String> {
    let started = epoch_secs()?;
    let materialized = materialize_subject(root, subject)?;
    let run = (|| {
        if let Some(assets) = trusted_assets {
            overlay_trusted_policy_floor(&materialized.root, policy, assets)?;
        }
        let adapter = sandbox_adapter(&materialized.root)?;
        let sandbox_identity = sandbox_identity(&adapter)?;
        run_profile(
            root,
            &materialized.root,
            root,
            profile,
            policy,
            &adapter,
            &sandbox_identity,
            subject,
            trusted_oid,
            trusted_digest,
            started,
        )
    })();
    let cleanup = remove_owned_tree(&materialized.root, &materialized.identity).map_err(|error| {
        format!(
            "promotion-validation-cleanup-failed: {}: {error}",
            materialized.root.display()
        )
    });
    match (run, cleanup) {
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
        (Ok(report), Ok(())) if report.status == "passed" => Ok(()),
        (Ok(_), Ok(())) => Err("policy promotion profile failed".into()),
    }
}

#[cfg(test)]
fn overlay_trusted_policy_floor(
    worktree: &Path,
    policy: &LocalValidationConfig,
    assets: &BTreeMap<String, TrustedPolicyAssetBytes>,
) -> Result<(), String> {
    validate_policy_asset_inventory(assets)?;
    for spec in POLICY_ASSET_SPECS {
        let asset = assets
            .get(spec.path)
            .ok_or_else(|| format!("trusted-policy asset is missing: {}", spec.path))?;
        let path = worktree.join(spec.path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| format!("candidate replacement path is unavailable: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "candidate replacement path is unsupported: {}",
                spec.path
            ));
        }
        fs::remove_file(&path)
            .map_err(|e| format!("cannot remove candidate asset replacement: {e}"))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("cannot restore exact trusted asset: {e}"))?;
        file.write_all(&asset.bytes)
            .map_err(|e| format!("cannot write exact trusted asset: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if spec.mode == 0o100755 { 0o500 } else { 0o400 }),
            )
            .map_err(|e| format!("cannot protect exact trusted asset: {e}"))?;
        }
    }
    let config_path = worktree.join(".mpd/config.json");
    let metadata = fs::symlink_metadata(&config_path)
        .map_err(|e| format!("candidate policy config is unavailable: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("candidate policy config is unsupported".into());
    }
    fs::remove_file(&config_path)
        .map_err(|e| format!("cannot remove candidate policy config: {e}"))?;
    let bytes = serde_json::to_vec(&serde_json::json!({ "local_validation": policy }))
        .map_err(|e| format!("cannot encode trusted policy config: {e}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config_path)
        .map_err(|e| format!("cannot restore trusted policy config: {e}"))?;
    file.write_all(&bytes)
        .map_err(|e| format!("cannot write trusted policy config: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o400))
            .map_err(|e| format!("cannot protect trusted policy config: {e}"))?;
    }
    Ok(())
}

fn write_policy_commit(
    root: &Path,
    object: &TrustedPolicyObjectV1,
    assets: &BTreeMap<String, TrustedPolicyAssetBytes>,
) -> Result<String, String> {
    validate_policy_asset_inventory(assets)?;
    if object.asset_schema != POLICY_ASSET_SCHEMA || object.assets != policy_asset_metadata(assets)
    {
        return Err("trusted-policy object asset inventory is non-canonical".into());
    }
    let (tool_lock, sandbox, hooks) = policy_asset_digests(assets)?;
    if object.tool_lock_digest != tool_lock
        || object.sandbox_digest != sandbox
        || object.hook_digest != hooks
    {
        return Err("trusted-policy object asset digests are inconsistent".into());
    }
    for asset in assets.values() {
        if git_hash_blob(root, &asset.bytes)? != asset.metadata.blob_oid {
            return Err(format!(
                "trusted-policy asset blob identity changed: {}",
                asset.metadata.path
            ));
        }
    }
    let policy_blob = git_hash_blob(
        root,
        &serde_json::to_vec(object).map_err(|e| e.to_string())?,
    )?;
    let temporary = std::env::temp_dir().join(format!(
        "mpd-policy-tree-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    fs::create_dir(&temporary)
        .map_err(|e| format!("cannot create trusted-policy temporary directory: {e}"))?;
    protect_dir(&temporary)?;
    let index = temporary.join("index");
    if fs::symlink_metadata(&index).is_ok() {
        return Err("trusted-policy temporary index already exists".into());
    }
    let construct = (|| -> Result<String, String> {
        let index_env = vec![git_env_pair("GIT_INDEX_FILE", &index)];
        let empty = canonical_git_run(root, &["read-tree", "--empty"], b"", &index_env, 0)?;
        if !empty.success {
            return Err("cannot initialize trusted-policy tree".into());
        }
        let mut entries = vec![(0o100644, policy_blob.clone(), "policy.json".to_string())];
        entries.extend(assets.values().map(|asset| {
            (
                asset.metadata.mode,
                asset.metadata.blob_oid.clone(),
                format!("assets/{}", asset.metadata.path),
            )
        }));
        for (mode, oid, path) in entries {
            let cacheinfo = format!("{mode:o},{oid},{path}");
            let status = canonical_git_run(
                root,
                &["update-index", "--add", "--cacheinfo", &cacheinfo],
                b"",
                &index_env,
                0,
            )?;
            if !status.success {
                return Err("cannot add trusted-policy tree entry".into());
            }
        }
        let output = canonical_git_run(root, &["write-tree"], b"", &index_env, 1024)?;
        if !output.success {
            return Err("cannot write trusted-policy tree".into());
        }
        String::from_utf8(output.stdout)
            .map(|value| value.trim().to_string())
            .map_err(|_| "non-UTF-8 trusted policy tree".into())
    })();
    let cleanup = (|| -> Result<(), String> {
        let lock = temporary.join("index.lock");
        for path in [&index, &lock] {
            if let Ok(metadata) = fs::symlink_metadata(path) {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err("trusted-policy temporary state is unsafe".into());
                }
                fs::remove_file(path)
                    .map_err(|e| format!("cannot remove trusted-policy index: {e}"))?;
            }
        }
        fs::remove_dir(&temporary)
            .map_err(|e| format!("cannot remove trusted-policy temporary directory: {e}"))
    })();
    let tree_oid = match (construct, cleanup) {
        (Err(error), _) => return Err(error),
        (_, Err(error)) => return Err(error),
        (Ok(oid), Ok(())) => oid,
    };
    validate_oid(&tree_oid)?;
    let identity_env = vec![
        git_env_pair("GIT_AUTHOR_NAME", "MPD Local Policy"),
        git_env_pair("GIT_AUTHOR_EMAIL", "mpd-local-policy@invalid"),
        git_env_pair("GIT_COMMITTER_NAME", "MPD Local Policy"),
        git_env_pair("GIT_COMMITTER_EMAIL", "mpd-local-policy@invalid"),
    ];
    let out = canonical_git_run(
        root,
        &[
            "commit-tree",
            &tree_oid,
            "-m",
            "mpd trusted validation policy v1",
        ],
        b"",
        &identity_env,
        1024,
    )?;
    if !out.success {
        return Err("cannot construct trusted policy commit".into());
    }
    let oid = String::from_utf8(out.stdout)
        .map_err(|_| "non-UTF-8 trusted policy oid")?
        .trim()
        .to_string();
    validate_oid(&oid)?;
    Ok(oid)
}

fn read_trusted_policy_object(root: &Path, oid: &str) -> Result<TrustedPolicyObjectV1, String> {
    read_trusted_policy_bundle(root, oid).map(|bundle| bundle.object)
}

fn read_trusted_policy_bundle(root: &Path, oid: &str) -> Result<TrustedPolicyBundleV1, String> {
    let kind = git_output(root, &["cat-file", "-t", "--", oid])?;
    if kind != "commit" {
        return Err("trusted-policy-invalid: trusted policy ref must name a direct commit".into());
    }
    let entries = trusted_policy_tree_entries(root, oid)?;
    let policy = entries
        .get("policy.json")
        .ok_or("trusted-policy-invalid: policy.json is missing")?;
    if policy.0 != 0o100644 || policy.1 != "blob" {
        return Err("trusted-policy-invalid: policy.json has unsupported mode or kind".into());
    }
    let raw = read_git_blob_capped(root, &policy.2, MAX_POLICY_BYTES, "policy.json")?;
    let object: TrustedPolicyObjectV1 = serde_json::from_slice(&raw)
        .map_err(|_| "trusted-policy-invalid: policy.json is malformed")?;
    if object.schema != 1 || object.asset_schema != POLICY_ASSET_SCHEMA {
        return Err("trusted-policy-invalid: unsupported policy object schema".into());
    }
    object.local_validation.validate()?;
    validate_oid(&object.checkpoint_oid)?;
    for digest in [
        &object.pretrust_proof_digest,
        &object.bootstrap_nonce_digest,
        &object.coordinator_digest,
        &object.hook_digest,
        &object.tool_lock_digest,
        &object.sandbox_digest,
    ] {
        Digest::from_hex(digest)
            .map_err(|_| "trusted-policy-invalid: policy object contains an invalid digest")?;
    }
    if let Some(previous) = &object.previous_trusted_policy_oid {
        validate_oid(previous)?;
    }
    if object.assets.len() != POLICY_ASSET_SPECS.len() {
        return Err("trusted-policy-invalid: asset inventory is missing or has extras".into());
    }
    let mut expected_metadata = BTreeMap::new();
    for metadata in &object.assets {
        if expected_metadata
            .insert(metadata.path.clone(), metadata.clone())
            .is_some()
        {
            return Err("trusted-policy-invalid: duplicate asset inventory path".into());
        }
    }
    let expected_paths = trusted_policy_expected_tree_paths();
    if entries.keys().cloned().collect::<BTreeSet<_>>() != expected_paths {
        return Err("trusted-policy-invalid: policy tree is missing or has extra entries".into());
    }
    let mut assets = BTreeMap::new();
    for spec in POLICY_ASSET_SPECS {
        let metadata = expected_metadata
            .get(spec.path)
            .ok_or_else(|| format!("trusted-policy-invalid: missing asset {}", spec.path))?;
        let embedded = format!("assets/{}", spec.path);
        let entry = entries
            .get(&embedded)
            .ok_or_else(|| format!("trusted-policy-invalid: missing embedded asset {embedded}"))?;
        if entry.0 != spec.mode
            || entry.1 != "blob"
            || entry.2 != metadata.blob_oid
            || metadata.mode != spec.mode
            || metadata.path != spec.path
        {
            return Err(format!(
                "trusted-policy-invalid: asset mode/kind/identity differs: {}",
                spec.path
            ));
        }
        let bytes = read_git_blob_capped(
            root,
            &entry.2,
            MAX_POLICY_ASSET_BYTES,
            &format!("asset {}", spec.path),
        )?;
        let asset = TrustedPolicyAssetBytes {
            metadata: metadata.clone(),
            bytes,
        };
        assets.insert(spec.path.into(), asset);
    }
    validate_policy_asset_inventory(&assets)
        .map_err(|error| format!("trusted-policy-invalid: {error}"))?;
    let (tool_lock, sandbox, hooks) = policy_asset_digests(&assets)?;
    if object.tool_lock_digest != tool_lock
        || object.sandbox_digest != sandbox
        || object.hook_digest != hooks
    {
        return Err("trusted-policy-invalid: aggregate asset digests differ".into());
    }
    Ok(TrustedPolicyBundleV1 { object, assets })
}

fn trusted_policy_expected_tree_paths() -> BTreeSet<String> {
    let mut paths = BTreeSet::from(["policy.json".to_string(), "assets".to_string()]);
    for spec in POLICY_ASSET_SPECS {
        let embedded = format!("assets/{}", spec.path);
        paths.insert(embedded.clone());
        let mut parent = Path::new(&embedded).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            paths.insert(path.to_string_lossy().into_owned());
            parent = path.parent();
        }
    }
    paths
}

fn trusted_policy_tree_entries(
    root: &Path,
    oid: &str,
) -> Result<BTreeMap<String, (u32, String, String)>, String> {
    let output = canonical_git(
        root,
        &["ls-tree", "-r", "-t", "-z", "--full-tree", oid],
        1024 * 1024,
    )?;
    if !output.success {
        return Err(
            "trusted-policy-invalid: policy tree enumeration failed or exceeded cap".into(),
        );
    }
    let mut entries = BTreeMap::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|v| !v.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("trusted-policy-invalid: malformed tree entry")?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|_| "trusted-policy-invalid: non-UTF-8 tree header")?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| "trusted-policy-invalid: non-UTF-8 tree path")?;
        let mut fields = header.split(' ');
        let mode = u32::from_str_radix(
            fields
                .next()
                .ok_or("trusted-policy-invalid: missing tree mode")?,
            8,
        )
        .map_err(|_| "trusted-policy-invalid: malformed tree mode")?;
        let kind = fields
            .next()
            .ok_or("trusted-policy-invalid: missing tree kind")?
            .to_string();
        let entry_oid = fields
            .next()
            .ok_or("trusted-policy-invalid: missing tree oid")?
            .to_string();
        if fields.next().is_some()
            || !matches!(kind.as_str(), "blob" | "tree")
            || (kind == "tree" && mode != 0o040000)
            || entries
                .insert(path.to_string(), (mode, kind, entry_oid.clone()))
                .is_some()
        {
            return Err("trusted-policy-invalid: malformed or duplicate tree entry".into());
        }
        validate_oid(&entry_oid)?;
    }
    Ok(entries)
}

fn read_git_blob_capped(
    root: &Path,
    oid: &str,
    cap: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    validate_oid(oid)?;
    if git_output(root, &["cat-file", "-t", "--", oid])? != "blob" {
        return Err(format!("trusted-policy-invalid: {label} is not a blob"));
    }
    let size = git_output(root, &["cat-file", "-s", "--", oid])?
        .parse::<usize>()
        .map_err(|_| format!("trusted-policy-invalid: {label} size is malformed"))?;
    if size == 0 || size > cap {
        return Err(format!(
            "trusted-policy-invalid: {label} exceeds its size cap"
        ));
    }
    let output = canonical_git(root, &["cat-file", "blob", "--", oid], size)?;
    if !output.success || output.stdout.len() != size {
        return Err(format!("trusted-policy-invalid: cannot read exact {label}"));
    }
    Ok(output.stdout)
}

#[cfg(test)]
fn verify_scope_against_checkpoint(
    root: &Path,
    scope: &CheckpointScopeV1,
    checkpoint: &str,
) -> Result<(), String> {
    for entry in &scope.entries {
        match entry {
            CheckpointEntryV1::Present {
                path,
                mode,
                blob_oid,
            } => {
                let (found_mode, found_oid) = base_tree_entry(root, checkpoint, path)?
                    .ok_or_else(|| format!("checkpoint missing declared Present {path}"))?;
                if found_mode != *mode || found_oid != *blob_oid {
                    return Err(format!("checkpoint postimage differs for {path}"));
                }
            }
            CheckpointEntryV1::Deleted {
                path,
                base_mode,
                base_blob_oid,
            } => {
                if base_tree_entry(root, checkpoint, path)?.is_some() {
                    return Err(format!("checkpoint retained declared Deleted {path}"));
                }
                let (mode, oid) = base_tree_entry(root, &scope.recorded_base_oid, path)?
                    .ok_or_else(|| format!("checkpoint deletion base missing {path}"))?;
                if mode != *base_mode || oid != *base_blob_oid {
                    return Err(format!("checkpoint deletion base differs for {path}"));
                }
            }
        }
    }
    let changed = git_name_list(
        root,
        &[
            "diff",
            "--name-only",
            "-z",
            &scope.recorded_base_oid,
            checkpoint,
            "--",
        ],
    )?;
    let declared: BTreeSet<&str> = scope.entries.iter().map(CheckpointEntryV1::path).collect();
    if changed.iter().any(|path| !declared.contains(path.as_str())) {
        return Err("checkpoint has paths outside its reviewed scope".into());
    }
    Ok(())
}

#[cfg(test)]
fn bootstrap_nonce_digest(nonce: &str) -> String {
    let mut bytes = BOOTSTRAP_NONCE_DOMAIN.to_vec();
    bytes.extend_from_slice(nonce.as_bytes());
    Digest::of_bytes(&bytes).to_hex()
}

#[cfg(test)]
fn pretrust_allowed_effect_digest() -> String {
    Digest::of_bytes(b"read:checkpoint,scope,security,policy,tool-lock,sandbox,hooks,coordinator,head,index,refs,config,status;write:exclusive-proof;checks:0").to_hex()
}

#[cfg(test)]
fn public_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .map_err(|e| format!("cannot obtain public nonce entropy: {e}"))?
        .read_exact(&mut bytes)
        .map_err(|e| format!("cannot read public nonce entropy: {e}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
fn digest_required_file(root: &Path, relative: &str) -> Result<String, String> {
    let text = openspec_core::read_contained_capped(root, &root.join(relative), 16 * 1024 * 1024)
        .map_err(|e| format!("required first-adoption input {relative}: {e}"))?;
    Ok(Digest::of_bytes(text.as_bytes()).to_hex())
}

fn digest_validation_assets(root: &Path) -> Result<String, String> {
    let mut bytes = Vec::new();
    for path in [
        "security/policy/local-ci-policy.json",
        "security/sandbox/validation.bwrap",
        "security/sandbox/validation.sb",
        "security/semgrep/local-ci.yml",
    ] {
        let value = fs::read(root.join(path))
            .map_err(|e| format!("required validation asset {path}: {e}"))?;
        if value.is_empty() || value.len() > 4 * 1024 * 1024 {
            return Err(format!(
                "required validation asset is empty or oversized: {path}"
            ));
        }
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&value);
        bytes.push(0);
    }
    Ok(Digest::of_bytes(&bytes).to_hex())
}

#[cfg(test)]
fn digest_hook_sources(root: &Path) -> Result<String, String> {
    let mut bytes = Vec::new();
    for path in [".githooks/pre-commit", ".githooks/pre-push"] {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(
            &fs::read(root.join(path)).map_err(|e| format!("required hook source {path}: {e}"))?,
        );
        bytes.push(0);
    }
    Ok(Digest::of_bytes(&bytes).to_hex())
}

#[cfg(test)]
fn first_adoption_dir(root: &Path) -> Result<PathBuf, String> {
    let dir = first_adoption_dir_read_only(root)?;
    if fs::symlink_metadata(&dir).is_err() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create first-adoption state directory: {e}"))?;
    }
    let meta = fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("first-adoption state directory is unsafe".into());
    }
    protect_dir(&dir)?;
    Ok(dir)
}

fn policy_state_dir(root: &Path) -> Result<PathBuf, String> {
    let dir = git_common_dir(root)?.join(POLICY_STATE_DIR);
    if fs::symlink_metadata(&dir).is_err() {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create policy state directory: {e}"))?;
    }
    let metadata = fs::symlink_metadata(&dir).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("policy state directory is unsafe".into());
    }
    protect_dir(&dir)?;
    Ok(dir)
}

/// Resolve clone-private first-adoption state without creating it. Preview and
/// validation paths use this helper so a refused/read-only operation has no
/// filesystem side effect.
#[cfg(test)]
fn first_adoption_dir_read_only(root: &Path) -> Result<PathBuf, String> {
    let raw = git_output(root, &["rev-parse", "--git-common-dir"])?;
    let common = if Path::new(&raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        root.join(raw)
    };
    Ok(common.join(FIRST_ADOPTION_DIR))
}

#[cfg(test)]
fn capture_pretrust_protected_state(
    root: &Path,
    config: &LocalValidationConfig,
) -> Result<PretrustProtectedStateV1, String> {
    let head_oid = pretrust_git_output(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    validate_oid(&head_oid)?;
    let head_ref = pretrust_git_output(root, &["symbolic-ref", "--quiet", "HEAD"])?;
    let index_path = pretrust_git_output(root, &["rev-parse", "--git-path", "index"])?;
    let index_path = absolute_git_path(root, &index_path);
    let index_digest = digest_protected_file(&index_path)?;
    let refs = pretrust_git_output_bytes(
        root,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(objecttype)%00",
        ],
        16 * 1024 * 1024,
    )?;
    let refs_digest = Digest::of_bytes(&refs).to_hex();
    let config_path = absolute_git_path(
        root,
        &pretrust_git_output(root, &["rev-parse", "--git-path", "config"])?,
    );
    let local_config_digest = digest_protected_file(&config_path)?;
    let status = pretrust_git_output_bytes(
        root,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignored=no",
        ],
        64 * 1024 * 1024,
    )?;
    let source_status_digest = Digest::of_bytes(&status).to_hex();
    let common = absolute_git_path(
        root,
        &pretrust_git_output(root, &["rev-parse", "--git-common-dir"])?,
    );
    let default_hooks = common.join("hooks");
    let configured_hooks =
        pretrust_git_optional(root, &["config", "--local", "--get", "core.hooksPath"])?
            .map(|path| absolute_git_path(root, &path));
    let hooks_digest = digest_json(&(
        digest_validation_path(&default_hooks)?,
        configured_hooks
            .as_deref()
            .map(digest_validation_path)
            .transpose()?,
        digest_hook_sources(root)?,
    ))?;
    Ok(PretrustProtectedStateV1 {
        head_oid,
        head_ref,
        index_digest,
        refs_digest,
        local_config_digest,
        hooks_digest,
        source_status_digest,
        configured_graph_digest: Digest::of_bytes(&canonical_policy_bytes(config)?).to_hex(),
    })
}

#[cfg(test)]
fn pretrust_git_output(root: &Path, args: &[&str]) -> Result<String, String> {
    let bytes = pretrust_git_output_bytes(root, args, 1024 * 1024)?;
    String::from_utf8(bytes)
        .map(|value| value.trim().to_string())
        .map_err(|_| "pretrust Git metadata is non-UTF-8".into())
}

#[cfg(test)]
fn pretrust_git_optional(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = canonical_git(root, args, 1024 * 1024)?;
    if !output.success {
        return Ok(None);
    }
    let value =
        String::from_utf8(output.stdout).map_err(|_| "pretrust Git metadata is non-UTF-8")?;
    Ok((!value.trim().is_empty()).then(|| value.trim().to_string()))
}

#[cfg(test)]
fn pretrust_git_output_bytes(root: &Path, args: &[&str], cap: usize) -> Result<Vec<u8>, String> {
    let output = canonical_git(root, args, cap)?;
    if !output.success {
        return Err("pretrust Git inspection failed or exceeded its cap".into());
    }
    Ok(output.stdout)
}

#[cfg(test)]
fn absolute_git_path(root: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

#[cfg(test)]
fn digest_protected_file(path: &Path) -> Result<String, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(Digest::of_bytes(b"absent").to_hex())
        }
        Err(error) => Err(format!("cannot inspect protected state: {error}")),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("protected state path is not a regular file".into())
        }
        Ok(metadata) if metadata.len() > 64 * 1024 * 1024 => {
            Err("protected state file exceeds its cap".into())
        }
        Ok(_) => fs::read(path)
            .map(|bytes| Digest::of_bytes(&bytes).to_hex())
            .map_err(|e| format!("cannot read protected state: {e}")),
    }
}

#[cfg(test)]
fn digest_validation_path(path: &Path) -> Result<String, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(Digest::of_bytes(b"absent").to_hex())
        }
        Err(error) => Err(format!("cannot inspect hook state: {error}")),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("hook state root is a symlink".into())
        }
        Ok(metadata) if metadata.is_file() => digest_protected_file(path),
        Ok(metadata) if metadata.is_dir() => digest_json(&inventory_private_state(path)?),
        Ok(_) => Err("hook state root has unsupported type".into()),
    }
}

#[cfg(test)]
fn inventory_private_state(root: &Path) -> Result<BTreeMap<String, String>, String> {
    fn visit(
        root: &Path,
        relative: &Path,
        output: &mut BTreeMap<String, String>,
        total: &mut u64,
    ) -> Result<(), String> {
        let current = root.join(relative);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|e| format!("cannot inspect protected inventory: {e}"))?;
        if metadata.file_type().is_symlink() {
            return Err("protected inventory contains a symlink".into());
        }
        if metadata.is_dir() {
            if !relative.as_os_str().is_empty() {
                output.insert(
                    relative.to_string_lossy().into_owned(),
                    format!("dir:{:o}", mode_of(&metadata)),
                );
            }
            let mut children = fs::read_dir(&current)
                .map_err(|e| format!("cannot enumerate protected inventory: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("cannot enumerate protected inventory: {e}"))?;
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                visit(root, &relative.join(child.file_name()), output, total)?;
            }
        } else if metadata.is_file() {
            *total = total
                .checked_add(metadata.len())
                .ok_or("protected inventory byte overflow")?;
            if *total > 64 * 1024 * 1024 || output.len() >= 10_000 {
                return Err("protected inventory exceeds its cap".into());
            }
            output.insert(
                relative.to_string_lossy().into_owned(),
                format!(
                    "file:{:o}:{}:{}",
                    mode_of(&metadata),
                    metadata.len(),
                    digest_protected_file(&current)?
                ),
            );
        } else {
            return Err("protected inventory contains unsupported state".into());
        }
        Ok(())
    }
    let mut output = BTreeMap::new();
    let mut total = 0;
    visit(root, Path::new(""), &mut output, &mut total)?;
    Ok(output)
}

#[cfg(test)]
fn verify_exclusive_proof_effect(
    state: &Path,
    before: &BTreeMap<String, String>,
    proof_path: &Path,
    expected_bytes: &[u8],
) -> Result<(), String> {
    let relative = proof_path
        .strip_prefix(state)
        .map_err(|_| "pretrust proof escaped private state")?
        .to_string_lossy()
        .into_owned();
    let mut after = inventory_private_state(state)?;
    let proof_entry = after
        .remove(&relative)
        .ok_or("exclusive pretrust proof write was not observed")?;
    if &after != before {
        return Err("pretrust-private-state-mutated-outside-proof".into());
    }
    let metadata = fs::symlink_metadata(proof_path)
        .map_err(|e| format!("cannot inspect exclusive pretrust proof: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err("exclusive pretrust proof identity is unsafe".into());
        }
    }
    if fs::read(proof_path).map_err(|e| e.to_string())? != expected_bytes {
        return Err("exclusive pretrust proof bytes changed after creation".into());
    }
    if !proof_entry.starts_with("file:") {
        return Err("exclusive pretrust proof inventory entry is invalid".into());
    }
    Ok(())
}

#[cfg(test)]
fn remove_owned_proof(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect failed pretrust proof: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("failed pretrust proof is not safely removable".into());
    }
    fs::remove_file(path).map_err(|e| format!("cannot remove failed pretrust proof: {e}"))
}

#[cfg(test)]
fn write_owner_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err("first-adoption proof exceeds cap".into());
    }
    let parent = path.parent().ok_or("first-adoption proof has no parent")?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err("first-adoption proof directory is unsafe".into());
    }
    protect_dir(parent)?;
    if path.exists() {
        return Err("first-adoption proof path already exists".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot exclusively create pretrust proof: {e}"))?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    sync_parent_directory(parent)?;
    Ok(())
}

#[cfg(test)]
fn read_proof_by_digest(root: &Path, wanted: &str) -> Result<PretrustCheckpointProofV1, String> {
    crate::digest::Digest::from_hex(wanted)?;
    let proofs = first_adoption_dir_read_only(root)?.join("proofs");
    let mut found: Option<PretrustCheckpointProofV1> = None;
    for entry in fs::read_dir(&proofs).map_err(|_| "pretrust proof is unavailable")? {
        let entry = entry.map_err(|e| e.to_string())?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_POLICY_BYTES as u64
        {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|e| e.to_string())?;
        if Digest::of_bytes(&bytes).to_hex() == wanted {
            found =
                Some(serde_json::from_slice(&bytes).map_err(|_| "pretrust proof is malformed")?);
            break;
        }
    }
    let proof = found.ok_or("pretrust proof digest was not found")?;
    let observation = PretrustEffectObservationV1 {
        schema: 1,
        protected_before_digest: proof.protected_before_digest.clone(),
        protected_after_digest: proof.protected_after_digest.clone(),
        private_state_before_digest: proof.private_state_before_digest.clone(),
        private_state_after_without_proof_digest: proof
            .private_state_after_without_proof_digest
            .clone(),
        exclusive_write: proof.proof_relative_path.clone(),
        configured_checks_executed: proof.configured_checks_executed,
    };
    if proof.schema != PRETRUST_PROOF_SCHEMA
        || crate::digest::Digest::from_hex(&proof.nonce_digest).is_err()
        || proof.allowed_effect_digest != pretrust_allowed_effect_digest()
        || proof.observed_effect_digest != digest_json(&observation)?
        || proof.protected_before_digest != proof.protected_after_digest
        || proof.private_state_before_digest != proof.private_state_after_without_proof_digest
        || proof.configured_checks_executed != 0
        || proof.proof_relative_path != format!("proofs/{}.json", proof.nonce_digest)
    {
        return Err("pretrust proof is stale or has an invalid effect contract".into());
    }
    Ok(proof)
}

/// Read-only proof invalidation check for an explicit restart. The digest must
/// resolve to the original bounded proof and bind exactly the checkpoint being
/// superseded; no proof, directory, or other private state is created.
#[cfg(test)]
pub fn verify_restart_superseded_proof(
    root: &Path,
    change: &str,
    checkpoint: &str,
    proof_digest: &str,
) -> Result<(), String> {
    let proof = read_proof_by_digest(root, proof_digest)?;
    if proof.change != change || proof.checkpoint_oid != checkpoint {
        return Err("restart proof does not bind the superseded checkpoint".into());
    }
    Ok(())
}

/// Install only clone-private coordinator and launchers after the trust CAS.
/// It is intentionally explicit and never called by bootstrap or validation.
/// The journal permits an interrupted operation to resume from a verified stage;
/// any drift restores the clone to trusted-but-inactive without touching the ref.
pub fn activate_reviewed_policy(
    root: &Path,
    commit: &str,
    confirmed_policy_digest: &str,
    coordinator: &Path,
    confirmed_coordinator_digest: &str,
    hooks: &Path,
) -> Result<ActivationJournalV1, String> {
    Digest::from_hex(confirmed_policy_digest)?;
    Digest::from_hex(confirmed_coordinator_digest)?;
    if hooks != Path::new(".githooks") {
        return Err("policy activation requires the exact tracked hooks path .githooks".into());
    }
    validate_oid(commit)?;
    let subject = capture_subject(root, Some(commit))?;
    if subject.pushed_oid != commit
        || subject.pushed_kind != "commit"
        || !subject.tag_chain.is_empty()
    {
        return Err("policy activation requires one direct immutable commit object id".into());
    }
    let candidate = subject_local_validation(root, &subject)?;
    candidate.validate()?;
    let policy_bytes = canonical_policy_bytes(&candidate)?;
    if Digest::of_bytes(&policy_bytes).to_hex() != confirmed_policy_digest {
        return Err("confirmed policy digest does not match the immutable commit".into());
    }
    let assets = capture_subject_policy_assets(root, &subject)?;
    let profile = assets
        .get("security/sandbox/validation.sb")
        .ok_or("immutable policy omits the fixed macOS profile")?;
    #[cfg(target_os = "macos")]
    {
        if profile.bytes != crate::sandbox_macos::FIXED_PROFILE.as_bytes() {
            return Err(
                "immutable policy profile differs from the compiled exact-host contract".into(),
            );
        }
        crate::sandbox_macos::verify_certified_host()?;
        crate::sandbox_macos::probe_symbols()?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = profile;
        return Err("policy activation is not certified on this host".into());
    }
    for hook in [".githooks/pre-commit", ".githooks/pre-push"] {
        let asset = assets
            .get(hook)
            .ok_or_else(|| format!("immutable policy omits tracked wrapper {hook}"))?;
        if asset.metadata.mode != 0o100755 {
            return Err(format!(
                "tracked wrapper {hook} is not executable in the immutable commit"
            ));
        }
    }
    if !coordinator.is_absolute() {
        return Err("coordinator must be an absolute canonical path".into());
    }
    let input_metadata = fs::symlink_metadata(coordinator)
        .map_err(|error| format!("cannot inspect reviewed coordinator: {error}"))?;
    if input_metadata.file_type().is_symlink() || !input_metadata.is_file() {
        return Err("reviewed coordinator must be a no-follow regular file".into());
    }
    let canonical = fs::canonicalize(coordinator)
        .map_err(|error| format!("cannot canonicalize reviewed coordinator: {error}"))?;
    if canonical != coordinator {
        return Err("coordinator path must already be canonical".into());
    }
    if digest_file(&canonical)? != confirmed_coordinator_digest {
        return Err("confirmed executable digest does not match the reviewed coordinator".into());
    }

    let (tool_lock_digest, sandbox_digest, hook_digest) = policy_asset_digests(&assets)?;
    let mut proof_preimage = b"mpd:owner-policy-activation:v1\0".to_vec();
    for value in [
        commit,
        confirmed_policy_digest,
        confirmed_coordinator_digest,
        &hook_digest,
    ] {
        proof_preimage.extend_from_slice(value.as_bytes());
        proof_preimage.push(0);
    }
    let activation_proof_digest = Digest::of_bytes(&proof_preimage).to_hex();
    let activation_confirmation_digest = Digest::of_bytes(
        [
            b"mpd:owner-policy-confirmation:v1\0".as_slice(),
            &proof_preimage,
        ]
        .concat()
        .as_slice(),
    )
    .to_hex();

    let current_oid = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?;
    let current_bundle = current_oid
        .as_deref()
        .map(|oid| read_trusted_policy_bundle(root, oid))
        .transpose()?;
    let same_reviewed_policy = current_bundle.as_ref().is_some_and(|bundle| {
        bundle.object.local_validation == candidate
            && bundle.object.assets == policy_asset_metadata(&assets)
            && bundle.assets == assets
            && bundle.object.checkpoint_oid == commit
            && bundle.object.pretrust_proof_digest == activation_proof_digest
            && bundle.object.bootstrap_nonce_digest == activation_confirmation_digest
            && bundle.object.coordinator_digest == confirmed_coordinator_digest
    });
    let trusted_policy_oid = if same_reviewed_policy {
        current_oid.clone().ok_or("trusted policy disappeared")?
    } else {
        let object = TrustedPolicyObjectV1 {
            schema: 1,
            local_validation: candidate,
            asset_schema: POLICY_ASSET_SCHEMA,
            assets: policy_asset_metadata(&assets),
            previous_trusted_policy_oid: current_oid.clone(),
            checkpoint_oid: commit.to_string(),
            pretrust_proof_digest: activation_proof_digest,
            bootstrap_nonce_digest: activation_confirmation_digest,
            coordinator_digest: confirmed_coordinator_digest.to_string(),
            hook_digest,
            tool_lock_digest,
            sandbox_digest,
        };
        let new_oid = write_policy_commit(root, &object, &assets)?;
        let expected_old = current_oid
            .clone()
            .unwrap_or_else(|| "0".repeat(new_oid.len()));
        let status = canonical_git(
            root,
            &[
                "update-ref",
                "--no-deref",
                TRUSTED_POLICY_REF,
                &new_oid,
                &expected_old,
            ],
            0,
        )?;
        if !status.success {
            return Err("policy activation CAS lost; no hook or configuration was changed".into());
        }
        new_oid
    };
    let trusted = read_trusted_policy_object(root, &trusted_policy_oid)?;
    let trusted_digest =
        Digest::of_bytes(&serde_json::to_vec(&trusted).map_err(|error| error.to_string())?)
            .to_hex();
    activate_trusted_policy_inner(
        root,
        &trusted_digest,
        &canonical,
        confirmed_coordinator_digest,
        None,
    )
}

#[cfg(test)]
pub fn activate_trusted_policy(
    root: &Path,
    expected_policy_digest: &str,
    coordinator: &Path,
    expected_coordinator_digest: &str,
) -> Result<ActivationJournalV1, String> {
    activate_trusted_policy_inner(
        root,
        expected_policy_digest,
        coordinator,
        expected_coordinator_digest,
        None,
    )
}

fn shell_single_quote(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err("coordinator path cannot be represented safely in a hook wrapper".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn activate_trusted_policy_inner(
    root: &Path,
    expected_policy_digest: &str,
    coordinator: &Path,
    expected_coordinator_digest: &str,
    injected_failure_after: Option<ActivationStageV1>,
) -> Result<ActivationJournalV1, String> {
    crate::digest::Digest::from_hex(expected_policy_digest)?;
    crate::digest::Digest::from_hex(expected_coordinator_digest)?;
    let oid = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?
    .ok_or("trusted-policy-missing")?;
    let bundle = read_trusted_policy_bundle(root, &oid)?;
    let policy = bundle.object;
    let policy_digest =
        Digest::of_bytes(&serde_json::to_vec(&policy).map_err(|e| e.to_string())?).to_hex();
    if policy_digest != expected_policy_digest {
        return Err("expected policy digest does not match trusted policy object".into());
    }
    if policy.coordinator_digest != expected_coordinator_digest {
        return Err("expected coordinator digest does not match trusted policy".into());
    }
    let (_, _, trusted_hook_digest) = policy_asset_digests(&bundle.assets)?;
    if trusted_hook_digest != policy.hook_digest {
        return Err("trusted hook asset bytes are internally inconsistent".into());
    }
    let canonical = fs::canonicalize(coordinator)
        .map_err(|e| format!("cannot canonicalize reviewed coordinator: {e}"))?;
    if !canonical.is_absolute() {
        return Err("coordinator must be an absolute path".into());
    }
    let coordinator_bytes =
        fs::read(&canonical).map_err(|e| format!("cannot read reviewed coordinator: {e}"))?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || Digest::of_bytes(&coordinator_bytes).to_hex() != expected_coordinator_digest
    {
        return Err("reviewed coordinator digest changed".into());
    }
    let state = policy_state_dir(root)?;
    let journal_path = state.join("activation-journal.json");
    let trusted_hooks = git_common_dir(root)?.join("mpd/trusted-hooks");
    let installed_coordinator = trusted_hooks.join("mpd-coordinator");
    let new_journal = |prior_hooks_path| ActivationJournalV1 {
        schema: ACTIVATION_JOURNAL_SCHEMA,
        trusted_policy_oid: oid.clone(),
        trusted_policy_digest: policy_digest.clone(),
        reviewed_coordinator_digest: expected_coordinator_digest.to_string(),
        stage: ActivationStageV1::Prepared,
        prior_hooks_path,
        installed_path_digests: BTreeMap::new(),
        actor: "owner".into(),
        updated_at_epoch_secs: now_epoch_secs(),
    };
    let existing = read_activation_journal(&journal_path)?;
    let mut journal = match existing {
        None => new_journal(git_optional(
            root,
            &["config", "--local", "--get", "core.hooksPath"],
        )?),
        Some(journal)
            if journal.trusted_policy_oid == oid
                && journal.trusted_policy_digest == policy_digest
                && journal.reviewed_coordinator_digest == expected_coordinator_digest =>
        {
            journal
        }
        Some(journal) => {
            verify_completed_activation_for_replacement(root, &trusted_hooks, &journal)?;
            new_journal(journal.prior_hooks_path)
        }
    };
    if journal.trusted_policy_oid != oid
        || journal.trusted_policy_digest != policy_digest
        || journal.reviewed_coordinator_digest != expected_coordinator_digest
    {
        return Err("activation journal belongs to different trusted policy".into());
    }
    let result = (|| -> Result<(), String> {
        write_activation_journal(&journal_path, &journal)?;
        maybe_inject_activation_failure(&injected_failure_after, &journal.stage)?;
        journal.stage = ActivationStageV1::TrustedInactive;
        journal.updated_at_epoch_secs = now_epoch_secs();
        write_activation_journal(&journal_path, &journal)?;
        maybe_inject_activation_failure(&injected_failure_after, &journal.stage)?;
        fs::create_dir_all(&trusted_hooks).map_err(|e| e.to_string())?;
        protect_dir(&trusted_hooks)?;
        journal.stage = ActivationStageV1::LauncherStaged;
        journal.updated_at_epoch_secs = now_epoch_secs();
        write_activation_journal(&journal_path, &journal)?;
        maybe_inject_activation_failure(&injected_failure_after, &journal.stage)?;
        replace_owned_file(&installed_coordinator, &coordinator_bytes, 0o500)?;
        if Digest::of_bytes(&fs::read(&installed_coordinator).map_err(|e| e.to_string())?).to_hex()
            != expected_coordinator_digest
        {
            return Err("installed coordinator digest mismatch".into());
        }
        journal.installed_path_digests.insert(
            "mpd-coordinator".into(),
            expected_coordinator_digest.to_string(),
        );
        journal.stage = ActivationStageV1::CoordinatorInstalled;
        journal.updated_at_epoch_secs = now_epoch_secs();
        write_activation_journal(&journal_path, &journal)?;
        maybe_inject_activation_failure(&injected_failure_after, &journal.stage)?;
        for (hook, subcommand) in [("pre-commit", "pre-commit"), ("pre-push", "pre-push")] {
            let installed = installed_coordinator
                .to_str()
                .ok_or("installed coordinator path is not UTF-8")?;
            let bytes = format!(
                "#!/bin/sh\nexec {} hook {} \"$@\"\n",
                shell_single_quote(installed)?,
                subcommand
            )
            .into_bytes();
            let path = trusted_hooks.join(hook);
            replace_owned_file(&path, &bytes, 0o500)?;
            journal
                .installed_path_digests
                .insert(hook.into(), Digest::of_bytes(&bytes).to_hex());
        }
        journal.stage = ActivationStageV1::HooksInstalled;
        journal.updated_at_epoch_secs = now_epoch_secs();
        write_activation_journal(&journal_path, &journal)?;
        maybe_inject_activation_failure(&injected_failure_after, &journal.stage)?;
        let absolute_hooks = fs::canonicalize(&trusted_hooks).map_err(|e| e.to_string())?;
        let status = canonical_git(
            root,
            &[
                "config",
                "--local",
                "core.hooksPath",
                absolute_hooks
                    .to_str()
                    .ok_or("non-UTF-8 trusted hooks path")?,
            ],
            0,
        )?;
        if !status.success {
            return Err("cannot configure absolute trusted core.hooksPath".into());
        }
        journal.stage = ActivationStageV1::HooksPathSet;
        journal.updated_at_epoch_secs = now_epoch_secs();
        write_activation_journal(&journal_path, &journal)?;
        maybe_inject_activation_failure(&injected_failure_after, &journal.stage)?;
        if git_optional(root, &["config", "--local", "--get", "core.hooksPath"])?
            != Some(absolute_hooks.display().to_string())
        {
            return Err(
                "trusted core.hooksPath did not persist as the absolute private path".into(),
            );
        }
        for (name, expected) in &journal.installed_path_digests {
            if !matches!(name.as_str(), "mpd-coordinator" | "pre-commit" | "pre-push")
                || Digest::of_bytes(&fs::read(trusted_hooks.join(name)).map_err(|e| e.to_string())?)
                    .to_hex()
                    != *expected
            {
                return Err("installed activation bytes drifted".into());
            }
        }
        journal.stage = ActivationStageV1::VerifiedActive;
        journal.updated_at_epoch_secs = now_epoch_secs();
        write_activation_journal(&journal_path, &journal)?;
        maybe_inject_activation_failure(&injected_failure_after, &journal.stage)?;
        Ok(())
    })();
    if let Err(error) = result {
        rollback_activation(root, &trusted_hooks, &installed_coordinator, &journal)?;
        journal.stage = ActivationStageV1::TrustedInactive;
        journal.installed_path_digests.clear();
        journal.updated_at_epoch_secs = now_epoch_secs();
        write_activation_journal(&journal_path, &journal)?;
        return Err(error);
    }
    Ok(journal)
}

fn verify_completed_activation_for_replacement(
    root: &Path,
    trusted_hooks: &Path,
    journal: &ActivationJournalV1,
) -> Result<(), String> {
    if journal.schema != ACTIVATION_JOURNAL_SCHEMA
        || journal.stage != ActivationStageV1::VerifiedActive
        || journal.installed_path_digests.len() != 3
    {
        return Err("activation journal belongs to different incomplete policy".into());
    }
    let canonical_hooks = fs::canonicalize(trusted_hooks)
        .map_err(|_| "completed activation hook directory is unavailable")?;
    if git_optional(root, &["config", "--local", "--get", "core.hooksPath"])?
        != Some(canonical_hooks.display().to_string())
    {
        return Err("completed activation hooksPath drifted before replacement".into());
    }
    for name in ["mpd-coordinator", "pre-commit", "pre-push"] {
        let expected = journal
            .installed_path_digests
            .get(name)
            .ok_or("completed activation journal inventory is incomplete")?;
        let path = canonical_hooks.join(name);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "completed activation file is unavailable")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("completed activation file is unsafe".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0
                || metadata.permissions().mode() & 0o100 == 0
            {
                return Err("completed activation file mode drifted".into());
            }
        }
        if digest_file(&path)? != *expected {
            return Err("completed activation file bytes drifted".into());
        }
    }
    Ok(())
}

fn maybe_inject_activation_failure(
    injected: &Option<ActivationStageV1>,
    stage: &ActivationStageV1,
) -> Result<(), String> {
    if injected.as_ref() == Some(stage) {
        Err(format!("injected-activation-failure-after-{stage:?}"))
    } else {
        Ok(())
    }
}

pub(crate) fn git_common_dir(root: &Path) -> Result<PathBuf, String> {
    let raw = git_output(root, &["rev-parse", "--git-common-dir"])?;
    Ok(if Path::new(&raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        root.join(raw)
    })
}

fn read_activation_journal(path: &Path) -> Result<Option<ActivationJournalV1>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_POLICY_BYTES as u64 {
        return Err("activation journal is unsafe".into());
    }
    Ok(Some(
        serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|_| "activation journal is malformed")?,
    ))
}
fn write_activation_journal(path: &Path, journal: &ActivationJournalV1) -> Result<(), String> {
    replace_owned_file(
        path,
        &serde_json::to_vec(journal).map_err(|e| e.to_string())?,
        0o600,
    )
}
fn replace_owned_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("owned state target has no parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err("owned state directory is unsafe".into());
    }
    protect_dir(parent)?;
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("refusing to replace non-regular owned state".into());
        }
    }
    let temp = parent.join(format!(
        ".{}.mpd-tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("non-UTF-8 owned file")?,
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temp).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    }
    fs::rename(&temp, path).map_err(|e| e.to_string())?;
    Ok(())
}
fn rollback_activation(
    root: &Path,
    hooks: &Path,
    coordinator: &Path,
    journal: &ActivationJournalV1,
) -> Result<(), String> {
    for path in [
        hooks.join("pre-commit"),
        hooks.join("pre-push"),
        coordinator.to_path_buf(),
    ] {
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.is_file() && !meta.file_type().is_symlink() {
                fs::remove_file(path).map_err(|e| e.to_string())?;
            }
        }
    }
    match &journal.prior_hooks_path {
        Some(previous) => {
            let status =
                canonical_git(root, &["config", "--local", "core.hooksPath", previous], 0)?;
            if !status.success {
                return Err("cannot restore prior core.hooksPath".into());
            }
        }
        None => {
            let status = canonical_git(
                root,
                &["config", "--local", "--unset-all", "core.hooksPath"],
                0,
            )?;
            if !status.success && status.code != Some(5) {
                return Err("cannot clear partial core.hooksPath".into());
            }
        }
    }
    Ok(())
}
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Re-open all posttrust bytes before the sole Build rewind. This accepts the
/// proof digest, never a raw nonce, and performs no Git/config mutation.
#[cfg(test)]
pub fn verify_first_adoption_reconciliation(
    root: &Path,
    change: &str,
    checkpoint: &str,
    policy_object: &str,
    pretrust_proof_digest: &str,
    security_evidence: &str,
) -> Result<PretrustCheckpointProofV1, String> {
    validate_oid(checkpoint)?;
    validate_oid(policy_object)?;
    let current = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?
    .ok_or("trusted-policy-missing")?;
    if current != policy_object {
        return Err("trusted policy ref no longer matches the requested policy object".into());
    }
    let policy = read_trusted_policy_object(root, &current)?;
    let proof = read_proof_by_digest(root, pretrust_proof_digest)?;
    if proof.change != change
        || proof.checkpoint_oid != checkpoint
        || policy.checkpoint_oid != checkpoint
        || policy.pretrust_proof_digest != pretrust_proof_digest
        || policy.bootstrap_nonce_digest != proof.nonce_digest
    {
        return Err("posttrust proof/policy/checkpoint bindings differ".into());
    }
    let evidence_path = openspec_core::Project::new(root)
        .change_dir(change)
        .join(security_evidence);
    let evidence = openspec_core::read_contained_capped(root, &evidence_path, 1024 * 1024)
        .map_err(|e| format!("invalid first-adoption security evidence: {e}"))?;
    if Digest::of_bytes(evidence.as_bytes()).to_hex() != proof.security_evidence_digest {
        return Err("Security(code) evidence changed after pretrust proof".into());
    }
    verify_scope_against_checkpoint(root, &proof.checkpoint_scope, checkpoint)?;
    if Digest::of_bytes(&canonical_policy_bytes(&policy.local_validation)?).to_hex()
        != proof.candidate_policy_digest
        || digest_required_file(root, "security/tool-lock.json")? != proof.tool_lock_digest
        || digest_validation_assets(root)? != proof.sandbox_digest
        || digest_hook_sources(root)? != proof.hook_digest
    {
        return Err("reviewed policy/tool/sandbox/hook bytes drifted".into());
    }
    let journal_path = first_adoption_dir(root)?.join("activation-journal.json");
    let journal = read_activation_journal(&journal_path)?
        .ok_or("trusted policy is inactive: activation journal missing")?;
    let policy_digest =
        Digest::of_bytes(&serde_json::to_vec(&policy).map_err(|e| e.to_string())?).to_hex();
    if journal.stage != ActivationStageV1::VerifiedActive
        || journal.trusted_policy_oid != current
        || journal.trusted_policy_digest != policy_digest
        || journal.reviewed_coordinator_digest != proof.coordinator_digest
    {
        return Err("trusted policy activation is incomplete or stale".into());
    }
    let hooks = git_common_dir(root)?.join("mpd/trusted-hooks");
    let active = git_optional(root, &["config", "--local", "--get", "core.hooksPath"])?
        .ok_or("trusted core.hooksPath is absent")?;
    if Path::new(&active) != hooks {
        return Err(
            "trusted core.hooksPath does not name the clone-private hooks directory".into(),
        );
    }
    for (name, expected) in &journal.installed_path_digests {
        if Digest::of_bytes(&fs::read(hooks.join(name)).map_err(|e| e.to_string())?).to_hex()
            != *expected
        {
            return Err("active coordinator or hook bytes drifted".into());
        }
    }
    Ok(proof)
}

/// Capture a peeled local commit and tree without interpreting a revision as a
/// shell expression. Git performs the revision grammar; output is validated as
/// a full hexadecimal object id before it is returned to callers.
pub fn capture_subject(root: &Path, requested: Option<&str>) -> Result<Subject, String> {
    let requested = requested.unwrap_or("HEAD");
    if requested.len() > 512 || requested.bytes().any(|b| b.is_ascii_control()) {
        return Err("invalid validation subject token".into());
    }
    let pushed_oid = git_output(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{requested}^{{object}}"),
        ],
    )?;
    validate_oid(&pushed_oid)?;
    let (pushed_kind, tag_chain, commit) = resolve_composite_subject(root, &pushed_oid)?;
    let tree = git_output(
        root,
        &["show", "-s", "--format=%T", "--end-of-options", &commit],
    )?;
    validate_oid(&tree)?;
    Ok(Subject {
        requested: requested.to_string(),
        pushed_oid,
        pushed_kind,
        tag_chain,
        commit,
        tree,
    })
}

fn resolve_composite_subject(
    root: &Path,
    pushed_oid: &str,
) -> Result<(String, Vec<TagChainEntryV1>, String), String> {
    validate_oid(pushed_oid)?;
    let pushed_kind = git_object_type(root, pushed_oid)?;
    let mut current = pushed_oid.to_string();
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total_bytes = 0_u64;
    loop {
        if !seen.insert(current.clone()) {
            return Err("malformed-tag-chain: repeated tag object".into());
        }
        match git_object_type(root, &current)?.as_str() {
            "commit" => return Ok((pushed_kind, chain, current)),
            "tag" => {
                if chain.len() == MAX_TAG_DEPTH {
                    return Err("resource-limit: annotated tag depth exceeds 16".into());
                }
                let size = git_object_size(root, &current)?;
                if size > MAX_TAG_OBJECT_BYTES {
                    return Err("object-too-large: annotated tag exceeds 1 MiB".into());
                }
                total_bytes = total_bytes
                    .checked_add(size)
                    .ok_or("resource-limit: annotated tag chain byte overflow")?;
                if total_bytes > MAX_TAG_CHAIN_BYTES {
                    return Err("resource-limit: annotated tag chain exceeds 16 MiB".into());
                }
                let bytes = git_object_bytes(root, &current, size)?;
                let (target_oid, target_kind) = parse_tag_header(&bytes)?;
                let actual_kind = git_object_type(root, &target_oid)?;
                if target_kind != actual_kind {
                    return Err("malformed-tag-chain: declared target kind differs".into());
                }
                chain.push(TagChainEntryV1 {
                    oid: current,
                    target_oid: target_oid.clone(),
                    target_kind,
                });
                current = target_oid;
            }
            "tree" | "blob" => return Err("unsupported-push-object".into()),
            _ => return Err("unsupported-push-object".into()),
        }
    }
}

fn parse_tag_header(bytes: &[u8]) -> Result<(String, String), String> {
    let header_end = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or("malformed-tag-chain: tag header is unterminated")?;
    if header_end > MAX_TAG_HEADER_BYTES {
        return Err("object-too-large: annotated tag header exceeds 64 KiB".into());
    }
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "malformed-tag-chain: tag header is not UTF-8")?;
    let mut target_oid = None;
    let mut target_kind = None;
    for line in header.lines() {
        if let Some(value) = line.strip_prefix("object ") {
            if target_oid.replace(value.to_string()).is_some() {
                return Err("malformed-tag-chain: duplicate object header".into());
            }
        } else if let Some(value) = line.strip_prefix("type ") {
            if target_kind.replace(value.to_string()).is_some() {
                return Err("malformed-tag-chain: duplicate type header".into());
            }
        }
    }
    let target_oid = target_oid.ok_or("malformed-tag-chain: object header is missing")?;
    validate_oid(&target_oid)?;
    let target_kind = target_kind.ok_or("malformed-tag-chain: type header is missing")?;
    if !matches!(target_kind.as_str(), "tag" | "commit" | "tree" | "blob") {
        return Err("malformed-tag-chain: unsupported declared target kind".into());
    }
    Ok((target_oid, target_kind))
}

/// Parse, validate, and bind policy data without executing it. A missing trusted
/// ref is intentionally a bootstrap blocker, not an implicit first trust root.
pub fn preflight(
    root: &Path,
    requested: Option<&str>,
    _config: &LocalValidationConfig,
) -> Result<PolicyPreflight, String> {
    let subject = capture_subject(root, requested)?;
    let config = subject_local_validation(root, &subject)?;
    config.validate()?;
    let adapter_path = match std::env::consts::OS {
        "macos" => None,
        "linux" => ["/usr/bin/bwrap", "/usr/bin/bubblewrap"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .find(|path| path.is_file()),
        _ => None,
    };
    let _adapter =
        crate::sandbox::SandboxAdapter::select(std::env::consts::OS, root, adapter_path)?;
    // Selection proves only the fixed host/profile/SPI contract. Exact roots
    // and canaries are deliberately rebuilt for every real validation run.
    let canonical = canonical_policy_bytes(&config)?;
    let candidate_policy_digest = Digest::of_bytes(&canonical).to_hex();
    let trusted_policy_oid = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", TRUSTED_POLICY_REF],
    )?;
    let (trusted_policy_digest, blocker) = match trusted_policy_oid.as_deref() {
        None => (
            None,
            Some(
                "trusted-policy-missing: run the exact digest-confirmed `mpd policy activate` command; validation will not execute candidate policy".into(),
            ),
        ),
        Some(oid) => {
            validate_oid(oid)?;
            let trusted = read_trusted_policy_bundle(root, oid)?;
            let bytes = canonical_policy_bytes(&trusted.object.local_validation)?;
            let digest = Digest::of_bytes(
                &serde_json::to_vec(&trusted.object).map_err(|e| e.to_string())?,
            )
            .to_hex();
            let subject_assets = capture_subject_policy_assets(root, &subject)?;
            let blocker = if bytes != canonical {
                Some(
                    "policy-approval-required: candidate local_validation differs from the clone-local trusted policy; validation will not execute candidate policy".into(),
                )
            } else if policy_asset_metadata(&subject_assets) != trusted.object.assets {
                Some(
                    "policy-approval-required: exact subject executable/hook/rule/sandbox/offline/tool-lock assets differ from the trusted policy; validation will not execute candidate policy".into(),
                )
            } else {
                None
            };
            (Some(digest), blocker)
        }
    };
    Ok(PolicyPreflight {
        subject,
        candidate_policy_digest,
        trusted_policy_oid,
        trusted_policy_digest,
        blocker,
    })
}

fn subject_local_validation(
    root: &Path,
    subject: &Subject,
) -> Result<LocalValidationConfig, String> {
    let bytes = subject_file_bytes(root, subject, ".mpd/config.json", MAX_POLICY_BYTES)?;
    let config: crate::config::Config = serde_json::from_slice(&bytes)
        .map_err(|e| format!("exact-subject .mpd/config.json is malformed: {e}"))?;
    config.local_validation.ok_or_else(|| {
        "exact-subject structured local_validation is absent; legacy test cannot authorize validation"
            .into()
    })
}

fn subject_file_bytes(
    root: &Path,
    subject: &Subject,
    path: &str,
    cap: usize,
) -> Result<Vec<u8>, String> {
    if path.is_empty()
        || Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("unsafe exact-subject policy path".into());
    }
    let expression = format!("{}:{path}", subject.commit);
    let oid = git_output(
        root,
        &["rev-parse", "--verify", "--end-of-options", &expression],
    )?;
    validate_oid(&oid)?;
    if git_output(root, &["cat-file", "-t", "--", &oid])? != "blob" {
        return Err(format!("exact-subject policy input is not a blob: {path}"));
    }
    let size = git_output(root, &["cat-file", "-s", "--", &oid])?
        .parse::<usize>()
        .map_err(|_| format!("invalid exact-subject policy size: {path}"))?;
    if size == 0 || size > cap {
        return Err(format!(
            "exact-subject policy input exceeds its cap: {path}"
        ));
    }
    let output = canonical_git(root, &["cat-file", "blob", "--", &oid], size)?;
    if !output.success || output.stdout.len() != size {
        return Err(format!(
            "cannot read exact-subject policy input exactly: {path}"
        ));
    }
    Ok(output.stdout)
}

/// Read a trusted policy only when the OID names the canonical commit/tree
/// bundle. Legacy blob-only roots lack the reviewed asset bytes and therefore
/// fail closed.
#[cfg(test)]
fn read_trusted_policy_bytes(root: &Path, oid: &str) -> Result<(Vec<u8>, String), String> {
    let kind = git_output(root, &["cat-file", "-t", "--", oid])?;
    if kind == "commit" {
        let bundle = read_trusted_policy_bundle(root, oid)?;
        let bytes = canonical_policy_bytes(&bundle.object.local_validation)?;
        let object_bytes = serde_json::to_vec(&bundle.object).map_err(|e| e.to_string())?;
        return Ok((bytes, Digest::of_bytes(&object_bytes).to_hex()));
    }
    Err("trusted-policy-invalid: legacy policy object has no reviewed asset bundle".into())
}

/// Canonical digest of the trusted policy object currently named by `oid`.
/// This is the posttrust reconciliation binding, not the proof digest.
#[cfg(test)]
pub fn trusted_policy_object_digest(root: &Path, oid: &str) -> Result<String, String> {
    read_trusted_policy_bytes(root, oid).map(|(_, digest)| digest)
}

/// Validate one line of Git's pre-push wire protocol. Git specifies the order
/// as `local-ref local-oid remote-ref remote-oid`, not the more intuitive
/// object-first order. It is intentionally byte constrained: exactly four
/// space-separated fields, LF terminated by the caller, and no tabs/CR/control
/// bytes. Ref names are display-only and never executed.
#[allow(dead_code)] // activated by the clone-private pre-push coordinator slice
pub fn parse_pre_push_record(line: &[u8]) -> Result<PushRecord, String> {
    if line.is_empty()
        || line.len() > 4096
        || line
            .iter()
            .any(|b| *b == b'\r' || *b == b'\t' || (*b < 0x20 && *b != b' '))
    {
        return Err("malformed pre-push record".into());
    }
    let fields: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
    if fields.len() != 4 || fields.iter().any(|f| f.is_empty()) {
        return Err("pre-push record must contain exactly four fields".into());
    }
    let local_ref = std::str::from_utf8(fields[0])
        .map_err(|_| "non-UTF-8 pre-push ref")?
        .to_string();
    let local_oid = std::str::from_utf8(fields[1])
        .map_err(|_| "non-UTF-8 pre-push oid")?
        .to_string();
    let remote_ref = std::str::from_utf8(fields[2])
        .map_err(|_| "non-UTF-8 pre-push ref")?
        .to_string();
    let remote_oid = std::str::from_utf8(fields[3])
        .map_err(|_| "non-UTF-8 pre-push oid")?
        .to_string();
    if local_ref == "(delete)" {
        if local_oid.chars().any(|c| c != '0') {
            return Err("delete record must use an all-zero local oid".into());
        }
    } else {
        validate_oid(&local_oid)?;
        if is_zero_oid(&local_oid) {
            return Err("non-delete record must use a nonzero local oid".into());
        }
    }
    validate_oid(&remote_oid)?;
    if local_ref == "(delete)" && is_zero_oid(&remote_oid) {
        return Err("delete record must name a nonzero remote oid".into());
    }
    Ok(PushRecord {
        local_oid,
        local_ref,
        remote_oid,
        remote_ref,
    })
}

/// Parse the complete pre-push stdin stream. A missing terminal LF, oversized
/// batch, blank line, duplicate update, or malformed record is a hard blocker;
/// callers receive no partial record set that could later be mistaken for a
/// complete authorization subject.
#[allow(dead_code)] // activated by the clone-private pre-push coordinator slice
pub fn parse_pre_push_records(input: &[u8]) -> Result<Vec<PushRecord>, String> {
    if input.is_empty() || input.len() > MAX_PUSH_BYTES || !input.ends_with(b"\n") {
        return Err("malformed pre-push batch".into());
    }
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for line in input[..input.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err("malformed pre-push batch contains an empty record".into());
        }
        if out.len() == MAX_PUSH_RECORDS {
            return Err("pre-push batch exceeds the record cap".into());
        }
        let record = parse_pre_push_record(line)?;
        let key = format!(
            "{}\0{}\0{}\0{}",
            record.local_ref, record.local_oid, record.remote_ref, record.remote_oid
        );
        if !seen.insert(key) {
            return Err("pre-push batch contains a duplicate update".into());
        }
        out.push(record);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRecord {
    pub local_oid: String,
    pub local_ref: String,
    pub remote_oid: String,
    pub remote_ref: String,
}

/// One fully resolved non-deletion update.  The outer object and every
/// annotated tag are part of its identity; a receipt for only the peeled
/// commit must never accidentally authorize a tag message that was not
/// inspected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PushSubject {
    pub local_oid: String,
    pub peeled_commit: String,
    pub tree_oid: String,
    pub tag_chain: Vec<TagChainEntryV1>,
}

/// Authorization for exactly one invocation of Git's pre-push protocol. It is
/// never consulted to authorize a later push. A clone-private audit copy lets
/// status report authorization separately from later transport/parity facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushAuthorizationV1 {
    pub schema: u32,
    pub authorization_id: String,
    pub invocation_nonce: String,
    pub authorized_at_epoch_secs: u64,
    pub remote_name: String,
    pub remote_location_digest: String,
    pub updates: Vec<PushRecord>,
    pub baseline_digest: String,
    pub updates_digest: String,
    pub subjects_digest: String,
    pub object_set_digest: String,
    pub object_count: usize,
    pub object_bytes: u64,
    pub deletion_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_approval_digest: Option<String>,
    pub scanner_digest: String,
    pub rules_digest: String,
    pub trusted_policy_digest: String,
    pub effective_policy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionApprovalV1 {
    pub schema: u32,
    pub id: String,
    pub nonce: String,
    pub remote_name: String,
    pub remote_location_digest: String,
    pub remote_ref: String,
    pub old_oid: String,
    pub policy_digest: String,
    pub created_epoch_secs: u64,
}

#[derive(Debug, Clone)]
struct OutgoingObject {
    oid: String,
    kind: String,
    size: u64,
}

pub fn create_deletion_approval(
    root: &Path,
    remote_name: &str,
    remote_location: &str,
    remote_ref: &str,
    old_oid: &str,
    config: &LocalValidationConfig,
) -> Result<DeletionApprovalV1, String> {
    validate_hook_argument(remote_name, "remote name")?;
    validate_hook_argument(remote_location, "remote location")?;
    validate_deletable_ref(remote_ref)?;
    validate_oid(old_oid)?;
    if is_zero_oid(old_oid) {
        return Err("deletion approval requires a nonzero advertised old oid".into());
    }
    require_remote_baseline(root, old_oid)?;
    doctor_activation_health(root)?;
    let preflight = preflight(root, None, config)?;
    if let Some(blocker) = preflight.blocker {
        return Err(format!("deletion approval blocked: {blocker}"));
    }
    let policy_digest = preflight.candidate_policy_digest;
    let remote_location_digest = Digest::of_bytes(remote_location.as_bytes()).to_hex();
    let (pending, consumed) = deletion_approval_directories(root, true)?;
    let mut existing = read_pending_deletion_approvals(&pending)?;
    if let Some(approval) = existing.iter().find(|approval| {
        approval.remote_name == remote_name
            && approval.remote_location_digest == remote_location_digest
            && approval.remote_ref == remote_ref
            && approval.old_oid == old_oid
            && approval.policy_digest == policy_digest
    }) {
        return Ok(approval.clone());
    }
    if existing.len() >= MAX_DELETION_APPROVALS {
        return Err("deletion approval count exceeds its cap".into());
    }
    let mut approval = DeletionApprovalV1 {
        schema: 1,
        id: String::new(),
        nonce: random_hex_nonce()?,
        remote_name: remote_name.into(),
        remote_location_digest,
        remote_ref: remote_ref.into(),
        old_oid: old_oid.into(),
        policy_digest,
        created_epoch_secs: epoch_secs()?,
    };
    approval.id = deletion_approval_id(&approval)?;
    let path = pending.join(format!("{}.json", approval.id));
    write_exclusive_private_file(
        &path,
        &serde_json::to_vec(&approval).map_err(|error| error.to_string())?,
    )?;
    // Ensure the destination namespace exists before an eventual hook-time
    // atomic consume; approval creation is the only operation allowed to
    // create these directories.
    protect_dir(&consumed)?;
    existing.clear();
    Ok(approval)
}

fn consume_deletion_approval(
    root: &Path,
    remote_name: &str,
    remote_location: &str,
    record: &PushRecord,
    policy_digest: &str,
) -> Result<String, String> {
    let (pending, consumed) = deletion_approval_directories(root, false)?;
    let remote_location_digest = Digest::of_bytes(remote_location.as_bytes()).to_hex();
    let mut matches = read_pending_deletion_approvals(&pending)?
        .into_iter()
        .filter(|approval| {
            approval.remote_name == remote_name
                && approval.remote_location_digest == remote_location_digest
                && approval.remote_ref == record.remote_ref
                && approval.old_oid == record.remote_oid
                && approval.policy_digest == policy_digest
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(if matches.is_empty() {
            "deletion-approval-missing: create one exact one-use approval and retry".into()
        } else {
            "deletion-approval-ambiguous: remove duplicate pending approvals".into()
        });
    }
    let approval = matches.pop().unwrap();
    let source = pending.join(format!("{}.json", approval.id));
    let destination = consumed.join(format!("{}.json", approval.id));
    if fs::symlink_metadata(&destination).is_ok() {
        return Err("deletion-approval-replay: approval was already consumed".into());
    }
    fs::rename(&source, &destination)
        .map_err(|error| format!("deletion-approval-consume-failed: {error}"))?;
    Ok(approval.id)
}

fn validate_deletable_ref(reference: &str) -> Result<(), String> {
    if reference == "refs/heads/main" || reference.starts_with("refs/tags/") {
        return Err("protected-ref-deletion-denied: main and tags cannot be deleted".into());
    }
    if !crate::git::valid_branch_ref(reference) {
        return Err("deletion approval requires a valid non-main branch ref".into());
    }
    Ok(())
}

fn deletion_approval_directories(root: &Path, create: bool) -> Result<(PathBuf, PathBuf), String> {
    let base = if create {
        policy_state_dir(root)?.join("deletion-approvals")
    } else {
        git_common_dir(root)?
            .join(POLICY_STATE_DIR)
            .join("deletion-approvals")
    };
    let pending = base.join("pending");
    let consumed = base.join("consumed");
    if create {
        fs::create_dir_all(&pending).map_err(|error| error.to_string())?;
        fs::create_dir_all(&consumed).map_err(|error| error.to_string())?;
        protect_dir(&base)?;
        protect_dir(&pending)?;
        protect_dir(&consumed)?;
    }
    for directory in [&pending, &consumed] {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| "deletion approval state is missing or unsafe")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("deletion approval state is missing or unsafe".into());
        }
    }
    Ok((pending, consumed))
}

fn read_pending_deletion_approvals(directory: &Path) -> Result<Vec<DeletionApprovalV1>, String> {
    let mut approvals = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        if approvals.len() == MAX_DELETION_APPROVALS {
            return Err("deletion approval count exceeds its cap".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_DELETION_APPROVAL_BYTES
            || path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            return Err("deletion approval file is unsafe".into());
        }
        let approval: DeletionApprovalV1 =
            serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
                .map_err(|_| "deletion approval is malformed")?;
        if approval.schema != 1
            || approval.id != deletion_approval_id(&approval)?
            || path.file_stem().and_then(|value| value.to_str()) != Some(&approval.id)
        {
            return Err("deletion approval identity is invalid".into());
        }
        approvals.push(approval);
    }
    Ok(approvals)
}

fn deletion_approval_id(approval: &DeletionApprovalV1) -> Result<String, String> {
    let mut value = approval.clone();
    value.id.clear();
    digest_json(&value)
}

fn random_hex_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("cannot obtain push-authorization nonce: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn push_authorization_id(authorization: &PushAuthorizationV1) -> Result<String, String> {
    let mut payload = authorization.clone();
    payload.authorization_id.clear();
    digest_json(&payload)
}

fn push_authorization_audit_path(root: &Path) -> Result<PathBuf, String> {
    Ok(git_common_dir(root)?
        .join(POLICY_STATE_DIR)
        .join("last-push-authorization.json"))
}

fn save_push_authorization_audit(
    root: &Path,
    authorization: &PushAuthorizationV1,
) -> Result<(), String> {
    if authorization.schema != 1
        || authorization.authorization_id != push_authorization_id(authorization)?
        || authorization.updates.is_empty()
        || authorization.updates.len() > MAX_PUSH_RECORDS
    {
        return Err("push authorization audit identity is invalid".into());
    }
    let bytes = serde_json::to_vec(authorization)
        .map_err(|error| format!("cannot encode push authorization audit: {error}"))?;
    if bytes.len() as u64 > MAX_PUSH_AUTHORIZATION_AUDIT_BYTES {
        return Err("push authorization audit exceeds its byte cap".into());
    }
    replace_owned_file(&push_authorization_audit_path(root)?, &bytes, 0o600)
}

/// Read the most recent pre-push authorization audit. This is observation only:
/// the record is never accepted by the pre-push authorization path.
pub fn load_push_authorization_audit(root: &Path) -> Result<Option<PushAuthorizationV1>, String> {
    let path = push_authorization_audit_path(root)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect push authorization audit: {error}")),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_PUSH_AUTHORIZATION_AUDIT_BYTES
    {
        return Err("push authorization audit is unsafe".into());
    }
    let authorization: PushAuthorizationV1 =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|_| "push authorization audit is malformed")?;
    if authorization.schema != 1
        || authorization.authorization_id != push_authorization_id(&authorization)?
        || authorization.updates.is_empty()
        || authorization.updates.len() > MAX_PUSH_RECORDS
    {
        return Err("push authorization audit identity is invalid".into());
    }
    Ok(Some(authorization))
}

fn write_exclusive_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() as u64 > MAX_DELETION_APPROVAL_BYTES {
        return Err("deletion approval exceeds its byte cap".into());
    }
    let parent = path.parent().ok_or("deletion approval has no parent")?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("deletion approval parent is unsafe".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

/// Push-authorization domain-separation tags (not secrets — see Cond 6/15 of
/// `secret-fixture-hygiene`). Hoisted to `concat!`-built consts so the
/// compiled bytes — and therefore `push_authorization_id` — are unchanged
/// from the un-split byte-string literals they replace: `concat!` is
/// compile-time concatenation, so `OUTGOING_SCAN_TAG.as_bytes()` and
/// `SECRET_RULES_TAG.as_bytes()` produce identical bytes to before this
/// hoist. Pinned by
/// `push_authorization_digest_tags_are_pinned_to_their_pre_refactor_bytes`.
const OUTGOING_SCAN_TAG: &str = concat!("mpd-builtin-", "outgoing-secret-scan-v2");
const SECRET_RULES_TAG: &str = concat!("mpd-builtin-", "secret-rules-v1");

/// Authorize one complete pre-push invocation without mutating the repository.
/// `remote_name` and `remote_location` are bounded display context only: object
/// discovery comes solely from Git's supplied object names and local object
/// database, so neither string reaches Git as an argument.
pub fn authorize_pre_push(
    root: &Path,
    remote_name: &str,
    remote_location: &str,
    input: &[u8],
    config: &LocalValidationConfig,
) -> Result<PushAuthorizationV1, String> {
    validate_hook_argument(remote_name, "remote name")?;
    validate_hook_argument(remote_location, "remote location")?;
    let records = parse_pre_push_records(input)?;
    doctor_activation_health(root)?;
    let preflight = preflight(root, None, config)?;
    if let Some(blocker) = preflight.blocker {
        return Err(format!("pre-push blocked: {blocker}"));
    }
    let trusted_policy_digest = preflight
        .trusted_policy_digest
        .ok_or_else(|| "pre-push blocked: trusted-policy-invalid".to_string())?;
    let effective_policy_digest = preflight.candidate_policy_digest;
    let deletions = records
        .iter()
        .filter(|record| record.local_ref == "(delete)")
        .collect::<Vec<_>>();
    if deletions.len() > 1 {
        return Err("pre-push permits at most one separately approved deletion per batch".into());
    }
    for record in &deletions {
        validate_deletable_ref(&record.remote_ref)?;
        require_remote_baseline(root, &record.remote_oid)?;
    }
    let non_deletions: Vec<&PushRecord> = records
        .iter()
        .filter(|record| record.local_ref != "(delete)")
        .collect();

    let mut subjects = Vec::new();
    let mut subject_seen = std::collections::BTreeSet::new();
    let mut objects = std::collections::BTreeSet::new();
    let mut enumerated_bytes = 0usize;
    for record in &non_deletions {
        require_remote_baseline(root, &record.remote_oid)?;
        let subject = resolve_push_subject(root, &record.local_oid)?;
        let key = digest_json(&subject)?;
        if subject_seen.insert(key) {
            subjects.push(subject.clone());
        }
        let (update_objects, update_bytes) =
            enumerate_update_objects(root, &record.local_oid, &record.remote_oid)?;
        enumerated_bytes = enumerated_bytes
            .checked_add(update_bytes)
            .ok_or("outgoing-enumeration-cap-exceeded")?;
        if enumerated_bytes > MAX_PUSH_ENUM_TOTAL_BYTES {
            return Err("outgoing-enumeration-cap-exceeded".into());
        }
        for oid in update_objects {
            objects.insert(oid);
        }
        // rev-list follows an annotated tag but does not promise to report every
        // tag object itself. Tag messages are transferred objects too.
        for tag in subject.tag_chain {
            objects.insert(tag.oid);
        }
    }
    if objects.len() > MAX_PUSH_OBJECTS {
        return Err("outgoing-object-cap-exceeded".into());
    }

    let mut outgoing = Vec::with_capacity(objects.len());
    let mut object_bytes = 0u64;
    let mut metadata_bytes = 0u64;
    for oid in objects {
        let kind = git_object_type(root, &oid)?;
        if !matches!(kind.as_str(), "blob" | "tree" | "commit" | "tag") {
            return Err("unsupported-push-object".into());
        }
        let size = git_object_size(root, &oid)?;
        let ceiling = if kind == "blob" {
            MAX_PUSH_BLOB_BYTES
        } else {
            MAX_PUSH_METADATA_BYTES
        };
        if size > ceiling {
            return Err("outgoing-object-size-cap-exceeded".into());
        }
        object_bytes = object_bytes
            .checked_add(size)
            .ok_or("outgoing-object-byte-cap-exceeded")?;
        if object_bytes > MAX_PUSH_OBJECT_BYTES {
            return Err("outgoing-object-byte-cap-exceeded".into());
        }
        if matches!(kind.as_str(), "commit" | "tag") {
            metadata_bytes = metadata_bytes
                .checked_add(size)
                .ok_or("outgoing-metadata-cap-exceeded")?;
            if metadata_bytes > MAX_PUSH_METADATA_TOTAL {
                return Err("outgoing-metadata-cap-exceeded".into());
            }
        }
        outgoing.push(OutgoingObject { oid, kind, size });
    }
    outgoing.sort_by(|a, b| a.oid.cmp(&b.oid));
    let commit_oids: Vec<String> = outgoing
        .iter()
        .filter(|object| object.kind == "commit")
        .map(|object| object.oid.clone())
        .collect();
    let path_map = map_outgoing_blob_paths(root, &commit_oids)?;
    scan_outgoing_objects(root, &outgoing, &path_map)?;

    // A source profile may be reused *within this invocation* for subjects
    // sharing a peeled commit. There is deliberately no cross-invocation cache.
    let mut validated_commits = std::collections::BTreeSet::new();
    for subject in &subjects {
        if validated_commits.insert(subject.peeled_commit.clone()) {
            let report = validate_profile_ephemeral(
                root,
                Some(&subject.peeled_commit),
                Some(&config.gates.pre_push),
                config,
            )?;
            if report.status != "passed" {
                return Err(format!(
                    "pre-push validation failed for {}",
                    subject.peeled_commit
                ));
            }
        }
    }

    let updates_digest = digest_json(&records)?;
    let baseline_digest = digest_json(
        &records
            .iter()
            .map(|record| (&record.remote_ref, &record.remote_oid))
            .collect::<Vec<_>>(),
    )?;
    let subjects_digest = digest_json(&subjects)?;
    let object_set_digest = digest_json(
        &outgoing
            .iter()
            .map(|o| (&o.oid, &o.kind, o.size))
            .collect::<Vec<_>>(),
    )?;
    let deletion_approval_digest = deletions
        .first()
        .map(|record| {
            consume_deletion_approval(
                root,
                remote_name,
                remote_location,
                record,
                &effective_policy_digest,
            )
        })
        .transpose()?;
    let mut authorization = PushAuthorizationV1 {
        schema: 1,
        authorization_id: String::new(),
        invocation_nonce: random_hex_nonce()?,
        authorized_at_epoch_secs: epoch_secs()?,
        remote_name: remote_name.into(),
        remote_location_digest: Digest::of_bytes(remote_location.as_bytes()).to_hex(),
        updates: records.clone(),
        baseline_digest,
        updates_digest,
        subjects_digest,
        object_set_digest,
        object_count: outgoing.len(),
        object_bytes,
        deletion_count: deletions.len(),
        deletion_approval_digest,
        // D1 changed the outgoing SCAN semantics (path-mapped allowlisting),
        // not the underlying secret-detection RULES in `checks::secrets` — so
        // only `scanner_digest` bumps. Bumping `rules_digest` too would be
        // dishonest: nothing about the rule set actually changed (Cond 10 —
        // scanner digests are honest, not incremented reflexively).
        scanner_digest: Digest::of_bytes(OUTGOING_SCAN_TAG.as_bytes()).to_hex(),
        rules_digest: Digest::of_bytes(SECRET_RULES_TAG.as_bytes()).to_hex(),
        trusted_policy_digest,
        effective_policy_digest,
    };
    authorization.authorization_id = push_authorization_id(&authorization)?;
    save_push_authorization_audit(root, &authorization)?;
    Ok(authorization)
}

fn validate_hook_argument(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(format!("malformed-hook-input: invalid {what}"));
    }
    Ok(())
}

fn is_zero_oid(oid: &str) -> bool {
    oid.bytes().all(|byte| byte == b'0')
}

fn resolve_push_subject(root: &Path, outer: &str) -> Result<PushSubject, String> {
    let (_, tag_chain, peeled_commit) = resolve_composite_subject(root, outer)?;
    let tree_oid = git_output(
        root,
        &[
            "show",
            "-s",
            "--format=%T",
            "--end-of-options",
            &peeled_commit,
        ],
    )?;
    validate_oid(&tree_oid)?;
    Ok(PushSubject {
        local_oid: outer.into(),
        peeled_commit,
        tree_oid,
        tag_chain,
    })
}

fn enumerate_update_objects(
    root: &Path,
    local: &str,
    remote: &str,
) -> Result<(Vec<String>, usize), String> {
    let mut args = vec![
        "rev-list",
        "--objects",
        "--no-object-names",
        "--end-of-options",
        local,
    ];
    let exclusion;
    if !is_zero_oid(remote) {
        exclusion = format!("^{remote}");
        args.push(&exclusion);
    }
    let text = git_output_capped(
        root,
        &args,
        MAX_PUSH_ENUM_BYTES,
        "outgoing object enumeration",
    )?;
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut bytes = 0usize;
    for oid in text.lines() {
        validate_oid(oid)?;
        bytes = bytes
            .checked_add(oid.len().saturating_add(1))
            .ok_or("outgoing-enumeration-cap-exceeded")?;
        if seen.insert(oid.to_string()) {
            if out.len() == MAX_PUSH_OBJECTS {
                return Err("outgoing-object-cap-exceeded".into());
            }
            out.push(oid.to_string());
        }
    }
    Ok((out, bytes))
}

/// Map every blob introduced or modified by `commits` to the repo-relative
/// path(s) it was staged at (D1). `enumerate_update_objects` deliberately
/// keeps `--no-object-names`, so this is a second, capped pass rather than a
/// change to the authoritative object set.
///
/// Per-commit `diff-tree` is used instead of trusting `rev-list`'s own
/// single first-seen name: `rev-list` names each object once, so a secret
/// blob present at BOTH an allowlisted fixture path and a real source path
/// would be scanned only under the fixture name and wrongly suppressed. With
/// diff-tree, every path binding introduced anywhere in the outgoing range is
/// observed, and a multi-path blob is scanned once per distinct path.
///
/// A path that fails UTF-8 decoding or canonical-path validation is a hard
/// error for the whole mapping pass, exactly like a structural parse failure
/// or cap overflow: the push is blocked, never partially skipped. This is
/// deliberately NOT "drop this one occurrence and keep going" — a diff-tree
/// row we cannot safely name is exactly the kind of row an attacker needs to
/// launder a multi-binding secret (the same blob committed at BOTH an
/// allowlisted path and an invalid-byte path; if the invalid row were merely
/// dropped, the blob would map to only the allowlisted path and the finding
/// at the real, unscanned path would be silently suppressed). Fail-closed at
/// the whole-pass level closes that hole unconditionally: an operator with a
/// genuinely non-UTF-8/non-canonical tracked path must fix it before the
/// push can be authorized at all.
fn map_outgoing_blob_paths(
    root: &Path,
    commits: &[String],
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut pair_count = 0usize;
    let mut total_bytes = 0usize;
    for commit in commits {
        validate_oid(commit)?;
        let output = canonical_git(
            root,
            &[
                "diff-tree",
                "-r",
                "-m",
                "--no-renames",
                "--root",
                "--no-commit-id",
                "--raw",
                "-z",
                "--end-of-options",
                commit,
            ],
            MAX_PUSH_ENUM_BYTES,
        )
        .map_err(|error| {
            // `canonical_git` fails this way both on genuine cap overflow
            // ("... exceeded its cap") and on unrelated spawn/IO failures;
            // only the former is honestly a cap-exceeded condition.
            if error.contains("exceeded its cap") {
                "outgoing-path-mapping-cap-exceeded".to_string()
            } else {
                format!("outgoing-path-mapping-git-failed: {error}")
            }
        })?;
        if !output.success {
            return Err("outgoing-path-mapping-cap-exceeded".into());
        }
        total_bytes = total_bytes
            .checked_add(output.stdout.len())
            .ok_or("outgoing-path-mapping-cap-exceeded")?;
        if total_bytes > MAX_PUSH_ENUM_TOTAL_BYTES {
            return Err("outgoing-path-mapping-cap-exceeded".into());
        }
        let mut fields: Vec<&[u8]> = output.stdout.split(|&byte| byte == 0).collect();
        if fields.last().is_some_and(|field| field.is_empty()) {
            fields.pop();
        }
        if !fields.len().is_multiple_of(2) {
            return Err("malformed outgoing path mapping record".into());
        }
        for pair in fields.chunks_exact(2) {
            let header = std::str::from_utf8(pair[0])
                .map_err(|_| "malformed outgoing path mapping record".to_string())?;
            let header = header
                .strip_prefix(':')
                .ok_or("malformed outgoing path mapping record")?;
            let parts: Vec<&str> = header.split(' ').collect();
            if parts.len() != 5 {
                return Err("malformed outgoing path mapping record".into());
            }
            let new_mode = parts[1];
            let new_oid = parts[3];
            let status = parts[4];
            if status.len() != 1 {
                return Err("malformed outgoing path mapping record".into());
            }
            if !matches!(status, "A" | "M" | "C" | "R" | "T") {
                // Deletions and other rows introduce no new blob to map.
                continue;
            }
            if new_mode.starts_with("160") || new_mode.starts_with("040") {
                // Gitlink (submodule) or tree row: not a blob, never mapped.
                continue;
            }
            validate_oid(new_oid)?;
            // F1 (Security-code): a row whose path is not valid UTF-8 or not
            // canonical MUST NOT be silently dropped. Dropping it here would
            // let a blob with one allowlisted, valid binding and one
            // invalid-path binding map to ONLY the allowlisted path,
            // wrongly suppressing a secret that also reaches the remote at
            // the (unscanned, unmapped) invalid path. Fail closed for the
            // whole push instead.
            let path = std::str::from_utf8(pair[1])
                .map_err(|_| "outgoing-path-mapping-unsafe-path".to_string())?;
            crate::digest::validate_canonical_path(path)
                .map_err(|_| "outgoing-path-mapping-unsafe-path".to_string())?;
            let paths = map.entry(new_oid.to_string()).or_default();
            if paths.insert(path.to_string()) {
                pair_count = pair_count
                    .checked_add(1)
                    .ok_or("outgoing-path-mapping-cap-exceeded")?;
                if pair_count > MAX_PUSH_PATH_MAPPINGS {
                    return Err("outgoing-path-mapping-cap-exceeded".into());
                }
            }
        }
    }
    Ok(map)
}

fn scan_outgoing_objects(
    root: &Path,
    objects: &[OutgoingObject],
    path_map: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), String> {
    let allowlist = crate::allowlist::Allowlist::load(root);
    let mut suppressed = 0usize;
    let mut blocked = false;
    for object in objects {
        if !matches!(object.kind.as_str(), "blob" | "commit" | "tag") {
            continue;
        }
        let bytes = git_object_bytes(root, &object.oid, object.size)?;
        // Arbitrary blobs are not necessarily UTF-8. Lossy decoding is
        // intentional: ASCII secret patterns remain observable without
        // rendering raw bytes in a terminal or durable receipt.
        let text = String::from_utf8_lossy(&bytes);
        let mapped = if object.kind == "blob" {
            path_map.get(&object.oid).filter(|paths| !paths.is_empty())
        } else {
            None
        };
        match mapped {
            Some(paths) => {
                // A mapped blob is scanned once per distinct path it was
                // introduced at, filtered through the path-glob allowlist.
                // Suppression requires an allowlist match under EVERY mapped
                // path — a finding surviving under any one path still
                // blocks (never first-wins).
                for path in paths {
                    for finding in crate::checks::secrets::scan_text(path, &text) {
                        if allowlist.is_allowed(path, finding.line, finding.rule) {
                            suppressed += 1;
                        } else {
                            blocked = true;
                        }
                    }
                }
            }
            None => {
                // Unmapped blobs, and commit/tag message text, keep the
                // synthetic full-strictness scan: no allowlist ever applies.
                let synthetic = format!("git-object:{}", object.oid);
                if !crate::checks::secrets::scan_text(&synthetic, &text).is_empty() {
                    blocked = true;
                }
            }
        }
    }
    // Suppression is always counted and reported, matching the allowlist
    // module's doctrine — never silent, even when the push is about to be
    // blocked by a different, non-suppressed finding.
    if suppressed > 0 {
        println!("  {suppressed} outgoing secret finding(s) suppressed by allowlist.");
    }
    if blocked {
        return Err("outgoing-secret-scan-failed".into());
    }
    Ok(())
}

fn git_object_exists(root: &Path, oid: &str) -> Result<bool, String> {
    canonical_git(root, &["cat-file", "-e", &format!("{oid}^{{object}}")], 0)
        .map(|output| output.success)
}

fn require_remote_baseline(root: &Path, oid: &str) -> Result<(), String> {
    if !is_zero_oid(oid) && !git_object_exists(root, oid)? {
        return Err(
            "remote-baseline-missing: fetch the advertised remote baseline and retry".into(),
        );
    }
    Ok(())
}

fn git_object_type(root: &Path, oid: &str) -> Result<String, String> {
    git_output(root, &["cat-file", "-t", "--", oid])
}
fn git_object_size(root: &Path, oid: &str) -> Result<u64, String> {
    git_output(root, &["cat-file", "-s", "--", oid])?
        .parse()
        .map_err(|_| "malformed Git object size".into())
}
fn git_object_bytes(root: &Path, oid: &str, cap: u64) -> Result<Vec<u8>, String> {
    let output = canonical_git(root, &["cat-file", "-p", "--", oid], cap as usize)
        .map_err(|_| "outgoing-object-read-cap-exceeded".to_string())?;
    if !output.success {
        return Err("outgoing-object-read-cap-exceeded".into());
    }
    Ok(output.stdout)
}
fn git_output_capped(
    root: &Path,
    args: &[&str],
    cap: usize,
    _label: &str,
) -> Result<String, String> {
    let output = canonical_git(root, args, cap)
        .map_err(|_| "outgoing-enumeration-cap-exceeded".to_string())?;
    if !output.success {
        return Err("outgoing-enumeration-cap-exceeded".into());
    }
    String::from_utf8(output.stdout).map_err(|_| "malformed outgoing object enumeration".into())
}
fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::of_bytes(&bytes).to_hex())
        .map_err(|e| format!("cannot bind push authorization: {e}"))
}

fn validate_oid(oid: &str) -> Result<(), String> {
    if !matches!(oid.len(), 40 | OID_MAX) || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Git object id is not a full hexadecimal oid".into());
    }
    Ok(())
}

fn git_output(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = canonical_git(root, args, MAX_GIT_STDOUT_BYTES)?;
    if !output.success {
        return Err("Git could not resolve the requested local validation subject".into());
    }
    let value =
        String::from_utf8(output.stdout).map_err(|_| "Git returned non-UTF-8 object metadata")?;
    Ok(value.trim().to_string())
}
fn git_optional(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = canonical_git(root, args, MAX_GIT_STDOUT_BYTES)?;
    if !output.success {
        return Ok(None);
    }
    let value =
        String::from_utf8(output.stdout).map_err(|_| "Git returned non-UTF-8 policy oid")?;
    let value = value.trim();
    Ok((!value.is_empty()).then(|| value.to_string()))
}

/// Execute one approved profile against an already captured immutable subject.
/// A receipt is published only after every check and the owned materialization
/// cleanup succeed.  Candidate policy remains inert until `preflight` proves it
/// byte-identical to the clone-private trusted policy.
pub fn validate_profile(
    root: &Path,
    requested: Option<&str>,
    profile_name: Option<&str>,
    config: &LocalValidationConfig,
) -> Result<ValidationReport, String> {
    validate_profile_inner(root, requested, profile_name, config, true)
}

/// Parse and validate the typed policy visible at an exact candidate root and
/// return its canonical digest. Callers bind this digest into candidate
/// identity before any configured program can execute.
pub fn load_candidate_policy(
    candidate_root: &Path,
) -> Result<(LocalValidationConfig, String), String> {
    let config = crate::config::Config::load_strict(candidate_root)?
        .local_validation
        .ok_or("candidate structured local_validation is absent")?;
    config.validate()?;
    let digest = Digest::of_bytes(&canonical_policy_bytes(&config)?).to_hex();
    Ok((config, digest))
}

/// Execute a profile against an already captured read-only Candidate subject.
/// This path never materializes HEAD and never publishes a Git note or Commit
/// receipt. The returned Build output, when applicable, is exported outside
/// the projection and bound to the exact candidate ID.
pub fn validate_candidate_profile(
    root: &Path,
    candidate_root: &Path,
    capture: &crate::candidate::CandidateCapture,
    profile: &str,
    expected_policy: &LocalValidationConfig,
) -> Result<CandidateProfileValidation, String> {
    if candidate_root.to_str() != Some(capture.clone_private_root.as_str()) {
        return Err("candidate profile root does not match its compact binding".into());
    }
    crate::candidate::reopen_candidate(root, capture)?;
    // Prove the mandatory platform isolation capability before consulting the
    // clone-local trust object or executing any candidate-defined argv.
    let adapter = sandbox_adapter(candidate_root)?;
    let adapter_identity = sandbox_identity(&adapter)?;
    validate_candidate_profile_inner(
        root,
        candidate_root,
        capture,
        profile,
        expected_policy,
        |output_root, policy, subject, trusted_oid, trusted_digest, started| {
            run_profile(
                root,
                candidate_root,
                output_root,
                profile,
                policy,
                &adapter,
                &adapter_identity,
                subject,
                trusted_oid,
                trusted_digest,
                started,
            )
        },
    )
}

fn validate_candidate_profile_inner<F>(
    root: &Path,
    candidate_root: &Path,
    capture: &crate::candidate::CandidateCapture,
    profile: &str,
    expected_policy: &LocalValidationConfig,
    execute: F,
) -> Result<CandidateProfileValidation, String>
where
    F: FnOnce(
        &Path,
        &LocalValidationConfig,
        &Subject,
        &str,
        &str,
        u64,
    ) -> Result<ValidationReport, String>,
{
    if candidate_root.to_str() != Some(capture.clone_private_root.as_str()) {
        return Err("candidate profile root does not match its compact binding".into());
    }
    let (candidate_policy, policy_digest) = load_candidate_policy(candidate_root)?;
    if candidate_policy != *expected_policy || policy_digest != capture.subject.policy_digest {
        return Err("candidate policy changed after candidate capture".into());
    }
    if !candidate_policy.profiles.contains_key(profile) {
        return Err(format!(
            "unknown candidate local-validation profile {profile:?}"
        ));
    }
    let (trusted_oid, trusted_digest) =
        trusted_candidate_policy_bindings(root, candidate_root, &candidate_policy)?;
    let started = epoch_secs()?;
    let output = OwnedRuntimeDir::create_with_prefix(started, "mpd-candidate-output-")?;
    let subject = Subject {
        requested: format!("candidate:{}", capture.subject.id),
        pushed_oid: capture.subject.base_commit.clone(),
        pushed_kind: "candidate".into(),
        tag_chain: Vec::new(),
        commit: capture.subject.base_commit.clone(),
        tree: capture.subject.base_tree.clone(),
    };
    let run = (|| {
        // This API, rather than its caller, owns the exact-subject boundary.
        // Reopen the canonical root/sidecar immediately around configured argv
        // so a forged binding starts nothing and execution-time replacement is
        // never accepted as the subject that passed.
        crate::candidate::reopen_candidate(root, capture)?;
        let executed = execute(
            &output.path,
            &candidate_policy,
            &subject,
            &trusted_oid,
            &trusted_digest,
            started,
        );
        let revalidated = crate::candidate::reopen_candidate(root, capture);
        let mut report = match (executed, revalidated) {
            (Ok(report), Ok(_)) => report,
            (Err(error), Ok(_)) => return Err(error),
            (Ok(_), Err(error)) => {
                return Err(format!(
                    "candidate changed during profile execution: {error}"
                ))
            }
            (Err(execution), Err(reopen)) => {
                return Err(format!(
                    "{execution}; candidate revalidation also failed: {reopen}"
                ))
            }
        };
        let mut owned_build_output = None;
        if report.status == "passed" && profile == candidate_policy.gates.build {
            let contract = candidate_policy
                .build_output
                .as_ref()
                .ok_or("candidate Build profile passed without a typed build_output contract")?;
            let output_path = output.path.join(&contract.path);
            let exported = export_candidate_runtime_build_output(
                root,
                &output_path,
                contract,
                &capture.subject.id,
                &capture.subject.change,
            )?;
            let receipt = report
                .receipt
                .as_mut()
                .ok_or("candidate profile passed without an ephemeral result receipt")?;
            receipt.build_output = Some(exported.output().clone());
            receipt.id = receipt_id(receipt)?;
            owned_build_output = Some(exported);
        }
        Ok(CandidateProfileValidation {
            report,
            build_output: owned_build_output,
        })
    })();
    let cleanup = output.cleanup();
    match (run, cleanup) {
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
        (Ok(report), Ok(())) => Ok(report),
    }
}

/// The pre-push path needs fresh execution but must not write a Git note or
/// any other ref.  Its result is consumed only by [`PushAuthorizationV1`] and
/// disappears with the hook process.
fn validate_profile_ephemeral(
    root: &Path,
    requested: Option<&str>,
    profile_name: Option<&str>,
    config: &LocalValidationConfig,
) -> Result<ValidationReport, String> {
    validate_profile_inner(root, requested, profile_name, config, false)
}

fn validate_profile_inner(
    root: &Path,
    requested: Option<&str>,
    profile_name: Option<&str>,
    config: &LocalValidationConfig,
    publish: bool,
) -> Result<ValidationReport, String> {
    let preflight = preflight(root, requested, config)?;
    let exact_config = subject_local_validation(root, &preflight.subject)?;
    let profile = profile_name.unwrap_or(&exact_config.gates.test);
    if !exact_config.profiles.contains_key(profile) {
        return Err(format!("unknown local-validation profile {profile:?}"));
    }
    if let Some(blocker) = preflight.blocker {
        return Ok(ValidationReport {
            schema: VALIDATION_SCHEMA,
            subject: preflight.subject,
            profile: profile.to_string(),
            status: "blocked".into(),
            receipt: None,
            blocker: Some(blocker),
            counts: ValidationCountsV1 {
                total: 0,
                passed: 0,
                failed: 0,
                blocked: 1,
                not_run: 0,
            },
            actions: vec!["resolve the reported blocker, then rerun local validation".into()],
        });
    }
    let trusted_oid = preflight
        .trusted_policy_oid
        .ok_or_else(|| "trusted-policy-missing".to_string())?;
    let trusted_digest = preflight
        .trusted_policy_digest
        .ok_or_else(|| "trusted-policy-invalid".to_string())?;
    let started = epoch_secs()?;
    let materialized = materialize_subject(root, &preflight.subject)?;
    let run = (|| {
        let materialized_config = crate::config::Config::load_strict(&materialized.root)?
            .local_validation
            .ok_or("exact-subject structured local_validation disappeared after materialization")?;
        if canonical_policy_bytes(&materialized_config)? != canonical_policy_bytes(&exact_config)? {
            return Err("exact-subject policy changed during materialization".into());
        }
        let adapter = sandbox_adapter(&materialized.root)?;
        let sandbox_identity = sandbox_identity(&adapter)?;
        run_profile(
            root,
            &materialized.root,
            root,
            profile,
            &materialized_config,
            &adapter,
            &sandbox_identity,
            &preflight.subject,
            &trusted_oid,
            &trusted_digest,
            started,
        )
    })();
    let cleanup = remove_owned_tree(&materialized.root, &materialized.identity).map_err(|error| {
        format!(
            "validation-cleanup-failed: {}: {error}",
            materialized.root.display()
        )
    });
    match (run, cleanup) {
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
        (Ok(mut report), Ok(())) => {
            if publish && report.status == "passed" {
                let receipt = report
                    .receipt
                    .take()
                    .ok_or("validation receipt missing after pass")?;
                let published = publish_receipt(root, &receipt)?;
                let classification = classify_receipt(root, &published);
                if classification.state != ReceiptState::Current {
                    return Err(format!(
                        "validation receipt winner is not current: {}",
                        classification.reasons.join(", ")
                    ));
                }
                report.receipt = classification.receipt;
            }
            Ok(report)
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the bindings are deliberately explicit at the execution boundary"
)]
fn run_profile(
    root: &Path,
    worktree: &Path,
    build_output_root: &Path,
    profile_name: &str,
    config: &LocalValidationConfig,
    adapter: &crate::sandbox::SandboxAdapter,
    sandbox: &str,
    subject: &Subject,
    trusted_oid: &str,
    trusted_digest: &str,
    started: u64,
) -> Result<ValidationReport, String> {
    let effective_checks = config.effective_checks(profile_name)?;
    let authority_digest = sandbox_authority_digest(subject, config, profile_name)?;
    let log_root = validation_private_root(root, started)?;
    let runtime = OwnedRuntimeDir::create(started)?;
    let supervisor = std::env::current_exe()
        .map_err(|e| format!("cannot resolve running MPD validator: {e}"))?;
    let validator_digest = digest_file(&supervisor)?;
    let common = git_common_dir(root)?;
    let cargo_home = common.join("mpd/cargo-home");
    let cargo_home_meta = fs::symlink_metadata(&cargo_home)
        .map_err(|e| format!("clone-private Cargo cache is unavailable: {e}"))?;
    if cargo_home_meta.file_type().is_symlink() || !cargo_home_meta.is_dir() {
        return Err("clone-private Cargo cache is unsafe".into());
    }
    let profile_started = std::time::Instant::now();
    let preflight = preflight_profile_inputs(
        root,
        worktree,
        &effective_checks,
        config,
        &supervisor,
        &cargo_home,
    )?;
    let locked_rustc = preflight
        .programs
        .get("rustc")
        .ok_or("locked rustc disappeared after complete profile preflight")?
        .clone();
    let mut sandbox_attestations = Vec::with_capacity(effective_checks.len() + 1);
    if let Some(cargo) = preflight.programs.get("cargo") {
        if let Some(attestation) = run_cargo_cache_preflight(
            adapter,
            &supervisor,
            cargo,
            &locked_rustc,
            &cargo_home,
            worktree,
            &runtime.path,
            Duration::from_secs(config.limits.aggregate_secs),
            &config.limits,
            &preflight.read_only_roots,
            &authority_digest,
        )? {
            sandbox_attestations.push(attestation);
        }
    }
    let mut results = Vec::with_capacity(effective_checks.len());
    let mut private_logs = Vec::with_capacity(effective_checks.len());
    let tools = preflight.digests;
    let cargo_lock_digest = tools
        .get("cargo-lock")
        .cloned()
        .ok_or("preflight omitted Cargo.lock digest")?;
    let advisory_lock_digest = tools
        .get("advisory-db")
        .cloned()
        .ok_or("preflight omitted advisory digest")?;
    let mut failed = false;
    // Console-only diagnostic for the first failing check (name, exit, and a
    // bounded terminal-safe output tail). Raw child bytes remain transient:
    // this string reaches stderr via the gate error path and is never
    // persisted into a receipt, log, or ledger record.
    let mut profile_failure: Option<String> = None;
    let mut build_output = None;
    for name in &effective_checks {
        let check = config
            .checks
            .get(name)
            .ok_or("profile references missing check")?;
        if failed {
            results.push(ValidationCheckResult {
                name: name.clone(),
                kind: format!("{:?}", check.kind),
                outcome: "not_run".into(),
                exit: None,
                count: None,
                duration_millis: 0,
                log_digest: Digest::of_bytes(b"").to_hex(),
            });
            continue;
        }
        let program = preflight
            .programs
            .get(&check.program)
            .ok_or_else(|| format!("preflight omitted required tool {:?}", check.program))?
            .clone();
        let expected_program_digest = tools
            .get(&check.program)
            .ok_or_else(|| format!("preflight omitted tool digest {:?}", check.program))?;
        if digest_file(&program)? != *expected_program_digest {
            return Err(format!(
                "locked executable changed before check {name:?}: {:?}",
                check.program
            ));
        }
        let home = runtime.path.join(format!("{name}-home"));
        let tmp = runtime.path.join(format!("{name}-tmp"));
        fs::create_dir(&home).map_err(|e| format!("cannot create private validation HOME: {e}"))?;
        fs::create_dir(&tmp)
            .map_err(|e| format!("cannot create private validation TMPDIR: {e}"))?;
        let cargo_target = tmp.join("cargo-target");
        fs::create_dir(&cargo_target)
            .map_err(|e| format!("cannot create private Cargo target: {e}"))?;
        protect_dir(&home)?;
        protect_dir(&tmp)?;
        protect_dir(&cargo_target)?;
        let args = preflight
            .args
            .get(name)
            .ok_or_else(|| format!("preflight omitted expanded argv for {name:?}"))?;
        let elapsed = profile_started.elapsed();
        let aggregate = Duration::from_secs(config.limits.aggregate_secs)
            .checked_sub(elapsed)
            .ok_or("aggregate-timeout: profile preflight exhausted the validation budget")?;
        let began = std::time::Instant::now();
        let execution = crate::sandbox::run_sandboxed(
            crate::sandbox::SandboxedRun {
                adapter,
                supervisor: &supervisor,
                program: &program,
                args,
                authority_digest: &authority_digest,
                home: &home,
                tmp: &tmp,
                worktree,
                cargo_home: Some(&cargo_home),
                cargo_target_dir: Some(&cargo_target),
                rustc: Some(&locked_rustc),
                read_only_roots: &preflight.read_only_roots,
            },
            crate::sandbox::RunnerLimits {
                per_check: Duration::from_secs(check.timeout_secs),
                aggregate,
                output_bytes: config.limits.output_bytes,
                log_bytes: config.limits.log_bytes,
                worktree_bytes: config.limits.worktree_bytes,
                child_processes: config.limits.child_processes,
                child_open_files: config.limits.child_open_files,
                child_file_bytes: config.limits.child_file_bytes,
            },
        )?;
        if let Some(attestation) = execution.attestation {
            sandbox_attestations.push(attestation);
        }
        if digest_file(&program)? != *expected_program_digest {
            return Err(format!(
                "locked executable changed during check {name:?}: {:?}",
                check.program
            ));
        }
        let (state, exit, stdout, stderr) = match execution.outcome {
            crate::sandbox::RunOutcome::Passed { stdout, stderr } => {
                ("passed", Some(0), stdout, stderr)
            }
            crate::sandbox::RunOutcome::Failed {
                status,
                stdout,
                stderr,
            } => ("failed", status, stdout, stderr),
            crate::sandbox::RunOutcome::Blocked {
                reason,
                stdout,
                stderr,
            } => (reason, None, stdout, stderr),
        };
        let count = test_count(&check.result_policy, &stdout, &stderr, state)?;
        let policy_passed = state == "passed"
            && result_policy_passes(&check.result_policy, count, &stdout, &stderr);
        if policy_passed
            && matches!(check.kind, crate::config::CheckKind::ReleaseBuild)
            && profile_name == config.gates.build
        {
            let configured = config
                .build_output
                .as_ref()
                .ok_or("Build profile passed without a typed build_output contract")?;
            let source_name = Path::new(&configured.path)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("build_output path has no UTF-8 filename")?;
            build_output = Some(export_runtime_build_output(
                build_output_root,
                &cargo_target.join("release").join(source_name),
                configured,
            )?);
        }
        let log = redact_output(&stdout, &stderr);
        let log_path = log_root.join(format!("{name}.log"));
        write_private_file(&log_path, &log)?;
        let log_digest = Digest::of_bytes(&log).to_hex();
        private_logs.push(PrivateLogEntryV1 {
            file: format!("{name}.log"),
            bytes: log.len() as u64,
            sha256: log_digest.clone(),
        });
        results.push(ValidationCheckResult {
            name: name.clone(),
            kind: format!("{:?}", check.kind),
            outcome: if policy_passed {
                "passed".into()
            } else {
                state.into()
            },
            exit,
            count,
            duration_millis: began.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            log_digest,
        });
        if !policy_passed && profile_failure.is_none() {
            let source = if stderr.is_empty() { &stdout } else { &stderr };
            let tail_start = source.len().saturating_sub(512);
            let tail =
                crate::harness::terminal_safe(&String::from_utf8_lossy(&source[tail_start..]))
                    .trim()
                    .to_string();
            profile_failure = Some(format!(
                "check {name:?} {state} (exit {exit:?}; output tail: {tail})"
            ));
        }
        failed = !policy_passed;
    }
    let completed_epoch_secs = epoch_secs()?;
    let manifest = PrivateRunManifestV1 {
        schema: 1,
        profile: profile_name.into(),
        subject: subject.clone(),
        completed_epoch_secs,
        logs: private_logs,
    };
    finalize_private_logs(&log_root, &manifest, &config.receipts)?;
    runtime.cleanup()?;
    let checks_bytes =
        serde_json::to_vec(&effective_checks).map_err(|e| format!("cannot encode checks: {e}"))?;
    let policy_digest = Digest::of_bytes(&canonical_policy_bytes(config)?).to_hex();
    let sandbox_inputs = sandbox_receipt_inputs(adapter, config)?;
    let run_request_digests = sandbox_attestations
        .iter()
        .map(|attestation| attestation.request_digest.clone())
        .collect();
    let run_authority_digests = sandbox_attestations
        .iter()
        .map(|attestation| attestation.authority_digest.clone())
        .collect();
    let run_root_inventory_digests = sandbox_attestations
        .iter()
        .map(|attestation| attestation.root_inventory_digest.clone())
        .collect();
    let run_canary_digests = sandbox_attestations
        .iter()
        .map(|attestation| attestation.canary_digest.clone())
        .collect();
    let mut receipt = ValidationReceiptV1 {
        schema: VALIDATION_SCHEMA,
        id: String::new(),
        subject: subject.clone(),
        profile: profile_name.into(),
        config_digest: policy_digest.clone(),
        checks_digest: Digest::of_bytes(&checks_bytes).to_hex(),
        trusted_policy_oid: trusted_oid.into(),
        trusted_before_policy_digest: trusted_digest.into(),
        candidate_policy_digest: policy_digest.clone(),
        effective_policy_digest: policy_digest,
        sandbox: SandboxReceiptBindingV1 {
            contract_version: config.sandbox.contract_version,
            adapter_digest: sandbox.into(),
            profile_digest: sandbox_inputs.profile_digest,
            environment_keys: sandbox_inputs.environment_keys,
            certified_host: sandbox_inputs.certified_host,
            adapter_abi_digest: sandbox_inputs.adapter_abi_digest,
            canary_contract_digest: sandbox_inputs.canary_contract_digest,
            residual_limitations: sandbox_inputs.residual_limitations,
            run_request_digests,
            run_authority_digests,
            run_root_inventory_digests,
            run_canary_digests,
        },
        validation_contract_version: 1,
        validator_version: env!("CARGO_PKG_VERSION").into(),
        validator_digest,
        platform: platform_receipt_binding(config),
        toolchain: toolchain_receipt_binding(config),
        cargo_lock_digest,
        advisory: advisory_receipt_binding(config, advisory_lock_digest),
        tool_policy_digest: digest_json(&config.tools)?,
        tool_digests: tools,
        results,
        started_epoch_secs: started,
        completed_epoch_secs,
        outcome: if failed {
            "failed".into()
        } else {
            "passed".into()
        },
        build_output,
    };
    receipt.id = receipt_id(&receipt)?;
    let counts = validation_counts(&receipt.results);
    let actions = if receipt.outcome == "passed" {
        Vec::new()
    } else {
        vec!["inspect the named failed or blocked check, fix it, and rerun validation".into()]
    };
    let blocker = if receipt.outcome == "passed" {
        None
    } else {
        profile_failure
    };
    Ok(ValidationReport {
        schema: VALIDATION_SCHEMA,
        subject: subject.clone(),
        profile: profile_name.into(),
        status: receipt.outcome.clone(),
        receipt: Some(receipt),
        blocker,
        counts,
        actions,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_cargo_cache_preflight(
    adapter: &crate::sandbox::SandboxAdapter,
    supervisor: &Path,
    cargo: &Path,
    rustc: &Path,
    cargo_home: &Path,
    worktree: &Path,
    runtime: &Path,
    aggregate: Duration,
    limits: &crate::config::ResourceLimitsConfig,
    read_only_roots: &[PathBuf],
    authority_digest: &str,
) -> Result<Option<crate::sandbox::SandboxAttestation>, String> {
    let home = runtime.join("preflight-home");
    let tmp = runtime.join("preflight-tmp");
    let target = tmp.join("cargo-target");
    fs::create_dir(&home).map_err(|e| format!("cannot create preflight HOME: {e}"))?;
    fs::create_dir(&tmp).map_err(|e| format!("cannot create preflight TMPDIR: {e}"))?;
    fs::create_dir(&target).map_err(|e| format!("cannot create preflight target: {e}"))?;
    protect_dir(&home)?;
    protect_dir(&tmp)?;
    protect_dir(&target)?;
    let args = [
        "metadata".to_string(),
        "--offline".to_string(),
        "--locked".to_string(),
        "--format-version".to_string(),
        "1".to_string(),
    ];
    let outcome = crate::sandbox::run_sandboxed(
        crate::sandbox::SandboxedRun {
            adapter,
            supervisor,
            program: cargo,
            args: &args,
            authority_digest,
            home: &home,
            tmp: &tmp,
            worktree,
            cargo_home: Some(cargo_home),
            cargo_target_dir: Some(&target),
            rustc: Some(rustc),
            read_only_roots,
        },
        crate::sandbox::RunnerLimits {
            per_check: Duration::from_secs(300),
            aggregate,
            output_bytes: limits.output_bytes,
            log_bytes: limits.log_bytes,
            worktree_bytes: limits.worktree_bytes,
            child_processes: limits.child_processes,
            child_open_files: limits.child_open_files,
            child_file_bytes: limits.child_file_bytes,
        },
    )?;
    let attestation = outcome.attestation;
    match outcome.outcome {
        crate::sandbox::RunOutcome::Passed { .. } => Ok(attestation),
        crate::sandbox::RunOutcome::Failed { status, stderr, .. } => {
            // Surface a bounded, terminal-safe tail of the child's stderr:
            // without it the operator cannot distinguish a stale offline
            // cache from an in-sandbox denial or toolchain fault.
            let tail_start = stderr.len().saturating_sub(512);
            let tail =
                crate::harness::terminal_safe(&String::from_utf8_lossy(&stderr[tail_start..]))
                    .trim()
                    .to_string();
            Err(format!(
                "cargo-cache-preflight-failed: Cargo.lock graph is not available offline (exit {:?}; stderr tail: {tail})",
                status
            ))
        }
        crate::sandbox::RunOutcome::Blocked { reason, .. } => {
            Err(format!("cargo-cache-preflight-blocked: {reason}"))
        }
    }
}

struct OwnedRuntimeDir {
    path: PathBuf,
    identity: OwnedTreeIdentity,
    armed: bool,
}

impl OwnedRuntimeDir {
    fn create(nonce: u64) -> Result<Self, String> {
        Self::create_with_prefix(nonce, "mpd-validation-runtime-")
    }

    fn create_with_prefix(nonce: u64, prefix: &str) -> Result<Self, String> {
        if prefix.is_empty()
            || prefix.len() > 64
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        {
            return Err("validation runtime prefix is invalid".into());
        }
        // The reviewed macOS Seatbelt profile grants child writes only below
        // /private/tmp (and /tmp). `std::env::temp_dir()` commonly resolves to
        // /var/folders on macOS, which would make every real Cargo invocation
        // fail despite a valid network-deny sandbox. Keep this boundary fixed
        // and reviewable instead of widening the profile to ambient TMPDIR.
        #[cfg(target_os = "macos")]
        let runtime_base = Path::new("/private/tmp");
        #[cfg(not(target_os = "macos"))]
        let runtime_base = Path::new("/tmp");
        let path = runtime_base.join(format!("{prefix}{}-{nonce}", std::process::id()));
        fs::create_dir(&path)
            .map_err(|e| format!("cannot create exclusive validation runtime: {e}"))?;
        protect_dir(&path)?;
        let identity = OwnedTreeIdentity::capture(&path, runtime_base, prefix)?;
        Ok(Self {
            path,
            identity,
            armed: true,
        })
    }

    fn cleanup(mut self) -> Result<(), String> {
        remove_owned_tree(&self.path, &self.identity).map_err(|error| {
            format!(
                "validation-runtime-cleanup-failed: {}: {error}",
                self.path.display()
            )
        })?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for OwnedRuntimeDir {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_owned_tree(&self.path, &self.identity);
        }
    }
}

fn sandbox_adapter(root: &Path) -> Result<crate::sandbox::SandboxAdapter, String> {
    let path = match std::env::consts::OS {
        "macos" => None,
        "linux" => ["/usr/bin/bwrap", "/usr/bin/bubblewrap"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.is_file()),
        _ => None,
    };
    crate::sandbox::SandboxAdapter::select(std::env::consts::OS, root, path)
}

fn sandbox_identity(adapter: &crate::sandbox::SandboxAdapter) -> Result<String, String> {
    let bytes = format!("{adapter:?}").into_bytes();
    Ok(Digest::of_bytes(&bytes).to_hex())
}

fn sandbox_authority_digest(
    subject: &Subject,
    config: &LocalValidationConfig,
    profile: &str,
) -> Result<String, String> {
    let mut bytes = b"mpd:sandbox-authority:v1\0".to_vec();
    bytes.extend_from_slice(
        &serde_json::to_vec(subject)
            .map_err(|error| format!("cannot encode sandbox subject: {error}"))?,
    );
    bytes.push(0);
    bytes.extend_from_slice(profile.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical_policy_bytes(config)?);
    Ok(Digest::of_bytes(&bytes).to_hex())
}

struct ProfileInputPreflight {
    programs: BTreeMap<String, PathBuf>,
    args: BTreeMap<String, Vec<String>>,
    digests: BTreeMap<String, String>,
    read_only_roots: Vec<PathBuf>,
}

fn preflight_profile_inputs(
    root: &Path,
    worktree: &Path,
    profile_checks: &[String],
    config: &LocalValidationConfig,
    supervisor: &Path,
    cargo_home: &Path,
) -> Result<ProfileInputPreflight, String> {
    verify_required_toolchain(worktree, config)?;
    let mut required = config
        .required_toolchain
        .components
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    required.insert("rustc".to_string());
    let mut args = BTreeMap::new();
    for name in profile_checks {
        let check = config
            .checks
            .get(name)
            .ok_or_else(|| format!("profile references missing check {name:?}"))?;
        // Construct only the redaction-aware representation at the diagnostic
        // boundary. Execution and receipt binding continue to use exact argv.
        let _safe_display =
            crate::config::SensitiveArgvDisplay::new(&check.args, check.output.as_ref())
                .to_string();
        let declared = config.tools.get(&check.program).ok_or_else(|| {
            format!(
                "check {name:?} references undeclared locked tool {:?}",
                check.program
            )
        })?;
        if declared.program != check.program {
            return Err(format!(
                "tool {:?} must use the same canonical program key",
                check.program
            ));
        }
        required.insert(check.program.clone());
        if check.program == "cargo" {
            match check.args.first().map(String::as_str) {
                Some("fmt") => {
                    required.insert("rustfmt".into());
                }
                Some("clippy") => {
                    required.insert("cargo-clippy".into());
                }
                _ => {}
            }
        }
        args.insert(name.clone(), expand_locked_args(root, &check.args, config)?);
    }

    let advisory_digest = verify_advisory_database(root, worktree, config)?;
    let read_only_roots = approved_sandbox_read_roots(root, worktree, &required, config)?;
    let cargo_home_meta = fs::symlink_metadata(cargo_home)
        .map_err(|e| format!("clone-private Cargo cache is unavailable: {e}"))?;
    if cargo_home_meta.file_type().is_symlink() || !cargo_home_meta.is_dir() {
        return Err("clone-private Cargo cache is unsafe".into());
    }
    let cargo_lock = openspec_core::read_contained_capped(
        worktree,
        &worktree.join(&config.offline.cargo_lock),
        16 * 1024 * 1024,
    )
    .map_err(|e| format!("exact-subject Cargo.lock is unavailable: {e}"))?;

    let mut programs = BTreeMap::new();
    let mut digests = BTreeMap::new();
    for name in required {
        let program = resolve_program(root, worktree, &name, supervisor)?;
        let digest = digest_file(&program)?;
        programs.insert(name.clone(), program);
        digests.insert(name, digest);
    }
    digests.insert("advisory-db".into(), advisory_digest);
    digests.insert(
        "cargo-lock".into(),
        Digest::of_bytes(cargo_lock.as_bytes()).to_hex(),
    );
    Ok(ProfileInputPreflight {
        programs,
        args,
        digests,
        read_only_roots,
    })
}

fn verify_required_toolchain(
    worktree: &Path,
    config: &LocalValidationConfig,
) -> Result<(), String> {
    if config.offline.cargo_target != platform_key()? {
        return Err("configured Cargo target differs from the current locked platform".into());
    }
    let lock_text = openspec_core::read_contained_capped(
        worktree,
        &worktree.join("security/tool-lock.json"),
        4 * 1024 * 1024,
    )
    .map_err(|e| format!("locked tool inventory is unavailable: {e}"))?;
    let lock: serde_json::Value = serde_json::from_str(&lock_text)
        .map_err(|e| format!("locked tool inventory is malformed: {e}"))?;
    let rust = lock["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|entry| entry["name"] == "rust-toolchain"))
        .ok_or("rust-toolchain lock entry is missing")?;
    if rust["version"].as_str() != Some(&config.required_toolchain.rust_release)
        || rust["platform"].as_str() != Some(&config.offline.cargo_target)
    {
        return Err("required Rust release/host differs from the reviewed tool lock".into());
    }
    let executables = rust["executables"]
        .as_object()
        .ok_or("rust-toolchain executable inventory is missing")?;
    for component in &config.required_toolchain.components {
        if !executables.contains_key(component) {
            return Err(format!(
                "required Rust component {component:?} is absent from the tool lock"
            ));
        }
    }
    Ok(())
}

fn approved_sandbox_read_roots(
    root: &Path,
    worktree: &Path,
    required: &BTreeSet<String>,
    config: &LocalValidationConfig,
) -> Result<Vec<PathBuf>, String> {
    let lock_path = worktree.join("security/tool-lock.json");
    let lock_text = openspec_core::read_contained_capped(worktree, &lock_path, 4 * 1024 * 1024)
        .map_err(|e| format!("locked tool inventory is unavailable: {e}"))?;
    let lock: serde_json::Value = serde_json::from_str(&lock_text)
        .map_err(|e| format!("locked tool inventory is malformed: {e}"))?;
    let entries = lock["tools"]
        .as_array()
        .ok_or("tool-lock tools must be an array")?;
    let common = fs::canonicalize(git_common_dir(root)?)
        .map_err(|e| format!("cannot canonicalize clone-private Git directory: {e}"))?;
    let mut roots = BTreeSet::new();
    for name in required {
        if name == "mpd-self" {
            continue;
        }
        let policy_name = if matches!(
            name.as_str(),
            "cargo" | "rustc" | "rustfmt" | "cargo-clippy"
        ) {
            "rust-toolchain"
        } else {
            name.as_str()
        };
        let entry = entries
            .iter()
            .find(|entry| entry["name"] == policy_name)
            .ok_or_else(|| format!("tool-lock entry is missing: {policy_name}"))?;
        let mut declared_roots = Vec::new();
        if let Some(value) = entry["package_root"].as_str() {
            declared_roots.push(value);
        }
        if let Some(values) = entry["dependency_roots"].as_array() {
            for value in values {
                declared_roots.push(value.as_str().ok_or_else(|| {
                    format!("dependency_roots for {policy_name} must contain strings")
                })?);
            }
        }
        for value in declared_roots {
            let path = fs::canonicalize(value).map_err(|e| {
                format!("cannot canonicalize approved dependency root for {policy_name}: {e}")
            })?;
            if path == Path::new("/") {
                return Err("approved sandbox dependency root cannot be host /".into());
            }
            roots.insert(path);
        }
        if let Some(value) = entry["install_root"].as_str() {
            let path = fs::canonicalize(common.join(value)).map_err(|e| {
                format!("cannot canonicalize clone-private install root for {policy_name}: {e}")
            })?;
            if !path.starts_with(&common) {
                return Err("clone-private tool root escaped the Git common directory".into());
            }
            roots.insert(path);
        }
    }
    let advisory = common.join(&config.offline.advisory_db_path);
    if advisory.is_dir() {
        roots
            .insert(fs::canonicalize(advisory).map_err(|e| {
                format!("cannot canonicalize clone-private advisory database: {e}")
            })?);
    }
    let mut minimal = Vec::<PathBuf>::new();
    for root in roots {
        if minimal.iter().any(|approved| root.starts_with(approved)) {
            continue;
        }
        minimal.retain(|approved| !approved.starts_with(&root));
        minimal.push(root);
    }
    if minimal.len() > 32 {
        return Err("approved sandbox dependency roots exceed the compiled cap".into());
    }
    Ok(minimal)
}

struct SandboxReceiptInputs {
    profile_digest: String,
    environment_keys: Vec<String>,
    certified_host: String,
    adapter_abi_digest: String,
    canary_contract_digest: String,
    residual_limitations: Vec<String>,
}

#[cfg(target_os = "macos")]
fn macos_receipt_identity() -> Result<(String, String, String, Vec<String>), String> {
    Ok((
        crate::sandbox_macos::certified_host_label()?,
        crate::sandbox_macos::adapter_abi_digest(),
        crate::sandbox_macos::canary_contract_digest(),
        crate::sandbox_macos::residual_limitations(),
    ))
}

#[cfg(not(target_os = "macos"))]
fn macos_receipt_identity() -> Result<(String, String, String, Vec<String>), String> {
    Err("macOS receipt identity is unavailable on this host".into())
}

fn sandbox_receipt_inputs(
    adapter: &crate::sandbox::SandboxAdapter,
    config: &LocalValidationConfig,
) -> Result<SandboxReceiptInputs, String> {
    let profile = match adapter {
        crate::sandbox::SandboxAdapter::Macos { profile, .. }
        | crate::sandbox::SandboxAdapter::Linux { profile, .. } => profile,
    };
    let profile_digest = digest_file(profile)?;
    let compiled_environment_keys = crate::sandbox::SANDBOX_ENV_CONTRACT_KEYS
        .iter()
        .map(|key| key.to_string())
        .collect::<Vec<_>>();
    if config.sandbox.environment_allowlist.0 != compiled_environment_keys {
        return Err(
            "sandbox environment allowlist differs from the compiled deny-default contract".into(),
        );
    }
    let (certified_host, adapter_abi_digest, canary_contract_digest, residual_limitations) =
        match adapter {
            crate::sandbox::SandboxAdapter::Macos { .. } => macos_receipt_identity()?,
            crate::sandbox::SandboxAdapter::Linux { .. } => (
                format!(
                    "NOT CERTIFIED/{}/{}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
                Digest::of_bytes(b"mpd:linux-bubblewrap-experimental:v1").to_hex(),
                Digest::of_bytes(b"mpd:linux-canaries-not-certified:v1").to_hex(),
                vec!["Linux containment remains experimental and is not release-certified".into()],
            ),
        };
    Ok(SandboxReceiptInputs {
        profile_digest,
        environment_keys: config.sandbox.environment_allowlist.0.clone(),
        certified_host,
        adapter_abi_digest,
        canary_contract_digest,
        residual_limitations,
    })
}

fn platform_receipt_binding(config: &LocalValidationConfig) -> PlatformReceiptBindingV1 {
    PlatformReceiptBindingV1 {
        operating_system: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        cargo_target: config.offline.cargo_target.clone(),
    }
}

fn toolchain_receipt_binding(config: &LocalValidationConfig) -> ToolchainReceiptBindingV1 {
    ToolchainReceiptBindingV1 {
        rust_release: config.required_toolchain.rust_release.clone(),
        host: config.required_toolchain.host.clone(),
        components: config.required_toolchain.components.clone(),
    }
}

fn advisory_receipt_binding(
    config: &LocalValidationConfig,
    lock_digest: String,
) -> AdvisoryReceiptBindingV1 {
    AdvisoryReceiptBindingV1 {
        revision: config.offline.advisory_revision.clone(),
        tree: config.offline.advisory_tree.clone(),
        lock_digest,
        max_age_days: config.offline.advisory_max_age_days,
    }
}

fn validation_counts(results: &[ValidationCheckResult]) -> ValidationCountsV1 {
    let mut counts = ValidationCountsV1 {
        total: results.len(),
        passed: 0,
        failed: 0,
        blocked: 0,
        not_run: 0,
    };
    for result in results {
        match result.outcome.as_str() {
            "passed" => counts.passed += 1,
            "failed" => counts.failed += 1,
            "not_run" => counts.not_run += 1,
            _ => counts.blocked += 1,
        }
    }
    counts
}

fn resolve_program(
    root: &Path,
    worktree: &Path,
    name: &str,
    supervisor: &Path,
) -> Result<PathBuf, String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("locked tool key is invalid".into());
    }
    if name == "mpd-self" {
        return canonical_locked_executable(supervisor, None, None);
    }
    let lock_path = worktree.join("security/tool-lock.json");
    let lock_text = openspec_core::read_contained_capped(worktree, &lock_path, 4 * 1024 * 1024)
        .map_err(|e| format!("locked tool inventory is unavailable: {e}"))?;
    let lock: serde_json::Value = serde_json::from_str(&lock_text)
        .map_err(|e| format!("locked tool inventory is malformed: {e}"))?;
    if lock["schema_version"] != 1 {
        return Err("unsupported tool-lock schema".into());
    }
    let tools = lock["tools"]
        .as_array()
        .ok_or("tool-lock tools must be an array")?;

    if matches!(name, "cargo" | "rustc" | "rustfmt" | "cargo-clippy") {
        let entry = tools
            .iter()
            .find(|entry| entry["name"] == "rust-toolchain")
            .ok_or("rust-toolchain lock entry is missing")?;
        require_platform(entry)?;
        if entry.get("executable_paths").is_some() {
            return resolve_declared_tool_entry(root, entry, name);
        }
        if !cfg!(target_os = "macos") {
            return Err(
                "rust-toolchain lock entry must declare executable_paths on this platform".into(),
            );
        }
        let root_path = entry["package_root"]
            .as_str()
            .ok_or("rust-toolchain package root is missing")?;
        let expected = entry["executables"][name]
            .as_str()
            .ok_or_else(|| format!("rust-toolchain executable digest is missing: {name}"))?;
        let path = Path::new("/opt/homebrew/bin").join(name);
        return canonical_locked_executable(&path, Some(Path::new(root_path)), Some(expected));
    }

    let entry = tools
        .iter()
        .find(|entry| entry["name"] == name)
        .ok_or_else(|| format!("tool-lock entry is missing: {name}"))?;
    require_platform_if_present(entry)?;
    if entry.get("executable_paths").is_some() {
        return resolve_declared_tool_entry(root, entry, name);
    }
    match entry["acquisition"].as_str() {
        Some("homebrew-package-root") => {
            let root_path = entry["package_root"]
                .as_str()
                .ok_or("Homebrew package root is missing")?;
            let expected = entry["executable_sha256"]
                .as_str()
                .ok_or("Homebrew executable digest is missing")?;
            canonical_locked_executable(
                &Path::new("/opt/homebrew/bin").join(name),
                Some(Path::new(root_path)),
                Some(expected),
            )
        }
        Some("homebrew-bottle-root") => {
            let root_path = entry["package_root"]
                .as_str()
                .ok_or("Homebrew bottle package root is missing")?;
            let inventory_relative = entry["inventory"]
                .as_str()
                .ok_or("Homebrew bottle inventory path is missing")?;
            let common = git_common_dir(root)?;
            let inventory_path = common.join(inventory_relative);
            let inventory_text =
                openspec_core::read_contained_capped(&common, &inventory_path, 1024 * 1024)
                    .map_err(|e| format!("Homebrew bottle inventory is unavailable: {e}"))?;
            let inventory: serde_json::Value = serde_json::from_str(&inventory_text)
                .map_err(|e| format!("Homebrew bottle inventory is malformed: {e}"))?;
            let expected_bottle = entry["bottle_sha256"]
                .as_str()
                .ok_or("reviewed Homebrew bottle digest is missing")?;
            if inventory["schema"] != 1
                || inventory["name"] != name
                || inventory["source_package_sha256"] != expected_bottle
            {
                return Err("Homebrew bottle inventory differs from reviewed policy".into());
            }
            let expected_executable = inventory["executable_sha256"]
                .as_str()
                .ok_or("Homebrew bottle executable digest is missing")?;
            let expected_receipt = inventory["install_receipt_sha256"]
                .as_str()
                .ok_or("Homebrew bottle install-receipt digest is missing")?;
            crate::digest::Digest::from_hex(expected_receipt)?;
            let receipt = Path::new(root_path).join("INSTALL_RECEIPT.json");
            if digest_file(&receipt)? != expected_receipt {
                return Err("Homebrew bottle install receipt changed after bootstrap".into());
            }
            canonical_locked_executable(
                &Path::new("/opt/homebrew/bin").join(name),
                Some(Path::new(root_path)),
                Some(expected_executable),
            )
        }
        Some("crates.io-archive" | "pypi-wheel") => {
            let install_root = entry["install_root"]
                .as_str()
                .ok_or("clone-private install root is missing")?;
            let common = git_common_dir(root)?;
            let install = common.join(install_root);
            let inventory_path = install.join("installed.json");
            let inventory_text =
                openspec_core::read_contained_capped(&common, &inventory_path, 1024 * 1024)
                    .map_err(|e| format!("clone-private tool inventory is unavailable: {e}"))?;
            let inventory: serde_json::Value = serde_json::from_str(&inventory_text)
                .map_err(|e| format!("clone-private tool inventory is malformed: {e}"))?;
            if inventory["schema"] != 1 || inventory["name"] != name {
                return Err(format!(
                    "clone-private tool inventory identity differs: {name}"
                ));
            }
            let expected_source = match entry["acquisition"].as_str() {
                Some("crates.io-archive") => entry["package_sha256"].as_str(),
                Some("pypi-wheel") => {
                    let host = platform_key()?;
                    entry["platform_archives"][host]["sha256"].as_str()
                }
                _ => None,
            }
            .ok_or("reviewed source package digest is missing")?;
            if inventory["source_package_sha256"] != expected_source {
                return Err(format!(
                    "clone-private tool source identity differs: {name}"
                ));
            }
            let expected_executable = inventory["executable_sha256"]
                .as_str()
                .ok_or("clone-private executable digest is missing")?;
            canonical_locked_executable(
                &install.join("bin").join(name),
                Some(&install),
                Some(expected_executable),
            )
        }
        _ => Err(format!(
            "unsupported acquisition root for locked tool {name:?}"
        )),
    }
}

/// Resolve a platform entry point named by reviewed lock data instead of an
/// ambient PATH convention. Relative entry points are confined to either a
/// declared external package root or an owner-private Git-common install root.
/// Clone-private installs additionally require an inventory that binds the
/// reviewed source archive identity and the exact installed executable bytes.
fn resolve_declared_tool_entry(
    root: &Path,
    entry: &serde_json::Value,
    name: &str,
) -> Result<PathBuf, String> {
    let relative = entry["executable_paths"][name]
        .as_str()
        .ok_or_else(|| format!("tool-lock executable path is missing: {name}"))?;
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("tool-lock executable path is unsafe: {name}"));
    }
    let expected = entry["executables"][name]
        .as_str()
        .or_else(|| entry["executable_sha256"].as_str())
        .ok_or_else(|| format!("tool-lock executable digest is missing: {name}"))?;
    crate::digest::Digest::from_hex(expected)?;

    if let Some(install_relative) = entry["install_root"].as_str() {
        let install_relative = Path::new(install_relative);
        if install_relative.as_os_str().is_empty()
            || install_relative.is_absolute()
            || install_relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("clone-private tool install root is unsafe".into());
        }
        let common = fs::canonicalize(git_common_dir(root)?)
            .map_err(|e| format!("cannot canonicalize Git common directory: {e}"))?;
        let install = fs::canonicalize(common.join(install_relative))
            .map_err(|e| format!("cannot canonicalize clone-private tool root: {e}"))?;
        if install == common || !install.starts_with(&common) {
            return Err("clone-private tool root escaped the Git common directory".into());
        }
        let source = entry["package_sha256"]
            .as_str()
            .ok_or("clone-private tool source digest is missing")?;
        crate::digest::Digest::from_hex(source)?;
        let inventory_relative = entry["inventory"].as_str().unwrap_or("installed.json");
        let inventory_relative = Path::new(inventory_relative);
        if inventory_relative.as_os_str().is_empty()
            || inventory_relative.is_absolute()
            || inventory_relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("clone-private tool inventory path is unsafe".into());
        }
        let inventory_path = install.join(inventory_relative);
        let inventory_text =
            openspec_core::read_contained_capped(&install, &inventory_path, 1024 * 1024)
                .map_err(|e| format!("clone-private tool inventory is unavailable: {e}"))?;
        let inventory: serde_json::Value = serde_json::from_str(&inventory_text)
            .map_err(|e| format!("clone-private tool inventory is malformed: {e}"))?;
        if inventory["schema"] != 1
            || inventory["source_package_sha256"].as_str() != Some(source)
            || inventory["executables"][name]["path"].as_str()
                != Some(relative.to_str().ok_or("non-UTF-8 executable path")?)
            || inventory["executables"][name]["sha256"].as_str() != Some(expected)
        {
            return Err("clone-private tool inventory differs from reviewed policy".into());
        }
        return canonical_locked_executable(
            &install.join(relative),
            Some(&install),
            Some(expected),
        );
    }

    let package_root = entry["package_root"]
        .as_str()
        .ok_or("declared executable path requires package_root or install_root")?;
    let package_root = Path::new(package_root);
    if !package_root.is_absolute() {
        return Err("external package root must be absolute".into());
    }
    canonical_locked_executable(
        &package_root.join(relative),
        Some(package_root),
        Some(expected),
    )
}

fn platform_key() -> Result<&'static str, String> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => Ok("aarch64-apple-darwin"),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin"),
        ("aarch64", "linux") => Ok("aarch64-unknown-linux-gnu"),
        ("x86_64", "linux") => Ok("x86_64-unknown-linux-gnu"),
        _ => Err("unsupported locked-tool platform".into()),
    }
}

fn require_platform(entry: &serde_json::Value) -> Result<(), String> {
    if entry["platform"].as_str() != Some(platform_key()?) {
        return Err("locked package root is for a different platform".into());
    }
    Ok(())
}

fn require_platform_if_present(entry: &serde_json::Value) -> Result<(), String> {
    if entry.get("platform").is_some() {
        require_platform(entry)?;
    }
    Ok(())
}

fn canonical_locked_executable(
    path: &Path,
    trust_root: Option<&Path>,
    expected_digest: Option<&str>,
) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path).map_err(|e| {
        format!(
            "cannot canonicalize locked executable {}: {e}",
            path.display()
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|e| {
        format!(
            "cannot inspect locked executable {}: {e}",
            canonical.display()
        )
    })?;
    if !canonical.is_absolute() || !metadata.is_file() {
        return Err("locked executable is not an absolute regular file".into());
    }
    if let Some(root) = trust_root {
        let root = fs::canonicalize(root)
            .map_err(|e| format!("cannot canonicalize locked package root: {e}"))?;
        if !canonical.starts_with(&root) {
            return Err("locked executable escaped its approved package root".into());
        }
    }
    if let Some(expected) = expected_digest {
        crate::digest::Digest::from_hex(expected)?;
        if digest_file(&canonical)? != expected {
            return Err(format!(
                "locked executable digest mismatch: {}",
                canonical.display()
            ));
        }
    }
    Ok(canonical)
}

fn expand_locked_args(
    root: &Path,
    args: &[String],
    config: &LocalValidationConfig,
) -> Result<Vec<String>, String> {
    let advisory = git_common_dir(root)?.join(&config.offline.advisory_db_path);
    args.iter()
        .map(|argument| match argument.as_str() {
            "${MPD_ADVISORY_DB}" => advisory
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| "advisory database path is non-UTF-8".into()),
            value if value.contains("${") => Err(format!(
                "unsupported locked argument placeholder: {value:?}"
            )),
            value => Ok(value.to_string()),
        })
        .collect()
}

fn verify_advisory_database(
    root: &Path,
    worktree: &Path,
    config: &LocalValidationConfig,
) -> Result<String, String> {
    let lock_path = worktree.join("security/advisory-db.lock.json");
    let lock_text = openspec_core::read_contained_capped(worktree, &lock_path, 1024 * 1024)
        .map_err(|e| format!("advisory database lock is unavailable: {e}"))?;
    let lock: serde_json::Value = serde_json::from_str(&lock_text)
        .map_err(|e| format!("advisory database lock is malformed: {e}"))?;
    if lock["schema_version"] != 1 {
        return Err("unsupported advisory database lock schema".into());
    }
    let commit = lock["commit"]
        .as_str()
        .ok_or("advisory database commit is missing")?;
    validate_oid(commit)?;
    if commit != config.offline.advisory_revision {
        return Err("advisory database revision differs from typed offline policy".into());
    }
    let expected_tree = lock["git_tree_oid"]
        .as_str()
        .ok_or("advisory database tree OID is missing")?;
    validate_oid(expected_tree)?;
    if expected_tree != config.offline.advisory_tree {
        return Err("advisory database tree differs from typed offline policy".into());
    }
    let expected_listing = lock["tree_listing_sha256"]
        .as_str()
        .ok_or("advisory database listing digest is missing")?;
    crate::digest::Digest::from_hex(expected_listing)?;
    let max_age_days = lock["max_age_days"]
        .as_u64()
        .filter(|days| (1..=90).contains(days))
        .ok_or("advisory database max_age_days must be in 1..=90")?;
    if max_age_days != config.offline.advisory_max_age_days {
        return Err("advisory freshness differs from typed offline policy".into());
    }
    let database = git_common_dir(root)?.join(&config.offline.advisory_db_path);
    let metadata = fs::symlink_metadata(&database)
        .map_err(|e| format!("advisory database checkout is unavailable: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("advisory database checkout is unsafe".into());
    }
    let git = |args: &[&str]| -> Result<Vec<u8>, String> {
        let output = canonical_git(&database, args, 16 * 1024 * 1024)?;
        if !output.success {
            return Err("advisory database inspection failed or exceeded its cap".into());
        }
        Ok(output.stdout)
    };
    let observed_commit = String::from_utf8(git(&["rev-parse", "HEAD^{commit}"])?)
        .map_err(|_| "advisory database commit is non-UTF-8")?;
    if observed_commit.trim() != commit {
        return Err("advisory database commit differs from the reviewed lock".into());
    }
    let observed_tree = String::from_utf8(git(&["rev-parse", "HEAD^{tree}"])?)
        .map_err(|_| "advisory database tree is non-UTF-8")?;
    if observed_tree.trim() != expected_tree {
        return Err("advisory database tree differs from the reviewed lock".into());
    }
    let listing = git(&["ls-tree", "-r", "-z", "--full-tree", commit])?;
    if Digest::of_bytes(&listing).to_hex() != expected_listing {
        return Err("advisory database listing differs from the reviewed lock".into());
    }
    let commit_epoch = String::from_utf8(git(&["show", "-s", "--format=%ct", commit])?)
        .map_err(|_| "advisory database time is non-UTF-8")?
        .trim()
        .parse::<u64>()
        .map_err(|_| "advisory database commit time is invalid")?;
    let now = epoch_secs()?;
    let max_age = max_age_days.saturating_mul(86_400);
    if commit_epoch > now.saturating_add(300) || now.saturating_sub(commit_epoch) > max_age {
        return Err("advisory database snapshot is outside its freshness policy".into());
    }
    Ok(Digest::of_bytes(lock_text.as_bytes()).to_hex())
}

fn validation_private_root(root: &Path, nonce: u64) -> Result<PathBuf, String> {
    let common = git_common_dir(root)?;
    let mut base = common;
    for component in ["mpd", "validation", "logs"] {
        base.push(component);
        ensure_private_dir(&base)?;
    }
    let path = base.join(format!("run-{}-{}", std::process::id(), nonce));
    fs::create_dir(&path)
        .map_err(|e| format!("cannot create exclusive private validation root: {e}"))?;
    protect_dir(&path)?;
    Ok(path)
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err("clone-private validation path is unsafe".into())
        }
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err("clone-private validation directory is not owner-only".into());
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| "cannot create clone-private validation directory")?;
            protect_dir(path)
        }
        Err(_) => Err("cannot inspect clone-private validation directory".into()),
    }
}

fn protect_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot protect private directory: {e}"))?;
    }
    Ok(())
}
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create exclusive private validation log: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("cannot write private validation log: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot protect private validation log: {e}"))?;
    }
    file.sync_all()
        .map_err(|e| format!("cannot sync private validation log: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot inspect private validation log: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err("private validation log lacks owner-only regular-file identity".into());
        }
    }
    Ok(())
}

fn validate_private_file(path: &Path, cap: u64) -> Result<fs::Metadata, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "clone-private validation file is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > cap {
        return Err("clone-private validation file is unsafe or oversized".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err("clone-private validation file is not exclusive owner-only data".into());
        }
    }
    Ok(metadata)
}

fn read_private_file_capped(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let metadata = validate_private_file(path, cap)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|_| "cannot open clone-private validation file")?;
    let opened = file
        .metadata()
        .map_err(|_| "cannot stat clone-private validation file")?;
    if !same_file_identity(&metadata, &opened) {
        return Err("clone-private validation file changed while opening".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read clone-private validation file")?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > cap {
        return Err("clone-private validation file changed or exceeded its cap".into());
    }
    Ok(bytes)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or("clone-private validation file has no parent")?;
    ensure_private_dir(parent)?;
    if path.exists() {
        validate_private_file(path, 16 * 1024 * 1024)?;
    }
    let temporary = parent.join(format!(
        ".{}.mpd-tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("clone-private validation filename is non-UTF-8")?,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    let result = (|| -> Result<(), String> {
        write_private_file(&temporary, bytes)?;
        fs::rename(&temporary, path)
            .map_err(|_| "cannot atomically replace clone-private validation file")?;
        sync_parent_directory(parent)
    })();
    if result.is_err() && temporary.exists() {
        validate_private_file(&temporary, bytes.len() as u64)?;
        fs::remove_file(&temporary)
            .map_err(|_| "cannot clean clone-private validation temporary file")?;
    }
    result
}

struct PrivateRotationLock {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PrivateRotationLock {
    fn acquire(base: &Path) -> Result<Self, String> {
        let path = base.join("rotation.lock");
        write_private_file(&path, b"mpd-validation-log-rotation-v1\n")
            .map_err(|_| "private validation log rotation is already locked")?;
        let metadata = validate_private_file(&path, 128)?;
        Ok(Self {
            path,
            device: device_of(&metadata),
            inode: inode_of(&metadata),
        })
    }
}

impl Drop for PrivateRotationLock {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && device_of(&metadata) == self.device
                && inode_of(&metadata) == self.inode
            {
                let _ = fs::remove_file(&self.path);
                if let Some(parent) = self.path.parent() {
                    let _ = sync_parent_directory(parent);
                }
            }
        }
    }
}

fn finalize_private_logs(
    run: &Path,
    manifest: &PrivateRunManifestV1,
    limits: &crate::config::ReceiptLimits,
) -> Result<(), String> {
    let base = run
        .parent()
        .ok_or("private validation run has no inventory root")?;
    ensure_private_dir(base)?;
    let run_name = run
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.starts_with("run-") && !name.contains('/'))
        .ok_or("private validation run name is unsafe")?
        .to_string();
    let manifest_bytes =
        serde_json::to_vec(manifest).map_err(|_| "cannot encode private validation manifest")?;
    write_private_atomic(&run.join("manifest.json"), &manifest_bytes)?;
    let _lock = PrivateRotationLock::acquire(base)?;
    let inventory_path = base.join("inventory.json");
    let mut inventory = if inventory_path.exists() {
        serde_json::from_slice::<PrivateLogInventoryV1>(&read_private_file_capped(
            &inventory_path,
            1024 * 1024,
        )?)
        .map_err(|_| "private validation log inventory is corrupt")?
    } else {
        PrivateLogInventoryV1 {
            schema: 1,
            runs: Vec::new(),
        }
    };
    if inventory.schema != 1 || inventory.runs.len() > 256 {
        return Err("private validation log inventory is invalid".into());
    }
    let mut seen = BTreeSet::new();
    for entry in &inventory.runs {
        if !seen.insert(entry.directory.clone()) {
            return Err("private validation log inventory has duplicate runs".into());
        }
        validate_private_run(base, entry)?;
    }
    if seen.contains(&run_name) {
        return Err("private validation log inventory already contains this run".into());
    }
    let new_entry = private_run_inventory_entry(base, &run_name)?;
    if new_entry.log_count > limits.log_count_cap || new_entry.log_bytes > limits.log_byte_cap {
        return Err("private validation run exceeds configured retention caps".into());
    }
    inventory.runs.push(new_entry);
    inventory.runs.sort_by(|left, right| {
        (left.completed_epoch_secs, &left.directory)
            .cmp(&(right.completed_epoch_secs, &right.directory))
    });
    while inventory
        .runs
        .iter()
        .map(|entry| entry.log_count)
        .sum::<usize>()
        > limits.log_count_cap
        || inventory
            .runs
            .iter()
            .map(|entry| entry.log_bytes)
            .sum::<u64>()
            > limits.log_byte_cap
    {
        let oldest = inventory
            .runs
            .first()
            .cloned()
            .ok_or("private validation log rotation cannot satisfy configured caps")?;
        let path = base.join(&oldest.directory);
        let identity = OwnedTreeIdentity::capture(&path, base, "run-")?;
        remove_owned_tree(&path, &identity)?;
        inventory.runs.remove(0);
    }
    let bytes = serde_json::to_vec(&inventory)
        .map_err(|_| "cannot encode private validation log inventory")?;
    write_private_atomic(&inventory_path, &bytes)
}

fn private_run_inventory_entry(
    base: &Path,
    directory: &str,
) -> Result<PrivateRunInventoryEntryV1, String> {
    if !directory.starts_with("run-")
        || Path::new(directory)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("private validation log inventory contains an unsafe run path".into());
    }
    let run = base.join(directory);
    let metadata =
        fs::symlink_metadata(&run).map_err(|_| "private validation run is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("private validation run is unsafe".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("private validation run is not owner-only".into());
        }
    }
    let manifest_bytes = read_private_file_capped(&run.join("manifest.json"), 1024 * 1024)?;
    let manifest: PrivateRunManifestV1 = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| "private validation run manifest is corrupt")?;
    if manifest.schema != 1 || manifest.logs.len() > 64 {
        return Err("private validation run manifest is invalid".into());
    }
    let mut expected = BTreeSet::from(["manifest.json".to_string()]);
    let mut log_bytes = 0u64;
    for log in &manifest.logs {
        if log.file.is_empty()
            || !log.file.ends_with(".log")
            || Path::new(&log.file)
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || !expected.insert(log.file.clone())
        {
            return Err("private validation run manifest contains an unsafe log path".into());
        }
        Digest::from_hex(&log.sha256)
            .map_err(|_| "private validation run manifest contains an invalid digest")?;
        let bytes = read_private_file_capped(&run.join(&log.file), log.bytes)?;
        if bytes.len() as u64 != log.bytes || Digest::of_bytes(&bytes).to_hex() != log.sha256 {
            return Err("private validation log differs from its manifest".into());
        }
        log_bytes = log_bytes
            .checked_add(log.bytes)
            .ok_or("private validation log bytes overflow")?;
    }
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(&run).map_err(|_| "cannot enumerate private validation run")? {
        let entry = entry.map_err(|_| "cannot enumerate private validation run")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "private validation run contains a non-UTF-8 entry")?;
        observed.insert(name);
    }
    if observed != expected {
        return Err("private validation run contains untracked files".into());
    }
    Ok(PrivateRunInventoryEntryV1 {
        directory: directory.into(),
        manifest_sha256: Digest::of_bytes(&manifest_bytes).to_hex(),
        log_count: manifest.logs.len(),
        log_bytes,
        completed_epoch_secs: manifest.completed_epoch_secs,
    })
}

fn validate_private_run(base: &Path, entry: &PrivateRunInventoryEntryV1) -> Result<(), String> {
    let observed = private_run_inventory_entry(base, &entry.directory)?;
    if observed != *entry {
        return Err("private validation run differs from its inventory".into());
    }
    Ok(())
}

fn redact_output(stdout: &[u8], stderr: &[u8]) -> Vec<u8> {
    // No finite pattern list can safely recognize every credential or source
    // secret. Keep raw child bytes transient and persist only a closed summary.
    serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "stdout": {
            "bytes": stdout.len(),
            "sha256": Digest::of_bytes(stdout).to_hex(),
        },
        "stderr": {
            "bytes": stderr.len(),
            "sha256": Digest::of_bytes(stderr).to_hex(),
        },
        "raw_output_retained": false,
    }))
    .expect("closed validation log summary is serializable")
}
fn test_count(
    policy: &crate::config::ResultPolicy,
    stdout: &[u8],
    stderr: &[u8],
    state: &str,
) -> Result<Option<u64>, String> {
    if !matches!(policy, crate::config::ResultPolicy::RustTestCount) {
        return Ok(None);
    }
    if state != "passed" {
        return Ok(None);
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    let mut total = 0_u64;
    let mut summaries = 0_u64;
    for line in text.lines() {
        let Some(summary) = line.trim().strip_prefix("test result: ok. ") else {
            continue;
        };
        let passed = summary
            .split_once(" passed;")
            .ok_or("malformed Rust test summary")?
            .0
            .parse::<u64>()
            .map_err(|_| "malformed Rust passed-test count")?;
        total = total
            .checked_add(passed)
            .ok_or("Rust passed-test count overflow")?;
        summaries = summaries
            .checked_add(1)
            .ok_or("Rust test-summary count overflow")?;
        if summaries > 10_000 {
            return Err("too many Rust test summaries".into());
        }
    }
    Ok((summaries > 0).then_some(total))
}
fn result_policy_passes(
    policy: &crate::config::ResultPolicy,
    count: Option<u64>,
    stdout: &[u8],
    stderr: &[u8],
) -> bool {
    match policy {
        crate::config::ResultPolicy::ExitZero => true,
        crate::config::ResultPolicy::RustTestCount => count.unwrap_or(0) > 0,
        crate::config::ResultPolicy::MpdDoctor => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(stdout),
                String::from_utf8_lossy(stderr)
            );
            text.contains("doctor") || text.contains("passed")
        }
    }
}
fn digest_file(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|b| Digest::of_bytes(&b).to_hex())
        .map_err(|e| format!("cannot read identity input: {e}"))
}
fn epoch_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "clock unavailable".into())
}

fn receipt_id(receipt: &ValidationReceiptV1) -> Result<String, String> {
    let mut payload = receipt.clone();
    payload.id.clear();
    serde_json::to_vec(&payload)
        .map(|b| Digest::of_bytes(&b).to_hex())
        .map_err(|e| format!("cannot canonicalize validation receipt: {e}"))
}

fn validate_receipt(receipt: &ValidationReceiptV1, subject: &Subject) -> Result<(), String> {
    if receipt.schema != VALIDATION_SCHEMA
        || receipt.subject != *subject
        || receipt.id != receipt_id(receipt)?
        || receipt.results.len() > 64
    {
        return Err("invalid validation receipt".into());
    }
    if receipt.outcome == "passed" && receipt.results.iter().any(|r| r.outcome != "passed") {
        return Err("invalid validation receipt outcome".into());
    }
    if receipt.profile.is_empty()
        || receipt.profile.len() > 128
        || receipt.validator_version.is_empty()
        || receipt.validator_version.len() > 128
        || receipt.results.iter().any(|result| {
            result.name.is_empty()
                || result.name.len() > 128
                || result.kind.is_empty()
                || result.kind.len() > 128
                || !matches!(
                    result.outcome.as_str(),
                    "passed" | "failed" | "not_run" | "blocked" | "resource-limit" | "timeout"
                )
        })
    {
        return Err("invalid validation receipt bounded fields".into());
    }
    for digest in [
        &receipt.config_digest,
        &receipt.checks_digest,
        &receipt.trusted_before_policy_digest,
        &receipt.candidate_policy_digest,
        &receipt.effective_policy_digest,
        &receipt.sandbox.adapter_digest,
        &receipt.sandbox.profile_digest,
        &receipt.sandbox.adapter_abi_digest,
        &receipt.sandbox.canary_contract_digest,
        &receipt.validator_digest,
        &receipt.cargo_lock_digest,
        &receipt.advisory.lock_digest,
        &receipt.tool_policy_digest,
    ] {
        Digest::from_hex(digest).map_err(|_| "invalid validation receipt digest")?;
    }
    let attestation_lengths = [
        receipt.sandbox.run_request_digests.len(),
        receipt.sandbox.run_authority_digests.len(),
        receipt.sandbox.run_root_inventory_digests.len(),
        receipt.sandbox.run_canary_digests.len(),
    ];
    if attestation_lengths.iter().any(|length| *length > 65)
        || attestation_lengths
            .iter()
            .any(|length| *length != attestation_lengths[0])
        || (receipt.outcome == "passed"
            && receipt.sandbox.certified_host.starts_with("macOS ")
            && receipt.sandbox.run_request_digests.len() < receipt.results.len())
        || receipt
            .sandbox
            .run_canary_digests
            .iter()
            .any(|digest| digest != &receipt.sandbox.canary_contract_digest)
    {
        return Err("invalid validation receipt sandbox attestation".into());
    }
    for digest in receipt
        .sandbox
        .run_request_digests
        .iter()
        .chain(&receipt.sandbox.run_authority_digests)
        .chain(&receipt.sandbox.run_root_inventory_digests)
        .chain(&receipt.sandbox.run_canary_digests)
    {
        Digest::from_hex(digest).map_err(|_| "invalid validation receipt attestation digest")?;
    }
    validate_oid(&receipt.trusted_policy_oid)
        .map_err(|_| "invalid validation receipt trusted policy object")?;
    validate_oid(&receipt.advisory.revision)
        .map_err(|_| "invalid validation receipt advisory revision")?;
    validate_oid(&receipt.advisory.tree).map_err(|_| "invalid validation receipt advisory tree")?;
    Ok(())
}

/// Validate a ledger-carried receipt without consulting mutable process state.
/// Status may display the receipt only when its self-authenticating subject,
/// bounded fields, exact-host adapter identity, and canary contract are still
/// current.  This never executes a validation lane.
pub fn validate_receipt_for_status(receipt: &ValidationReceiptV1) -> Result<(), String> {
    validate_receipt(receipt, &receipt.subject)?;
    let (host, adapter_abi, canary_contract, residual_limitations) = macos_receipt_identity()?;
    if receipt.sandbox.certified_host != host {
        return Err("sandbox host drifted from the receipt certification boundary".into());
    }
    if receipt.sandbox.adapter_abi_digest != adapter_abi {
        return Err("sandbox SPI/ABI identity drifted from the receipt".into());
    }
    if receipt.sandbox.canary_contract_digest != canary_contract {
        return Err("sandbox canary contract drifted from the receipt".into());
    }
    if receipt.sandbox.residual_limitations != residual_limitations {
        return Err("sandbox residual-limitations contract drifted from the receipt".into());
    }
    Ok(())
}

fn receipt_profile_key(receipt: &ValidationReceiptV1) -> Result<String, String> {
    digest_json(&(
        &receipt.profile,
        &receipt.config_digest,
        &receipt.checks_digest,
        &receipt.trusted_before_policy_digest,
        &receipt.candidate_policy_digest,
        &receipt.effective_policy_digest,
        sandbox_static_key(&receipt.sandbox),
        &receipt.validator_digest,
        &receipt.platform,
        &receipt.toolchain,
        &receipt.cargo_lock_digest,
        &receipt.advisory,
        &receipt.tool_policy_digest,
        &receipt.tool_digests,
    ))
}

fn sandbox_static_key(
    sandbox: &SandboxReceiptBindingV1,
) -> (u32, &str, &str, &[String], &str, &str, &str, &[String]) {
    (
        sandbox.contract_version,
        &sandbox.adapter_digest,
        &sandbox.profile_digest,
        &sandbox.environment_keys,
        &sandbox.certified_host,
        &sandbox.adapter_abi_digest,
        &sandbox.canary_contract_digest,
        &sandbox.residual_limitations,
    )
}

fn sandbox_static_equal(left: &SandboxReceiptBindingV1, right: &SandboxReceiptBindingV1) -> bool {
    sandbox_static_key(left) == sandbox_static_key(right)
}

/// Classify clone-local evidence against the exact reusable-input bindings the
/// caller expects. Invalid note bytes are distinct from absence; a prior
/// profile with changed dependencies is stale and names every changed class.
pub fn classify_receipt(root: &Path, expected: &ValidationReceiptV1) -> ReceiptClassification {
    let (_, envelope) = match read_note_envelope(root, &expected.subject) {
        Ok(value) => value,
        Err(error) => {
            return ReceiptClassification {
                state: ReceiptState::Invalid,
                reasons: vec![error],
                receipt: None,
            };
        }
    };
    let key = match receipt_profile_key(expected) {
        Ok(key) => key,
        Err(error) => {
            return ReceiptClassification {
                state: ReceiptState::Invalid,
                reasons: vec![error],
                receipt: None,
            };
        }
    };
    if let Some(receipt) = envelope.receipts.get(&key) {
        return ReceiptClassification {
            state: ReceiptState::Current,
            reasons: Vec::new(),
            receipt: Some(receipt.clone()),
        };
    }
    let Some(receipt) = envelope
        .receipts
        .values()
        .find(|receipt| receipt.profile == expected.profile)
        .cloned()
    else {
        return ReceiptClassification {
            state: ReceiptState::Missing,
            reasons: vec!["no receipt exists for the requested profile".into()],
            receipt: None,
        };
    };
    let mut reasons = Vec::new();
    for (changed, label) in [
        (receipt.subject != expected.subject, "subject"),
        (receipt.config_digest != expected.config_digest, "config"),
        (receipt.checks_digest != expected.checks_digest, "checks"),
        (
            receipt.trusted_before_policy_digest != expected.trusted_before_policy_digest,
            "trusted-policy",
        ),
        (
            receipt.candidate_policy_digest != expected.candidate_policy_digest,
            "candidate-policy",
        ),
        (
            receipt.effective_policy_digest != expected.effective_policy_digest,
            "effective-policy",
        ),
        (
            !sandbox_static_equal(&receipt.sandbox, &expected.sandbox),
            "sandbox",
        ),
        (receipt.platform != expected.platform, "platform"),
        (receipt.toolchain != expected.toolchain, "toolchain"),
        (
            receipt.cargo_lock_digest != expected.cargo_lock_digest,
            "cargo-lock",
        ),
        (receipt.advisory != expected.advisory, "advisory-database"),
        (
            receipt.tool_policy_digest != expected.tool_policy_digest,
            "tool-policy",
        ),
        (
            receipt.validator_digest != expected.validator_digest,
            "validator",
        ),
        (
            receipt.tool_digests != expected.tool_digests,
            "tools-or-offline-inputs",
        ),
    ] {
        if changed {
            reasons.push(format!("changed-dependency:{label}"));
        }
    }
    if reasons.is_empty() {
        reasons.push("profile receipt key is inconsistent with its canonical bindings".into());
    }
    ReceiptClassification {
        state: ReceiptState::Stale,
        reasons,
        receipt: Some(receipt),
    }
}

fn publish_receipt(
    root: &Path,
    receipt: &ValidationReceiptV1,
) -> Result<ValidationReceiptV1, String> {
    validate_receipt(receipt, &receipt.subject)?;
    let (old, mut envelope) = match read_note_envelope(root, &receipt.subject) {
        Ok(value) => value,
        Err(error) if error.starts_with("invalid validation note") => (
            validation_notes_ref(root)?,
            ValidationNoteEnvelopeV1 {
                schema: VALIDATION_SCHEMA,
                receipts: BTreeMap::new(),
            },
        ),
        Err(error) => return Err(error),
    };
    let profile_key = receipt_profile_key(receipt)?;
    envelope
        .receipts
        .insert(profile_key.clone(), receipt.clone());
    let note =
        serde_json::to_vec(&envelope).map_err(|e| format!("cannot encode validation note: {e}"))?;
    if note.len() > MAX_NOTE_BYTES {
        return Err("validation note exceeds its cap".into());
    }
    let blob = git_hash_blob(root, &note)?;
    let new_commit = build_note_commit(
        root,
        old.as_deref(),
        receipt.subject.attached_object_oid(),
        &blob,
        receipt.completed_epoch_secs,
    )?;
    let expected = old.unwrap_or_else(|| "0".repeat(receipt.subject.commit.len()));
    #[cfg(test)]
    let note_cas_barrier = {
        NOTE_CAS_BARRIER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|hook| hook.root == root)
            .map(|hook| hook.barrier.clone())
    };
    #[cfg(test)]
    if let Some(barrier) = note_cas_barrier {
        let (arrivals, ready) = &*barrier;
        let mut arrivals = arrivals.lock().expect("note barrier arrivals");
        *arrivals += 1;
        if *arrivals == 2 {
            ready.notify_all();
        } else {
            let _ = ready
                .wait_timeout_while(arrivals, Duration::from_secs(5), |count| *count < 2)
                .expect("note barrier wait");
        }
    }
    let status = canonical_git(
        root,
        &[
            "update-ref",
            "--no-deref",
            VALIDATION_NOTES_REF,
            &new_commit,
            &expected,
        ],
        0,
    )?;
    if !status.success {
        return Err("validation receipt publication unstable: notes CAS lost".into());
    }
    let (_, winner) = read_note_envelope(root, &receipt.subject)?;
    let winner = winner
        .receipts
        .get(&profile_key)
        .cloned()
        .ok_or_else(|| "validation receipt winner is missing profile".to_string())?;
    if winner != *receipt {
        return Err("validation receipt winner differs after publication".into());
    }
    Ok(winner)
}

fn validation_notes_ref(root: &Path) -> Result<Option<String>, String> {
    let symbolic = canonical_git(root, &["symbolic-ref", "-q", VALIDATION_NOTES_REF], 1024)?;
    if symbolic.success {
        return Err("validation notes ref must be literal and direct".into());
    }
    let old = git_optional(
        root,
        &["rev-parse", "--verify", "--quiet", VALIDATION_NOTES_REF],
    )?;
    let Some(old) = old else {
        return Ok(None);
    };
    validate_oid(&old)?;
    if git_output(root, &["cat-file", "-t", "--", &old])? != "commit" {
        return Err("validation notes ref must name a commit".into());
    }
    Ok(Some(old))
}

fn read_note_envelope(
    root: &Path,
    subject: &Subject,
) -> Result<(Option<String>, ValidationNoteEnvelopeV1), String> {
    let old = validation_notes_ref(root)?;
    let Some(old) = old else {
        return Ok((
            None,
            ValidationNoteEnvelopeV1 {
                schema: VALIDATION_SCHEMA,
                receipts: Default::default(),
            },
        ));
    };
    let attached = subject.attached_object_oid();
    let path = format!("{}/{}", &attached[..2], &attached[2..]);
    let listing = canonical_git(root, &["ls-tree", &old, "--", &path], 4096)?;
    if !listing.success {
        return Err("invalid validation note: tree lookup failed".into());
    }
    if listing.stdout.is_empty() {
        return Ok((
            Some(old),
            ValidationNoteEnvelopeV1 {
                schema: VALIDATION_SCHEMA,
                receipts: Default::default(),
            },
        ));
    }
    let listing = String::from_utf8(listing.stdout)
        .map_err(|_| "invalid validation note: non-UTF-8 tree entry")?;
    let (header, listed_path) = listing
        .trim_end()
        .split_once('\t')
        .ok_or("invalid validation note: malformed tree entry")?;
    let mut fields = header.split(' ');
    let mode = fields.next();
    let kind = fields.next();
    let blob = fields.next();
    if fields.next().is_some()
        || mode != Some("100644")
        || kind != Some("blob")
        || listed_path != path
    {
        return Err("invalid validation note: conflicting tree entry".into());
    }
    let blob = blob.ok_or("invalid validation note: missing blob identity")?;
    validate_oid(blob).map_err(|_| "invalid validation note: malformed blob identity")?;
    if git_output(root, &["cat-file", "-t", "--", blob])? != "blob" {
        return Err("invalid validation note: entry is not a blob".into());
    }
    let size = git_output(root, &["cat-file", "-s", "--", blob])?
        .parse::<usize>()
        .map_err(|_| "invalid validation note: malformed size")?;
    if size == 0 || size > MAX_NOTE_BYTES {
        return Err("invalid validation note: oversized".into());
    }
    let output = canonical_git(root, &["cat-file", "blob", "--", blob], size)?;
    if !output.success || output.stdout.len() != size {
        return Err("invalid validation note: exact blob read failed".into());
    }
    let envelope: ValidationNoteEnvelopeV1 = serde_json::from_slice(&output.stdout)
        .map_err(|_| "invalid validation note".to_string())?;
    if envelope.schema != VALIDATION_SCHEMA {
        return Err("invalid validation note schema".into());
    }
    if envelope.receipts.len() > 64 {
        return Err("invalid validation note: too many receipts".into());
    }
    for (key, receipt) in &envelope.receipts {
        validate_receipt(receipt, subject)?;
        if *key != receipt_profile_key(receipt)? {
            return Err("invalid validation note profile key".into());
        }
    }
    Ok((Some(old), envelope))
}

fn build_note_commit(
    root: &Path,
    old: Option<&str>,
    subject: &str,
    blob: &str,
    timestamp: u64,
) -> Result<String, String> {
    let base = std::env::temp_dir();
    let temporary = base.join(format!(
        "mpd-validation-index-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_nanos()
    ));
    fs::create_dir(&temporary)
        .map_err(|_| "cannot create private validation notes temporary directory")?;
    protect_dir(&temporary)?;
    let identity = OwnedTreeIdentity::capture(&temporary, &base, "mpd-validation-index-")?;
    let index = temporary.join("index");
    let date = format!("@{timestamp} +0000");
    let env = vec![
        git_env_pair("GIT_INDEX_FILE", &index),
        git_env_pair("GIT_AUTHOR_NAME", "MPD Local Evidence"),
        git_env_pair("GIT_AUTHOR_EMAIL", "mpd-local-evidence@invalid"),
        git_env_pair("GIT_COMMITTER_NAME", "MPD Local Evidence"),
        git_env_pair("GIT_COMMITTER_EMAIL", "mpd-local-evidence@invalid"),
        git_env_pair("GIT_AUTHOR_DATE", &date),
        git_env_pair("GIT_COMMITTER_DATE", &date),
    ];
    let construct = (|| -> Result<String, String> {
        if let Some(old) = old {
            let status = canonical_git_run(
                root,
                &["read-tree", &format!("{old}^{{tree}}")],
                b"",
                &env,
                0,
            )?;
            if !status.success {
                return Err("cannot read existing validation notes tree".into());
            }
        } else {
            let status = canonical_git_run(root, &["read-tree", "--empty"], b"", &env, 0)?;
            if !status.success {
                return Err("cannot initialize validation notes tree".into());
            }
        }
        let path = format!("{}/{}", &subject[..2], &subject[2..]);
        let cacheinfo = format!("100644,{blob},{path}");
        let status = canonical_git_run(
            root,
            &["update-index", "--add", "--cacheinfo", &cacheinfo],
            b"",
            &env,
            0,
        )?;
        if !status.success {
            return Err("cannot construct validation notes tree".into());
        }
        let tree = canonical_git_run(root, &["write-tree"], b"", &env, 1024)?;
        if !tree.success {
            return Err("cannot write validation notes tree".into());
        }
        let tree = String::from_utf8(tree.stdout)
            .map_err(|_| "Git returned non-UTF-8 notes tree")?
            .trim()
            .to_string();
        validate_oid(&tree)?;
        let mut args = vec!["commit-tree", tree.as_str()];
        if let Some(old) = old {
            args.extend(["-p", old]);
        }
        let commit =
            canonical_git_run(root, &args, b"mpd local validation evidence\n", &env, 1024)?;
        if !commit.success {
            return Err("Git refused validation notes object".into());
        }
        let commit = String::from_utf8(commit.stdout)
            .map_err(|_| "Git returned non-UTF-8 notes oid")?
            .trim()
            .to_string();
        validate_oid(&commit)?;
        Ok(commit)
    })();
    let cleanup = remove_owned_tree(&temporary, &identity);
    match (construct, cleanup) {
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(format!(
            "validation notes temporary cleanup failed: {error}"
        )),
        (Ok(commit), Ok(())) => Ok(commit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BuildOutputConfig, CheckConfig, CheckKind, EnvironmentAllowlist, GateProfiles,
        HookPolicyConfig, NetworkAdapter, OfflinePolicyConfig, ProfileConfig, ReceiptLimits,
        RequiredToolchainConfig, ResourceLimitsConfig, ResultPolicy, SandboxPolicyConfig,
        ToolConfig, ToolRequirement,
    };
    use std::collections::BTreeMap;

    fn test_policy() -> LocalValidationConfig {
        let mut tools = BTreeMap::new();
        tools.insert(
            "true".into(),
            ToolConfig {
                program: "true".into(),
                version_args: Vec::new(),
                requirement: ToolRequirement::Required,
                install_hint: "test fixture".into(),
            },
        );
        let mut checks = BTreeMap::new();
        let mut profile_checks = Vec::new();
        for (name, kind) in [
            ("format", CheckKind::Format),
            ("lint", CheckKind::Lint),
            ("test", CheckKind::Test),
            ("release-build", CheckKind::ReleaseBuild),
            ("dependency-audit", CheckKind::DependencyAudit),
            ("secret-scan", CheckKind::SecretScan),
            ("sast", CheckKind::Sast),
            ("self-check", CheckKind::SelfCheck),
            ("nonfunctional", CheckKind::Nonfunctional),
        ] {
            checks.insert(
                name.into(),
                CheckConfig {
                    kind,
                    program: "true".into(),
                    args: Vec::new(),
                    timeout_secs: 1,
                    result_policy: ResultPolicy::ExitZero,
                    output: None,
                },
            );
            profile_checks.push(name.into());
        }
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "profile".into(),
            ProfileConfig {
                includes: Vec::new(),
                checks: profile_checks,
            },
        );
        LocalValidationConfig {
            schema: 1,
            required_toolchain: RequiredToolchainConfig {
                rust_release: "1.91.0".into(),
                host: None,
                components: vec!["true".into()],
            },
            tools,
            checks,
            profiles,
            gates: GateProfiles {
                build: "profile".into(),
                security_code: "profile".into(),
                test: "profile".into(),
                pre_push: "profile".into(),
                high_risk_test: "profile".into(),
                docs_build: None,
                docs_security_code: None,
                docs_test: None,
            },
            hooks: HookPolicyConfig {
                path: ".githooks".into(),
                require_bundled: true,
            },
            receipts: ReceiptLimits {
                log_count_cap: 16,
                log_byte_cap: 1024,
            },
            offline: OfflinePolicyConfig {
                cargo_lock: "Cargo.lock".into(),
                cargo_target: "aarch64-apple-darwin".into(),
                advisory_db_path: "mpd/advisory-db".into(),
                advisory_revision: "a".repeat(40),
                advisory_tree: "b".repeat(40),
                advisory_max_age_days: 30,
            },
            sandbox: SandboxPolicyConfig {
                contract_version: 1,
                network_adapter: NetworkAdapter::PlatformMandatory,
                environment_allowlist: EnvironmentAllowlist(vec!["PATH".into()]),
            },
            limits: ResourceLimitsConfig {
                checks_per_profile: 16,
                aggregate_secs: 64,
                output_bytes: 1024,
                log_bytes: 1024,
                worktree_bytes: 1024 * 1024,
                child_processes: 32,
                child_open_files: 64,
                child_file_bytes: 1024 * 1024,
            },
            build_output: None,
            deploy_output: None,
        }
    }

    #[cfg(unix)]
    struct CandidateTransactionFixture {
        root: PathBuf,
        pending: crate::cli::PendingCandidateBuild,
        output: PathBuf,
        candidate_root: PathBuf,
        candidate_record: PathBuf,
    }

    #[cfg(unix)]
    fn candidate_transaction_fixture(name: &str) -> CandidateTransactionFixture {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "mpd-candidate-transaction-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("openspec/changes/tx")).unwrap();
        fs::create_dir_all(root.join(".mpd")).unwrap();
        fs::write(root.join("src.txt"), b"head\n").unwrap();
        fs::write(root.join(".mpd/.gitignore"), b"build-output/\nstate/\n").unwrap();
        fs::write(
            root.join("openspec/changes/tx/manifest.json"),
            b"{\"version\":1,\"paths\":[\"**\"],\"shared_paths\":[]}",
        )
        .unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(&root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "transaction@example.invalid"]);
        git(&["config", "user.name", "Candidate Transaction"]);
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "base"]);
        fs::write(root.join("src.txt"), b"candidate\n").unwrap();
        let captured = crate::candidate::capture_candidate(&root, "tx", &"a".repeat(64))
            .expect("capture candidate transaction fixture");
        let capture = captured.projection.capture.clone();
        let candidate_root = PathBuf::from(&capture.clone_private_root);
        let candidate_record = PathBuf::from(&capture.storage.record_path);
        let runtime = root.join("runtime-artifact");
        fs::write(&runtime, b"candidate-artifact\n").unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o644)).unwrap();
        let contract = BuildOutputConfig {
            name: "candidate-artifact".into(),
            path: "runtime/artifact".into(),
            max_bytes: 1024,
            required_mode: 0o644,
        };
        let owned = export_candidate_runtime_build_output(
            &root,
            &runtime,
            &contract,
            &capture.subject.id,
            "tx",
        )
        .expect("export candidate transaction fixture");
        let output = root.join(&owned.output().path);
        let mut pending = crate::cli::PendingCandidateBuild::new(captured);
        pending.attach_output(owned);
        CandidateTransactionFixture {
            root,
            pending,
            output,
            candidate_root,
            candidate_record,
        }
    }

    #[cfg(unix)]
    fn remove_candidate_transaction_root(root: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fn make_writable(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if metadata.file_type().is_symlink() {
                return;
            }
            if metadata.is_dir() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                for entry in fs::read_dir(path).unwrap() {
                    make_writable(&entry.unwrap().path());
                }
            } else if metadata.is_file() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        make_writable(root);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_post_link_failure_cleans_only_owned_publication() {
        use std::os::unix::fs::PermissionsExt;

        for (mode, expected) in [
            (2, "after directory creation"),
            (1, "after link before staging unlink"),
            (3, "after staging unlink"),
        ] {
            let root = std::env::temp_dir().join(format!(
                "mpd-candidate-output-returned-fault-{mode}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join(".mpd")).unwrap();
            let source = root.join("artifact");
            fs::write(&source, b"artifact\n").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
            let contract = BuildOutputConfig {
                name: "artifact".into(),
                path: "runtime/artifact".into(),
                max_bytes: 1024,
                required_mode: 0o644,
            };
            let candidate_id = "b".repeat(64);
            set_candidate_output_failure(&root, mode);
            let error = export_candidate_runtime_build_output(
                &root,
                &source,
                &contract,
                &candidate_id,
                "tx",
            )
            .unwrap_err();
            assert!(error.contains(expected), "mode {mode}: {error}");
            assert!(!root.join(".mpd/build-output").join(candidate_id).exists());
            assert_eq!(fs::read(&source).unwrap(), b"artifact\n");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_retry_preserves_unproven_preexisting_entries() {
        use std::os::unix::fs::PermissionsExt;

        let prepare = |name: &str| {
            let root = std::env::temp_dir().join(format!(
                "mpd-candidate-output-foreign-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join(".mpd")).unwrap();
            let source = root.join("artifact");
            fs::write(&source, b"reviewed artifact\n").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
            let contract = BuildOutputConfig {
                name: "artifact".into(),
                path: "runtime/artifact".into(),
                max_bytes: 1024,
                required_mode: 0o644,
            };
            let candidate_id = Digest::of_bytes(name.as_bytes()).to_hex();
            let mut owned = export_candidate_runtime_build_output(
                &root,
                &source,
                &contract,
                &candidate_id,
                "tx",
            )
            .unwrap();
            let output = root.join(owned.output().path.as_str());
            owned.retain();
            drop(owned);
            (root, source, contract, candidate_id, output)
        };

        let (root, source, contract, candidate_id, output) = prepare("destination-mismatch");
        fs::remove_file(&output).unwrap();
        fs::write(&output, b"foreign destination\n").unwrap();
        let error =
            export_candidate_runtime_build_output(&root, &source, &contract, &candidate_id, "tx")
                .unwrap_err();
        assert!(error.contains("differs"));
        assert_eq!(fs::read(&output).unwrap(), b"foreign destination\n");
        remove_candidate_transaction_root(&root);

        let (root, source, contract, candidate_id, output) = prepare("identity-mismatch");
        let stage = output.parent().unwrap().join(".artifact.mpd-stage-v1");
        fs::write(&stage, b"foreign staging\n").unwrap();
        let error =
            export_candidate_runtime_build_output(&root, &source, &contract, &candidate_id, "tx")
                .unwrap_err();
        assert!(error.contains("different identities"));
        assert_eq!(fs::read(&output).unwrap(), b"reviewed artifact\n");
        assert_eq!(fs::read(&stage).unwrap(), b"foreign staging\n");
        remove_candidate_transaction_root(&root);
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_adoption_uses_open_source_and_preserves_on_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "mpd-candidate-output-source-replacement-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".mpd")).unwrap();
        let source = root.join("artifact");
        fs::write(&source, b"opened source bytes\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        let contract = BuildOutputConfig {
            name: "artifact".into(),
            path: "runtime/artifact".into(),
            max_bytes: 1024,
            required_mode: 0o644,
        };
        let candidate_id = Digest::of_bytes(b"source-replacement").to_hex();
        let mut owned =
            export_candidate_runtime_build_output(&root, &source, &contract, &candidate_id, "tx")
                .unwrap();
        let output = root.join(owned.output().path.as_str());
        owned.retain();
        drop(owned);
        set_candidate_output_failure(&root, 4);
        let error =
            export_candidate_runtime_build_output(&root, &source, &contract, &candidate_id, "tx")
                .unwrap_err();
        assert!(error.contains("changed during adoption"));
        assert_eq!(fs::read(&output).unwrap(), b"opened source bytes\n");
        assert_eq!(
            fs::read(&source).unwrap(),
            b"replacement-after-source-open\n"
        );
        remove_candidate_transaction_root(&root);
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_proof_to_arm_races_preserve_and_rollback_exactly() {
        use std::os::unix::fs::PermissionsExt;

        for (mode, name) in [(5, "replacement"), (6, "aba")] {
            let root = std::env::temp_dir().join(format!(
                "mpd-candidate-output-proof-arm-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join(".mpd")).unwrap();
            let source = root.join("artifact");
            fs::write(&source, b"proven artifact\n").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
            let contract = BuildOutputConfig {
                name: "artifact".into(),
                path: "runtime/artifact".into(),
                max_bytes: 1024,
                required_mode: 0o644,
            };
            let candidate_id = Digest::of_bytes(name.as_bytes()).to_hex();
            let mut owned = export_candidate_runtime_build_output(
                &root,
                &source,
                &contract,
                &candidate_id,
                "tx",
            )
            .unwrap();
            let output = root.join(owned.output().path.as_str());
            owned.retain();
            drop(owned);

            set_candidate_output_failure(&root, mode);
            let error = export_candidate_runtime_build_output(
                &root,
                &source,
                &contract,
                &candidate_id,
                "tx",
            )
            .unwrap_err();
            assert!(
                error.contains("identity changed after content proof"),
                "mode {mode}: {error}"
            );

            if mode == 5 {
                assert_eq!(fs::read(&output).unwrap(), b"proof-to-arm replacement\n");
                assert_eq!(
                    fs::read(output.with_extension("proof-original")).unwrap(),
                    b"proven artifact\n"
                );
            } else {
                assert_eq!(fs::read(&output).unwrap(), b"proven artifact\n");
                assert!(!output.with_extension("aba-original").exists());
                let mut entries = fs::read_dir(output.parent().unwrap())
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>();
                entries.sort();
                assert_eq!(entries, vec![output.file_name().unwrap()]);
            }
            remove_candidate_transaction_root(&root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_lock_hierarchy_refuses_permissive_or_multiply_linked_state() {
        use std::os::unix::fs::PermissionsExt;

        let contract = BuildOutputConfig {
            name: "artifact".into(),
            path: "runtime/artifact".into(),
            max_bytes: 1024,
            required_mode: 0o644,
        };
        for case in [
            "base-mode",
            "locks-mode",
            "lock-file-links",
            "candidate-mode",
        ] {
            let root = std::env::temp_dir().join(format!(
                "mpd-candidate-lock-{case}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join(".mpd")).unwrap();
            let source = root.join("artifact");
            fs::write(&source, b"artifact\n").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
            let candidate_id = Digest::of_bytes(case.as_bytes()).to_hex();
            let base = root.join(".mpd/build-output");
            let locks = base.join(".locks");
            match case {
                "base-mode" => {
                    fs::create_dir(&base).unwrap();
                    fs::set_permissions(&base, fs::Permissions::from_mode(0o770)).unwrap();
                }
                "locks-mode" => {
                    fs::create_dir(&base).unwrap();
                    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::create_dir(&locks).unwrap();
                    fs::set_permissions(&locks, fs::Permissions::from_mode(0o770)).unwrap();
                }
                "lock-file-links" => {
                    fs::create_dir(&base).unwrap();
                    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::create_dir(&locks).unwrap();
                    fs::set_permissions(&locks, fs::Permissions::from_mode(0o700)).unwrap();
                    let lock = locks.join(format!("{candidate_id}.lock"));
                    fs::write(&lock, b"").unwrap();
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::hard_link(&lock, locks.join("extra-link")).unwrap();
                }
                "candidate-mode" => {
                    fs::create_dir(&base).unwrap();
                    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
                    fs::create_dir(&locks).unwrap();
                    fs::set_permissions(&locks, fs::Permissions::from_mode(0o700)).unwrap();
                    let candidate = base.join(&candidate_id);
                    fs::create_dir(&candidate).unwrap();
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o770)).unwrap();
                }
                _ => unreachable!(),
            }
            let error = export_candidate_runtime_build_output(
                &root,
                &source,
                &contract,
                &candidate_id,
                "tx",
            )
            .unwrap_err();
            assert!(
                error.contains("owner/mode/link count")
                    || error.contains("directory owner/mode/link count"),
                "{case}: {error}"
            );
            remove_candidate_transaction_root(&root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_crash_child() {
        let Ok(root) = std::env::var("MPD_TEST_CANDIDATE_OUTPUT_ROOT") else {
            return;
        };
        let source = std::env::var("MPD_TEST_CANDIDATE_OUTPUT_SOURCE").unwrap();
        let candidate_id = std::env::var("MPD_TEST_CANDIDATE_OUTPUT_ID").unwrap();
        let contract = BuildOutputConfig {
            name: "crash-artifact".into(),
            path: "runtime/artifact".into(),
            max_bytes: 1024,
            required_mode: 0o644,
        };
        let _owned = export_candidate_runtime_build_output(
            Path::new(&root),
            Path::new(&source),
            &contract,
            &candidate_id,
            "crash",
        )
        .unwrap();
        maybe_crash_candidate_output("pre-ledger-cas");
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_sigkill_boundaries_retry_to_one_output_and_one_ledger_event() {
        use crate::ledger::{ExactSaveOutcome, GateRecord, Ledger, Verdict};
        use crate::phase::Phase;
        use std::os::unix::fs::PermissionsExt;

        let gate = |output| GateRecord {
            verdict: Verdict::Pass,
            by: "crash-test".into(),
            evidence: None,
            checks: None,
            at: "2026-07-19".into(),
            failure_class: None,
            exploitability: None,
            attempt: 1,
            started_at_epoch_secs: 1,
            completed_at_epoch_secs: 2,
            receipt: None,
            persona_tuning: None,
            candidate: None,
            build_output: output,
            deploy_result: None,
            validation_receipt: None,
            judgment_artifact_sha256: None,
        };
        for stage in [
            "directory-created",
            "hard-link-published",
            "staging-unlinked",
            "pre-ledger-cas",
        ] {
            let root = std::env::temp_dir().join(format!(
                "mpd-candidate-output-crash-{stage}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join(".mpd/state")).unwrap();
            assert!(Command::new("git")
                .args(["init", "-q"])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
            let source = root.join("runtime-artifact");
            fs::write(&source, b"crash-safe-artifact\n").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
            let mut ledger = Ledger::new("crash", "mpd", false, crate::ledger::ChangeKind::Fix);
            ledger.record(Phase::Architecture, gate(None)).unwrap();
            ledger.record(Phase::SecurityPlan, gate(None)).unwrap();
            crate::ledger::save(&root, &ledger).unwrap();
            let candidate_id = Digest::of_bytes(format!("candidate-{stage}").as_bytes()).to_hex();
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "local_validation::tests::candidate_output_crash_child",
                    "--nocapture",
                ])
                .env("MPD_TEST_CANDIDATE_OUTPUT_ROOT", &root)
                .env("MPD_TEST_CANDIDATE_OUTPUT_SOURCE", &source)
                .env("MPD_TEST_CANDIDATE_OUTPUT_ID", &candidate_id)
                .env("MPD_TEST_CANDIDATE_OUTPUT_CRASH", stage)
                .output()
                .unwrap();
            assert!(
                !child.status.success(),
                "{stage} child unexpectedly survived: stdout={} stderr={}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );

            let contract = BuildOutputConfig {
                name: "crash-artifact".into(),
                path: "runtime/artifact".into(),
                max_bytes: 1024,
                required_mode: 0o644,
            };
            let mut owned = export_candidate_runtime_build_output(
                &root,
                &source,
                &contract,
                &candidate_id,
                "crash",
            )
            .unwrap_or_else(|error| panic!("{stage} retry failed: {error}"));
            owned.revalidate(&root).unwrap();
            let (mut durable, observed) =
                crate::ledger::load_observed_exact(&root, "crash").unwrap();
            durable
                .record(Phase::Build, gate(Some(owned.output().clone())))
                .unwrap();
            assert!(matches!(
                crate::ledger::save_exact_observed(&root, &durable, &observed),
                ExactSaveOutcome::Committed
            ));
            let output_path = root.join(owned.output().path.as_str());
            owned.retain();
            drop(owned);

            let retry = export_candidate_runtime_build_output(
                &root,
                &source,
                &contract,
                &candidate_id,
                "crash",
            )
            .unwrap_err();
            assert!(retry.contains("already bound"));
            let durable = crate::ledger::load(&root, "crash").unwrap();
            assert_eq!(
                durable
                    .history
                    .iter()
                    .filter(|event| event.phase == Phase::Build)
                    .count(),
                1,
                "{stage} recorded more than one Build event"
            );
            let directory = root.join(".mpd/build-output").join(&candidate_id);
            let entries = fs::read_dir(&directory)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(entries.len(), 1, "{stage} left staging/orphan files");
            assert_eq!(entries[0].path(), output_path);
            remove_candidate_transaction_root(&root);
        }
    }

    // =====================================================================
    // D2 — Build-output binding is authoritative through `gates` only
    // =====================================================================

    fn stub_candidate_capture(change: &str, id: &str) -> crate::candidate::CandidateCapture {
        crate::candidate::CandidateCapture {
            subject: crate::candidate::CandidateSubject {
                version: 1,
                change: change.to_string(),
                base_commit: "a".repeat(40),
                base_tree: "b".repeat(40),
                manifest_digest: "c".repeat(64),
                entries_digest: "d".repeat(64),
                policy_digest: "e".repeat(64),
                source_digest: "f".repeat(64),
                id: id.to_string(),
            },
            clone_private_root: "/stub/candidate-root".into(),
            storage: crate::candidate::CandidateStorageBinding {
                record_path: "/stub/candidate-record.json".into(),
                record_sha256: "0".repeat(64),
                root_device: 0,
                root_inode: 0,
                record_device: 0,
                record_inode: 0,
            },
            counts: crate::candidate::CandidateCounts::default(),
            excluded_dirty_digest: "1".repeat(64),
            excluded_dirty_sample: Vec::new(),
            declared_status_digest: "2".repeat(64),
            captured_at_epoch_secs: 0,
        }
    }

    fn stub_build_output(candidate_id: &str, path: &str) -> BuildOutputV1 {
        BuildOutputV1 {
            schema: BUILD_OUTPUT_SCHEMA,
            name: "artifact".into(),
            path: path.into(),
            max_bytes: 1024,
            required_mode: 0o644,
            size: 4,
            mode: 0o644,
            device: 0,
            inode: 0,
            sha256: "3".repeat(64),
            candidate_id: Some(candidate_id.to_string()),
        }
    }

    fn stub_gate_record(
        candidate: Option<crate::candidate::CandidateCapture>,
        build_output: Option<BuildOutputV1>,
    ) -> crate::ledger::GateRecord {
        crate::ledger::GateRecord {
            verdict: crate::ledger::Verdict::Pass,
            by: "fixture".into(),
            evidence: None,
            checks: None,
            at: "2026-07-19".into(),
            failure_class: None,
            exploitability: None,
            attempt: 1,
            started_at_epoch_secs: 0,
            completed_at_epoch_secs: 0,
            receipt: None,
            persona_tuning: None,
            candidate,
            build_output,
            deploy_result: None,
            validation_receipt: None,
            judgment_artifact_sha256: None,
        }
    }

    /// Condition 5 / D2: a Security(code)/Test-style gate record — carrying
    /// `candidate` but never `build_output` — must never be treated as a
    /// binding. This is the exact `:1414` false-positive the redesign
    /// removes: before D2, any record referencing the candidate ID (via
    /// either field) errored "no typed Build output" instead of simply not
    /// being a binding.
    #[test]
    fn candidate_carrying_record_without_build_output_is_never_a_binding() {
        let root = std::env::temp_dir().join(format!(
            "mpd-ledger-bound-candidate-only-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".mpd")).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let candidate_id = Digest::of_bytes(b"candidate-only").to_hex();
        let relative = format!(".mpd/build-output/{candidate_id}/artifact");

        let mut ledger = crate::ledger::Ledger::new(
            "rebind-candidate-only",
            "mpd",
            false,
            crate::ledger::ChangeKind::Fix,
        );
        ledger.gates.insert(
            crate::phase::Phase::SecurityCode,
            stub_gate_record(
                Some(stub_candidate_capture(
                    "rebind-candidate-only",
                    &candidate_id,
                )),
                None,
            ),
        );
        crate::ledger::save(&root, &ledger).unwrap();

        assert!(!candidate_output_ledger_bound(
            &root,
            "rebind-candidate-only",
            &candidate_id,
            &relative
        )
        .unwrap());

        fs::remove_dir_all(&root).unwrap();
    }

    /// D2's core fix: a Build PASS that was rewound by
    /// `invalidate_for_freshness` leaves its typed `build_output` in
    /// `history` only — `gates` no longer carries it. Re-export of the same
    /// candidate ID must succeed (not poisoned by the superseded event), and
    /// binding must resume the instant a live `gates` record carries the
    /// output again.
    #[test]
    fn rewound_history_only_build_output_does_not_poison_re_export() {
        let root = std::env::temp_dir().join(format!(
            "mpd-ledger-bound-rewound-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".mpd")).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let candidate_id = Digest::of_bytes(b"rewound-candidate").to_hex();
        let relative = format!(".mpd/build-output/{candidate_id}/artifact");

        let mut ledger = crate::ledger::Ledger::new(
            "rebind-rewound",
            "mpd",
            false,
            crate::ledger::ChangeKind::Fix,
        );
        let capture = stub_candidate_capture("rebind-rewound", &candidate_id);
        let output = stub_build_output(&candidate_id, &relative);
        ledger.history.push(crate::ledger::GateEvent {
            phase: crate::phase::Phase::Build,
            record: stub_gate_record(Some(capture.clone()), Some(output.clone())),
        });
        // `gates` deliberately does NOT carry Build — this is exactly what
        // `invalidate_for_freshness` leaves behind after a freshness rewind.
        crate::ledger::save(&root, &ledger).unwrap();

        assert!(
            !candidate_output_ledger_bound(&root, "rebind-rewound", &candidate_id, &relative)
                .unwrap(),
            "a history-only Build output must not bind re-export"
        );

        // A live re-record of Build (the freshly re-run Build passing again)
        // makes it a real binding once more, at the same path.
        ledger.gates.insert(
            crate::phase::Phase::Build,
            stub_gate_record(Some(capture), Some(output)),
        );
        crate::ledger::save(&root, &ledger).unwrap();
        assert!(
            candidate_output_ledger_bound(&root, "rebind-rewound", &candidate_id, &relative)
                .unwrap(),
            "a live gates Build output must bind"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    /// Condition 4: a live `gates` binding at a DIFFERENT path still errors
    /// (the anti-double-bind path-consistency check is unchanged).
    #[test]
    fn live_gates_build_output_at_a_different_path_still_errors() {
        let root = std::env::temp_dir().join(format!(
            "mpd-ledger-bound-different-path-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".mpd")).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let candidate_id = Digest::of_bytes(b"different-path").to_hex();
        let bound_path = format!(".mpd/build-output/{candidate_id}/artifact");

        let mut ledger = crate::ledger::Ledger::new(
            "rebind-different-path",
            "mpd",
            false,
            crate::ledger::ChangeKind::Fix,
        );
        ledger.gates.insert(
            crate::phase::Phase::Build,
            stub_gate_record(
                Some(stub_candidate_capture(
                    "rebind-different-path",
                    &candidate_id,
                )),
                Some(stub_build_output(&candidate_id, &bound_path)),
            ),
        );
        crate::ledger::save(&root, &ledger).unwrap();

        let error = candidate_output_ledger_bound(
            &root,
            "rebind-different-path",
            &candidate_id,
            "different/artifact/path",
        )
        .unwrap_err();
        assert!(error.contains("different output path"), "{error}");

        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn candidate_transaction_owns_output_across_precommit_and_cas_outcomes() {
        for failure in ["post-export-rehash", "ledger-record", "cas-before-rename"] {
            let CandidateTransactionFixture {
                root,
                mut pending,
                output,
                candidate_root,
                candidate_record,
            } = candidate_transaction_fixture(failure);
            if failure == "cas-before-rename" {
                let result = crate::cli::resolve_candidate_save_outcome(
                    &root,
                    Some(&mut pending),
                    crate::ledger::ExactSaveOutcome::NotCommitted(std::io::Error::other(
                        "injected before-rename failure",
                    )),
                );
                assert!(result.unwrap_err().contains("before-rename"));
            }
            // A post-export rehash error, ledger.record error, and a classified
            // before-rename CAS error all exit while the same pending guard is armed.
            drop(pending);
            assert!(!output.exists(), "{failure} left an unbound output");
            assert!(!candidate_root.exists(), "{failure} left a candidate root");
            assert!(
                !candidate_record.exists(),
                "{failure} left a candidate sidecar"
            );
            remove_candidate_transaction_root(&root);
        }

        let CandidateTransactionFixture {
            root,
            mut pending,
            output,
            candidate_root,
            candidate_record,
        } = candidate_transaction_fixture("confirmed-after-rename");
        let warning = crate::cli::resolve_candidate_save_outcome(
            &root,
            Some(&mut pending),
            crate::ledger::ExactSaveOutcome::CommittedAfterRename {
                error: "injected directory sync failure".into(),
            },
        )
        .unwrap()
        .unwrap();
        assert!(warning.contains("confirmed by exact readback"));
        drop(pending);
        assert!(output.is_file());
        assert!(candidate_root.is_dir());
        assert!(candidate_record.is_file());
        remove_candidate_transaction_root(&root);

        let CandidateTransactionFixture {
            root,
            mut pending,
            output,
            candidate_root,
            candidate_record,
        } = candidate_transaction_fixture("uncertain-after-rename");
        let error = crate::cli::resolve_candidate_save_outcome(
            &root,
            Some(&mut pending),
            crate::ledger::ExactSaveOutcome::UncertainAfterRename(std::io::Error::other(
                "injected readback mismatch",
            )),
        )
        .unwrap_err();
        assert!(error.contains("uncertain"));
        drop(pending);
        assert!(output.is_file());
        assert!(candidate_root.is_dir());
        assert!(candidate_record.is_file());
        remove_candidate_transaction_root(&root);
    }

    #[cfg(unix)]
    #[test]
    fn candidate_output_revalidation_blocks_delete_and_preserves_replacement_symmetrically() {
        let CandidateTransactionFixture {
            root,
            pending,
            output,
            candidate_root,
            candidate_record,
        } = candidate_transaction_fixture("deleted-before-cas");
        fs::remove_file(&output).unwrap();
        assert!(pending.revalidate_output(&root).is_err());
        drop(pending);
        assert!(!candidate_root.exists());
        assert!(!candidate_record.exists());
        assert!(!output.exists());
        remove_candidate_transaction_root(&root);

        let CandidateTransactionFixture {
            root,
            pending,
            output,
            candidate_root,
            candidate_record,
        } = candidate_transaction_fixture("replacement-before-cas");
        let moved = output.with_extension("owned-moved");
        fs::rename(&output, &moved).unwrap();
        fs::write(&output, b"concurrent replacement\n").unwrap();
        assert!(pending.revalidate_output(&root).is_err());
        drop(pending);
        assert_eq!(fs::read(&output).unwrap(), b"concurrent replacement\n");
        assert!(moved.is_file());
        assert!(candidate_root.is_dir());
        assert!(candidate_record.is_file());
        remove_candidate_transaction_root(&root);

        let CandidateTransactionFixture {
            root,
            mut pending,
            output,
            candidate_root,
            candidate_record,
        } = candidate_transaction_fixture("replacement-after-commit");
        let moved = output.with_extension("owned-moved");
        fs::rename(&output, &moved).unwrap();
        fs::write(&output, b"post-commit replacement\n").unwrap();
        let error = crate::cli::resolve_candidate_save_outcome(
            &root,
            Some(&mut pending),
            crate::ledger::ExactSaveOutcome::Committed,
        )
        .unwrap_err();
        assert!(error.contains("after the exact ledger commit"));
        drop(pending);
        assert_eq!(fs::read(&output).unwrap(), b"post-commit replacement\n");
        assert!(moved.is_file());
        assert!(candidate_root.is_dir());
        assert!(candidate_record.is_file());
        remove_candidate_transaction_root(&root);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    /// True only when actually inside the validation sandbox: the marker
    /// alone is not trusted (an ambient variable must not silently skip
    /// coverage in uncontained runs); the denied-read canary corroborates it.
    fn nested_in_validation_sandbox() -> bool {
        std::env::var_os("MPD_SANDBOXED").is_some() && std::fs::read("/private/etc/hosts").is_err()
    }

    #[test]
    fn candidate_profile_runs_retained_dirty_bytes_without_git_receipt_mutation() {
        if nested_in_validation_sandbox() {
            eprintln!("skipped: cannot nest the validation sandbox");
            return;
        }
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "mpd-candidate-profile-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let git = |directory: &Path, args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(directory)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "candidate@example.invalid"],
        );
        git(&root, &["config", "user.name", "Candidate Profile"]);

        fs::write(
            root.join("Cargo.toml"),
            b"[package]\nname = \"tiny-candidate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("src/main.rs"),
            b"fn main() { println!(\"head\"); }\n#[cfg(test)] mod tests { #[test] fn passes() { assert_eq!(2 + 2, 4); } }\n",
        )
        .unwrap();
        let generated = Command::new("/opt/homebrew/bin/cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );

        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for spec in POLICY_ASSET_SPECS {
            let source = workspace.join(spec.path);
            let destination = root.join(spec.path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(&source, &destination).unwrap();
        }
        fs::create_dir_all(root.join(".mpd")).unwrap();
        fs::write(
            root.join(".mpd/.gitignore"),
            b"build-output/\nlocal/\nstate/\n",
        )
        .unwrap();

        let private = root.join(".git/mpd");
        let advisory = private.join("advisory-db");
        fs::create_dir_all(&advisory).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        git(&advisory, &["init", "-q"]);
        git(
            &advisory,
            &["config", "user.email", "advisory@example.invalid"],
        );
        git(&advisory, &["config", "user.name", "Advisory Fixture"]);
        fs::write(advisory.join("README.md"), b"offline advisory fixture\n").unwrap();
        git(&advisory, &["add", "README.md"]);
        git(&advisory, &["commit", "-q", "-m", "advisory fixture"]);
        let advisory_commit = String::from_utf8(git(&advisory, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_string();
        let advisory_tree = String::from_utf8(git(&advisory, &["rev-parse", "HEAD^{tree}"]))
            .unwrap()
            .trim()
            .to_string();
        let advisory_listing = git(&advisory, &["ls-tree", "-r", "-z", "--full-tree", "HEAD"]);
        let advisory_listing_digest = Digest::of_bytes(&advisory_listing).to_hex();
        fs::write(
            root.join("security/advisory-db.lock.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1,
                "commit": advisory_commit,
                "git_tree_oid": advisory_tree,
                "tree_listing_sha256": advisory_listing_digest,
                "max_age_days": 30
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir(private.join("cargo-home")).unwrap();
        fs::set_permissions(
            private.join("cargo-home"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        let mut policy = crate::config::Config::load_strict(&workspace)
            .unwrap()
            .local_validation
            .unwrap();
        policy.required_toolchain.components = vec!["cargo".into()];
        policy.tools.retain(|name, _| name == "cargo");
        let cargo_check = |kind, args: &[&str], result_policy| CheckConfig {
            kind,
            program: "cargo".into(),
            args: args.iter().map(|value| (*value).to_string()).collect(),
            timeout_secs: 120,
            result_policy,
            output: None,
        };
        policy.checks = BTreeMap::from([
            (
                "format".into(),
                cargo_check(
                    CheckKind::Format,
                    &["fmt", "--all", "--", "--check"],
                    ResultPolicy::ExitZero,
                ),
            ),
            (
                "lint".into(),
                cargo_check(
                    CheckKind::Lint,
                    &["check", "--locked", "--all-targets"],
                    ResultPolicy::ExitZero,
                ),
            ),
            (
                "test".into(),
                cargo_check(
                    CheckKind::Test,
                    &["test", "--locked"],
                    ResultPolicy::RustTestCount,
                ),
            ),
            (
                "release".into(),
                cargo_check(
                    CheckKind::ReleaseBuild,
                    &["build", "--release", "--locked"],
                    ResultPolicy::ExitZero,
                ),
            ),
            (
                "self-check".into(),
                cargo_check(CheckKind::SelfCheck, &["--version"], ResultPolicy::ExitZero),
            ),
            (
                "dependency".into(),
                cargo_check(
                    CheckKind::DependencyAudit,
                    &["--version"],
                    ResultPolicy::ExitZero,
                ),
            ),
            (
                "secret".into(),
                cargo_check(
                    CheckKind::SecretScan,
                    &["--version"],
                    ResultPolicy::ExitZero,
                ),
            ),
            (
                "sast".into(),
                cargo_check(CheckKind::Sast, &["--version"], ResultPolicy::ExitZero),
            ),
            (
                "nonfunctional".into(),
                cargo_check(
                    CheckKind::Nonfunctional,
                    &["--version"],
                    ResultPolicy::ExitZero,
                ),
            ),
        ]);
        policy.profiles = BTreeMap::from([
            (
                "build".into(),
                ProfileConfig {
                    includes: Vec::new(),
                    checks: ["format", "lint", "test", "release"]
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                },
            ),
            (
                "security".into(),
                ProfileConfig {
                    includes: Vec::new(),
                    checks: ["self-check", "dependency", "secret", "sast"]
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                },
            ),
            (
                "test".into(),
                ProfileConfig {
                    includes: vec!["build".into(), "security".into()],
                    checks: Vec::new(),
                },
            ),
            (
                "high".into(),
                ProfileConfig {
                    includes: vec!["test".into()],
                    checks: vec!["nonfunctional".into()],
                },
            ),
        ]);
        policy.gates = GateProfiles {
            build: "build".into(),
            security_code: "security".into(),
            test: "test".into(),
            pre_push: "test".into(),
            high_risk_test: "high".into(),
            docs_build: None,
            docs_security_code: None,
            docs_test: None,
        };
        policy.offline.advisory_db_path = "mpd/advisory-db".into();
        policy.offline.advisory_revision = advisory_commit;
        policy.offline.advisory_tree = advisory_tree;
        policy.offline.advisory_max_age_days = 30;
        policy.limits.aggregate_secs = 600;
        policy.limits.log_bytes = 1024 * 1024;
        policy.receipts.log_byte_cap = 1024 * 1024;
        policy.build_output = Some(BuildOutputConfig {
            name: "tiny-release".into(),
            path: ".mpd/build-output/tiny-candidate".into(),
            max_bytes: 16 * 1024 * 1024,
            required_mode: 0o755,
        });
        policy.deploy_output = None;
        policy.validate().unwrap();
        fs::write(
            root.join(".mpd/config.json"),
            serde_json::to_vec_pretty(&serde_json::json!({ "local_validation": policy })).unwrap(),
        )
        .unwrap();
        fs::create_dir_all(root.join("openspec/changes/candidate-build")).unwrap();
        fs::write(
            root.join("openspec/changes/candidate-build/manifest.json"),
            b"{\"version\":1,\"paths\":[\"**\"],\"shared_paths\":[]}",
        )
        .unwrap();
        git(&root, &["add", "-A"]);
        git(
            &root,
            &["commit", "--no-verify", "-q", "-m", "passing HEAD"],
        );

        let assets = test_policy_assets(&root);
        let (tool_lock, sandbox, hooks) = policy_asset_digests(&assets).unwrap();
        let checkpoint = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let fixed = "a".repeat(64);
        let object = TrustedPolicyObjectV1 {
            schema: 1,
            local_validation: policy.clone(),
            asset_schema: POLICY_ASSET_SCHEMA,
            assets: policy_asset_metadata(&assets),
            previous_trusted_policy_oid: None,
            checkpoint_oid: checkpoint,
            pretrust_proof_digest: fixed.clone(),
            bootstrap_nonce_digest: fixed.clone(),
            coordinator_digest: fixed,
            hook_digest: hooks,
            tool_lock_digest: tool_lock,
            sandbox_digest: sandbox,
        };
        let trusted_oid = write_policy_commit(&root, &object, &assets).unwrap();
        git(&root, &["update-ref", TRUSTED_POLICY_REF, &trusted_oid]);

        fs::write(
            root.join("src/main.rs"),
            b"fn main() { println!(\"dirty candidate\"); }\n#[cfg(test)] mod tests { #[test] fn fails() { assert_eq!(3 * 3, 8); } }\n",
        )
        .unwrap();
        let (candidate_policy, policy_digest) = load_candidate_policy(&root).unwrap();
        let captured =
            crate::candidate::capture_candidate(&root, "candidate-build", &policy_digest).unwrap();
        let refs_before = git(
            &root,
            &["for-each-ref", "--format=%(refname) %(objectname)"],
        );
        let objects_before = git(&root, &["count-objects", "-v"]);
        let index_before = fs::read(root.join(".git/index")).unwrap();
        let status_before = git(&root, &["status", "--porcelain=v2", "-z"]);

        let mut configured_argv_calls = 0usize;
        let forged_root = root.join("src");
        let error = validate_candidate_profile_inner(
            &root,
            &forged_root,
            &captured.projection.capture,
            &candidate_policy.gates.build,
            &candidate_policy,
            |_, _, _, _, _, _| {
                configured_argv_calls += 1;
                unreachable!("forged candidate root must start no configured argv")
            },
        )
        .unwrap_err();
        assert!(error.contains("root does not match"));
        let mut forged_capture = captured.projection.capture.clone();
        forged_capture.storage.record_sha256 = "0".repeat(64);
        let error = validate_candidate_profile_inner(
            &root,
            captured.root(),
            &forged_capture,
            &candidate_policy.gates.build,
            &candidate_policy,
            |_, _, _, _, _, _| {
                configured_argv_calls += 1;
                unreachable!("forged candidate binding must start no configured argv")
            },
        )
        .unwrap_err();
        assert!(error.contains("compact binding"));
        assert_eq!(configured_argv_calls, 0);

        // Regression: HEAD contains a passing test, but the uncommitted
        // Candidate contains a failing one. The objective candidate path must
        // report that failure rather than substituting the passing commit.
        let head_source = git(&root, &["show", "HEAD:src/main.rs"]);
        assert!(String::from_utf8_lossy(&head_source).contains("assert_eq!(2 + 2, 4)"));
        let candidate_failure = validate_candidate_profile_inner(
            &root,
            captured.root(),
            &captured.projection.capture,
            &candidate_policy.gates.security_code,
            &candidate_policy,
            |_, _, subject, _, _, _| {
                let source = fs::read_to_string(captured.root().join("src/main.rs")).unwrap();
                assert!(source.contains("assert_eq!(3 * 3, 8)"));
                Ok(ValidationReport {
                    schema: VALIDATION_SCHEMA,
                    subject: subject.clone(),
                    profile: "security".into(),
                    status: "failed".into(),
                    receipt: None,
                    blocker: Some("candidate test failed".into()),
                    counts: ValidationCountsV1 {
                        total: 1,
                        passed: 0,
                        failed: 1,
                        blocked: 0,
                        not_run: 0,
                    },
                    actions: Vec::new(),
                })
            },
        )
        .unwrap();
        assert_eq!(candidate_failure.report.status, "failed");
        assert_eq!(
            candidate_failure.report.blocker.as_deref(),
            Some("candidate test failed")
        );

        // Condition 19: a PASSING non-Build profile must never attach a
        // typed build_output. The guard at this call site is keyed on the
        // configured profile name (`profile == candidate_policy.gates.build`)
        // rather than a literal `Phase::Build` check, so this exercises the
        // real invariant `candidate_output_ledger_bound`'s D2 binding
        // predicate depends on: Build stays the only profile this ever
        // happens for.
        let security_code_pass = validate_candidate_profile_inner(
            &root,
            captured.root(),
            &captured.projection.capture,
            &candidate_policy.gates.security_code,
            &candidate_policy,
            |_, _, subject, _, _, _| {
                Ok(ValidationReport {
                    schema: VALIDATION_SCHEMA,
                    subject: subject.clone(),
                    profile: "security".into(),
                    status: "passed".into(),
                    receipt: Some(test_receipt(subject.clone(), "security")),
                    blocker: None,
                    counts: ValidationCountsV1 {
                        total: 1,
                        passed: 1,
                        failed: 0,
                        blocked: 0,
                        not_run: 0,
                    },
                    actions: Vec::new(),
                })
            },
        )
        .unwrap();
        assert_eq!(security_code_pass.report.status, "passed");
        assert!(
            security_code_pass.build_output.is_none(),
            "only the configured Build profile may ever attach a typed build_output"
        );
        assert!(security_code_pass
            .report
            .receipt
            .as_ref()
            .unwrap()
            .build_output
            .is_none());

        let validation = validate_candidate_profile_inner(
            &root,
            captured.root(),
            &captured.projection.capture,
            &candidate_policy.gates.build,
            &candidate_policy,
            |output_root, _, subject, _, _, _| {
                let produced = output_root.join(".mpd/build-output/tiny-candidate");
                fs::create_dir_all(produced.parent().unwrap()).unwrap();
                fs::write(&produced, b"candidate-built-bytes").unwrap();
                fs::set_permissions(&produced, fs::Permissions::from_mode(0o755)).unwrap();
                Ok(ValidationReport {
                    schema: VALIDATION_SCHEMA,
                    subject: subject.clone(),
                    profile: "build".into(),
                    status: "passed".into(),
                    receipt: Some(test_receipt(subject.clone(), "build")),
                    blocker: None,
                    counts: ValidationCountsV1 {
                        total: 1,
                        passed: 1,
                        failed: 0,
                        blocked: 0,
                        not_run: 0,
                    },
                    actions: Vec::new(),
                })
            },
        )
        .unwrap();
        assert_eq!(validation.report.status, "passed");
        let mut owned_output = validation.build_output.unwrap();
        let output = validation.report.receipt.unwrap().build_output.unwrap();
        assert_eq!(owned_output.output(), &output);
        owned_output.revalidate(&root).unwrap();
        assert_eq!(
            output.candidate_id.as_deref(),
            Some(captured.projection.capture.subject.id.as_str())
        );
        assert!(root.join(&output.path).is_file());
        assert_eq!(
            refs_before,
            git(
                &root,
                &["for-each-ref", "--format=%(refname) %(objectname)"]
            )
        );
        assert_eq!(objects_before, git(&root, &["count-objects", "-v"]));
        assert_eq!(index_before, fs::read(root.join(".git/index")).unwrap());
        assert_eq!(
            status_before,
            git(&root, &["status", "--porcelain=v2", "-z"])
        );
        assert!(git_output(
            &root,
            &["rev-parse", "--verify", "--quiet", VALIDATION_NOTES_REF]
        )
        .is_err());
        assert_eq!(
            fs::read_to_string(root.join("src/main.rs")).unwrap(),
            "fn main() { println!(\"dirty candidate\"); }\n#[cfg(test)] mod tests { #[test] fn fails() { assert_eq!(3 * 3, 8); } }\n"
        );

        let gate = |candidate, build_output| crate::ledger::GateRecord {
            verdict: crate::ledger::Verdict::Pass,
            by: "fixture".into(),
            evidence: None,
            checks: Some(crate::ledger::CheckSummary {
                tests_passed: Some(1),
                secrets_clean: None,
                scanner: None,
                command: Some("candidate build fixture".into()),
            }),
            at: "2026-07-19".into(),
            failure_class: None,
            exploitability: None,
            attempt: 1,
            started_at_epoch_secs: 1,
            completed_at_epoch_secs: 2,
            receipt: None,
            persona_tuning: None,
            candidate,
            build_output,
            deploy_result: None,
            validation_receipt: None,
            judgment_artifact_sha256: None,
        };
        let mut ledger = crate::ledger::Ledger::new(
            "candidate-build",
            "mpd",
            false,
            crate::ledger::ChangeKind::Fix,
        );
        ledger.strict = true;
        ledger
            .record(crate::phase::Phase::Architecture, gate(None, None))
            .unwrap();
        ledger
            .record(crate::phase::Phase::SecurityPlan, gate(None, None))
            .unwrap();
        ledger
            .record(
                crate::phase::Phase::Build,
                gate(
                    Some(captured.projection.capture.clone()),
                    Some(output.clone()),
                ),
            )
            .unwrap();
        crate::ledger::save(&root, &ledger).unwrap();
        let durable = crate::ledger::load(&root, "candidate-build").unwrap();
        let build = durable.gates.get(&crate::phase::Phase::Build).unwrap();
        assert_eq!(
            build.candidate.as_ref().unwrap().subject.id,
            captured.projection.capture.subject.id
        );
        assert_eq!(
            build.build_output.as_ref().unwrap().candidate_id,
            Some(captured.projection.capture.subject.id.clone())
        );
        assert_eq!(
            refs_before,
            git(
                &root,
                &["for-each-ref", "--format=%(refname) %(objectname)"]
            )
        );
        assert_eq!(objects_before, git(&root, &["count-objects", "-v"]));
        assert_eq!(index_before, fs::read(root.join(".git/index")).unwrap());
        assert_eq!(
            status_before,
            git(&root, &["status", "--porcelain=v2", "-z"])
        );
        owned_output.retain();
        captured.cleanup().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn wire_record_is_strict() {
        let zero = "0".repeat(40);
        let oid = "a".repeat(40);
        assert!(parse_pre_push_record(
            format!("refs/heads/main {oid} refs/heads/main {zero}").as_bytes()
        )
        .is_ok());
        assert!(parse_pre_push_record(b"a b c").is_err());
        assert!(parse_pre_push_record(b"a\tb c d").is_err());
        assert!(parse_pre_push_record(b"a b c d e").is_err());
        assert!(parse_pre_push_record(
            format!("refs/heads/main {zero} refs/heads/main {zero}").as_bytes()
        )
        .is_err());
        assert!(
            parse_pre_push_record(format!("(delete) {zero} refs/heads/main {oid}").as_bytes())
                .is_ok()
        );
        assert!(parse_pre_push_record(
            format!("(delete) {zero} refs/heads/main {zero}").as_bytes()
        )
        .is_err());
        let expression =
            parse_pre_push_record(format!("HEAD~1 {oid} refs/heads/expression {zero}").as_bytes())
                .unwrap();
        assert_eq!(expression.local_ref, "HEAD~1");
        for malformed in [
            format!(" refs/heads/main {oid} refs/heads/main {zero}"),
            format!("refs/heads/main  {oid} refs/heads/main {zero}"),
            format!("refs/heads/main {oid} refs/heads/main {zero} "),
            format!("refs/heads/main {oid}\r refs/heads/main {zero}"),
            format!("refs/heads/main {oid}\u{1b} refs/heads/main {zero}"),
            format!("refs/heads/main {} refs/heads/main {zero}", "a".repeat(39)),
            format!("(delete) {oid} refs/heads/main {oid}"),
            format!("refs/heads/main {zero} refs/heads/main {oid}"),
        ] {
            assert!(
                parse_pre_push_record(malformed.as_bytes()).is_err(),
                "accepted malformed record {malformed:?}"
            );
        }
    }

    #[test]
    fn wire_batch_requires_terminal_lf_and_deduplicates_exact_updates() {
        let zero = "0".repeat(40);
        let oid = "a".repeat(40);
        let record = format!("refs/heads/main {oid} refs/heads/main {zero}");
        assert_eq!(
            parse_pre_push_records(format!("{record}\n").as_bytes())
                .unwrap()
                .len(),
            1
        );
        assert!(parse_pre_push_records(record.as_bytes()).is_err());
        assert!(parse_pre_push_records(format!("{record}\n{record}\n").as_bytes()).is_err());
        assert!(parse_pre_push_records(format!("{record}\n\n").as_bytes()).is_err());

        let delete = format!("(delete) {zero} refs/heads/old {oid}");
        let expression = format!("HEAD~1 {oid} refs/heads/expression {zero}");
        let batch =
            parse_pre_push_records(format!("{record}\n{delete}\n{expression}\n").as_bytes())
                .unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(
            batch
                .iter()
                .filter(|row| row.local_ref == "(delete)")
                .count(),
            1
        );
    }

    #[test]
    fn wire_batch_accepts_ten_thousand_shared_subject_refs_under_the_byte_cap() {
        let zero = "0".repeat(40);
        let oid = "a".repeat(40);
        let mut input = Vec::new();
        for index in 0..MAX_PUSH_RECORDS {
            input.extend_from_slice(format!("r{index:04} {oid} x{index:04} {zero}\n").as_bytes());
        }
        assert!(input.len() < MAX_PUSH_BYTES);
        let records = parse_pre_push_records(&input).unwrap();
        assert_eq!(records.len(), MAX_PUSH_RECORDS);
        assert_eq!(
            records
                .iter()
                .map(|record| &record.local_oid)
                .collect::<BTreeSet<_>>()
                .len(),
            1,
            "all updates intentionally share one complete direct subject"
        );

        input.extend_from_slice(format!("overflow {oid} overflow {zero}\n").as_bytes());
        assert!(parse_pre_push_records(&input)
            .unwrap_err()
            .contains("record cap"));
    }

    #[test]
    fn trusted_policy_comparison_is_byte_exact() {
        let canonical = br#"{\"schema\":1,\"checks\":{}}"#;
        assert_eq!(Digest::of_bytes(canonical), Digest::of_bytes(canonical));
        assert_ne!(
            Digest::of_bytes(canonical),
            Digest::of_bytes(br#"{\"checks\":{},\"schema\":1}"#)
        );
    }

    #[test]
    fn promotion_rejects_unconfirmed_candidate_before_any_candidate_command() {
        let root = promotion_fixture("unconfirmed");
        let subject = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let marker = root.join("candidate-ran");
        let mut candidate = test_policy();
        candidate.tools.insert(
            "candidate-canary".into(),
            ToolConfig {
                program: "candidate-canary".into(),
                version_args: Vec::new(),
                requirement: ToolRequirement::Required,
                install_hint: "must not run before confirmation".into(),
            },
        );
        candidate.checks.get_mut("format").unwrap().program = "candidate-canary".into();
        write_policy_commit_subject(&root, &candidate, "candidate-canary", &marker);
        let candidate_oid = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        assert_ne!(candidate_oid, subject);

        let error = promote_trusted_policy(&root, &candidate_oid, &"0".repeat(64)).unwrap_err();
        assert!(error.contains("reviewed policy digest"));
        assert!(
            !marker.exists(),
            "candidate command ran before confirmation"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn trusted_policy_ref_rejects_symbolic_refs() {
        let root = promotion_fixture("symbolic-ref");
        assert!(Command::new("git")
            .args([
                "symbolic-ref",
                TRUSTED_POLICY_REF,
                "refs/heads/does-not-matter",
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            trusted_policy_ref(&root).unwrap_err(),
            "trusted-policy-invalid: trusted policy ref must be literal and direct"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn promoted_object_binds_prior_trusted_oid_and_reviewed_assets() {
        let root = promotion_fixture("object-lineage");
        let previous = "a".repeat(40);
        let fixed = "b".repeat(64);
        let assets = test_policy_assets(&root);
        let (tool_lock, sandbox, hooks) = policy_asset_digests(&assets).unwrap();
        let object = TrustedPolicyObjectV1 {
            schema: 1,
            local_validation: test_policy(),
            asset_schema: POLICY_ASSET_SCHEMA,
            assets: policy_asset_metadata(&assets),
            previous_trusted_policy_oid: Some(previous.clone()),
            checkpoint_oid: git_output(&root, &["rev-parse", "HEAD"]).unwrap(),
            pretrust_proof_digest: fixed.clone(),
            bootstrap_nonce_digest: fixed.clone(),
            coordinator_digest: fixed.clone(),
            hook_digest: hooks,
            tool_lock_digest: tool_lock,
            sandbox_digest: sandbox,
        };
        let oid = write_policy_commit(&root, &object, &assets).unwrap();
        assert_eq!(read_trusted_policy_object(&root, &oid).unwrap(), object);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn promotion_semantic_diff_keeps_prior_floor_after_candidate_removal_and_downgrade() {
        let trusted = test_policy();
        let mut candidate = test_policy();
        let format = candidate.checks.remove("format").unwrap();
        candidate.checks.insert("format-v2".into(), format);
        for profile in candidate.profiles.values_mut() {
            for name in &mut profile.checks {
                if name == "format" {
                    *name = "format-v2".into();
                }
            }
        }
        candidate.checks.get_mut("lint").unwrap().timeout_secs = 2;
        let diff = policy_semantic_diff(&trusted, &candidate).unwrap();
        assert!(diff
            .iter()
            .any(|line| line.contains("check \"format\" is absent")));
        assert!(diff
            .iter()
            .any(|line| line.contains("check \"format-v2\" added")));
        assert!(diff.iter().any(|line| {
            line.contains("check \"lint\" changed")
                && line.contains("runs separately after the trusted definition")
        }));
    }

    #[test]
    fn promotion_rejects_malformed_and_moved_trusted_refs_without_overwrite() {
        let root = promotion_fixture("ref-races");
        let blob = git_hash_blob(&root, b"not a policy commit").unwrap();
        assert!(Command::new("git")
            .args(["update-ref", TRUSTED_POLICY_REF, &blob])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            trusted_policy_ref(&root).unwrap_err(),
            "trusted-policy-invalid: trusted policy ref must name a direct commit"
        );

        let fixed = "c".repeat(64);
        let checkpoint = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let assets = test_policy_assets(&root);
        let (tool_lock, sandbox, hooks) = policy_asset_digests(&assets).unwrap();
        let old = TrustedPolicyObjectV1 {
            schema: 1,
            local_validation: test_policy(),
            asset_schema: POLICY_ASSET_SCHEMA,
            assets: policy_asset_metadata(&assets),
            previous_trusted_policy_oid: None,
            checkpoint_oid: checkpoint.clone(),
            pretrust_proof_digest: fixed.clone(),
            bootstrap_nonce_digest: fixed.clone(),
            coordinator_digest: fixed.clone(),
            hook_digest: hooks,
            tool_lock_digest: tool_lock,
            sandbox_digest: sandbox,
        };
        let old_oid = write_policy_commit(&root, &old, &assets).unwrap();
        let proposed = TrustedPolicyObjectV1 {
            previous_trusted_policy_oid: Some(old_oid.clone()),
            ..old.clone()
        };
        let proposed_oid = write_policy_commit(&root, &proposed, &assets).unwrap();
        let concurrent = TrustedPolicyObjectV1 {
            previous_trusted_policy_oid: Some(old_oid.clone()),
            coordinator_digest: "e".repeat(64),
            ..old.clone()
        };
        let concurrent_oid = write_policy_commit(&root, &concurrent, &assets).unwrap();
        assert!(Command::new("git")
            .args(["update-ref", TRUSTED_POLICY_REF, &old_oid, &blob])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["update-ref", TRUSTED_POLICY_REF, &concurrent_oid, &old_oid])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(publish_promoted_policy(&root, &old_oid, &proposed_oid, &proposed).is_err());
        assert_eq!(trusted_policy_ref(&root).unwrap(), concurrent_oid);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn trusted_policy_bundle_rejects_missing_extra_corrupt_replaced_and_legacy_assets() {
        let root = promotion_fixture("asset-adversaries");
        let assets = test_policy_assets(&root);
        let (tool_lock, sandbox, hooks) = policy_asset_digests(&assets).unwrap();
        let fixed = "f".repeat(64);
        let object = TrustedPolicyObjectV1 {
            schema: 1,
            local_validation: test_policy(),
            asset_schema: POLICY_ASSET_SCHEMA,
            assets: policy_asset_metadata(&assets),
            previous_trusted_policy_oid: None,
            checkpoint_oid: git_output(&root, &["rev-parse", "HEAD"]).unwrap(),
            pretrust_proof_digest: fixed.clone(),
            bootstrap_nonce_digest: fixed.clone(),
            coordinator_digest: fixed,
            hook_digest: hooks,
            tool_lock_digest: tool_lock,
            sandbox_digest: sandbox,
        };
        let canonical = write_policy_commit(&root, &object, &assets).unwrap();
        assert!(read_trusted_policy_bundle(&root, &canonical).is_ok());

        let missing =
            rewrite_policy_tree_for_test(&root, &canonical, "assets/security/tool-lock.json", None);
        assert!(read_trusted_policy_bundle(&root, &missing)
            .unwrap_err()
            .contains("missing or has extra"));

        let extra_blob = git_hash_blob(&root, b"unexpected asset").unwrap();
        let extra = rewrite_policy_tree_for_test(
            &root,
            &canonical,
            "assets/unexpected",
            Some((0o100644, &extra_blob)),
        );
        assert!(read_trusted_policy_bundle(&root, &extra)
            .unwrap_err()
            .contains("missing or has extra"));

        let corrupt_blob = git_hash_blob(&root, b"corrupt replacement").unwrap();
        let corrupt = rewrite_policy_tree_for_test(
            &root,
            &canonical,
            "assets/security/tool-lock.json",
            Some((0o100644, &corrupt_blob)),
        );
        assert!(read_trusted_policy_bundle(&root, &corrupt)
            .unwrap_err()
            .contains("identity differs"));

        let original_tool_lock = &assets["security/tool-lock.json"].metadata.blob_oid;
        let replaced_mode = rewrite_policy_tree_for_test(
            &root,
            &canonical,
            "assets/security/tool-lock.json",
            Some((0o100755, original_tool_lock)),
        );
        assert!(read_trusted_policy_bundle(&root, &replaced_mode)
            .unwrap_err()
            .contains("mode/kind/identity differs"));

        let mut legacy = serde_json::to_value(&object).unwrap();
        legacy.as_object_mut().unwrap().remove("asset_schema");
        legacy.as_object_mut().unwrap().remove("assets");
        let legacy_blob = git_hash_blob(&root, &serde_json::to_vec(&legacy).unwrap()).unwrap();
        let legacy_oid = rewrite_policy_tree_for_test(
            &root,
            &canonical,
            "policy.json",
            Some((0o100644, &legacy_blob)),
        );
        assert!(read_trusted_policy_bundle(&root, &legacy_oid)
            .unwrap_err()
            .contains("policy.json is malformed"));
        let legacy_blob =
            git_hash_blob(&root, &canonical_policy_bytes(&test_policy()).unwrap()).unwrap();
        assert!(read_trusted_policy_bytes(&root, &legacy_blob)
            .unwrap_err()
            .contains("legacy policy object has no reviewed asset bundle"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn prior_floor_overlay_replaces_every_candidate_policy_asset_before_execution() {
        let root = promotion_fixture("candidate-asset-replacement");
        let worktree = root.join("materialized");
        fs::create_dir_all(worktree.join(".mpd")).unwrap();
        let trusted = test_policy_assets(&root);
        for spec in POLICY_ASSET_SPECS {
            let path = worktree.join(spec.path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, format!("candidate replacement: {}\n", spec.path)).unwrap();
        }
        let mut candidate = test_policy();
        candidate.checks.get_mut("lint").unwrap().timeout_secs = 2;
        fs::write(
            worktree.join(".mpd/config.json"),
            serde_json::to_vec(&serde_json::json!({ "local_validation": candidate })).unwrap(),
        )
        .unwrap();

        let prior = test_policy();
        overlay_trusted_policy_floor(&worktree, &prior, &trusted).unwrap();
        for spec in POLICY_ASSET_SPECS {
            assert_eq!(
                fs::read(worktree.join(spec.path)).unwrap(),
                trusted[spec.path].bytes,
                "candidate replaced trusted asset {}",
                spec.path
            );
        }
        let restored: crate::config::Config =
            serde_json::from_slice(&fs::read(worktree.join(".mpd/config.json")).unwrap()).unwrap();
        assert_eq!(restored.local_validation, Some(prior));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exact_asset_comparison_detects_candidate_replacement_before_execution() {
        let root = promotion_fixture("preflight-asset-replacement");
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for spec in POLICY_ASSET_SPECS {
            let destination = root.join(spec.path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(source_root.join(spec.path), &destination).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &destination,
                    fs::Permissions::from_mode(if spec.mode == 0o100755 { 0o755 } else { 0o644 }),
                )
                .unwrap();
            }
        }
        fs::write(
            root.join(".mpd/config.json"),
            serde_json::to_vec(&crate::config::Config {
                local_validation: Some(test_policy()),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let mut add = Command::new("git");
        add.arg("add").arg("--").arg(".mpd/config.json");
        for spec in POLICY_ASSET_SPECS {
            add.arg(spec.path);
        }
        assert!(add.current_dir(&root).status().unwrap().success());
        assert!(Command::new("git")
            .args([
                "-c",
                "user.name=MPD Test",
                "-c",
                "user.email=mpd-test@invalid",
                "commit",
                "-qm",
                "trusted subject",
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let checkpoint = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let subject = capture_subject(&root, Some(&checkpoint)).unwrap();
        let assets = capture_subject_policy_assets(&root, &subject).unwrap();
        let (tool_lock, sandbox, hooks) = policy_asset_digests(&assets).unwrap();
        let fixed = "9".repeat(64);
        let object = TrustedPolicyObjectV1 {
            schema: 1,
            local_validation: test_policy(),
            asset_schema: POLICY_ASSET_SCHEMA,
            assets: policy_asset_metadata(&assets),
            previous_trusted_policy_oid: None,
            checkpoint_oid: checkpoint,
            pretrust_proof_digest: fixed.clone(),
            bootstrap_nonce_digest: fixed.clone(),
            coordinator_digest: fixed,
            hook_digest: hooks,
            tool_lock_digest: tool_lock,
            sandbox_digest: sandbox,
        };
        let policy_oid = write_policy_commit(&root, &object, &assets).unwrap();
        assert!(Command::new("git")
            .args(["update-ref", TRUSTED_POLICY_REF, &policy_oid])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        fs::write(
            root.join("security/semgrep/local-ci.yml"),
            b"candidate replacement must remain inert\n",
        )
        .unwrap();
        assert!(Command::new("git")
            .args(["add", "--", "security/semgrep/local-ci.yml"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "-c",
                "user.name=MPD Test",
                "-c",
                "user.email=mpd-test@invalid",
                "commit",
                "-qm",
                "candidate replacement",
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let candidate = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let candidate = capture_subject(&root, Some(&candidate)).unwrap();
        let candidate_assets = capture_subject_policy_assets(&root, &candidate).unwrap();
        assert_ne!(policy_asset_metadata(&candidate_assets), object.assets);
        let _ = fs::remove_dir_all(root);
    }

    fn promotion_fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-policy-promotion-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".mpd")).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        write_policy_commit_subject(&root, &test_policy(), "initial", &root.join("unused"));
        root
    }

    fn write_policy_commit_subject(
        root: &Path,
        policy: &LocalValidationConfig,
        program: &str,
        marker: &Path,
    ) {
        let config = crate::config::Config {
            local_validation: Some(policy.clone()),
            ..Default::default()
        };
        fs::write(
            root.join(".mpd/config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        if program == "candidate-canary" {
            fs::write(
                root.join(program),
                format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
            )
            .unwrap();
        } else {
            fs::write(root.join("initial"), b"fixture").unwrap();
        }
        assert!(Command::new("git")
            .args(["add", "--", ".mpd/config.json", program])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "-c",
                "user.name=MPD Test",
                "-c",
                "user.email=mpd-test@invalid",
                "commit",
                "-qm",
                "policy",
            ])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
    }

    fn test_policy_assets(root: &Path) -> BTreeMap<String, TrustedPolicyAssetBytes> {
        let mut assets = BTreeMap::new();
        for spec in POLICY_ASSET_SPECS {
            let path = root.join(spec.path);
            let bytes = fs::read(&path)
                .unwrap_or_else(|_| format!("fixture trusted asset: {}\n", spec.path).into_bytes());
            let metadata = TrustedPolicyAssetV1 {
                path: spec.path.into(),
                mode: spec.mode,
                size: bytes.len() as u64,
                sha256: Digest::of_bytes(&bytes).to_hex(),
                blob_oid: git_hash_blob(root, &bytes).unwrap(),
            };
            assets.insert(
                spec.path.into(),
                TrustedPolicyAssetBytes { metadata, bytes },
            );
        }
        validate_policy_asset_inventory(&assets).unwrap();
        assets
    }

    fn rewrite_policy_tree_for_test(
        root: &Path,
        base_commit: &str,
        path: &str,
        replacement: Option<(u32, &str)>,
    ) -> String {
        let index = std::env::temp_dir().join(format!(
            "mpd-policy-test-index-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(Command::new("git")
            .args(["read-tree", &format!("{base_commit}^{{tree}}")])
            .env("GIT_INDEX_FILE", &index)
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        let status = match replacement {
            Some((mode, oid)) => Command::new("git")
                .args([
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("{mode:o},{oid},{path}"),
                ])
                .env("GIT_INDEX_FILE", &index)
                .current_dir(root)
                .status()
                .unwrap(),
            None => Command::new("git")
                .args(["update-index", "--force-remove", "--", path])
                .env("GIT_INDEX_FILE", &index)
                .current_dir(root)
                .status()
                .unwrap(),
        };
        assert!(status.success());
        let tree = Command::new("git")
            .args(["write-tree"])
            .env("GIT_INDEX_FILE", &index)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(tree.status.success());
        fs::remove_file(&index).unwrap();
        let tree = String::from_utf8(tree.stdout).unwrap();
        let commit = Command::new("git")
            .args(["commit-tree", tree.trim(), "-m", "tampered policy fixture"])
            .env("GIT_AUTHOR_NAME", "MPD Test")
            .env("GIT_AUTHOR_EMAIL", "mpd-test@invalid")
            .env("GIT_COMMITTER_NAME", "MPD Test")
            .env("GIT_COMMITTER_EMAIL", "mpd-test@invalid")
            .current_dir(root)
            .output()
            .unwrap();
        assert!(commit.status.success());
        String::from_utf8(commit.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn build_output_rejects_symlink_and_rechecks_copy_identity() {
        let root = std::env::temp_dir().join(format!(
            "mpd-build-output-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("out")).unwrap();
        fs::write(root.join("out/release"), b"release bytes").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("out/release"), fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let contract = BuildOutputConfig {
            name: "release".into(),
            path: "out/release".into(),
            max_bytes: 1024,
            required_mode: 0o755,
        };
        let output = capture_configured_build_output(&root, &contract).unwrap();
        let installed = install_build_output(&root, &output, "installed/mpd").unwrap();
        assert_eq!(output.candidate_id, None);
        assert_eq!(installed.candidate_id, None);
        assert_eq!(output.sha256, installed.sha256);
        assert_eq!(
            identity(&root, "installed/mpd").unwrap().sha256,
            output.sha256
        );
        let mut candidate_bound = output.clone();
        candidate_bound.candidate_id = Some("a".repeat(64));
        let candidate_installed =
            install_build_output(&root, &candidate_bound, "installed/candidate-mpd").unwrap();
        assert_eq!(
            candidate_installed.candidate_id,
            candidate_bound.candidate_id
        );
        assert_eq!(
            capture_recorded_build_output(&root, &candidate_bound).unwrap(),
            candidate_bound
        );
        let mut malformed_candidate = candidate_bound.clone();
        malformed_candidate.candidate_id = Some("A".repeat(64));
        assert!(
            install_build_output(&root, &malformed_candidate, "installed/malformed-candidate")
                .is_err()
        );
        fs::rename(root.join("out/release"), root.join("out/original")).unwrap();
        fs::write(root.join("out/release"), b"release bytes").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("out/release"), fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        assert!(install_build_output(&root, &output, "installed/same-bytes-replacement").is_err());
        fs::write(root.join("out/release"), b"replacement").unwrap();
        assert!(install_build_output(&root, &output, "installed/mpd2").is_err());
        let wrong_mode = BuildOutputConfig {
            required_mode: 0o700,
            ..contract.clone()
        };
        assert!(capture_configured_build_output(&root, &wrong_mode).is_err());
        let too_small = BuildOutputConfig {
            max_bytes: 1,
            ..contract.clone()
        };
        assert!(capture_configured_build_output(&root, &too_small).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("out/release", root.join("link")).unwrap();
            assert!(capture_build_output(&root, "link").is_err());
            fs::hard_link(root.join("out/release"), root.join("hard-link")).unwrap();
            assert!(capture_build_output(&root, "out/release").is_err());
        }
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn typed_deploy_copies_once_and_never_executes_the_installed_candidate() {
        use crate::config::{DeployOutputConfig, ExactCopyInstallConfig, ExactCopyInstallKind};
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "mpd-typed-deploy-calls-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("out")).unwrap();
        let marker = root.join("executed-marker");
        fs::write(
            root.join("out/release"),
            format!("#!/bin/sh\n: > '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(root.join("out/release"), fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = fs::metadata(root.join("out/release")).unwrap();
        let contract = BuildOutputConfig {
            name: "release".into(),
            path: "out/release".into(),
            max_bytes: metadata.len().saturating_add(1),
            required_mode: mode_of(&metadata),
        };
        let build = capture_configured_build_output(&root, &contract).unwrap();
        let deploy = DeployOutputConfig::Execute {
            artifact: "release".into(),
            install: ExactCopyInstallConfig {
                kind: ExactCopyInstallKind::ExactCopy,
            },
            installed_path: "installed/mpd".into(),
            target: "test-target".into(),
        };
        let calls = || {
            DEPLOY_CALLS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&root)
                .copied()
                .unwrap_or_default()
        };
        let (installs, forbidden_spawns) = calls();
        let receipt = execute_typed_deploy(&root, Some(&contract), &deploy, Some(&build)).unwrap();
        assert!(receipt.verified && receipt.install_executed && !receipt.probe_executed);
        assert_eq!(calls(), (installs + 1, forbidden_spawns));
        assert!(!marker.exists(), "Deploy executed the installed candidate");
        assert_eq!(
            capture_build_output(&root, "installed/mpd").unwrap().sha256,
            build.sha256
        );
        fs::write(
            root.join("readiness.txt"),
            b"reviewed deploy-ready evidence",
        )
        .unwrap();
        let readiness = DeployOutputConfig::Readiness {
            evidence: "readiness.txt".into(),
            target: "review-only".into(),
        };
        let (installs, forbidden_spawns) = calls();
        let receipt = execute_typed_deploy(&root, None, &readiness, None).unwrap();
        assert!(receipt.verified);
        assert!(!receipt.install_executed && !receipt.probe_executed);
        assert_eq!(calls(), (installs, forbidden_spawns));
        DEPLOY_CALLS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&root);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn durable_log_summary_never_contains_raw_credentials_or_high_entropy_canaries() {
        // Assembled from split literals (design D3) so this fixture stays
        // scanner-clean as source text; the runtime bytes are byte-for-byte
        // the fixture this replaces — see the redaction assertions below,
        // each of which keeps its exact prior meaning.
        let aws = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let slack = format!("xox{}", "b-EXAMPLE-PLACEHOLDER-notarealslacktokenfixture");
        let secret = format!("password=hunter{} MPD_SECRET_CANARY {aws} {slack}", 2);
        let high_entropy = b"c5f7c4b930504fe89d9cb853a3a710d7b6d632e456af0de99e84f8d20e7f4301";
        let summary = redact_output(secret.as_bytes(), high_entropy);
        let rendered = String::from_utf8(summary).unwrap();
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("MPD_SECRET_CANARY"));
        assert!(!rendered.contains(&aws));
        assert!(!rendered.contains(&format!("xox{}", "b-")));
        assert!(!rendered.contains(std::str::from_utf8(high_entropy).unwrap()));
        assert!(rendered.contains("\"raw_output_retained\":false"));
    }

    #[test]
    fn push_authorization_digest_tags_are_pinned_to_their_pre_refactor_bytes() {
        // Condition 15: these hex values were computed independently, via
        // `shasum -a 256`, from the exact PRE-CHANGE byte-string literals
        // that `OUTGOING_SCAN_TAG`/`SECRET_RULES_TAG` above replace — before
        // those consts existed. They are not derived from the refactored
        // code, so this assertion cannot bless a corrupted split; a mismatch
        // means push-authorization identity moved.
        let expected_outgoing = "1692455ed0b33838a5118fab8cc4cc97b8d148df2bd0539c042a348930dca302";
        let expected_rules = "373fb2d875bb435747854a9e2e09791d8a07e67192a00d5d17f9ed089721bfa6";
        assert_eq!(
            Digest::of_bytes(OUTGOING_SCAN_TAG.as_bytes()).to_hex(),
            expected_outgoing
        );
        assert_eq!(
            Digest::of_bytes(SECRET_RULES_TAG.as_bytes()).to_hex(),
            expected_rules
        );
    }

    #[test]
    fn rust_test_count_sums_real_passed_totals_and_rejects_malformed_or_zero() {
        let output = b"test result: ok. 12 passed; 0 failed; 1 ignored\n\
            test result: ok. 7 passed; 0 failed; 0 ignored\n";
        assert_eq!(
            test_count(&ResultPolicy::RustTestCount, output, b"", "passed").unwrap(),
            Some(19)
        );
        assert_eq!(
            test_count(
                &ResultPolicy::RustTestCount,
                b"test result: ok. nope passed; 0 failed\n",
                b"",
                "passed"
            ),
            Err("malformed Rust passed-test count".into())
        );
        assert!(!result_policy_passes(
            &ResultPolicy::RustTestCount,
            Some(0),
            b"",
            b""
        ));
    }

    #[test]
    fn pretrust_snapshot_measures_protected_mutations_and_never_runs_configured_check() {
        let root = push_fixture("pretrust-effects");
        fs::create_dir_all(root.join(".githooks")).unwrap();
        fs::write(root.join(".githooks/pre-commit"), b"tracked hook\n").unwrap();
        fs::write(root.join(".githooks/pre-push"), b"tracked hook\n").unwrap();
        let marker = root.join("configured-check-ran");
        let canary = root.join("canary-tool");
        fs::write(
            &canary,
            format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&canary, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut policy = test_policy();
        policy.tools.insert(
            "canary".into(),
            ToolConfig {
                program: "canary".into(),
                version_args: Vec::new(),
                requirement: ToolRequirement::Required,
                install_hint: "must never execute during pretrust".into(),
            },
        );
        policy.checks.get_mut("format").unwrap().program = "canary".into();
        policy.validate().unwrap();

        let mut previous = capture_pretrust_protected_state(&root, &policy).unwrap();
        assert!(
            !marker.exists(),
            "pretrust snapshot executed configured policy"
        );
        fs::write(root.join("safe.txt"), b"source mutation\n").unwrap();
        let source = capture_pretrust_protected_state(&root, &policy).unwrap();
        assert_ne!(
            digest_json(&previous).unwrap(),
            digest_json(&source).unwrap()
        );
        previous = source;
        assert!(Command::new("git")
            .args(["add", "safe.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let index = capture_pretrust_protected_state(&root, &policy).unwrap();
        assert_ne!(
            digest_json(&previous).unwrap(),
            digest_json(&index).unwrap()
        );
        previous = index;
        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        assert!(Command::new("git")
            .args(["update-ref", "refs/test/effect-canary", &head])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let refs = capture_pretrust_protected_state(&root, &policy).unwrap();
        assert_ne!(digest_json(&previous).unwrap(), digest_json(&refs).unwrap());
        previous = refs;
        assert!(Command::new("git")
            .args(["config", "--local", "mpd.effect-canary", "changed"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let config = capture_pretrust_protected_state(&root, &policy).unwrap();
        assert_ne!(
            digest_json(&previous).unwrap(),
            digest_json(&config).unwrap()
        );
        previous = config;
        fs::write(
            root.join(".git/hooks/pre-commit"),
            b"forbidden hook mutation\n",
        )
        .unwrap();
        let hooks = capture_pretrust_protected_state(&root, &policy).unwrap();
        assert_ne!(
            digest_json(&previous).unwrap(),
            digest_json(&hooks).unwrap()
        );
        assert!(
            !marker.exists(),
            "pretrust snapshot executed configured policy"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pretrust_effect_accepts_only_one_exclusive_owner_private_proof() {
        let state = std::env::temp_dir().join(format!(
            "mpd-pretrust-effect-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(state.join("proofs")).unwrap();
        protect_dir(&state.join("proofs")).unwrap();
        fs::write(state.join("sentinel"), b"protected").unwrap();
        let before = inventory_private_state(&state).unwrap();
        let proof = state.join("proofs/expected.json");
        write_owner_private(&proof, b"bounded-proof").unwrap();
        verify_exclusive_proof_effect(&state, &before, &proof, b"bounded-proof").unwrap();
        fs::write(state.join("forbidden-mutation"), b"changed").unwrap();
        assert!(verify_exclusive_proof_effect(&state, &before, &proof, b"bounded-proof").is_err());
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn first_adoption_bootstrap_is_same_input_idempotent_and_rejects_different_nonce() {
        let root = push_fixture("bootstrap-response-loss");
        let state = first_adoption_dir(&root).unwrap();
        fs::create_dir_all(state.join("proofs")).unwrap();
        let policy = test_policy();
        let policy_digest = Digest::of_bytes(&canonical_policy_bytes(&policy).unwrap()).to_hex();
        fs::create_dir_all(root.join(".mpd")).unwrap();
        fs::write(
            root.join(".mpd/config.json"),
            serde_json::to_vec(&crate::config::Config {
                local_validation: Some(policy.clone()),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        let source_assets = test_policy_assets(&root);
        for spec in POLICY_ASSET_SPECS {
            let path = root.join(spec.path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &source_assets[spec.path].bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if spec.mode == 0o100755 { 0o755 } else { 0o644 }),
                )
                .unwrap();
            }
        }
        let mut add = Command::new("git");
        add.arg("add").arg("--").arg(".mpd/config.json");
        for spec in POLICY_ASSET_SPECS {
            add.arg(spec.path);
        }
        assert!(add.current_dir(&root).status().unwrap().success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "reviewed policy subject"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let checkpoint = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let tree = git_output(&root, &["rev-parse", "HEAD^{tree}"]).unwrap();
        let subject = capture_subject(&root, Some(&checkpoint)).unwrap();
        let committed_assets = capture_subject_policy_assets(&root, &subject).unwrap();
        let (tool_lock_digest, sandbox_digest, hook_digest) =
            policy_asset_digests(&committed_assets).unwrap();
        let nonce = "public-response-loss-nonce";
        let nonce_digest = bootstrap_nonce_digest(nonce);
        let fixed = "a".repeat(64);
        let observation = PretrustEffectObservationV1 {
            schema: 1,
            protected_before_digest: fixed.clone(),
            protected_after_digest: fixed.clone(),
            private_state_before_digest: fixed.clone(),
            private_state_after_without_proof_digest: fixed.clone(),
            exclusive_write: format!("proofs/{nonce_digest}.json"),
            configured_checks_executed: 0,
        };
        let proof = PretrustCheckpointProofV1 {
            schema: PRETRUST_PROOF_SCHEMA,
            change: "fixture".into(),
            checkpoint_oid: checkpoint.clone(),
            checkpoint_tree_oid: tree,
            checkpoint_scope: CheckpointScopeV1 {
                schema: 1,
                change: "fixture".into(),
                manifest_digest: fixed.clone(),
                recorded_base_oid: checkpoint.clone(),
                recorded_branch_ref: "refs/heads/main".into(),
                recorded_upstream_oid: None,
                entries: Vec::new(),
                aggregate_digest: fixed.clone(),
            },
            checkpoint_chain_digest: fixed.clone(),
            security_evidence: "security.md".into(),
            security_evidence_digest: fixed.clone(),
            candidate_policy_digest: policy_digest.clone(),
            tool_lock_digest,
            sandbox_digest,
            hook_digest,
            coordinator_digest: fixed.clone(),
            sandbox_contract: "pretrust-control-plane-v1".into(),
            allowed_effect_digest: pretrust_allowed_effect_digest(),
            observed_effect_digest: digest_json(&observation).unwrap(),
            protected_before_digest: fixed.clone(),
            protected_after_digest: fixed.clone(),
            private_state_before_digest: fixed.clone(),
            private_state_after_without_proof_digest: fixed,
            proof_relative_path: format!("proofs/{nonce_digest}.json"),
            configured_checks_executed: 0,
            nonce_digest,
        };
        let proof_bytes = serde_json::to_vec(&proof).unwrap();
        let proof_digest = Digest::of_bytes(&proof_bytes).to_hex();
        write_owner_private(&state.join("proofs/proof.json"), &proof_bytes).unwrap();
        let request = BootstrapRequest {
            checkpoint_oid: &checkpoint,
            reviewed_policy_digest: &policy_digest,
            pretrust_proof_digest: &proof_digest,
            nonce,
        };
        let (winner, retry) =
            bootstrap_first_adoption_policy(&root, &policy, request.clone()).unwrap();
        assert!(!retry);
        assert_eq!(
            bootstrap_first_adoption_policy(&root, &policy, request).unwrap(),
            (winner, true)
        );
        let different = BootstrapRequest {
            checkpoint_oid: &checkpoint,
            reviewed_policy_digest: &policy_digest,
            pretrust_proof_digest: &proof_digest,
            nonce: "different-nonce",
        };
        assert!(bootstrap_first_adoption_policy(&root, &policy, different).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn activation_rolls_back_every_persisted_stage_and_resumes_to_verified_active() {
        for stage in [
            ActivationStageV1::Prepared,
            ActivationStageV1::TrustedInactive,
            ActivationStageV1::LauncherStaged,
            ActivationStageV1::CoordinatorInstalled,
            ActivationStageV1::HooksInstalled,
            ActivationStageV1::HooksPathSet,
            ActivationStageV1::VerifiedActive,
        ] {
            let root = push_fixture(&format!("activation-{stage:?}"));
            fs::create_dir_all(root.join(".githooks")).unwrap();
            fs::write(root.join(".githooks/pre-commit"), b"#!/bin/sh\nexit 0\n").unwrap();
            fs::write(root.join(".githooks/pre-push"), b"#!/bin/sh\nexit 0\n").unwrap();
            let coordinator = root.join("reviewed-coordinator");
            fs::write(&coordinator, b"#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&coordinator, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let coordinator_digest = digest_file(&coordinator).unwrap();
            let checkpoint = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
            let fixed = "a".repeat(64);
            let assets = test_policy_assets(&root);
            let (tool_lock, sandbox, hooks) = policy_asset_digests(&assets).unwrap();
            let object = TrustedPolicyObjectV1 {
                schema: 1,
                local_validation: test_policy(),
                asset_schema: POLICY_ASSET_SCHEMA,
                assets: policy_asset_metadata(&assets),
                previous_trusted_policy_oid: None,
                checkpoint_oid: checkpoint,
                pretrust_proof_digest: fixed.clone(),
                bootstrap_nonce_digest: fixed.clone(),
                coordinator_digest: coordinator_digest.clone(),
                hook_digest: hooks,
                tool_lock_digest: tool_lock,
                sandbox_digest: sandbox,
            };
            let policy_oid = write_policy_commit(&root, &object, &assets).unwrap();
            assert!(Command::new("git")
                .args(["update-ref", TRUSTED_POLICY_REF, &policy_oid])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
            let policy_digest = Digest::of_bytes(&serde_json::to_vec(&object).unwrap()).to_hex();
            let error = activate_trusted_policy_inner(
                &root,
                &policy_digest,
                &coordinator,
                &coordinator_digest,
                Some(stage.clone()),
            )
            .unwrap_err();
            assert!(error.contains("injected-activation-failure"));
            assert_eq!(
                git_output(&root, &["rev-parse", TRUSTED_POLICY_REF]).unwrap(),
                policy_oid
            );
            assert!(
                git_optional(&root, &["config", "--local", "--get", "core.hooksPath"])
                    .unwrap()
                    .is_none()
            );
            let journal = read_activation_journal(
                &policy_state_dir(&root)
                    .unwrap()
                    .join("activation-journal.json"),
            )
            .unwrap()
            .unwrap();
            assert_eq!(journal.stage, ActivationStageV1::TrustedInactive);
            assert!(journal.installed_path_digests.is_empty());
            let trusted_hooks = git_common_dir(&root).unwrap().join("mpd/trusted-hooks");
            assert!(!trusted_hooks.join("mpd-coordinator").exists());
            assert!(!trusted_hooks.join("pre-commit").exists());
            assert!(!trusted_hooks.join("pre-push").exists());

            let resumed =
                activate_trusted_policy(&root, &policy_digest, &coordinator, &coordinator_digest)
                    .unwrap();
            assert_eq!(resumed.stage, ActivationStageV1::VerifiedActive);
            assert_eq!(
                git_output(&root, &["rev-parse", TRUSTED_POLICY_REF]).unwrap(),
                policy_oid
            );
            assert_eq!(
                git_optional(&root, &["config", "--local", "--get", "core.hooksPath"]).unwrap(),
                Some(
                    fs::canonicalize(&trusted_hooks)
                        .unwrap()
                        .display()
                        .to_string()
                )
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reviewed_policy_activation_is_single_route_digest_bound_and_idempotent() {
        use std::os::unix::fs::PermissionsExt;

        let root = push_fixture("reviewed-policy-activation");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        fs::create_dir_all(root.join(".mpd")).unwrap();
        let policy = test_policy();
        fs::write(
            root.join(".mpd/config.json"),
            serde_json::to_vec_pretty(&crate::config::Config {
                local_validation: Some(policy.clone()),
                ..Default::default()
            })
            .unwrap(),
        )
        .unwrap();
        for spec in POLICY_ASSET_SPECS {
            let destination = root.join(spec.path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(source.join(spec.path), &destination).unwrap();
            fs::set_permissions(
                &destination,
                fs::Permissions::from_mode(if spec.mode == 0o100755 { 0o755 } else { 0o644 }),
            )
            .unwrap();
        }
        assert!(Command::new("git")
            .args(["add", ".mpd/config.json", ".githooks", "security"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "reviewed policy"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let commit = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let policy_digest = Digest::of_bytes(&canonical_policy_bytes(&policy).unwrap()).to_hex();
        let coordinator = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let coordinator_digest = digest_file(&coordinator).unwrap();

        let first = activate_reviewed_policy(
            &root,
            &commit,
            &policy_digest,
            &coordinator,
            &coordinator_digest,
            Path::new(".githooks"),
        )
        .unwrap();
        assert_eq!(first.stage, ActivationStageV1::VerifiedActive);
        let trusted_before = first.trusted_policy_oid.clone();
        let second = activate_reviewed_policy(
            &root,
            &commit,
            &policy_digest,
            &coordinator,
            &coordinator_digest,
            Path::new(".githooks"),
        )
        .unwrap();
        assert_eq!(second.trusted_policy_oid, trusted_before);
        assert_eq!(second.stage, ActivationStageV1::VerifiedActive);

        let upgraded_coordinator = root.join("reviewed-coordinator-v2");
        fs::copy(&coordinator, &upgraded_coordinator).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&upgraded_coordinator)
            .unwrap()
            .write_all(b"\0")
            .unwrap();
        fs::set_permissions(&upgraded_coordinator, fs::Permissions::from_mode(0o700)).unwrap();
        let upgraded_coordinator = fs::canonicalize(upgraded_coordinator).unwrap();
        let upgraded_digest = digest_file(&upgraded_coordinator).unwrap();
        let upgraded = activate_reviewed_policy(
            &root,
            &commit,
            &policy_digest,
            &upgraded_coordinator,
            &upgraded_digest,
            Path::new(".githooks"),
        )
        .unwrap();
        assert_ne!(upgraded.trusted_policy_oid, trusted_before);
        assert_eq!(upgraded.stage, ActivationStageV1::VerifiedActive);
        assert_eq!(
            digest_file(
                &git_common_dir(&root)
                    .unwrap()
                    .join("mpd/trusted-hooks/mpd-coordinator")
            )
            .unwrap(),
            upgraded_digest
        );
        doctor_activation_health(&root).unwrap();
        let active = git_output(&root, &["config", "--local", "--get", "core.hooksPath"]).unwrap();
        assert_eq!(
            Path::new(&active),
            fs::canonicalize(git_common_dir(&root).unwrap().join("mpd/trusted-hooks")).unwrap()
        );
        assert!(activate_reviewed_policy(
            &root,
            &commit,
            &policy_digest,
            &coordinator,
            &coordinator_digest,
            Path::new("hooks")
        )
        .is_err());
        let approval = create_deletion_approval(
            &root,
            "origin",
            "/tmp/reviewed-policy-remote.git",
            "refs/heads/obsolete",
            &commit,
            &policy,
        )
        .unwrap();
        assert_eq!(approval.remote_ref, "refs/heads/obsolete");
        let delete = format!(
            "(delete) {} refs/heads/obsolete {commit}\n",
            "0".repeat(commit.len())
        );
        let authorization = authorize_pre_push(
            &root,
            "origin",
            "/tmp/reviewed-policy-remote.git",
            delete.as_bytes(),
            &policy,
        )
        .unwrap();
        assert_eq!(authorization.deletion_count, 1);
        assert_eq!(authorization.object_count, 0);
        assert_eq!(authorization.deletion_approval_digest, Some(approval.id));
        assert_eq!(authorization.invocation_nonce.len(), 64);
        let audited = load_push_authorization_audit(&root).unwrap().unwrap();
        assert_eq!(audited.authorization_id, authorization.authorization_id);
        assert_eq!(audited.updates, authorization.updates);
        assert!(authorize_pre_push(
            &root,
            "origin",
            "/tmp/reviewed-policy-remote.git",
            delete.as_bytes(),
            &policy,
        )
        .unwrap_err()
        .contains("deletion-approval-missing"));
        assert!(create_deletion_approval(
            &root,
            "origin",
            "/tmp/reviewed-policy-remote.git",
            "refs/heads/main",
            &commit,
            &policy,
        )
        .unwrap_err()
        .contains("protected-ref-deletion-denied"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn materialization_reads_commit_blobs_without_checkout_state() {
        let root = std::env::temp_dir().join(format!("mpd-materialize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["config", "user.email", "test@example.invalid"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["config", "user.name", "test"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join("nested/input.txt"), "exact bytes\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "."])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "subject"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let subject = capture_subject(&root, None).unwrap();
        std::fs::write(root.join("nested/input.txt"), "dirty bytes\n").unwrap();
        let materialized = materialize_subject(&root, &subject).unwrap();
        assert_eq!(
            std::fs::read_to_string(materialized.root.join("nested/input.txt")).unwrap(),
            "exact bytes\n"
        );
        let _ = std::fs::remove_dir_all(materialized.root);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn materialization_budgets_entries_paths_and_aggregate_before_projection_effects() {
        let root = std::env::temp_dir().join(format!(
            "mpd-materialize-limits-{}-{}",
            std::process::id(),
            epoch_secs().unwrap()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        for (key, value) in [
            ("user.email", "test@example.invalid"),
            ("user.name", "test"),
        ] {
            assert!(Command::new("git")
                .args(["config", key, value])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        std::fs::write(root.join("a"), b"aa").unwrap();
        std::fs::write(root.join("b"), b"bb").unwrap();
        std::fs::write(root.join("long-name"), b"cc").unwrap();
        assert!(Command::new("git")
            .args(["add", "."])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "subject"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let subject = capture_subject(&root, None).unwrap();
        let parent = root.join(".git/mpd-materialization-limits");
        std::fs::create_dir(&parent).unwrap();

        let cases = [
            (
                "entry",
                MaterializationLimits {
                    entries: 2,
                    ..MaterializationLimits::PRODUCTION
                },
                "entry count",
            ),
            (
                "path",
                MaterializationLimits {
                    path_bytes: 4,
                    ..MaterializationLimits::PRODUCTION
                },
                "path exceeds",
            ),
            (
                "aggregate",
                MaterializationLimits {
                    total_bytes: 5,
                    ..MaterializationLimits::PRODUCTION
                },
                "aggregate bytes",
            ),
        ];
        for (label, limits, expected) in cases {
            let prefix = format!(".limit-{label}-");
            let error =
                materialize_subject_in_with_limits(&root, &subject, &parent, &prefix, limits)
                    .unwrap_err();
            assert!(error.contains(expected), "{label}: {error}");
            assert!(parent.read_dir().unwrap().next().is_none(), "{label}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn materialization_never_runs_checkout_hooks_filters_or_submodules() {
        let root = push_fixture("materialization-canaries");
        std::fs::write(root.join("filtered.txt"), "committed raw bytes\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "filtered.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join(".gitattributes"), "*.txt filter=canary\n").unwrap();
        assert!(Command::new("git")
            .args(["add", ".gitattributes"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "filtered subject"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        let filter_marker = root.join("filter-executed");
        let hook_marker = root.join("hook-executed");
        let filter = root.join("filter-canary.sh");
        std::fs::write(
            &filter,
            format!(
                "#!/bin/sh\nprintf ran > '{}'\ncat\n",
                filter_marker.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&filter, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (key, value) in [
            (
                "filter.canary.smudge",
                filter.to_str().expect("UTF-8 test filter path"),
            ),
            ("filter.canary.required", "true"),
        ] {
            assert!(Command::new("git")
                .args(["config", "--local", key, value])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        let hook = root.join(".git/hooks/post-checkout");
        std::fs::write(
            &hook,
            format!("#!/bin/sh\nprintf ran > '{}'\n", hook_marker.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let subject = capture_subject(&root, None).unwrap();
        let materialized = materialize_subject(&root, &subject).unwrap();
        assert_eq!(
            std::fs::read_to_string(materialized.root.join("filtered.txt")).unwrap(),
            "committed raw bytes\n"
        );
        assert!(!filter_marker.exists());
        assert!(!hook_marker.exists());
        let _ = std::fs::remove_dir_all(materialized.root);

        assert!(Command::new("git")
            .args(["config", "--local", "--unset-all", "filter.canary.required"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["config", "--local", "--unset-all", "filter.canary.smudge"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        assert!(Command::new("git")
            .args([
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{head},vendor/sub"),
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "gitlink subject"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let gitlink_subject = capture_subject(&root, None).unwrap();
        assert!(materialize_subject(&root, &gitlink_subject)
            .unwrap_err()
            .contains("unsupported entry"));
        assert!(!filter_marker.exists());
        assert!(!hook_marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn required_push_tool_missing_from_lock_blocks_without_execution() {
        let root = push_fixture("missing-push-tool");
        std::fs::create_dir_all(root.join("security")).unwrap();
        std::fs::write(
            root.join("security/tool-lock.json"),
            br#"{"schema_version":1,"tools":[]}"#,
        )
        .unwrap();
        let marker = root.join("missing-tool-executed");
        let error =
            resolve_program(&root, &root, "gitleaks", Path::new("/usr/bin/true")).unwrap_err();
        assert!(error.contains("tool-lock entry is missing: gitleaks"));
        assert!(
            !marker.exists(),
            "missing tool resolution executed a command"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn declared_clone_private_tool_entry_binds_source_inventory_path_and_bytes() {
        let root = push_fixture("declared-tool-entry");
        let install = root.join(".git/mpd/tools/rust-fixture");
        std::fs::create_dir_all(install.join("bin")).unwrap();
        let cargo = install.join("bin/cargo");
        let rustc = install.join("bin/rustc");
        std::fs::write(&cargo, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&rustc, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o500)).unwrap();
            std::fs::set_permissions(&rustc, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        let cargo_digest = Digest::of_bytes(&std::fs::read(&cargo).unwrap()).to_hex();
        let rustc_digest = Digest::of_bytes(&std::fs::read(&rustc).unwrap()).to_hex();
        let source_digest = "a".repeat(64);
        let inventory = serde_json::json!({
            "schema": 1,
            "source_package_sha256": source_digest,
            "executables": {
                "cargo": { "path": "bin/cargo", "sha256": cargo_digest },
                "rustc": { "path": "bin/rustc", "sha256": rustc_digest },
            }
        });
        std::fs::write(
            install.join("installed.json"),
            serde_json::to_vec(&inventory).unwrap(),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("security")).unwrap();
        let lock = serde_json::json!({
            "schema_version": 1,
            "tools": [{
                "name": "rust-toolchain",
                "version": "1.91.0",
                "acquisition": "verified-local-archive",
                "package_sha256": source_digest,
                "install_root": "mpd/tools/rust-fixture",
                "inventory": "installed.json",
                "platform": platform_key().unwrap(),
                "executable_paths": {
                    "cargo": "bin/cargo",
                    "rustc": "bin/rustc"
                },
                "executables": {
                    "cargo": cargo_digest,
                    "rustc": rustc_digest
                }
            }]
        });
        std::fs::write(
            root.join("security/tool-lock.json"),
            serde_json::to_vec(&lock).unwrap(),
        )
        .unwrap();

        assert_eq!(
            resolve_program(&root, &root, "cargo", Path::new("/usr/bin/true")).unwrap(),
            std::fs::canonicalize(&cargo).unwrap()
        );

        let mut wrong_source = inventory.clone();
        wrong_source["source_package_sha256"] = serde_json::Value::String("b".repeat(64));
        std::fs::write(
            install.join("installed.json"),
            serde_json::to_vec(&wrong_source).unwrap(),
        )
        .unwrap();
        assert!(
            resolve_program(&root, &root, "cargo", Path::new("/usr/bin/true"))
                .unwrap_err()
                .contains("inventory differs")
        );

        std::fs::write(
            install.join("installed.json"),
            serde_json::to_vec(&inventory).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(&cargo, b"#!/bin/sh\nexit 9\n").unwrap();
        assert!(
            resolve_program(&root, &root, "cargo", Path::new("/usr/bin/true"))
                .unwrap_err()
                .contains("digest mismatch")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_subject_policy_excludes_dirty_worktree_config() {
        let root = std::env::temp_dir().join(format!(
            "mpd-exact-policy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".mpd")).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        for (key, value) in [
            ("user.email", "test@example.invalid"),
            ("user.name", "test"),
        ] {
            assert!(Command::new("git")
                .args(["config", key, value])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        let committed = test_policy();
        let config = crate::config::Config {
            local_validation: Some(committed.clone()),
            ..Default::default()
        };
        fs::write(
            root.join(".mpd/config.json"),
            serde_json::to_vec_pretty(&config).unwrap(),
        )
        .unwrap();
        assert!(Command::new("git")
            .args(["add", ".mpd/config.json"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "policy"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let subject = capture_subject(&root, None).unwrap();
        let mut dirty = committed.clone();
        dirty.schema = 99;
        let dirty_config = crate::config::Config {
            local_validation: Some(dirty),
            ..Default::default()
        };
        fs::write(
            root.join(".mpd/config.json"),
            serde_json::to_vec_pretty(&dirty_config).unwrap(),
        )
        .unwrap();
        assert_eq!(
            subject_local_validation(&root, &subject).unwrap(),
            committed
        );
        let policy = test_policy();
        let expanded =
            expand_locked_args(&root, &["${MPD_ADVISORY_DB}".to_string()], &policy).unwrap();
        assert!(expanded[0].ends_with(".git/mpd/advisory-db"));
        assert!(expand_locked_args(&root, &["${UNKNOWN}".to_string()], &policy).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn repository_static_policy_assets_are_semantically_valid() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        static_policy_check(&root).unwrap();
    }

    fn push_fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-push-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        for (key, value) in [
            ("user.email", "test@example.invalid"),
            ("user.name", "test"),
        ] {
            assert!(Command::new("git")
                .args(["config", key, value])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        std::fs::write(root.join("safe.txt"), "safe\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "."])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "baseline"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        root
    }

    #[test]
    fn push_subject_includes_nested_tags_and_excludes_dirty_worktree_bytes() {
        let root = push_fixture("nested-tags");
        assert!(Command::new("git")
            .args(["tag", "light", "HEAD"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["tag", "-a", "inner", "-m", "inner", "HEAD"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["tag", "-a", "outer", "-m", "outer", "inner"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(
            root.join("safe.txt"),
            "dirty secret = \"abc123abc123abc123abc123\"\n",
        )
        .unwrap();
        let snapshot = || {
            [
                git_output(&root, &["rev-parse", "HEAD"]).unwrap(),
                git_output(
                    &root,
                    &["for-each-ref", "--format=%(refname)%00%(objectname)"],
                )
                .unwrap(),
                git_output(&root, &["status", "--porcelain=v2", "-z"]).unwrap(),
                git_output(&root, &["config", "--local", "--null", "--list"]).unwrap(),
            ]
        };
        let before = snapshot();
        let commit = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let light = git_output(&root, &["rev-parse", "light"]).unwrap();
        let direct = resolve_push_subject(&root, &commit).unwrap();
        let lightweight = resolve_push_subject(&root, &light).unwrap();
        let outer = git_output(&root, &["rev-parse", "outer"]).unwrap();
        let subject = resolve_push_subject(&root, &outer).unwrap();
        assert!(direct.tag_chain.is_empty());
        assert!(lightweight.tag_chain.is_empty());
        assert_eq!(direct.local_oid, direct.peeled_commit);
        assert_eq!(lightweight, direct);
        assert_eq!(subject.tag_chain.len(), 2);
        assert_eq!(subject.peeled_commit, commit);
        assert_eq!(
            snapshot(),
            before,
            "subject resolution must not mutate HEAD, refs, config, index, or dirty worktree state"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_enumeration_handles_new_force_mixed_delete_multi_ref_and_shared_graphs() {
        let root = push_fixture("graph-shapes");
        let baseline = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        std::fs::write(root.join("safe.txt"), "new branch bytes\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "safe.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "new branch tip"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let new_tip = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let zero = "0".repeat(new_tip.len());
        let (new_objects, _) = enumerate_update_objects(&root, &new_tip, &zero).unwrap();
        assert!(new_objects.contains(&new_tip));
        assert!(
            new_objects.len() >= 3,
            "commit/tree/blob closure is complete"
        );

        assert!(Command::new("git")
            .args(["checkout", "-qb", "alternate", &baseline])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join("alternate.txt"), "alternate force-push bytes\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "alternate.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "alternate tip"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let force_tip = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let before = [
            git_output(&root, &["rev-parse", "HEAD"]).unwrap(),
            git_output(
                &root,
                &["for-each-ref", "--format=%(refname)%00%(objectname)"],
            )
            .unwrap(),
            git_output(&root, &["status", "--porcelain=v2", "-z"]).unwrap(),
            git_output(&root, &["config", "--local", "--null", "--list"]).unwrap(),
        ];
        let (force_objects, _) = enumerate_update_objects(&root, &force_tip, &new_tip).unwrap();
        assert!(force_objects.contains(&force_tip));
        assert!(!force_objects.contains(&new_tip));

        let input = format!(
            "refs/heads/one {force_tip} refs/heads/one {zero}\nrefs/heads/two {force_tip} refs/heads/two {zero}\n(delete) {zero} refs/heads/old {baseline}\n"
        );
        let records = parse_pre_push_records(input.as_bytes()).unwrap();
        assert_eq!(records.len(), 3);
        let mut union = BTreeSet::new();
        for record in records
            .iter()
            .filter(|record| record.local_ref != "(delete)")
        {
            let (objects, _) =
                enumerate_update_objects(&root, &record.local_oid, &record.remote_oid).unwrap();
            union.extend(objects);
        }
        assert_eq!(
            union,
            enumerate_update_objects(&root, &force_tip, &zero)
                .unwrap()
                .0
                .into_iter()
                .collect(),
            "two refs sharing a graph deduplicate the outgoing object union"
        );
        let missing = "f".repeat(force_tip.len());
        assert_eq!(
            require_remote_baseline(&root, &missing),
            Err("remote-baseline-missing: fetch the advertised remote baseline and retry".into())
        );
        assert_eq!(require_remote_baseline(&root, &zero), Ok(()));
        assert_eq!(
            [
                git_output(&root, &["rev-parse", "HEAD"]).unwrap(),
                git_output(
                    &root,
                    &["for-each-ref", "--format=%(refname)%00%(objectname)"]
                )
                .unwrap(),
                git_output(&root, &["status", "--porcelain=v2", "-z"]).unwrap(),
                git_output(&root, &["config", "--local", "--null", "--list"]).unwrap(),
            ],
            before,
            "outgoing enumeration must not mutate repository state"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_helpers_enforce_read_and_enumeration_caps_without_mutation() {
        let root = push_fixture("outgoing-caps");
        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let before = [
            git_output(&root, &["rev-parse", "HEAD"]).unwrap(),
            git_output(
                &root,
                &["for-each-ref", "--format=%(refname)%00%(objectname)"],
            )
            .unwrap(),
            git_output(&root, &["status", "--porcelain=v2", "-z"]).unwrap(),
            git_output(&root, &["config", "--local", "--null", "--list"]).unwrap(),
        ];
        assert_eq!(
            git_object_bytes(&root, &head, 1),
            Err("outgoing-object-read-cap-exceeded".into())
        );
        assert_eq!(
            git_output_capped(
                &root,
                &["rev-list", "--objects", "--no-object-names", "HEAD"],
                1,
                "outgoing object enumeration",
            ),
            Err("outgoing-enumeration-cap-exceeded".into())
        );
        assert_eq!(
            [
                git_output(&root, &["rev-parse", "HEAD"]).unwrap(),
                git_output(
                    &root,
                    &["for-each-ref", "--format=%(refname)%00%(objectname)"],
                )
                .unwrap(),
                git_output(&root, &["status", "--porcelain=v2", "-z"]).unwrap(),
                git_output(&root, &["config", "--local", "--null", "--list"]).unwrap(),
            ],
            before,
            "bounded reads must not mutate repository state"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_scan_catches_secrets_fresh_despite_preexisting_receipt() {
        let root = push_fixture("outgoing-secrets");
        let baseline = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        std::fs::write(
            root.join("secret.txt"),
            "token = \"abc123abc123abc123abc123\"\n",
        )
        .unwrap();
        assert!(Command::new("git")
            .args(["add", "secret.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "add secret"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["rm", "-q", "secret.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "remove secret"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let (objects, _) = enumerate_update_objects(&root, &head, &baseline).unwrap();
        let outgoing = objects
            .into_iter()
            .map(|oid| OutgoingObject {
                size: git_object_size(&root, &oid).unwrap(),
                kind: git_object_type(&root, &oid).unwrap(),
                oid,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            scan_outgoing_objects(&root, &outgoing, &BTreeMap::new()),
            Err("outgoing-secret-scan-failed".into())
        );

        // Tag messages are separate transferred metadata, even when the tagged
        // commit tree itself is clean. Assembled from split literals so this
        // fixture stays scanner-clean as source text (design D3); the
        // runtime message is unchanged.
        let tag_message = format!("token = {}{}", "abc123abc123", "abc123abc123");
        assert!(Command::new("git")
            .args(["tag", "-a", "leaky", "-m", &tag_message, &baseline])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let tag = git_output(&root, &["rev-parse", "leaky"]).unwrap();
        let tag_object = OutgoingObject {
            size: git_object_size(&root, &tag).unwrap(),
            kind: git_object_type(&root, &tag).unwrap(),
            oid: tag,
        };
        assert_eq!(
            scan_outgoing_objects(&root, &[tag_object], &BTreeMap::new()),
            Err("outgoing-secret-scan-failed".into())
        );

        // Commit messages are transferred metadata too. A pre-existing
        // receipt-like note is deliberately irrelevant: every invocation must
        // perform this fixed outgoing scan before source receipt reuse.
        // Assembled from split literals (design D3); runtime message unchanged.
        let commit_message = format!("token = {}{}", "abc123abc123", "abc123abc123");
        assert!(Command::new("git")
            .args(["commit", "--allow-empty", "-qm", &commit_message])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let commit = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        assert!(Command::new("git")
            .args([
                "notes",
                "--ref",
                VALIDATION_NOTES_REF,
                "add",
                "-m",
                "pre-existing receipt must not bypass fresh scan",
                &commit,
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let refs_before = git_output(
            &root,
            &["for-each-ref", "--format=%(refname)%00%(objectname)"],
        )
        .unwrap();
        let commit_object = OutgoingObject {
            size: git_object_size(&root, &commit).unwrap(),
            kind: git_object_type(&root, &commit).unwrap(),
            oid: commit,
        };
        assert_eq!(
            scan_outgoing_objects(&root, &[commit_object], &BTreeMap::new()),
            Err("outgoing-secret-scan-failed".into())
        );
        assert_eq!(
            git_output(
                &root,
                &["for-each-ref", "--format=%(refname)%00%(objectname)"]
            )
            .unwrap(),
            refs_before,
            "fresh outgoing scanning must not mutate or replace receipts/refs"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_scan_allowlist_requires_match_under_every_mapped_path() {
        // D1 Cond 1/2/20: the path-mapped scan lets a genuinely allowlisted
        // fixture pass, but a blob with the SAME content also bound to a
        // real, non-allowlisted path must still block — allowlist matching
        // is per-path, never first-wins.
        let root = push_fixture("multi-binding");
        let baseline = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let mpd = root.join(".mpd");
        std::fs::create_dir_all(&mpd).unwrap();
        std::fs::write(
            mpd.join("secret-allowlist.json"),
            "{\"paths\": [\"fixtures/**\"]}",
        )
        .unwrap();
        let secret = "token = \"abc123abc123abc123abc123\"\n";
        std::fs::create_dir_all(root.join("fixtures")).unwrap();
        std::fs::write(root.join("fixtures/leak.txt"), secret).unwrap();
        assert!(Command::new("git")
            .args(["add", "fixtures/leak.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "allowlisted fixture"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let leak_oid = git_output(&root, &["rev-parse", "HEAD:fixtures/leak.txt"]).unwrap();

        let collect_outgoing = |head: &str| -> (Vec<OutgoingObject>, Vec<String>) {
            let (objects, _) = enumerate_update_objects(&root, head, &baseline).unwrap();
            let outgoing = objects
                .into_iter()
                .map(|oid| OutgoingObject {
                    size: git_object_size(&root, &oid).unwrap(),
                    kind: git_object_type(&root, &oid).unwrap(),
                    oid,
                })
                .collect::<Vec<_>>();
            let commit_oids = outgoing
                .iter()
                .filter(|o| o.kind == "commit")
                .map(|o| o.oid.clone())
                .collect();
            (outgoing, commit_oids)
        };

        let allowlisted_head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let (outgoing, commit_oids) = collect_outgoing(&allowlisted_head);
        let path_map = map_outgoing_blob_paths(&root, &commit_oids).unwrap();
        assert_eq!(
            path_map.get(&leak_oid).cloned().unwrap_or_default(),
            BTreeSet::from(["fixtures/leak.txt".to_string()])
        );
        assert_eq!(
            scan_outgoing_objects(&root, &outgoing, &path_map),
            Ok(()),
            "a secret at an allowlisted path alone must pass"
        );

        // Introduce the SAME content at a second, non-allowlisted path. Git
        // dedups identical blob content, so this is the exact multi-path
        // binding D1 exists to catch.
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/real.rs"), secret).unwrap();
        assert!(Command::new("git")
            .args(["add", "src/real.rs"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "same secret at a real source path"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let (outgoing, commit_oids) = collect_outgoing(&head);
        let path_map = map_outgoing_blob_paths(&root, &commit_oids).unwrap();
        let bound_paths = path_map.get(&leak_oid).cloned().unwrap_or_default();
        assert_eq!(
            bound_paths,
            BTreeSet::from(["fixtures/leak.txt".to_string(), "src/real.rs".to_string()])
        );
        assert_eq!(
            scan_outgoing_objects(&root, &outgoing, &path_map),
            Err("outgoing-secret-scan-failed".into()),
            "a finding surviving under any one mapped path must still block"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_scan_fails_closed_when_any_binding_of_a_blob_has_an_invalid_path() {
        // Security-code F1: an invalid-path binding must NEVER be silently
        // dropped. The exact laundering shape: the same blob is committed at
        // BOTH an allowlisted, canonical path AND a second, non-canonical
        // path (here, one containing a backslash — a valid Unix filename
        // byte, but rejected by `validate_canonical_path`). If the invalid
        // row were merely dropped, the blob would map to only the
        // allowlisted path and the secret would reach the remote unscanned
        // at the second path. The whole mapping pass must instead fail
        // closed, blocking the push outright.
        let root = push_fixture("invalid-binding");
        let baseline = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let mpd = root.join(".mpd");
        std::fs::create_dir_all(&mpd).unwrap();
        std::fs::write(
            mpd.join("secret-allowlist.json"),
            "{\"paths\": [\"fixtures/**\"]}",
        )
        .unwrap();
        let secret = "token = \"abc123abc123abc123abc123\"\n";
        std::fs::create_dir_all(root.join("fixtures")).unwrap();
        std::fs::write(root.join("fixtures/leak.txt"), secret).unwrap();
        assert!(Command::new("git")
            .args(["add", "fixtures/leak.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "allowlisted fixture"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        // The SAME content, committed again at a non-canonical path (a
        // literal backslash byte — legal on a Unix filesystem, rejected by
        // `validate_canonical_path`).
        let invalid_path = "fixtures/leak\\evil.txt";
        std::fs::write(root.join(invalid_path), secret).unwrap();
        assert!(Command::new("git")
            .args(["add", "--", invalid_path])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "same secret at a non-canonical path"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let (objects, _) = enumerate_update_objects(&root, &head, &baseline).unwrap();
        let outgoing = objects
            .into_iter()
            .map(|oid| OutgoingObject {
                size: git_object_size(&root, &oid).unwrap(),
                kind: git_object_type(&root, &oid).unwrap(),
                oid,
            })
            .collect::<Vec<_>>();
        let commit_oids = outgoing
            .iter()
            .filter(|o| o.kind == "commit")
            .map(|o| o.oid.clone())
            .collect::<Vec<_>>();

        let error = map_outgoing_blob_paths(&root, &commit_oids).unwrap_err();
        assert_eq!(error, "outgoing-path-mapping-unsafe-path");

        // The push must never reach a state where this blob is scanned only
        // under the allowlisted path: with the mapping pass itself failing,
        // `authorize_pre_push` never even calls `scan_outgoing_objects`, so
        // the secret at the invalid path can never be suppressed.
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_scan_annotated_tag_on_blob_stays_unmapped_and_never_allowlisted() {
        // D1 Cond 20: a blob reachable only via an annotated tag pointing
        // directly at it (never through any commit's tree diff) stays
        // unmapped and is scanned under the synthetic `git-object:<oid>`
        // name at full strictness — even a maximally permissive allowlist
        // must not suppress it.
        let root = push_fixture("tag-on-blob");
        let mpd = root.join(".mpd");
        std::fs::create_dir_all(&mpd).unwrap();
        std::fs::write(mpd.join("secret-allowlist.json"), "{\"paths\": [\"**\"]}").unwrap();
        let secret = "token = \"abc123abc123abc123abc123\"\n";
        let scratch = root.join("scratch-secret.txt");
        std::fs::write(&scratch, secret).unwrap();
        let hash_output = Command::new("git")
            .args(["hash-object", "-w", "--", "scratch-secret.txt"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(hash_output.status.success());
        let blob_oid = String::from_utf8(hash_output.stdout)
            .unwrap()
            .trim()
            .to_string();
        assert!(Command::new("git")
            .args([
                "tag",
                "-a",
                "blobtag",
                "-m",
                "annotate a blob directly",
                &blob_oid,
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let tag_oid = git_output(&root, &["rev-parse", "blobtag"]).unwrap();
        let objects = vec![
            OutgoingObject {
                size: git_object_size(&root, &blob_oid).unwrap(),
                kind: git_object_type(&root, &blob_oid).unwrap(),
                oid: blob_oid,
            },
            OutgoingObject {
                size: git_object_size(&root, &tag_oid).unwrap(),
                kind: git_object_type(&root, &tag_oid).unwrap(),
                oid: tag_oid,
            },
        ];
        // No commit ever diffs in this blob, so the path map is empty
        // regardless of which commits are passed.
        let path_map = map_outgoing_blob_paths(&root, &[]).unwrap();
        assert!(path_map.is_empty());
        assert_eq!(
            scan_outgoing_objects(&root, &objects, &path_map),
            Err("outgoing-secret-scan-failed".into()),
            "an unmapped blob reachable only via a direct tag must block despite a `**` allowlist"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_scan_maps_paths_introduced_by_a_merge_side_branch() {
        // D1 Cond 20: `-m` must cover merge commits — a path introduced only
        // by a merge's side-branch parent is still enumerated and mapped.
        let root = push_fixture("merge-side-branch");
        let baseline = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let default_branch = git_output(&root, &["symbolic-ref", "--short", "HEAD"]).unwrap();
        let mpd = root.join(".mpd");
        std::fs::create_dir_all(&mpd).unwrap();
        std::fs::write(
            mpd.join("secret-allowlist.json"),
            "{\"paths\": [\"fixtures/**\"]}",
        )
        .unwrap();
        let secret = "token = \"abc123abc123abc123abc123\"\n";

        assert!(Command::new("git")
            .args(["checkout", "-qb", "feature", &baseline])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::create_dir_all(root.join("fixtures")).unwrap();
        std::fs::write(root.join("fixtures/leak.txt"), secret).unwrap();
        assert!(Command::new("git")
            .args(["add", "fixtures/leak.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "feature branch secret fixture"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        assert!(Command::new("git")
            .args(["checkout", "-q", &default_branch])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join("safe2.txt"), "second mainline content\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "safe2.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-qm", "second mainline commit"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "merge",
                "-q",
                "--no-edit",
                "feature",
                "-m",
                "merge feature branch"
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let merge_oid = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let leak_oid = git_output(
            &root,
            &["rev-parse", &format!("{merge_oid}:fixtures/leak.txt")],
        )
        .unwrap();

        let (objects, _) = enumerate_update_objects(&root, &merge_oid, &baseline).unwrap();
        let outgoing = objects
            .into_iter()
            .map(|oid| OutgoingObject {
                size: git_object_size(&root, &oid).unwrap(),
                kind: git_object_type(&root, &oid).unwrap(),
                oid,
            })
            .collect::<Vec<_>>();
        let commit_oids = outgoing
            .iter()
            .filter(|o| o.kind == "commit")
            .map(|o| o.oid.clone())
            .collect::<Vec<_>>();
        assert!(
            commit_oids.len() >= 3,
            "feature, second-mainline, and merge commits are all outgoing"
        );
        let path_map = map_outgoing_blob_paths(&root, &commit_oids).unwrap();
        assert_eq!(
            path_map.get(&leak_oid).cloned().unwrap_or_default(),
            BTreeSet::from(["fixtures/leak.txt".to_string()]),
            "the side branch's introduced path must be mapped via the merge's -m diff"
        );
        assert_eq!(
            scan_outgoing_objects(&root, &outgoing, &path_map),
            Ok(()),
            "the merge-introduced allowlisted path must pass"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// `(whole-range mapping result, optional scan outcome)` — the paired
    /// return of [`permuted_outgoing_outcome`], named to keep the signature
    /// within clippy's type-complexity budget.
    type PermutedOutcome = (
        Result<BTreeMap<String, BTreeSet<String>>, String>,
        Option<Result<(), String>>,
    );

    /// Metamorphic-fixture helper for the D1 mapping pass: a fresh repo with
    /// the standard `fixtures/**` allowlist, one commit per `(path, content)`
    /// step in the given order. Returns the whole-range mapping result and —
    /// only when mapping succeeded, mirroring `authorize_pre_push`'s ordering
    /// — the scan outcome over the complete outgoing range.
    fn permuted_outgoing_outcome(tag: &str, steps: &[(&str, &str)]) -> PermutedOutcome {
        let root = push_fixture(tag);
        let baseline = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let mpd = root.join(".mpd");
        std::fs::create_dir_all(&mpd).unwrap();
        std::fs::write(
            mpd.join("secret-allowlist.json"),
            "{\"paths\": [\"fixtures/**\"]}",
        )
        .unwrap();
        for (path, content) in steps {
            let full = root.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, content).unwrap();
            assert!(Command::new("git")
                .args(["add", "--", path])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
            assert!(Command::new("git")
                .args(["commit", "-qm", "step"])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        let (objects, _) = enumerate_update_objects(&root, &head, &baseline).unwrap();
        let outgoing: Vec<OutgoingObject> = objects
            .into_iter()
            .map(|oid| OutgoingObject {
                size: git_object_size(&root, &oid).unwrap(),
                kind: git_object_type(&root, &oid).unwrap(),
                oid,
            })
            .collect();
        let commit_oids: Vec<String> = outgoing
            .iter()
            .filter(|o| o.kind == "commit")
            .map(|o| o.oid.clone())
            .collect();
        let mapping = map_outgoing_blob_paths(&root, &commit_oids);
        let scan = mapping
            .as_ref()
            .ok()
            .map(|path_map| scan_outgoing_objects(&root, &outgoing, path_map));
        let _ = std::fs::remove_dir_all(root);
        (mapping, scan)
    }

    const COMMIT_PERMUTATIONS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    /// D1 metamorphic property: the diff-tree mapping pass is a parser over
    /// git history, so its outcome must be a function of the SET of path
    /// bindings in the outgoing range — never of commit order, and never of
    /// unrelated files committed alongside. Blob oids are content-addressed,
    /// so the entire oid→paths map must be byte-identical across every
    /// permutation, and the suppress/block decision must never flip.
    #[test]
    fn outgoing_scan_outcome_is_invariant_under_commit_order_and_unrelated_files() {
        let secret = "token = \"abc123abc123abc123abc123\"\n";

        // Scenario A (suppressed): the secret exists ONLY at an allowlisted
        // path; the other two commits are unrelated plain files. Every
        // ordering must map identically and pass.
        let suppressed_steps: [(&str, &str); 3] = [
            ("fixtures/leak.txt", secret),
            ("notes/readme.txt", "plain notes\n"),
            ("docs/guide.txt", "more plain text\n"),
        ];
        let mut reference_map: Option<BTreeMap<String, BTreeSet<String>>> = None;
        for (index, order) in COMMIT_PERMUTATIONS.iter().enumerate() {
            let steps: Vec<(&str, &str)> = order.iter().map(|&i| suppressed_steps[i]).collect();
            let (mapping, scan) =
                permuted_outgoing_outcome(&format!("meta-suppressed-{index}"), &steps);
            let mapping = mapping.unwrap_or_else(|error| {
                panic!("permutation {order:?} must map cleanly, got {error}")
            });
            match &reference_map {
                None => reference_map = Some(mapping),
                Some(reference) => assert_eq!(
                    &mapping, reference,
                    "permutation {order:?} changed the oid→paths map"
                ),
            }
            assert_eq!(
                scan,
                Some(Ok(())),
                "permutation {order:?} flipped an allowlist-suppressed push to blocked"
            );
        }
        let reference = reference_map.unwrap();
        assert!(
            reference
                .values()
                .any(|paths| paths == &BTreeSet::from(["fixtures/leak.txt".to_string()])),
            "the secret blob must be bound to exactly its allowlisted path"
        );

        // Scenario B (blocked): the SAME secret content also bound at a real,
        // non-allowlisted source path. Every ordering must observe both
        // bindings and block.
        let blocked_steps: [(&str, &str); 3] = [
            ("fixtures/leak.txt", secret),
            ("src/real.rs", secret),
            ("notes/readme.txt", "plain notes\n"),
        ];
        let mut reference_map: Option<BTreeMap<String, BTreeSet<String>>> = None;
        for (index, order) in COMMIT_PERMUTATIONS.iter().enumerate() {
            let steps: Vec<(&str, &str)> = order.iter().map(|&i| blocked_steps[i]).collect();
            let (mapping, scan) =
                permuted_outgoing_outcome(&format!("meta-blocked-{index}"), &steps);
            let mapping = mapping.unwrap_or_else(|error| {
                panic!("permutation {order:?} must map cleanly, got {error}")
            });
            assert!(
                mapping.values().any(|paths| paths
                    == &BTreeSet::from([
                        "fixtures/leak.txt".to_string(),
                        "src/real.rs".to_string()
                    ])),
                "permutation {order:?} lost a binding of the dedup'd secret blob: {mapping:?}"
            );
            match &reference_map {
                None => reference_map = Some(mapping),
                Some(reference) => assert_eq!(
                    &mapping, reference,
                    "permutation {order:?} changed the oid→paths map"
                ),
            }
            assert_eq!(
                scan,
                Some(Err("outgoing-secret-scan-failed".into())),
                "permutation {order:?} let a multi-binding secret through"
            );
        }
    }

    /// Security-code F1 metamorphic invariant: an invalid-path binding
    /// ANYWHERE in the outgoing range — first, middle, or last commit — must
    /// hard-fail the whole mapping pass before the scan (and therefore any
    /// allowlist suppression) can run. Position must never matter.
    #[test]
    fn outgoing_scan_invalid_path_binding_fails_closed_at_every_commit_position() {
        let secret = "token = \"abc123abc123abc123abc123\"\n";
        let invalid: (&str, &str) = ("fixtures/leak\\evil.txt", secret);
        let allowlisted: (&str, &str) = ("fixtures/leak.txt", secret);
        let unrelated: (&str, &str) = ("notes/readme.txt", "plain notes\n");
        for position in 0..3 {
            let mut steps = vec![allowlisted, unrelated];
            steps.insert(position, invalid);
            let (mapping, scan) =
                permuted_outgoing_outcome(&format!("f1-position-{position}"), &steps);
            assert_eq!(
                mapping.unwrap_err(),
                "outgoing-path-mapping-unsafe-path",
                "an invalid binding at commit position {position} must fail the whole pass"
            );
            assert!(
                scan.is_none(),
                "the scan (and any allowlist) must never run after a failed mapping pass"
            );
        }
    }

    /// D1 boundary: a commit argument that is not a full hexadecimal oid is
    /// rejected by `validate_oid` before any git subprocess is spawned.
    #[test]
    fn map_outgoing_blob_paths_rejects_a_malformed_commit_argument() {
        let root = push_fixture("bad-oid");
        let error = map_outgoing_blob_paths(&root, &["not-a-valid-oid".to_string()]).unwrap_err();
        assert_eq!(error, "Git object id is not a full hexadecimal oid");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn receipt_note_detects_stale_invalid_and_wrong_subject_evidence() {
        let root = std::env::temp_dir().join(format!(
            "mpd-receipt-note-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join("input"), "receipt fixture\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "input"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@invalid",
                "commit",
                "-qm",
                "fixture"
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let subject = capture_subject(&root, None).unwrap();
        let mut receipt = ValidationReceiptV1 {
            schema: VALIDATION_SCHEMA,
            id: String::new(),
            subject: subject.clone(),
            profile: "profile".into(),
            config_digest: "a".repeat(64),
            checks_digest: "b".repeat(64),
            trusted_policy_oid: "c".repeat(40),
            trusted_before_policy_digest: "d".repeat(64),
            candidate_policy_digest: "1".repeat(64),
            effective_policy_digest: "2".repeat(64),
            sandbox: SandboxReceiptBindingV1 {
                contract_version: 1,
                adapter_digest: "3".repeat(64),
                profile_digest: "4".repeat(64),
                environment_keys: vec!["PATH".into()],
                certified_host: "NOT CERTIFIED/test/test".into(),
                adapter_abi_digest: "a".repeat(64),
                canary_contract_digest: "b".repeat(64),
                residual_limitations: vec!["test limitation".into()],
                run_request_digests: Vec::new(),
                run_authority_digests: Vec::new(),
                run_root_inventory_digests: Vec::new(),
                run_canary_digests: Vec::new(),
            },
            validation_contract_version: 1,
            validator_version: "0.1.0".into(),
            validator_digest: "e".repeat(64),
            platform: PlatformReceiptBindingV1 {
                operating_system: "test".into(),
                architecture: "test".into(),
                cargo_target: "test-target".into(),
            },
            toolchain: ToolchainReceiptBindingV1 {
                rust_release: "1.0.0".into(),
                host: Some("test-target".into()),
                components: vec!["cargo".into(), "rustc".into()],
            },
            cargo_lock_digest: "5".repeat(64),
            advisory: AdvisoryReceiptBindingV1 {
                revision: "6".repeat(40),
                tree: "7".repeat(40),
                lock_digest: "8".repeat(64),
                max_age_days: 30,
            },
            tool_policy_digest: "9".repeat(64),
            tool_digests: Default::default(),
            results: vec![ValidationCheckResult {
                name: "check".into(),
                kind: "SelfCheck".into(),
                outcome: "passed".into(),
                exit: Some(0),
                count: None,
                duration_millis: 1,
                log_digest: "f".repeat(64),
            }],
            started_epoch_secs: 1,
            completed_epoch_secs: 2,
            outcome: "passed".into(),
            build_output: None,
        };
        receipt.id = receipt_id(&receipt).unwrap();
        let written = publish_receipt(&root, &receipt).unwrap();
        assert_eq!(written.id, receipt.id);
        let mut changed_tool = receipt.clone();
        changed_tool
            .tool_digests
            .insert("cargo".into(), "9".repeat(64));
        changed_tool.id = receipt_id(&changed_tool).unwrap();
        let stale = classify_receipt(&root, &changed_tool);
        assert_eq!(stale.state, ReceiptState::Stale);
        assert_eq!(
            stale.reasons,
            vec!["changed-dependency:tools-or-offline-inputs"]
        );
        let identity = git_output(
            &root,
            &["show", "-s", "--format=%an <%ae>", VALIDATION_NOTES_REF],
        )
        .unwrap();
        assert_eq!(identity, "MPD Local Evidence <mpd-local-evidence@invalid>");
        let mut invalid_id = receipt.clone();
        invalid_id.id = "0".repeat(64);
        assert_eq!(
            validate_receipt(&invalid_id, &subject),
            Err("invalid validation receipt".into())
        );
        let mut invalid_outcome = receipt.clone();
        invalid_outcome.results[0].outcome = "failed".into();
        invalid_outcome.id = receipt_id(&invalid_outcome).unwrap();
        assert_eq!(
            validate_receipt(&invalid_outcome, &subject),
            Err("invalid validation receipt outcome".into())
        );
        let mut wrong = subject.clone();
        wrong.tree = "0".repeat(subject.tree.len());
        assert!(validate_receipt(&receipt, &wrong).is_err());

        for tag in ["outer-a", "outer-b"] {
            assert!(Command::new("git")
                .args([
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@invalid",
                    "tag",
                    "-a",
                    tag,
                    "-m",
                    tag,
                    "HEAD",
                ])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        let subject_a = capture_subject(&root, Some("outer-a")).unwrap();
        let subject_b = capture_subject(&root, Some("outer-b")).unwrap();
        assert_eq!(subject_a.commit, subject_b.commit);
        assert_ne!(
            subject_a.attached_object_oid(),
            subject_b.attached_object_oid()
        );
        assert_eq!(subject_a.tag_chain.len(), 1);
        assert_eq!(subject_b.tag_chain.len(), 1);

        let mut receipt_a = receipt.clone();
        receipt_a.subject = subject_a.clone();
        receipt_a.id = receipt_id(&receipt_a).unwrap();
        publish_receipt(&root, &receipt_a).unwrap();
        let mut receipt_b = receipt.clone();
        receipt_b.subject = subject_b.clone();
        receipt_b.id = receipt_id(&receipt_b).unwrap();
        publish_receipt(&root, &receipt_b).unwrap();
        assert_eq!(
            classify_receipt(&root, &receipt_a).state,
            ReceiptState::Current
        );
        assert_eq!(
            classify_receipt(&root, &receipt_b).state,
            ReceiptState::Current
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn isolated_git_repo(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        fs::write(root.join("input"), format!("{label}\n")).unwrap();
        assert!(Command::new("git")
            .args(["add", "input"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@invalid",
                "commit",
                "-qm",
                label,
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        root
    }

    fn test_receipt(subject: Subject, profile: &str) -> ValidationReceiptV1 {
        let mut receipt = ValidationReceiptV1 {
            schema: VALIDATION_SCHEMA,
            id: String::new(),
            subject,
            profile: profile.into(),
            config_digest: "a".repeat(64),
            checks_digest: "b".repeat(64),
            trusted_policy_oid: "c".repeat(40),
            trusted_before_policy_digest: "d".repeat(64),
            candidate_policy_digest: "1".repeat(64),
            effective_policy_digest: "2".repeat(64),
            sandbox: SandboxReceiptBindingV1 {
                contract_version: 1,
                adapter_digest: "3".repeat(64),
                profile_digest: "4".repeat(64),
                environment_keys: vec!["PATH".into()],
                certified_host: "NOT CERTIFIED/test/test".into(),
                adapter_abi_digest: "a".repeat(64),
                canary_contract_digest: "b".repeat(64),
                residual_limitations: vec!["test limitation".into()],
                run_request_digests: Vec::new(),
                run_authority_digests: Vec::new(),
                run_root_inventory_digests: Vec::new(),
                run_canary_digests: Vec::new(),
            },
            validation_contract_version: 1,
            validator_version: "0.1.0".into(),
            validator_digest: "e".repeat(64),
            platform: PlatformReceiptBindingV1 {
                operating_system: "test".into(),
                architecture: "test".into(),
                cargo_target: "test-target".into(),
            },
            toolchain: ToolchainReceiptBindingV1 {
                rust_release: "1.0.0".into(),
                host: Some("test-target".into()),
                components: vec!["cargo".into(), "rustc".into()],
            },
            cargo_lock_digest: "5".repeat(64),
            advisory: AdvisoryReceiptBindingV1 {
                revision: "6".repeat(40),
                tree: "7".repeat(40),
                lock_digest: "8".repeat(64),
                max_age_days: 30,
            },
            tool_policy_digest: "9".repeat(64),
            tool_digests: BTreeMap::new(),
            results: vec![ValidationCheckResult {
                name: "check".into(),
                kind: "SelfCheck".into(),
                outcome: "passed".into(),
                exit: Some(0),
                count: Some(1),
                duration_millis: 1,
                log_digest: "f".repeat(64),
            }],
            started_epoch_secs: 1,
            completed_epoch_secs: 2,
            outcome: "passed".into(),
            build_output: None,
        };
        receipt.id = receipt_id(&receipt).unwrap();
        receipt
    }

    fn plant_note_bytes(root: &Path, subject: &Subject, bytes: &[u8]) {
        let old = validation_notes_ref(root).unwrap();
        let blob = git_hash_blob(root, bytes).unwrap();
        let commit = build_note_commit(
            root,
            old.as_deref(),
            subject.attached_object_oid(),
            &blob,
            2,
        )
        .unwrap();
        let expected = old.unwrap_or_else(|| "0".repeat(subject.commit.len()));
        assert!(Command::new("git")
            .args([
                "update-ref",
                "--no-deref",
                VALIDATION_NOTES_REF,
                &commit,
                &expected,
            ])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn canonical_git_ignores_ambient_repository_identity_object_config_and_execution_state() {
        if let Some(root) = std::env::var_os("MPD_CANONICAL_GIT_CHILD_ROOT") {
            let root = PathBuf::from(root);
            let subject = capture_subject(&root, None).unwrap();
            let observed = git_output(&root, &["rev-parse", "HEAD^{commit}"]).unwrap();
            assert_eq!(observed, subject.commit);
            assert_eq!(
                git_hash_file(&root, &root.join("input")).unwrap(),
                git_output(&root, &["rev-parse", "HEAD:input"]).unwrap()
            );
            let receipt = test_receipt(subject, "ambient-isolation");
            publish_receipt(&root, &receipt).unwrap();
            let error = git_output(&root, &["cat-file", "-t", "--", &"0".repeat(40)]).unwrap_err();
            assert!(!error.contains("SECRET"));
            return;
        }
        let root = isolated_git_repo("git-env-root");
        let redirect = isolated_git_repo("git-env-redirect");
        let canary = root.join("execution-canary");
        let hooks = root.join("evil-hooks");
        fs::create_dir(&hooks).unwrap();
        let hook = hooks.join("reference-transaction");
        fs::write(
            &hook,
            format!("#!/bin/sh\necho hook > '{}'\n", canary.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let global = root.join("evil-global-config");
        fs::write(
            &global,
            format!(
                "[core]\n\thooksPath = {}\n\tpager = sh -c 'echo pager > {}'\n[commit]\n\tgpgSign = true\n[gpg]\n\tprogram = /usr/bin/false\n[filter \"evil\"]\n\tclean = sh -c 'echo filter > {}'\n",
                hooks.display(),
                canary.display(),
                canary.display()
            ),
        )
        .unwrap();
        assert!(Command::new("git")
            .args([
                "config",
                "--local",
                "core.hooksPath",
                hooks.to_str().unwrap()
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["config", "--local", "commit.gpgSign", "true"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "config",
                "--local",
                "core.pager",
                &format!("sh -c 'echo pager > {}'", canary.display()),
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "config",
                "--local",
                "filter.evil.clean",
                &format!("sh -c 'echo filter > {}'", canary.display()),
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        fs::write(root.join(".gitattributes"), "* filter=evil\n").unwrap();
        let ambient_index = root.join("ambient-index");
        fs::write(&ambient_index, b"sentinel").unwrap();
        let variables = [
            ("GIT_DIR", redirect.join(".git").into_os_string()),
            ("GIT_WORK_TREE", redirect.clone().into_os_string()),
            ("GIT_INDEX_FILE", ambient_index.clone().into_os_string()),
            (
                "GIT_OBJECT_DIRECTORY",
                redirect.join(".git/objects").into_os_string(),
            ),
            (
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                OsString::from("/nonexistent/SECRET-ALTERNATE"),
            ),
            (
                "GIT_REPLACE_REF_BASE",
                OsString::from("refs/replace/SECRET"),
            ),
            ("GIT_CONFIG_GLOBAL", global.into_os_string()),
            ("HOME", redirect.clone().into_os_string()),
        ];
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "local_validation::tests::canonical_git_ignores_ambient_repository_identity_object_config_and_execution_state",
                "--nocapture",
            ])
            .env("MPD_CANONICAL_GIT_CHILD_ROOT", &root);
        for (key, value) in &variables {
            child.env(key, value);
        }
        assert!(child.status().unwrap().success());
        assert_eq!(fs::read(&ambient_index).unwrap(), b"sentinel");
        assert!(!canary.exists());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(redirect);
    }

    #[test]
    fn note_store_rejects_symbolic_malformed_oversized_and_replaces_invalid_after_fresh_run() {
        let root = isolated_git_repo("note-adversarial");
        let subject = capture_subject(&root, None).unwrap();
        let receipt = test_receipt(subject.clone(), "profile");
        plant_note_bytes(&root, &subject, b"{");
        assert!(read_note_envelope(&root, &subject)
            .unwrap_err()
            .starts_with("invalid validation note"));
        assert_eq!(publish_receipt(&root, &receipt).unwrap(), receipt);
        let mut wrong = receipt.clone();
        wrong.subject.tree = "0".repeat(wrong.subject.tree.len());
        wrong.id = receipt_id(&wrong).unwrap();
        let wrong_key = receipt_profile_key(&wrong).unwrap();
        plant_note_bytes(
            &root,
            &subject,
            &serde_json::to_vec(&ValidationNoteEnvelopeV1 {
                schema: VALIDATION_SCHEMA,
                receipts: BTreeMap::from([(wrong_key, wrong)]),
            })
            .unwrap(),
        );
        assert_eq!(
            read_note_envelope(&root, &subject).unwrap_err(),
            "invalid validation receipt"
        );
        plant_note_bytes(&root, &subject, &vec![b'x'; MAX_NOTE_BYTES + 1]);
        assert_eq!(
            read_note_envelope(&root, &subject).unwrap_err(),
            "invalid validation note: oversized"
        );
        let old = validation_notes_ref(&root).unwrap().unwrap();
        let valid_blob = git_hash_blob(
            &root,
            &serde_json::to_vec(&ValidationNoteEnvelopeV1 {
                schema: VALIDATION_SCHEMA,
                receipts: BTreeMap::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let note_path = format!(
            "{}/{}",
            &subject.attached_object_oid()[..2],
            &subject.attached_object_oid()[2..]
        );
        let conflicting =
            rewrite_policy_tree_for_test(&root, &old, &note_path, Some((0o100755, &valid_blob)));
        assert!(Command::new("git")
            .args([
                "update-ref",
                "--no-deref",
                VALIDATION_NOTES_REF,
                &conflicting,
                &old,
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            read_note_envelope(&root, &subject).unwrap_err(),
            "invalid validation note: conflicting tree entry"
        );
        assert!(Command::new("git")
            .args(["update-ref", "-d", VALIDATION_NOTES_REF])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["symbolic-ref", VALIDATION_NOTES_REF, "refs/heads/master"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            read_note_envelope(&root, &subject).unwrap_err(),
            "validation notes ref must be literal and direct"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn note_store_concurrent_cas_has_one_winner_and_reparses_it_with_reflog_enabled() {
        let root = isolated_git_repo("note-cas");
        assert!(Command::new("git")
            .args(["config", "--local", "core.logAllRefUpdates", "always"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let subject = capture_subject(&root, None).unwrap();
        let left = test_receipt(subject.clone(), "left");
        let right = test_receipt(subject.clone(), "right");
        let barrier = std::sync::Arc::new((std::sync::Mutex::new(0), std::sync::Condvar::new()));
        *NOTE_CAS_BARRIER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(NoteCasHook {
            root: root.clone(),
            barrier,
        });
        let left_root = root.clone();
        let right_root = root.clone();
        let left_receipt = left.clone();
        let right_receipt = right.clone();
        let left_thread = std::thread::spawn(move || publish_receipt(&left_root, &left_receipt));
        let right_thread = std::thread::spawn(move || publish_receipt(&right_root, &right_receipt));
        let left_result = left_thread.join().unwrap();
        let right_result = right_thread.join().unwrap();
        *NOTE_CAS_BARRIER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        assert_eq!(left_result.is_ok() as u8 + right_result.is_ok() as u8, 1);
        let loser = match (left_result, right_result) {
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => error,
            _ => panic!("exactly one concurrent notes CAS must win"),
        };
        assert_eq!(
            loser,
            "validation receipt publication unstable: notes CAS lost"
        );
        let (_, envelope) = read_note_envelope(&root, &subject).unwrap();
        assert_eq!(envelope.receipts.len(), 1);
        let reflog = root.join(".git/logs/refs/notes/mpd-validation");
        assert!(reflog.is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn private_log_inventory_rotates_valid_runs_and_blocks_corrupt_links_and_locks() {
        let base = std::env::temp_dir().join(format!(
            "mpd-private-logs-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        protect_dir(&base).unwrap();
        let limits = ReceiptLimits {
            log_count_cap: 1,
            log_byte_cap: 1024,
        };
        for (run_name, completed) in [("run-one", 1), ("run-two", 2)] {
            let run = base.join(run_name);
            fs::create_dir(&run).unwrap();
            protect_dir(&run).unwrap();
            let log = b"closed-summary";
            write_private_file(&run.join("check.log"), log).unwrap();
            let subject_repo = isolated_git_repo(run_name);
            let subject = capture_subject(&subject_repo, None).unwrap();
            let _ = fs::remove_dir_all(subject_repo);
            let manifest = PrivateRunManifestV1 {
                schema: 1,
                profile: "required".into(),
                subject,
                completed_epoch_secs: completed,
                logs: vec![PrivateLogEntryV1 {
                    file: "check.log".into(),
                    bytes: log.len() as u64,
                    sha256: Digest::of_bytes(log).to_hex(),
                }],
            };
            finalize_private_logs(&run, &manifest, &limits).unwrap();
        }
        assert!(!base.join("run-one").exists());
        assert!(base.join("run-two").is_dir());
        fs::write(base.join("inventory.json"), b"corrupt").unwrap();
        let run = base.join("run-three");
        fs::create_dir(&run).unwrap();
        protect_dir(&run).unwrap();
        write_private_file(&run.join("check.log"), b"x").unwrap();
        let fixture = isolated_git_repo("run-three-subject");
        let manifest = PrivateRunManifestV1 {
            schema: 1,
            profile: "required".into(),
            subject: capture_subject(&fixture, None).unwrap(),
            completed_epoch_secs: 3,
            logs: vec![PrivateLogEntryV1 {
                file: "check.log".into(),
                bytes: 1,
                sha256: Digest::of_bytes(b"x").to_hex(),
            }],
        };
        assert_eq!(
            finalize_private_logs(&run, &manifest, &limits).unwrap_err(),
            "private validation log inventory is corrupt"
        );
        assert!(run.is_dir());
        fs::remove_file(base.join("inventory.json")).unwrap();
        let lock = PrivateRotationLock::acquire(&base).unwrap();
        assert_eq!(
            finalize_private_logs(&run, &manifest, &limits).unwrap_err(),
            "private validation log rotation is already locked"
        );
        drop(lock);
        #[cfg(unix)]
        {
            let external = base.join("external");
            write_private_file(&external, b"x").unwrap();
            let linked = run.join("linked.log");
            fs::hard_link(&external, &linked).unwrap();
            assert!(validate_private_file(&linked, 16).is_err());
            fs::remove_file(linked).unwrap();
        }
        let _ = fs::remove_dir_all(base);
        let _ = fs::remove_dir_all(fixture);
    }

    #[test]
    fn typed_install_detects_source_destination_and_temp_replacement_and_cleans_temps() {
        for mode in 1..=3 {
            let root = isolated_git_repo(&format!("install-race-{mode}"));
            fs::write(root.join("artifact"), b"reviewed artifact").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root.join("artifact"), fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            let mut output = capture_build_output(&root, "artifact").unwrap();
            output.name = "release".into();
            output.max_bytes = 1024;
            output.required_mode = output.mode;
            INSTALL_RACE_MODES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(root.clone(), mode);
            assert!(install_build_output(&root, &output, "installed").is_err());
            assert!(fs::read_dir(&root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".mpd-install-")
            }));
            let _ = fs::remove_dir_all(root);
        }
    }
}
