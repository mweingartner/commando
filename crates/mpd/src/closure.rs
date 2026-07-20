//! Content-addressed release-closure schemas, manifest, and evidence
//! lifecycle.
//!
//! Normative references: `openspec/changes/content-addressed-release-closure/
//! design.md` ("Durable schemas", "Dependency and invalidation rules") and
//! `archive-transaction.md` ("Types"). This module now covers:
//!
//! - the versioned, serde-defaulted evidence/closure record types
//!   (foundations stage);
//! - `ChangeManifest` parse/validate/seed and its content-addressed I/O
//!   (`openspec/changes/<name>/manifest.json`);
//! - `SystemScope`, the bounded, code-owned "displayed, not broadened"
//!   MPD-system path set a caller folds in alongside manifest scope;
//! - `DependencyPolicy::for_phase`, the sole phase-causal dependency
//!   allowlist, and `DependencySnapshot::for_phase` snapshot construction;
//! - `evidence_validity` (content-bound valid/stale/absent, independent of
//!   reuse eligibility) and `reuse_offer`/`evaluate_reuse` (the separate
//!   reuse-eligibility and actual-reuse-decision rules from
//!   `specs/evidence-reuse/spec.md`);
//! - `HermeticReusePolicy::validate`, closing the "reject secret-shaped
//!   environment names" security-plan requirement.
//! - `verify_commit_coherence`, the per-commit path-union proof that a
//!   closure commit descends cleanly from its recorded base with no
//!   out-of-scope path in any intermediate commit (archive-transaction.md
//!   "commit coherent"; security-plan.md's endpoint-diff HIGH finding).
//! - `verify_remote_parity`, the bounded, non-fetching, snapshot/recheck
//!   remote-parity observation (design.md "Remote observation";
//!   security-plan.md's TOCTOU/remote-token-confusion findings), wired into
//!   `cli.rs`'s `mpd publish [--verify]`.
//!
//! The archive-transaction executor (crash-safe journal/staging/recovery)
//! lives in `openspec_core::transaction`, not here.

use crate::digest::{self, Digest};
use crate::git;
use crate::ledger::{RiskAssessment, RiskLevel, Verdict};
use crate::pathmatch::glob_match;
use crate::phase::Phase;
use openspec_core::{assert_contained, read_capped, validate_change_name, Project};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Current schema for [`EvidenceReceipt`] / [`DependencySnapshot`].
pub const RECEIPT_SCHEMA: u32 = 2;
/// Current schema for [`HermeticReusePolicy`].
pub const HERMETIC_POLICY_SCHEMA: u32 = 1;
/// Current schema for [`ChangeManifest`].
pub const MANIFEST_SCHEMA: u32 = 1;
/// Maximum combined `paths` + `shared_paths` pattern count a manifest may
/// declare — defense in depth against an unbounded/adversarial manifest file
/// (design.md "Config, migration, and performance": "cap manifest paths,
/// patterns...").
pub const MAX_MANIFEST_PATTERNS: usize = 2000;

/// The closed, versioned vocabulary of content a gate receipt may bind.
/// [`crate::phase`]'s forthcoming `DependencyPolicy::for_phase` (a later
/// stage) draws exclusively from this enum, so a phase-causality audit
/// ("does an earlier phase's policy ever reference an output only a later
/// phase produces?") is exhaustive by construction — every arm must be
/// accounted for, and there is no open-ended string key a typo could hide
/// behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyKey {
    /// The canonical manifest plus named MPD-owned path rules.
    Scope,
    /// Current worktree bytes for user-declared matched tracked/untracked
    /// files — never the receipt-bearing ledger or local caches (that
    /// exclusion is what keeps a receipt digest from being self-referential).
    Source,
    /// Typed risk/threat-profile governance data.
    Governance,
    /// Phase-relevant normalized config values.
    Config,
    /// Design/plan artifact content (Design Mock, Architecture, Design
    /// Review/Sign-off phases).
    DesignArtifacts,
    /// The Design Mock's own artifact only. Separate from later Architecture
    /// output so authoring a plan cannot retroactively stale the mock receipt.
    DesignMockArtifact,
    /// Proposal/design/tasks contract, with task progress normalized. This is
    /// Architecture input, not a dependency of the earlier Design Mock.
    ArchitecturePlan,
    /// The configured test command text (Build, Test).
    TestCommand,
    /// Compiler/toolchain identity strings.
    Toolchain,
    /// Digests of artifacts the phase itself produced.
    ProducedArtifact,
    /// Security-code scanner identity strings (e.g. gitleaks/Semgrep
    /// versions).
    ScannerIdentity,
    /// The secret-scan allowlist file's content digest.
    AllowlistDigest,
    /// The configured deploy command text.
    DeployCommand,
    /// Shipped-behavior inputs a documentation pass summarizes.
    ShippedBehavior,
    /// The durable documentation content itself (Doc Validation).
    Documentation,
    /// Hermetic-reuse-only: OS/architecture/SDK platform identity.
    HermeticPlatform,
    /// Hermetic-reuse-only: executable-byte digest of a bound tool.
    HermeticExecutable,
    /// Hermetic-reuse-only: a declared, privacy-safe environment value
    /// digest (never the raw value).
    HermeticEnvironment,
    /// Hermetic-reuse-only: a declared project-relative external input
    /// digest.
    HermeticInput,
    /// A phase persona's effective instructions — its config tuning
    /// (`personas[tuning_key]`) plus its resolved base-directive text. Bound by
    /// the governed phases so a receipt stales if the persona's directive changed
    /// (config append OR directive-file edit), never on an unrelated config edit
    /// (design.md persona-tuning D5 §1). Added last so no existing variant's
    /// discriminant/ordering shifts.
    PersonaTuning,
}

impl DependencyKey {
    /// A short, stable kebab-case label — identical to this variant's serde
    /// tag (pinned by `every_dependency_key_round_trips_through_its_kebab_
    /// case_slug` and `dependency_key_label_matches_its_serde_tag` below), so
    /// error/status text and the wire format never drift apart.
    pub fn label(self) -> &'static str {
        use DependencyKey::*;
        match self {
            Scope => "scope",
            Source => "source",
            Governance => "governance",
            Config => "config",
            DesignArtifacts => "design-artifacts",
            DesignMockArtifact => "design-mock-artifact",
            ArchitecturePlan => "architecture-plan",
            TestCommand => "test-command",
            Toolchain => "toolchain",
            ProducedArtifact => "produced-artifact",
            ScannerIdentity => "scanner-identity",
            AllowlistDigest => "allowlist-digest",
            DeployCommand => "deploy-command",
            ShippedBehavior => "shipped-behavior",
            Documentation => "documentation",
            HermeticPlatform => "hermetic-platform",
            HermeticExecutable => "hermetic-executable",
            HermeticEnvironment => "hermetic-environment",
            HermeticInput => "hermetic-input",
            PersonaTuning => "persona-tuning",
        }
    }
}

impl fmt::Display for DependencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A versioned snapshot of exactly the dependency keys a phase's policy
/// allowlisted at receipt time, each bound to its content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySnapshot {
    /// Schema version.
    pub schema: u32,
    /// The bound key → digest values. A `BTreeMap` so two snapshots with the
    /// same logical content always serialize byte-identically (stable key
    /// order), independent of construction order.
    pub values: BTreeMap<DependencyKey, Digest>,
}

/// How a receipt's evidence came to exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EvidenceDisposition {
    /// The gate actually ran and produced this result.
    Executed,
    /// The verdict was carried forward from a prior valid receipt without
    /// re-running the gate.
    Reused {
        /// The original *executed* receipt this reuse points to. Reuse
        /// chains are always flattened to the executed origin at append
        /// time — a `Reused` receipt's `source_receipt` never itself names
        /// another `Reused` receipt.
        source_receipt: Digest,
    },
}

/// Content-bound evidence attached to a gate result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReceipt {
    /// Digest of the complete receipt payload excluding this field itself
    /// (`id` cannot be part of its own preimage).
    pub id: Digest,
    /// Schema version (see [`RECEIPT_SCHEMA`]).
    pub schema: u32,
    /// The phase this receipt backs.
    pub phase: Phase,
    /// How this evidence came to exist.
    pub disposition: EvidenceDisposition,
    /// The exact dependency snapshot this receipt was bound to.
    pub dependencies: DependencySnapshot,
}

/// The only accepted `external_state` declaration for v1: a closed enum
/// (rather than a free-form string) so an incomplete or misspelled opt-in
/// fails to parse rather than silently granting reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoExternalState {
    /// No relevant state exists outside what [`HermeticReusePolicy`]
    /// explicitly declares below.
    None,
}

/// A project-level opt-in enabling reuse for Build/Test/Security-code.
/// Absent or incomplete ⇒ those phases stay `always_execute` (the safe
/// default) — see design.md "Dependency and invalidation rules".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HermeticReusePolicy {
    /// Schema version (see [`HERMETIC_POLICY_SCHEMA`]).
    pub schema: u32,
    /// Declares no relevant state lives outside what's bound below.
    pub external_state: NoExternalState,
    /// Allowlisted, privacy-safe environment variable *names* (never
    /// values) whose value digests are bound into a hermetic snapshot.
    #[serde(default)]
    pub environment: Vec<String>,
    /// Project-relative external input paths bound into the snapshot.
    #[serde(default)]
    pub input_paths: Vec<String>,
}

/// The durable record of a completed archive's content-addressed closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveClosure {
    /// The commit HEAD must descend from for a closure commit to be
    /// coherent.
    pub base_commit: String,
    /// The dated archive directory this closure produced.
    pub archive_path: String,
    /// The archive transaction's identity (see
    /// `openspec_core::ArchiveTransactionPlan::id`).
    pub transaction_id: Digest,
    /// Exact Build Candidate whose retained tree is the source of a modern
    /// closure plan. Absent only on legacy archives created before candidate
    /// equivalence existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_id: Option<String>,
    /// The declared/system scope this closure covers — the manifest's
    /// (possibly glob) `paths`/`shared_paths` plus [`SystemScope::paths`],
    /// merged and deduplicated. Used for post-commit coherence
    /// (`verify_commit_coherence`), where a broad/legacy declared scope is a
    /// legitimate, intentionally permissive grant.
    pub allowed_paths: Vec<String>,
    /// A concrete, frozen snapshot — never a glob pattern — of every
    /// repository path that matched the declared/system scope *at the moment
    /// archive ran* (see [`resolve_scope_snapshot`]): every tracked/untracked
    /// path then matching `paths`/`shared_paths`, unioned with the always-
    /// concrete [`SystemScope::paths`] (so a directory this archive is about
    /// to create, e.g. the archive target, is still covered by prefix even
    /// though nothing exists under it yet). This is the closure's *own*
    /// protected scope while `.mpd/pending-closure` exists: `check
    /// --staged`/`status` use it instead of re-consulting the manifest's
    /// (possibly still-`**`) live patterns, so a file created *after*
    /// archival is never silently swept into "in scope" by a broad or legacy
    /// wildcard the manifest still literally carries — only
    /// `verify_commit_coherence` (a distinct, post-commit check) re-resolves
    /// glob patterns dynamically. Serde-defaulted (empty) so any archive
    /// closure recorded before this field existed degrades to "nothing
    /// concrete recorded" (fails closed — see `manifest_view`) rather than
    /// failing to parse.
    #[serde(default)]
    pub system_paths: Vec<String>,
    /// The digest the fully-applied scoped result matched at archive time.
    pub post_archive_digest: Digest,
    /// When this closure was recorded (Unix epoch seconds).
    pub archived_at: u64,
}

/// The ignored, crash-recoverable pointer to an in-flight archive
/// transaction (`.mpd/pending-closure`). Re-exported rather than redefined:
/// `openspec_core::transaction`'s executor owns this file's I/O (see
/// `archive-transaction.md`), so its `PendingClosurePointer` is the single
/// authoritative type for the on-disk shape — a second, independently
/// defined struct here would risk drifting out of sync with what the
/// executor actually reads/writes.
#[allow(unused_imports)]
pub use openspec_core::{PendingClosurePointer, PENDING_POINTER_SCHEMA};

/// A single local Git+scope observation captured together for
/// `publish`/commit-coherence checks: one `HEAD` OID, one index identity,
/// and one scoped-content digest, snapshotted as a unit so distinct
/// sub-observations can never be silently attributed to different
/// repository states (the local half of the TOCTOU fix in
/// design.md "Remote observation").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSnapshot {
    /// The `HEAD` commit OID at snapshot time.
    pub head: String,
    /// A digest identifying the index (staged tree) state.
    pub index: Digest,
    /// The scoped worktree content digest.
    pub scoped: Digest,
    /// Whether the included scope was clean (no unstaged changes) at
    /// snapshot time.
    pub included_clean: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParityState {
    Verified,
    NotVerified,
    Offline,
    Ahead,
    Behind,
    Diverged,
    Rewritten,
    Unstable,
    AncestryUnavailable,
    Unavailable,
}

impl ParityState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::NotVerified => "not verified",
            Self::Offline => "offline",
            Self::Ahead => "ahead",
            Self::Behind => "behind",
            Self::Diverged => "diverged",
            Self::Rewritten => "rewritten",
            Self::Unstable => "unstable",
            Self::AncestryUnavailable => "ancestry unavailable",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityObservation {
    pub schema: u32,
    pub change: String,
    pub remote: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub local_oid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_oid: Option<String>,
    pub state: ParityState,
    pub observed_at_epoch_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCoherence {
    pub coherent: bool,
    pub head: Option<String>,
    pub blockers: Vec<String>,
}

// =====================================================================
// Candidate-to-closure equivalence
// =====================================================================

/// Schema for [`CandidateClosurePlan`]. The plan is deliberately distinct
/// from both a Candidate gate receipt and an immutable Commit validation
/// receipt: equality of their trees never collapses those two subjects.
pub const CANDIDATE_CLOSURE_SCHEMA: u32 = 1;
const MAX_CLOSURE_TREE_ENTRIES: usize = 100_000;
const MAX_CLOSURE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CLOSURE_TREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// One canonical regular-file postimage admitted after Candidate capture.
/// Bytes are an input to plan construction only; the durable plan retains
/// their length and digest rather than duplicating source content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureFilePostimage {
    pub path: String,
    pub mode: u32,
    pub bytes: Vec<u8>,
}

impl ClosureFilePostimage {
    pub fn regular(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            mode: 0o100644,
            bytes: bytes.into(),
        }
    }
}

/// A current, canonical downstream judgment artifact. `receipt_id` is kept
/// separate from the file digest so the closure binds both what was reviewed
/// and the gate evidence that admitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseArtifactPostimage {
    pub phase: Phase,
    pub receipt_id: String,
    pub file: ClosureFilePostimage,
}

/// Durable documentation admitted only through a distinct Doc Validation
/// receipt. An empty file list is valid when the reviewed change has no
/// durable-document target, but the receipt identity remains mandatory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedDocumentationPostimages {
    pub doc_validation_receipt_id: String,
    pub files: Vec<ClosureFilePostimage>,
}

/// Exact archive-transaction outputs that are neither Candidate source nor
/// reviewed durable documentation. Spec writes are restricted to canonical
/// OpenSpec targets. The ledger postimage has a dedicated field because it is
/// mutable process state before archive and must prove its exact Candidate and
/// [`ArchiveClosure`] bindings before it can enter the commit expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicArchivePostimages {
    pub spec_writes: Vec<ClosureFilePostimage>,
    pub ledger: ClosureFilePostimage,
}

/// Canonical path/mode/content identity for one expected or observed commit
/// file. Git tree modes are normalized to exactly `100644` or `100755`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureTreeEntry {
    pub path: String,
    pub mode: u32,
    pub byte_len: u64,
    pub sha256: String,
}

/// Full expected post-archive tree. `candidate_id` and the later
/// `commit_oid` in [`CandidateClosureEquivalence`] intentionally remain
/// separate subject identities even when every entry is equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateClosurePlan {
    pub schema: u32,
    pub candidate_id: String,
    pub candidate_base_commit: String,
    pub archive_path: String,
    pub archive_transaction_id: String,
    pub overlay_digest: String,
    pub expected_tree_digest: String,
    pub entries: Vec<ClosureTreeEntry>,
}

/// Exact comparison of one immutable Commit tree with one Candidate-derived
/// closure plan. A non-equivalent comparison is a successful observation with
/// blockers, not a Commit receipt and not a remote-parity observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateClosureEquivalence {
    pub equivalent: bool,
    pub candidate_id: String,
    pub commit_oid: String,
    pub expected_tree_digest: String,
    pub observed_tree_digest: String,
    pub blockers: Vec<String>,
}

/// Build the only allowed Candidate-to-archive projection:
///
/// 1. the complete retained Candidate tree;
/// 2. current canonical downstream phase artifacts with their receipts;
/// 3. separately reviewed durable documentation;
/// 4. deterministic spec and exact closure-ledger postimages; and
/// 5. the active-change to dated-archive rename.
///
/// No live worktree bytes are consulted. Source/config/script/task changes
/// therefore cannot be smuggled in as an overlay, and mutable process state
/// has no generic overlay path.
pub fn build_candidate_closure_plan(
    candidate_root: &Path,
    candidate: &crate::candidate::CandidateProjection,
    closure: &ArchiveClosure,
    phase_artifacts: &[PhaseArtifactPostimage],
    documentation: &ReviewedDocumentationPostimages,
    archive: &DeterministicArchivePostimages,
) -> Result<CandidateClosurePlan, String> {
    validate_candidate_closure_binding(candidate_root, candidate, closure)?;

    let change = &candidate.capture.subject.change;
    let active_prefix = format!("openspec/changes/{change}");
    validate_archive_path(change, &active_prefix, &closure.archive_path)?;
    let manifest = load_manifest(candidate_root, change)
        .map_err(|error| format!("candidate closure cannot read its retained manifest: {error}"))?;
    if !manifest.is_ready() {
        return Err("candidate closure manifest is not ready".into());
    }

    let mut expected = inventory_closure_tree(candidate_root)?;
    verify_candidate_scope_entries(&expected, &candidate.entries)?;
    let mut overlay_claims = BTreeMap::<String, String>::new();
    let mut overlay_entries = Vec::<digest::Entry>::new();

    for artifact in phase_artifacts {
        Digest::from_hex(&artifact.receipt_id)
            .map_err(|_| "phase artifact receipt ID is not a canonical SHA-256 digest")?;
        let expected_name = match artifact.phase {
            Phase::SecurityCode => "security-code.md",
            Phase::DesignSignoff => "design-signoff.md",
            Phase::Test => "test.md",
            Phase::Documentation => "documentation.md",
            Phase::DocValidation => "doc-validation.md",
            _ => {
                return Err(format!(
                    "{} is not a post-Candidate canonical artifact phase",
                    artifact.phase.label()
                ))
            }
        };
        let expected_path = format!("{active_prefix}/{expected_name}");
        if artifact.file.path != expected_path {
            return Err(format!(
                "canonical {} artifact must be exactly {expected_path:?}",
                artifact.phase.label()
            ));
        }
        claim_overlay(
            &mut overlay_claims,
            &artifact.file.path,
            &format!("phase:{}", artifact.phase.slug()),
        )?;
        apply_postimage(&mut expected, &artifact.file)?;
        overlay_entries.push(postimage_digest_entry(
            &format!("phase/{}/{}", artifact.phase.slug(), artifact.receipt_id),
            &artifact.file,
        )?);
    }

    Digest::from_hex(&documentation.doc_validation_receipt_id)
        .map_err(|_| "Doc Validation receipt ID is not a canonical SHA-256 digest")?;
    for document in &documentation.files {
        validate_documentation_postimage(
            &manifest,
            &active_prefix,
            &closure.archive_path,
            document,
        )?;
        claim_overlay(
            &mut overlay_claims,
            &document.path,
            "reviewed-documentation",
        )?;
        apply_postimage(&mut expected, document)?;
        overlay_entries.push(postimage_digest_entry(
            &format!(
                "documentation/{}/{}",
                documentation.doc_validation_receipt_id, document.path
            ),
            document,
        )?);
    }

    for spec in &archive.spec_writes {
        validate_spec_postimage(spec)?;
        claim_overlay(&mut overlay_claims, &spec.path, "archive-spec-postimage")?;
        apply_postimage(&mut expected, spec)?;
        overlay_entries.push(postimage_digest_entry(
            &format!("archive-spec/{}", spec.path),
            spec,
        )?);
    }

    validate_archive_ledger_postimage(candidate, closure, &archive.ledger)?;
    claim_overlay(
        &mut overlay_claims,
        &archive.ledger.path,
        "archive-ledger-postimage",
    )?;
    apply_postimage(&mut expected, &archive.ledger)?;
    overlay_entries.push(postimage_digest_entry("archive-ledger", &archive.ledger)?);

    rename_expected_prefix(&mut expected, &active_prefix, &closure.archive_path)?;
    let entries = expected.into_values().collect::<Vec<_>>();
    validate_closure_entries(&entries)?;
    let expected_tree_digest = closure_tree_digest(&entries)?;
    let overlay_digest = digest::canonical_digest(
        "candidate-closure-overlays",
        CANDIDATE_CLOSURE_SCHEMA,
        overlay_entries,
    )
    .map_err(|error| error.to_string())?
    .to_hex();
    Ok(CandidateClosurePlan {
        schema: CANDIDATE_CLOSURE_SCHEMA,
        candidate_id: candidate.capture.subject.id.clone(),
        candidate_base_commit: candidate.capture.subject.base_commit.clone(),
        archive_path: closure.archive_path.clone(),
        archive_transaction_id: closure.transaction_id.to_hex(),
        overlay_digest,
        expected_tree_digest,
        entries,
    })
}

/// Materialize and compare an exact immutable Commit against a previously
/// built full-tree plan. This does not consult or update remote parity and
/// does not issue a Commit validation receipt.
pub fn verify_candidate_commit_equivalence(
    root: &Path,
    commit: &str,
    plan: &CandidateClosurePlan,
) -> Result<CandidateClosureEquivalence, String> {
    validate_candidate_closure_plan(plan)?;
    let subject = crate::local_validation::capture_subject(root, Some(commit))?;
    if subject.pushed_kind != "commit"
        || !subject.tag_chain.is_empty()
        || subject.commit != subject.pushed_oid
    {
        return Err("closure equivalence requires a direct immutable Commit subject".into());
    }
    let materialized = crate::local_validation::materialize_subject(root, &subject)?;
    let comparison = (|| {
        let observed = inventory_closure_tree(&materialized.root)?
            .into_values()
            .collect::<Vec<_>>();
        compare_candidate_closure_entries(plan, &subject.commit, &observed)
    })();
    match (comparison, materialized.cleanup()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(format!(
            "closure comparison completed but exact Commit cleanup failed: {cleanup}"
        )),
        (Err(error), Err(cleanup)) => Err(format!(
            "{error}; exact Commit cleanup also failed: {cleanup}"
        )),
    }
}

/// Persist a canonical Candidate closure plan in clone-private Git state.
/// The transaction ID is the only accepted filename and an existing unequal
/// plan blocks instead of being overwritten.
pub fn save_candidate_closure_plan(root: &Path, plan: &CandidateClosurePlan) -> Result<(), String> {
    validate_candidate_closure_plan(plan)?;
    let directory = candidate_closure_plan_directory(root, true)?;
    let path = directory.join(format!("{}.json", plan.archive_transaction_id));
    let mut bytes = serde_json::to_vec(plan).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if path.exists() {
        let existing = load_candidate_closure_plan(root, &plan.archive_transaction_id)?;
        return if existing == *plan {
            Ok(())
        } else {
            Err("a different Candidate closure plan already exists for this transaction".into())
        };
    }
    let temporary = directory.join(format!(
        ".{}.{}.tmp",
        plan.archive_transaction_id,
        std::process::id()
    ));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        use std::io::Write;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::rename(&temporary, &path).map_err(|error| error.to_string())?;
        std::fs::File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Load and canonicalize the clone-private plan for one archive transaction.
pub fn load_candidate_closure_plan(
    root: &Path,
    transaction_id: &str,
) -> Result<CandidateClosurePlan, String> {
    Digest::from_hex(transaction_id).map_err(|_| "Candidate closure transaction ID is invalid")?;
    let directory = candidate_closure_plan_directory(root, false)?;
    let path = directory.join(format!("{transaction_id}.json"));
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| "Candidate closure plan is missing")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 * 1024
    {
        return Err("Candidate closure plan is unsafe or oversized".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options.open(&path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    use std::io::Read;
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let plan: CandidateClosurePlan =
        serde_json::from_slice(&bytes).map_err(|_| "Candidate closure plan is malformed")?;
    validate_candidate_closure_plan(&plan)?;
    if plan.archive_transaction_id != transaction_id {
        return Err("Candidate closure plan transaction binding differs".into());
    }
    let mut canonical = serde_json::to_vec(&plan).map_err(|error| error.to_string())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("Candidate closure plan is not canonical".into());
    }
    Ok(plan)
}

fn candidate_closure_plan_directory(root: &Path, create: bool) -> Result<PathBuf, String> {
    let common = crate::local_validation::git_common_dir(root)?;
    let mpd = common.join("mpd");
    let directory = mpd.join("closure-plans");
    if create {
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mpd, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
    }
    for (path, label) in [
        (&mpd, "clone-private MPD directory"),
        (&directory, "Candidate closure plan directory"),
    ] {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| format!("{label} is unavailable"))?;
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
    }
    Ok(directory)
}

fn compare_candidate_closure_entries(
    plan: &CandidateClosurePlan,
    commit_oid: &str,
    observed: &[ClosureTreeEntry],
) -> Result<CandidateClosureEquivalence, String> {
    let observed_tree_digest = closure_tree_digest(observed)?;
    let mut expected_by_path = plan
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut observed_by_path = observed
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut paths = expected_by_path
        .keys()
        .chain(observed_by_path.keys())
        .copied()
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    let mut blockers = Vec::new();
    for path in paths {
        match (expected_by_path.remove(path), observed_by_path.remove(path)) {
            (Some(_), None) => blockers.push(format!("missing path {path:?}")),
            (None, Some(_)) => blockers.push(format!("extra path {path:?}")),
            (Some(expected), Some(observed)) => {
                if expected.mode != observed.mode {
                    blockers.push(format!(
                        "mode mismatch at {path:?}: expected {:o}, observed {:o}",
                        expected.mode, observed.mode
                    ));
                }
                if expected.byte_len != observed.byte_len || expected.sha256 != observed.sha256 {
                    blockers.push(format!("content digest mismatch at {path:?}"));
                }
            }
            (None, None) => unreachable!(),
        }
    }
    blockers.sort();
    Ok(CandidateClosureEquivalence {
        equivalent: blockers.is_empty() && observed_tree_digest == plan.expected_tree_digest,
        candidate_id: plan.candidate_id.clone(),
        commit_oid: commit_oid.to_string(),
        expected_tree_digest: plan.expected_tree_digest.clone(),
        observed_tree_digest,
        blockers,
    })
}

fn validate_candidate_closure_binding(
    candidate_root: &Path,
    candidate: &crate::candidate::CandidateProjection,
    closure: &ArchiveClosure,
) -> Result<(), String> {
    let subject = &candidate.capture.subject;
    for (label, value) in [
        ("candidate ID", subject.id.as_str()),
        (
            "candidate manifest digest",
            subject.manifest_digest.as_str(),
        ),
        ("candidate entries digest", subject.entries_digest.as_str()),
        ("candidate policy digest", subject.policy_digest.as_str()),
        ("candidate source digest", subject.source_digest.as_str()),
    ] {
        Digest::from_hex(value)
            .map_err(|_| format!("{label} is not a canonical SHA-256 digest"))?;
    }
    if subject.base_commit != closure.base_commit {
        return Err("archive base Commit differs from the Candidate base Commit".into());
    }
    if candidate_root.to_str() != Some(candidate.capture.clone_private_root.as_str()) {
        return Err("candidate closure root does not match its compact binding".into());
    }
    let metadata = std::fs::symlink_metadata(candidate_root)
        .map_err(|error| format!("candidate closure root is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("candidate closure root is not a no-follow directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.dev() != candidate.capture.storage.root_device
            || metadata.ino() != candidate.capture.storage.root_inode
        {
            return Err("candidate closure root changed filesystem identity".into());
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("candidate closure root is not owner-only".into());
        }
    }
    Ok(())
}

fn validate_archive_path(change: &str, active: &str, archive: &str) -> Result<(), String> {
    digest::validate_canonical_path(archive).map_err(|error| error.to_string())?;
    if archive == active
        || !archive.starts_with("openspec/changes/archive/")
        || !archive.ends_with(&format!("-{change}"))
    {
        return Err("archive path is not the canonical dated change destination".into());
    }
    Ok(())
}

fn claim_overlay(
    claims: &mut BTreeMap<String, String>,
    path: &str,
    kind: &str,
) -> Result<(), String> {
    digest::validate_canonical_path(path).map_err(|error| error.to_string())?;
    if let Some(first) = claims.insert(path.to_string(), kind.to_string()) {
        return Err(format!(
            "closure overlay path {path:?} is claimed by both {first} and {kind}"
        ));
    }
    Ok(())
}

fn postimage_entry(file: &ClosureFilePostimage) -> Result<ClosureTreeEntry, String> {
    digest::validate_canonical_path(&file.path).map_err(|error| error.to_string())?;
    if !matches!(file.mode, 0o100644 | 0o100755) {
        return Err(format!(
            "closure postimage {:?} has unsupported Git mode {:o}",
            file.path, file.mode
        ));
    }
    if file.bytes.len() as u64 > MAX_CLOSURE_FILE_BYTES {
        return Err(format!(
            "closure postimage {:?} exceeds its file-size cap",
            file.path
        ));
    }
    Ok(ClosureTreeEntry {
        path: file.path.clone(),
        mode: file.mode,
        byte_len: file.bytes.len() as u64,
        sha256: Digest::of_bytes(&file.bytes).to_hex(),
    })
}

fn postimage_digest_entry(
    label: &str,
    file: &ClosureFilePostimage,
) -> Result<digest::Entry, String> {
    let entry = postimage_entry(file)?;
    digest::Entry::file(
        label.to_string(),
        entry.mode,
        entry.byte_len,
        Digest::from_hex(&entry.sha256)?,
    )
    .map_err(|error| error.to_string())
}

fn apply_postimage(
    tree: &mut BTreeMap<String, ClosureTreeEntry>,
    file: &ClosureFilePostimage,
) -> Result<(), String> {
    let entry = postimage_entry(file)?;
    tree.insert(entry.path.clone(), entry);
    Ok(())
}

fn validate_documentation_postimage(
    manifest: &ChangeManifest,
    active_prefix: &str,
    archive_prefix: &str,
    document: &ClosureFilePostimage,
) -> Result<(), String> {
    if document.mode != 0o100644
        || path_is_within(active_prefix, &document.path)
        || path_is_within(archive_prefix, &document.path)
        || mutable_closure_process_path(&document.path)
        || !manifest
            .paths
            .iter()
            .chain(manifest.shared_paths.iter())
            .any(|pattern| glob_match(pattern, &document.path))
    {
        return Err(format!(
            "reviewed documentation postimage {:?} is not a regular declared durable-doc path",
            document.path
        ));
    }
    Ok(())
}

fn validate_spec_postimage(spec: &ClosureFilePostimage) -> Result<(), String> {
    let suffix = spec
        .path
        .strip_prefix("openspec/specs/")
        .and_then(|path| path.strip_suffix("/spec.md"));
    if spec.mode != 0o100644
        || suffix.is_none_or(|capability| {
            capability.is_empty()
                || capability.contains('/')
                || validate_change_name(capability).is_err()
        })
    {
        return Err(format!(
            "archive spec postimage {:?} is not a canonical regular capability spec",
            spec.path
        ));
    }
    Ok(())
}

fn validate_archive_ledger_postimage(
    candidate: &crate::candidate::CandidateProjection,
    closure: &ArchiveClosure,
    ledger: &ClosureFilePostimage,
) -> Result<(), String> {
    let expected_path = format!(".mpd/state/{}.json", candidate.capture.subject.change);
    if ledger.path != expected_path || ledger.mode != 0o100644 {
        return Err(
            "archive ledger postimage does not name the exact regular change ledger".into(),
        );
    }
    if ledger.bytes.len() as u64 > MAX_CLOSURE_FILE_BYTES {
        return Err("archive ledger postimage exceeds its file-size cap".into());
    }
    let parsed: crate::ledger::Ledger = serde_json::from_slice(&ledger.bytes)
        .map_err(|_| "archive ledger postimage is malformed")?;
    if parsed.change != candidate.capture.subject.change
        || parsed.archive_closure.as_ref() != Some(closure)
        || parsed
            .gates
            .get(&Phase::Build)
            .and_then(|record| record.candidate.as_ref())
            != Some(&candidate.capture)
    {
        return Err(
            "archive ledger postimage does not bind the exact Candidate and archive closure".into(),
        );
    }
    Ok(())
}

fn mutable_closure_process_path(path: &str) -> bool {
    path == ".mpd/current"
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
        || path.starts_with(".git/")
}

fn rename_expected_prefix(
    tree: &mut BTreeMap<String, ClosureTreeEntry>,
    source: &str,
    destination: &str,
) -> Result<(), String> {
    if tree.keys().any(|path| path_is_within(destination, path)) {
        return Err("archive destination already exists in the Candidate tree".into());
    }
    let source_paths = tree
        .keys()
        .filter(|path| path_is_within(source, path))
        .cloned()
        .collect::<Vec<_>>();
    if source_paths.is_empty() {
        return Err("Candidate tree has no active change directory to archive".into());
    }
    for source_path in source_paths {
        let mut entry = tree
            .remove(&source_path)
            .expect("source path was collected from the same map");
        let suffix = source_path
            .strip_prefix(source)
            .expect("source prefix was checked");
        entry.path = format!("{destination}{suffix}");
        if tree.insert(entry.path.clone(), entry).is_some() {
            return Err("archive rename produced a path collision".into());
        }
    }
    Ok(())
}

fn verify_candidate_scope_entries(
    tree: &BTreeMap<String, ClosureTreeEntry>,
    entries: &[crate::candidate::CandidateEntry],
) -> Result<(), String> {
    let mut previous: Option<&[u8]> = None;
    for candidate in entries {
        if previous.is_some_and(|prior| prior >= candidate.path_bytes.as_slice()) {
            return Err("candidate scope inventory is not strictly path-sorted".into());
        }
        previous = Some(&candidate.path_bytes);
        let path = std::str::from_utf8(&candidate.path_bytes)
            .map_err(|_| "candidate closure path is not UTF-8")?;
        match candidate.state {
            crate::candidate::CandidatePathState::Deleted => {
                if tree.contains_key(path) {
                    return Err(format!(
                        "retained Candidate tree still contains deleted path {path:?}"
                    ));
                }
            }
            crate::candidate::CandidatePathState::Present => {
                let observed = tree
                    .get(path)
                    .ok_or_else(|| format!("retained Candidate tree is missing {path:?}"))?;
                let mode = match candidate.mode {
                    Some(crate::candidate::CandidateMode::Regular) => 0o100644,
                    Some(crate::candidate::CandidateMode::Executable) => 0o100755,
                    None => return Err("present Candidate entry has no mode".into()),
                };
                if observed.mode != mode
                    || observed.byte_len != candidate.byte_len
                    || candidate.sha256.as_deref() != Some(observed.sha256.as_str())
                {
                    return Err(format!(
                        "retained Candidate tree differs from scoped entry {path:?}"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn inventory_closure_tree(root: &Path) -> Result<BTreeMap<String, ClosureTreeEntry>, String> {
    let mut entries = BTreeMap::new();
    let mut remaining_entries = MAX_CLOSURE_TREE_ENTRIES;
    let mut remaining_bytes = MAX_CLOSURE_TREE_BYTES;
    inventory_closure_directory(
        root,
        root,
        &mut entries,
        &mut remaining_entries,
        &mut remaining_bytes,
    )?;
    Ok(entries)
}

fn inventory_closure_directory(
    root: &Path,
    directory: &Path,
    entries: &mut BTreeMap<String, ClosureTreeEntry>,
    remaining_entries: &mut usize,
    remaining_bytes: &mut u64,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot inspect closure directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("closure inventory encountered a non-directory root".into());
    }
    let mut children = std::fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate closure directory: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate closure entry: {error}"))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if *remaining_entries == 0 {
            return Err("closure tree exceeds its entry cap".into());
        }
        *remaining_entries -= 1;
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "closure inventory escaped its root")?
            .to_str()
            .ok_or("closure path is not UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        digest::validate_canonical_path(&relative).map_err(|error| error.to_string())?;
        let before = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect closure entry: {error}"))?;
        if before.file_type().is_symlink() {
            return Err(format!("closure tree contains symlink {relative:?}"));
        }
        if before.is_dir() {
            inventory_closure_directory(root, &path, entries, remaining_entries, remaining_bytes)?;
            continue;
        }
        if !before.is_file() || before.len() > MAX_CLOSURE_FILE_BYTES {
            return Err(format!(
                "closure tree contains unsupported or oversized file {relative:?}"
            ));
        }
        *remaining_bytes = remaining_bytes
            .checked_sub(before.len())
            .ok_or("closure tree exceeds its aggregate byte cap")?;
        let content = digest::hash_file_non_following(&path).map_err(|error| error.to_string())?;
        let after = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot restat closure entry: {error}"))?;
        if !after.is_file() || after.len() != before.len() || content.length != before.len() {
            return Err(format!("closure file drifted while hashing {relative:?}"));
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
            {
                return Err(format!("closure file changed identity at {relative:?}"));
            }
            if after.permissions().mode() & 0o111 != 0 {
                0o100755
            } else {
                0o100644
            }
        };
        #[cfg(not(unix))]
        let mode = 0o100644;
        let entry = ClosureTreeEntry {
            path: relative.clone(),
            mode,
            byte_len: content.length,
            sha256: content.digest.to_hex(),
        };
        if entries.insert(relative, entry).is_some() {
            return Err("closure tree contains a duplicate canonical path".into());
        }
    }
    Ok(())
}

fn closure_tree_digest(entries: &[ClosureTreeEntry]) -> Result<String, String> {
    let mut canonical = Vec::with_capacity(entries.len());
    for entry in entries {
        canonical.push(
            digest::Entry::file(
                entry.path.clone(),
                entry.mode,
                entry.byte_len,
                Digest::from_hex(&entry.sha256)?,
            )
            .map_err(|error| error.to_string())?,
        );
    }
    Ok(digest::canonical_digest(
        "candidate-closure-tree",
        CANDIDATE_CLOSURE_SCHEMA,
        canonical,
    )
    .map_err(|error| error.to_string())?
    .to_hex())
}

fn validate_closure_entries(entries: &[ClosureTreeEntry]) -> Result<(), String> {
    if entries.len() > MAX_CLOSURE_TREE_ENTRIES {
        return Err("candidate closure plan exceeds its entry cap".into());
    }
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    for entry in entries {
        digest::validate_canonical_path(&entry.path).map_err(|error| error.to_string())?;
        if previous.is_some_and(|path| path.as_bytes() >= entry.path.as_bytes()) {
            return Err("candidate closure plan is not strictly path-sorted".into());
        }
        previous = Some(&entry.path);
        if !matches!(entry.mode, 0o100644 | 0o100755)
            || entry.byte_len > MAX_CLOSURE_FILE_BYTES
            || Digest::from_hex(&entry.sha256).is_err()
        {
            return Err(format!(
                "candidate closure entry {:?} is malformed",
                entry.path
            ));
        }
        total = total
            .checked_add(entry.byte_len)
            .ok_or("candidate closure byte count overflow")?;
        if total > MAX_CLOSURE_TREE_BYTES {
            return Err("candidate closure plan exceeds its aggregate byte cap".into());
        }
    }
    Ok(())
}

fn validate_candidate_closure_plan(plan: &CandidateClosurePlan) -> Result<(), String> {
    if plan.schema != CANDIDATE_CLOSURE_SCHEMA {
        return Err("unsupported candidate closure plan schema".into());
    }
    Digest::from_hex(&plan.candidate_id)
        .map_err(|_| "candidate closure plan has an invalid Candidate ID")?;
    Digest::from_hex(&plan.archive_transaction_id)
        .map_err(|_| "candidate closure plan has an invalid transaction ID")?;
    Digest::from_hex(&plan.overlay_digest)
        .map_err(|_| "candidate closure plan has an invalid overlay digest")?;
    Digest::from_hex(&plan.expected_tree_digest)
        .map_err(|_| "candidate closure plan has an invalid tree digest")?;
    if !git::valid_oid_hex(&plan.candidate_base_commit) {
        return Err("candidate closure plan has an invalid base Commit".into());
    }
    digest::validate_canonical_path(&plan.archive_path).map_err(|error| error.to_string())?;
    validate_closure_entries(&plan.entries)?;
    if closure_tree_digest(&plan.entries)? != plan.expected_tree_digest {
        return Err("candidate closure plan tree digest is stale".into());
    }
    Ok(())
}

// =====================================================================
// Change manifest
// =====================================================================

/// The optional remote-publication target a manifest may declare.
/// `reference` is serialized as `ref` (a Rust keyword, hence the rename).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishTarget {
    /// A manifest *token* naming a remote — resolved against the exact set
    /// of currently *configured* remote names by a later stage before any
    /// network use (see `crate::git::configured_remote_names`); never
    /// trusted as a URL or path (security-plan.md HIGH finding).
    pub remote: String,
    /// The fully-qualified branch ref to verify parity against. `refs/
    /// heads/*` only — v1 never resolves an annotated tag.
    #[serde(rename = "ref")]
    pub reference: String,
}

/// `openspec/changes/<name>/manifest.json`: the versioned, declared scope of
/// one change, plus its optional publication target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeManifest {
    /// Schema version (see [`MANIFEST_SCHEMA`]).
    pub version: u32,
    /// Repository-relative `*`/`**` scope patterns this change declares as
    /// its own (see [`crate::pathmatch::glob_match`]). Required (non-empty)
    /// before Architecture PASS — see design.md "Durable schemas"; `mpd
    /// manifest init` seeds this empty rather than guessing it.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Additional patterns this change may touch without claiming exclusive
    /// ownership (e.g. a shared `README.md`).
    #[serde(default)]
    pub shared_paths: Vec<String>,
    /// The optional remote/ref this change intends to publish to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<PublishTarget>,
}

/// One problem found by [`ChangeManifest::validate`]. Every variant fails
/// closed — manifest checks never silently coerce, drop, or widen scope
/// (design.md Conditions for Builder #5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestIssue {
    /// `version` is not a schema this build understands.
    UnknownVersion(u32),
    /// `paths` is empty — no scope is declared yet.
    NoDeclaredScope,
    /// `paths` + `shared_paths` together exceed [`MAX_MANIFEST_PATTERNS`].
    TooManyPatterns(usize),
    /// A pattern in `field` is not a safe canonical relative path (see
    /// [`crate::digest::validate_canonical_path`]): absolute, `.`/`..`, a
    /// NUL/backslash/control character, or an empty component.
    UnsafePathPattern {
        field: &'static str,
        pattern: String,
    },
    /// `publish.remote` is not even a syntactically safe remote-name token
    /// (this is a *syntax* check only — resolving it against configured
    /// remote names is a later stage's job, not this one's).
    UnsafeRemoteName(String),
    /// `publish.ref` is not a safe, well-formed `refs/heads/*` reference.
    UnsafeRef(String),
}

impl fmt::Display for ManifestIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestIssue::UnknownVersion(v) => write!(f, "unknown manifest version {v}"),
            ManifestIssue::NoDeclaredScope => write!(f, "no declared scope (paths is empty)"),
            ManifestIssue::TooManyPatterns(n) => {
                write!(
                    f,
                    "{n} scope patterns exceeds the {MAX_MANIFEST_PATTERNS} limit"
                )
            }
            ManifestIssue::UnsafePathPattern { field, pattern } => {
                write!(f, "unsafe {field} pattern: {pattern:?}")
            }
            ManifestIssue::UnsafeRemoteName(r) => write!(f, "unsafe publish.remote: {r:?}"),
            ManifestIssue::UnsafeRef(r) => write!(f, "unsafe publish.ref: {r:?}"),
        }
    }
}

impl std::error::Error for ManifestIssue {}

impl ChangeManifest {
    /// The manifest `mpd manifest` seeds: current schema, `paths`
    /// deliberately empty (declaring scope is a human act — design.md "no
    /// automatic scope guess is accepted"), no publish target.
    pub fn seed() -> ChangeManifest {
        ChangeManifest {
            version: MANIFEST_SCHEMA,
            paths: Vec::new(),
            shared_paths: Vec::new(),
            publish: None,
        }
    }

    /// The exact pretty-JSON text `mpd manifest` writes (trailing
    /// newline, matching every other durable JSON file `mpd` writes).
    pub fn seed_json() -> String {
        let mut json =
            serde_json::to_string_pretty(&Self::seed()).expect("seed manifest always serializes");
        json.push('\n');
        json
    }

    /// Every problem with this manifest (empty ⇒ safe to use as scope).
    /// Independent, exhaustive checks — every issue is reported, not just
    /// the first.
    pub fn validate(&self) -> Vec<ManifestIssue> {
        let mut issues = Vec::new();
        if self.version != MANIFEST_SCHEMA {
            issues.push(ManifestIssue::UnknownVersion(self.version));
        }
        if self.paths.is_empty() {
            issues.push(ManifestIssue::NoDeclaredScope);
        }
        let total = self.paths.len() + self.shared_paths.len();
        if total > MAX_MANIFEST_PATTERNS {
            issues.push(ManifestIssue::TooManyPatterns(total));
        }
        for pattern in &self.paths {
            if digest::validate_canonical_path(pattern).is_err() {
                issues.push(ManifestIssue::UnsafePathPattern {
                    field: "paths",
                    pattern: pattern.clone(),
                });
            }
        }
        for pattern in &self.shared_paths {
            if digest::validate_canonical_path(pattern).is_err() {
                issues.push(ManifestIssue::UnsafePathPattern {
                    field: "shared_paths",
                    pattern: pattern.clone(),
                });
            }
        }
        if let Some(publish) = &self.publish {
            if !git::valid_remote_name(&publish.remote) {
                issues.push(ManifestIssue::UnsafeRemoteName(publish.remote.clone()));
            }
            if !git::valid_branch_ref(&publish.reference) {
                issues.push(ManifestIssue::UnsafeRef(publish.reference.clone()));
            }
        }
        issues
    }

    /// Whether this manifest is safe and has a declared scope — the
    /// gate for using it as `Scope` dependency content. Not yet called by a
    /// production site (evidence-lifecycle `Scope` dependency-snapshot
    /// wiring is a separate, later integration point than remote parity/
    /// commit coherence); kept as the documented boolean gate `DependencyKey
    /// ::Scope` binding is specified to use, exercised directly by this
    /// module's own tests in the meantime.
    #[allow(dead_code)]
    pub fn is_ready(&self) -> bool {
        self.validate().is_empty()
    }

    /// Whether concrete repository-relative `path` (not a pattern) falls
    /// within this manifest's declared scope, its shared-paths allowlist, or
    /// the caller-supplied [`SystemScope`]. Used to classify a changed path
    /// as in/out of scope — never to broaden scope itself.
    pub fn covers(&self, path: &str, system: &SystemScope) -> bool {
        self.paths.iter().any(|p| glob_match(p, path))
            || self.shared_paths.iter().any(|p| glob_match(p, path))
            || system.paths().iter().any(|s| path_is_within(s, path))
    }
}

/// Whether `candidate` is exactly `scope_path` or nested under it (a
/// directory-prefix match on a `/`-boundary, never a bare string-prefix
/// match — `"a/b-evil"` must not be considered within `"a/b"`).
fn path_is_within(scope_path: &str, candidate: &str) -> bool {
    candidate == scope_path || candidate.starts_with(&format!("{scope_path}/"))
}

/// Whether concrete repository-relative `path` falls within one of the given
/// concrete (never glob) scope paths, either as an exact match or nested
/// under it. This is deliberately narrower than [`ChangeManifest::covers`] —
/// no `*`/`**` pattern is consulted — for classifying staged paths against a
/// [`ArchiveClosure::system_paths`] pending-closure scope, where the closure's
/// own realized footprint (not the possibly-wildcard declared manifest) is
/// the sole authority once `.mpd/pending-closure` exists.
pub fn covers_concrete_paths(scope_paths: &[String], path: &str) -> bool {
    scope_paths.iter().any(|s| path_is_within(s, path))
}

/// `<root>/openspec/changes/<change>/manifest.json`.
pub fn manifest_path(root: &Path, change: &str) -> Result<PathBuf, String> {
    validate_change_name(change).map_err(|e| e.to_string())?;
    Ok(root
        .join("openspec")
        .join("changes")
        .join(change)
        .join("manifest.json"))
}

/// Any failure loading a manifest. Deliberately distinguishes "not created
/// yet" ([`ManifestLoadError::NotFound`] — `manifest: incomplete`, not a
/// blocker on its own) from a real fail-closed problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestLoadError {
    /// `change` itself is not a safe change name.
    InvalidChangeName(String),
    /// No `manifest.json` exists for this change yet.
    NotFound,
    /// The path is unsafe (symlinked, oversized, or escapes the changes
    /// directory) — refused without reading through it.
    Unsafe(String),
    /// The file exists and is safe to read, but is not valid manifest JSON.
    Malformed(String),
}

impl fmt::Display for ManifestLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestLoadError::InvalidChangeName(e) => write!(f, "invalid change name: {e}"),
            ManifestLoadError::NotFound => write!(f, "no manifest.json for this change"),
            ManifestLoadError::Unsafe(e) => write!(f, "unsafe manifest path: {e}"),
            ManifestLoadError::Malformed(e) => write!(f, "malformed manifest.json: {e}"),
        }
    }
}

impl std::error::Error for ManifestLoadError {}

/// Load and parse a change's `manifest.json`. Symlink-refusing and
/// size-capped ([`openspec_core::read_capped`]); containment is checked
/// against `<root>/openspec/changes` ([`openspec_core::assert_contained`])
/// so a symlinked intermediate directory cannot redirect the read outside
/// the project. This performs no [`ChangeManifest::validate`] — callers
/// decide whether to treat a syntactically-parseable-but-unsafe manifest as
/// blocked.
pub fn load_manifest(root: &Path, change: &str) -> Result<ChangeManifest, ManifestLoadError> {
    let path = manifest_path(root, change).map_err(ManifestLoadError::InvalidChangeName)?;
    if !path.exists() {
        return Err(ManifestLoadError::NotFound);
    }
    let changes_dir = root.join("openspec").join("changes");
    assert_contained(&changes_dir, &path).map_err(|e| ManifestLoadError::Unsafe(e.to_string()))?;
    let text = read_capped(&path).map_err(|e| ManifestLoadError::Unsafe(e.to_string()))?;
    serde_json::from_str(&text).map_err(|e| ManifestLoadError::Malformed(e.to_string()))
}

/// Persist a change's `manifest.json` as pretty JSON with a trailing
/// newline. Containment is re-checked immediately before creating the parent
/// directory and again immediately before the write (mirrors
/// `crate::config::Config::save`'s TOCTOU-aware pattern), so a symlink
/// planted between checks cannot redirect the write outside the project.
pub fn save_manifest(root: &Path, change: &str, manifest: &ChangeManifest) -> io::Result<()> {
    let path = manifest_path(root, change).map_err(io::Error::other)?;
    let changes_dir = root.join("openspec").join("changes");
    let mut json = serde_json::to_string_pretty(manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    json.push('\n');
    openspec_core::atomic_write_contained(&changes_dir, &path, json.as_bytes())
        .map_err(io::Error::other)
}

// =====================================================================
// System scope
// =====================================================================

/// The bounded, code-owned set of MPD-system paths that are always in a
/// change's scope regardless of what the manifest declares — "displayed,
/// not broadened" (design.md "Git manifest semantics"). Every field is
/// supplied by the caller: deriving them from a real `Project` +
/// `ArchivePlan` (the active change directory, its ledger, merged spec
/// targets, the configured durable-doc target, and the dated archive
/// target) is a `cli.rs` integration-stage responsibility. This type's job
/// is purely to fold the caller-supplied, already-bounded list into scope
/// checks and the `scope` dependency digest — it never invents or widens
/// this set on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemScope {
    /// The active change directory, e.g.
    /// `openspec/changes/content-addressed-release-closure`.
    pub change_dir: String,
    /// The change's gate ledger, e.g.
    /// `.mpd/state/content-addressed-release-closure.json`.
    pub ledger_path: String,
    /// Merged spec targets `ArchivePlan` will write (`openspec/specs/<cap>/
    /// spec.md` for each capability this change touches).
    pub merged_spec_targets: Vec<String>,
    /// The configured durable-documentation target, when this change
    /// documents (`Documentation` phase applicable).
    pub doc_target: Option<String>,
    /// The dated archive destination directory `ArchivePlan` computed.
    pub archive_target: String,
}

impl SystemScope {
    /// Every system-owned path, deduplicated and in a fixed sorted order —
    /// so a target that happens to coincide with another (e.g. no doc target
    /// configured) is never counted or hashed twice, and the digest domain
    /// is order-independent by construction.
    pub fn paths(&self) -> Vec<String> {
        let mut out = vec![self.change_dir.clone(), self.ledger_path.clone()];
        out.extend(self.merged_spec_targets.iter().cloned());
        if let Some(doc) = &self.doc_target {
            out.push(doc.clone());
        }
        out.push(self.archive_target.clone());
        out.sort();
        out.dedup();
        out
    }
}

// =====================================================================
// Dependency values, hermetic completeness, snapshot construction
// =====================================================================

/// A computed content digest for each dependency key the caller currently
/// has content for. Building a snapshot only ever pulls the keys a phase's
/// policy allowlists ([`DependencyPolicy::for_phase`]) — keys outside that
/// allowlist are never consulted, so populating extra keys here is harmless.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyValues(BTreeMap<DependencyKey, Digest>);

impl DependencyValues {
    /// An empty set of computed values.
    pub fn new() -> DependencyValues {
        DependencyValues(BTreeMap::new())
    }

    /// Record `key`'s currently computed digest (builder style).
    pub fn with(mut self, key: DependencyKey, value: Digest) -> DependencyValues {
        self.0.insert(key, value);
        self
    }

    /// Record `key`'s currently computed digest in place.
    pub fn set(&mut self, key: DependencyKey, value: Digest) {
        self.0.insert(key, value);
    }

    /// `key`'s currently computed digest, if the caller has one.
    pub fn get(&self, key: DependencyKey) -> Option<Digest> {
        self.0.get(&key).copied().or_else(|| match key {
            // Test fixtures and v1 callers may still provide the old aggregate
            // key. Schema-v2 receipts are emitted with the split keys, but this
            // compatibility fallback keeps those inputs readable rather than
            // reclassifying them as a different contract.
            DependencyKey::DesignMockArtifact | DependencyKey::ArchitecturePlan => {
                self.0.get(&DependencyKey::DesignArtifacts).copied()
            }
            _ => None,
        })
    }
}

/// The closed set of dependency keys that are *hermetic-only*: never
/// mandatory for a plain (always-execute) receipt, but every one of which
/// must be bound for that receipt to become hermetic-reuse-eligible.
pub const HERMETIC_KEYS: [DependencyKey; 4] = [
    DependencyKey::HermeticPlatform,
    DependencyKey::HermeticExecutable,
    DependencyKey::HermeticEnvironment,
    DependencyKey::HermeticInput,
];

fn is_hermetic_key(key: DependencyKey) -> bool {
    HERMETIC_KEYS.contains(&key)
}

/// Whether `snapshot` binds every one of [`HERMETIC_KEYS`] — the "missing/
/// unreadable/undeclared dependencies make the receipt non-reusable" rule
/// from security-plan.md, decided purely from what the snapshot actually
/// contains (never from whether a project *declares* a hermetic policy —
/// that's a separate, syntactic check, see [`HermeticReusePolicy::validate`]).
pub fn hermetic_complete(snapshot: &DependencySnapshot) -> bool {
    HERMETIC_KEYS
        .iter()
        .all(|k| snapshot.values.contains_key(k))
}

/// Whether `phase` is one of the three phases design.md defaults to
/// `always_execute` and permits hermetic reuse for (Build, Test,
/// Security code). Deploy is also always-execute but is handled separately
/// (fixed, never reusable under any policy) — see [`reuse_offer`].
pub fn execution_bearing(phase: Phase) -> bool {
    matches!(phase, Phase::Build | Phase::Test | Phase::SecurityCode)
}

/// A policy's allowlisted key had no value in the supplied
/// [`DependencyValues`] and is not hermetic-optional — the snapshot cannot
/// be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingDependency(pub DependencyKey);

impl fmt::Display for MissingDependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing required dependency value: {}", self.0)
    }
}

impl std::error::Error for MissingDependency {}

impl DependencySnapshot {
    /// Build a phase's dependency snapshot: for every key
    /// [`DependencyPolicy::for_phase`] allowlists, include it if `values`
    /// has a computed digest. A missing *non-hermetic* key is an error (the
    /// phase cannot be snapshotted without it); a missing hermetic key is
    /// simply omitted (no project hermetic opt-in is configured — the
    /// receipt will default to always-execute, see [`reuse_offer`]).
    pub fn for_phase(
        phase: Phase,
        values: &DependencyValues,
    ) -> Result<DependencySnapshot, MissingDependency> {
        let mut map = BTreeMap::new();
        for &key in DependencyPolicy::for_phase(phase) {
            match values.get(key) {
                Some(d) => {
                    map.insert(key, d);
                }
                None if is_hermetic_key(key) => {}
                None => return Err(MissingDependency(key)),
            }
        }
        Ok(DependencySnapshot {
            schema: RECEIPT_SCHEMA,
            values: map,
        })
    }
}

// =====================================================================
// DependencyPolicy — the sole phase-causal dependency allowlist
// =====================================================================

/// The sole allowlist of which [`DependencyKey`]s a phase's receipt may
/// bind. This is the *only* place phase → dependency-key membership is
/// decided (design.md "Dependency and invalidation rules"); every table row
/// is pinned by `golden_dependency_policy_table` and every key's
/// phase-causality is mechanically checked by
/// `no_policy_binds_an_output_first_created_by_a_later_phase` below.
pub struct DependencyPolicy;

impl DependencyPolicy {
    /// The dependency keys a receipt for `phase` may bind.
    pub fn for_phase(phase: Phase) -> &'static [DependencyKey] {
        use DependencyKey::*;
        match phase {
            Phase::DesignMock => &[Scope, DesignMockArtifact, Governance],
            // Risk-relevant config is represented by the versioned assessment
            // folded into Governance below. Binding the whole Config object
            // here would make unrelated persona tuning retroactively stale
            // Architecture instead of the phase whose instructions changed.
            Phase::Architecture => &[Scope, ArchitecturePlan, Governance],
            Phase::DesignReview | Phase::DesignSignoff => {
                &[Scope, DesignMockArtifact, ArchitecturePlan, Governance]
            }
            // Source drift begins a fresh implementation at Build; it does not
            // retroactively invalidate the already-approved plan review.
            Phase::SecurityPlan => &[Scope, ArchitecturePlan, Governance, PersonaTuning],
            // Build binds source, test command, toolchain, and produced artifact
            // digests; it may additionally bind the hermetic keys under an
            // explicit project opt-in. (Build is not in the governed persona-tuning
            // set — its output is re-verified by the bound Security-code + Test.)
            Phase::Build => &[
                Scope,
                Source,
                TestCommand,
                Toolchain,
                ProducedArtifact,
                HermeticPlatform,
                HermeticExecutable,
                HermeticEnvironment,
                HermeticInput,
            ],
            // Test shares Build's shape plus the persona's effective directive
            // (persona-tuning): a Tester directive change stales a Test receipt.
            Phase::Test => &[
                Scope,
                Source,
                TestCommand,
                Toolchain,
                ProducedArtifact,
                PersonaTuning,
                HermeticPlatform,
                HermeticExecutable,
                HermeticEnvironment,
                HermeticInput,
            ],
            // Security (code) binds Security's set plus scanner identities
            // and the allowlist digest, the persona directive, and is also
            // hermetic-eligible.
            Phase::SecurityCode => &[
                Scope,
                ArchitecturePlan,
                Governance,
                Source,
                ScannerIdentity,
                AllowlistDigest,
                PersonaTuning,
                HermeticPlatform,
                HermeticExecutable,
                HermeticEnvironment,
                HermeticInput,
            ],
            // Documentation binds shipped-behavior inputs and the doc itself.
            Phase::Documentation => &[Scope, ShippedBehavior, Documentation],
            // Deploy binds source/build artifacts and the deploy command; it
            // is fixed always-execute and never reusable (see reuse_offer).
            Phase::Deploy => &[Scope, Source, ProducedArtifact, DeployCommand],
            // Doc Validation binds the artifacts Documentation produced plus the
            // (composite) persona's effective directive (persona-tuning).
            Phase::DocValidation => &[Scope, ShippedBehavior, Documentation, PersonaTuning],
            Phase::Done => &[],
        }
    }
}

// =====================================================================
// Evidence validity — independent of reuse eligibility
// =====================================================================

/// Why a piece of evidence is [`EvidenceValidity::Stale`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleReason {
    /// The receipt (or its dependency snapshot) was recorded under a schema
    /// this build no longer treats as current.
    SchemaChanged { recorded: u32, current: u32 },
    /// The content bound to `key` differs from what's currently computed (or
    /// can no longer be proven identical).
    DependencyChanged(DependencyKey),
}

impl fmt::Display for StaleReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StaleReason::SchemaChanged { recorded, current } => {
                write!(f, "schema changed (recorded {recorded}, current {current})")
            }
            StaleReason::DependencyChanged(key) => write!(f, "{key} changed"),
        }
    }
}

/// The content-bound validity of a piece of gate evidence — computed
/// entirely independently of reuse eligibility (evidence-reuse/spec.md
/// "Content validity and reuse eligibility SHALL be separate fields").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceValidity {
    /// No receipt exists at all (never-recorded, or a legacy pre-receipt
    /// gate record) — never treated as valid.
    Absent,
    /// A receipt exists but at least one bound dependency (or the schema
    /// itself) no longer matches. `reasons` names every differing class.
    Stale(Vec<StaleReason>),
    /// The receipt's complete recorded snapshot matches current content
    /// exactly.
    Valid,
}

impl EvidenceValidity {
    /// A short, stable status word for text/JSON rendering.
    pub fn label(&self) -> &'static str {
        match self {
            EvidenceValidity::Absent => "absent",
            EvidenceValidity::Stale(_) => "stale",
            EvidenceValidity::Valid => "valid",
        }
    }
}

/// Compute a receipt's content-bound validity against `current` (this
/// phase's freshly computed dependency values). Recomputes
/// [`DependencyPolicy::for_phase`]`(receipt.phase)` and compares every
/// allowlisted key: a legacy gate with no receipt is `Absent`; any schema or
/// per-key mismatch is `Stale` (every differing key named); exact equality
/// on every key is `Valid`. A hermetic key absent in both the receipt and
/// `current` is not itself a mismatch (no opt-in either then or now); one
/// that only *current* now has is not retroactively stale (the receipt
/// simply lacks it — see [`hermetic_complete`] for what that means for
/// reuse); losing a previously-bound hermetic value, or any value actually
/// differing, is stale (fail closed).
pub fn evidence_validity(
    receipt: Option<&EvidenceReceipt>,
    current: &DependencyValues,
) -> EvidenceValidity {
    let Some(receipt) = receipt else {
        return EvidenceValidity::Absent;
    };
    let mut reasons = Vec::new();
    if receipt.schema != RECEIPT_SCHEMA || receipt.dependencies.schema != RECEIPT_SCHEMA {
        reasons.push(StaleReason::SchemaChanged {
            recorded: receipt.schema,
            current: RECEIPT_SCHEMA,
        });
    }
    for &key in DependencyPolicy::for_phase(receipt.phase) {
        let recorded = receipt.dependencies.values.get(&key).copied();
        let now = current.get(key);
        match (recorded, now) {
            (Some(a), Some(b)) if a == b => {}
            (None, None) if is_hermetic_key(key) => {}
            (None, Some(_)) if is_hermetic_key(key) => {}
            _ => reasons.push(StaleReason::DependencyChanged(key)),
        }
    }
    if reasons.is_empty() {
        EvidenceValidity::Valid
    } else {
        EvidenceValidity::Stale(reasons)
    }
}

pub const RISK_CLASSIFIER_VERSION: u32 = 1;

/// Derive the minimum review risk from declared scope and the small set of
/// execution-bearing configuration signals. This deliberately classifies
/// conservatively: an unknown path below a sensitive root is High.
pub fn classify_effective_risk(
    manifest: &ChangeManifest,
    config: &crate::config::Config,
    requested: RiskLevel,
) -> RiskAssessment {
    let mut reasons = Vec::new();
    let mut paths = manifest.paths.clone();
    paths.extend(manifest.shared_paths.clone());
    paths.sort();
    paths.dedup();

    let categories: [(&str, &[&str]); 9] = [
        (
            "auth-or-credential",
            &["auth", "credential", "secret", "token", "keychain"],
        ),
        (
            "parser-or-untrusted-input",
            &["parser", "parse", "codec", "decode", "protocol", "input"],
        ),
        (
            "network",
            &["network", "http", "socket", "client", "server"],
        ),
        (
            "process-execution",
            &["process", "exec", "command", "shell", "scripts/"],
        ),
        ("git-or-hooks", &[".git", "git/", "hook"]),
        (
            "persistence",
            &[
                "persist",
                "database",
                "sqlite",
                "storage",
                "migration",
                "save",
            ],
        ),
        ("sandbox", &["sandbox", "seatbelt", "bwrap"]),
        (
            "cryptography",
            &["crypto", "cipher", "encrypt", "signature"],
        ),
        ("deployment", &["deploy", "install", "release", "package"]),
    ];
    let sensitive_roots = [
        ".githooks/",
        ".mpd/",
        "security/",
        "scripts/",
        "crates/mpd/src/checks",
        "crates/mpd/src/config",
        "crates/mpd/src/git",
        "crates/mpd/src/local_validation",
        "crates/mpd/src/sandbox",
    ];
    for path in &paths {
        let lower = path.to_ascii_lowercase();
        let before = reasons.len();
        for (category, needles) in categories {
            if needles.iter().any(|needle| lower.contains(needle)) {
                reasons.push(format!("{category}: {path}"));
            }
        }
        if reasons.len() == before && sensitive_roots.iter().any(|root| lower.starts_with(root)) {
            reasons.push(format!("unknown-sensitive-path: {path}"));
        }
    }
    if config.deploy.is_some()
        || config
            .local_validation
            .as_ref()
            .and_then(|local| local.deploy_output.as_ref())
            .is_some()
    {
        reasons.push("deployment-configured".into());
    }
    if config.local_validation.is_some() {
        reasons.push("local-validation-process-hook-sandbox-policy".into());
    }
    reasons.sort();
    reasons.dedup();
    let derived = if reasons.is_empty() {
        RiskLevel::Low
    } else {
        RiskLevel::High
    };
    let effective = requested.max(derived);
    let signal_bytes = serde_json::to_vec(&(
        RISK_CLASSIFIER_VERSION,
        &paths,
        &reasons,
        config.deploy.is_some(),
        config.local_validation.is_some(),
    ))
    .expect("risk classifier tuple is serializable");
    RiskAssessment {
        classifier_version: RISK_CLASSIFIER_VERSION,
        requested,
        derived,
        effective,
        reasons,
        signal_digest: Digest::of_bytes(&signal_bytes).to_hex(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaleEvidenceProjection {
    pub phase: Phase,
    pub rewind_phase: Phase,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FreshnessProjection {
    pub stored_phase: Phase,
    pub effective_phase: Phase,
    pub stale: Vec<StaleEvidenceProjection>,
}

fn stale_dependency_rewind(receipt_phase: Phase, reason: &StaleReason) -> Phase {
    match reason {
        StaleReason::SchemaChanged { .. } => receipt_phase,
        StaleReason::DependencyChanged(key) => match key {
            DependencyKey::DesignMockArtifact => Phase::DesignMock,
            DependencyKey::Scope
            | DependencyKey::Config
            | DependencyKey::DesignArtifacts
            | DependencyKey::ArchitecturePlan => Phase::Architecture,
            DependencyKey::Governance => match receipt_phase {
                Phase::SecurityPlan | Phase::SecurityCode => Phase::SecurityPlan,
                _ => Phase::Architecture,
            },
            DependencyKey::Source
            | DependencyKey::TestCommand
            | DependencyKey::Toolchain
            | DependencyKey::ProducedArtifact
            | DependencyKey::ScannerIdentity
            | DependencyKey::AllowlistDigest
            | DependencyKey::ShippedBehavior
            | DependencyKey::HermeticPlatform
            | DependencyKey::HermeticExecutable
            | DependencyKey::HermeticEnvironment
            | DependencyKey::HermeticInput => Phase::Build,
            DependencyKey::Documentation => Phase::Documentation,
            DependencyKey::DeployCommand => Phase::Deploy,
            DependencyKey::PersonaTuning => receipt_phase,
        },
    }
}

/// Read-only projection of current PASS evidence. Legacy receipt absence is
/// reported elsewhere but is not invented into a content-staleness rewind.
pub fn freshness_projection(
    root: &Path,
    change: &str,
    ledger: &crate::ledger::Ledger,
    config: &crate::config::Config,
) -> Result<FreshnessProjection, String> {
    let mut stale = Vec::new();
    for (&phase, record) in &ledger.gates {
        if record.verdict != Verdict::Pass || record.receipt.is_none() {
            continue;
        }
        let values = capture_dependency_values(root, change, ledger, config, phase)?;
        if let EvidenceValidity::Stale(found) = evidence_validity(record.receipt.as_ref(), &values)
        {
            let rewind_phase = found
                .iter()
                .map(|reason| stale_dependency_rewind(phase, reason))
                .min()
                .unwrap_or(phase);
            stale.push(StaleEvidenceProjection {
                phase,
                rewind_phase,
                reasons: found.into_iter().map(|reason| reason.to_string()).collect(),
            });
        }
    }
    stale.sort_by_key(|item| (item.rewind_phase, item.phase));
    let earliest = stale
        .iter()
        .map(|item| item.rewind_phase)
        .min()
        .unwrap_or(ledger.phase);
    Ok(FreshnessProjection {
        stored_phase: ledger.phase,
        effective_phase: ledger.phase.min(earliest),
        stale,
    })
}

// =====================================================================
// Reuse eligibility (display) and reuse decision (`gate --reuse`)
// =====================================================================

/// Whether valid evidence is currently offered for reuse, and why/why not —
/// distinct from [`EvidenceValidity`] (evidence-reuse/spec.md: "Valid
/// evidence MAY remain ineligible...").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseOffer {
    /// Evidence is not valid (stale/absent) or its origin verdict was FAIL —
    /// nothing valid exists to offer.
    NotOffered,
    /// This phase's evidence is external-state and fixed always-execute
    /// (Deploy) — reuse is never offered regardless of validity.
    NeverReusable,
    /// Valid, but the origin verdict was CONDITIONAL PASS — refused even
    /// after the condition later closed (evidence-reuse/spec.md).
    ConditionalRefused,
    /// Valid, execution-bearing phase (Build/Test/Security code), no
    /// complete hermetic policy bound — the offered next action is the
    /// fresh gate command, not `--reuse`.
    AlwaysExecutes,
    /// Valid, execution-bearing phase, with a complete hermetic policy
    /// bound — reuse is offered.
    HermeticEligible,
    /// Valid, judgment-tier phase — reuse is offered by default.
    Eligible,
}

/// Compute the reuse offer for evidence already known to be `validity`
/// (typically [`evidence_validity`]'s result), given the phase and the
/// origin gate's recorded [`Verdict`]. `snapshot` is the receipt's own
/// dependency snapshot (used only to check [`hermetic_complete`] for
/// execution-bearing phases) — pass `None` when there is no receipt.
pub fn reuse_offer(
    phase: Phase,
    origin_verdict: Verdict,
    validity: &EvidenceValidity,
    snapshot: Option<&DependencySnapshot>,
) -> ReuseOffer {
    if phase == Phase::Deploy {
        return ReuseOffer::NeverReusable;
    }
    if !matches!(validity, EvidenceValidity::Valid) {
        return ReuseOffer::NotOffered;
    }
    match origin_verdict {
        Verdict::Fail => return ReuseOffer::NotOffered,
        Verdict::ConditionalPass => return ReuseOffer::ConditionalRefused,
        Verdict::Pass => {}
    }
    if execution_bearing(phase) {
        let complete = snapshot.map(hermetic_complete).unwrap_or(false);
        if complete {
            ReuseOffer::HermeticEligible
        } else {
            ReuseOffer::AlwaysExecutes
        }
    } else {
        ReuseOffer::Eligible
    }
}

/// Why `gate --reuse <id>` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseRefusal {
    /// Deploy's evidence is external-state and never reusable.
    DeployNeverReusable,
    /// The candidate receipt's dependency snapshot is not currently valid.
    NotValid,
    /// The candidate's origin verdict was CONDITIONAL PASS.
    OriginWasConditional,
    /// The candidate's origin verdict was FAIL.
    OriginWasFail,
    /// The candidate is itself a `Reused` receipt, not the flattened
    /// executed origin — reuse always resolves to (and points at) the
    /// executed origin, never chains through another reuse.
    NotAnExecutedOrigin,
    /// The phase defaults to always-execute and no complete hermetic policy
    /// is bound on the candidate.
    AlwaysExecutes,
}

impl fmt::Display for ReuseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            ReuseRefusal::DeployNeverReusable => {
                "Deploy evidence is external-state and never reusable"
            }
            ReuseRefusal::NotValid => "evidence is not currently valid",
            ReuseRefusal::OriginWasConditional => {
                "origin verdict was CONDITIONAL PASS; a fresh gate is required"
            }
            ReuseRefusal::OriginWasFail => "origin verdict was FAIL",
            ReuseRefusal::NotAnExecutedOrigin => {
                "candidate is itself a reused receipt, not an executed origin"
            }
            ReuseRefusal::AlwaysExecutes => {
                "phase defaults to always-execute (no complete hermetic policy)"
            }
        };
        f.write_str(text)
    }
}

/// Decide whether `gate <phase> --reuse` naming `origin` may append a
/// flattened reused receipt: `origin` must be an `Executed` receipt whose
/// verdict was unconditional PASS, whose dependency snapshot is currently
/// `Valid`, and — for an execution-bearing phase — hermetic-complete. This
/// performs no I/O and executes no check; on `Ok`, callers build the
/// appended receipt with [`EvidenceReceipt::reused_from`].
pub fn evaluate_reuse(
    phase: Phase,
    origin_verdict: Verdict,
    origin: &EvidenceReceipt,
    validity: &EvidenceValidity,
) -> Result<(), ReuseRefusal> {
    if phase == Phase::Deploy {
        return Err(ReuseRefusal::DeployNeverReusable);
    }
    if !matches!(origin.disposition, EvidenceDisposition::Executed) {
        return Err(ReuseRefusal::NotAnExecutedOrigin);
    }
    match origin_verdict {
        Verdict::Fail => return Err(ReuseRefusal::OriginWasFail),
        Verdict::ConditionalPass => return Err(ReuseRefusal::OriginWasConditional),
        Verdict::Pass => {}
    }
    if !matches!(validity, EvidenceValidity::Valid) {
        return Err(ReuseRefusal::NotValid);
    }
    if execution_bearing(phase) && !hermetic_complete(&origin.dependencies) {
        return Err(ReuseRefusal::AlwaysExecutes);
    }
    Ok(())
}

impl EvidenceReceipt {
    /// Compute this receipt's own content-addressed id: SHA-256 of its
    /// complete payload (`schema`, `phase`, `disposition`, `dependencies`)
    /// serialized as canonical JSON — `id` itself is excluded (it cannot be
    /// part of its own preimage). Field order is deterministic (fixed struct
    /// field order plus `DependencySnapshot`'s `BTreeMap` key order), so two
    /// logically identical receipts always hash identically.
    fn compute_id(
        schema: u32,
        phase: Phase,
        disposition: &EvidenceDisposition,
        dependencies: &DependencySnapshot,
    ) -> Digest {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: u32,
            phase: Phase,
            disposition: &'a EvidenceDisposition,
            dependencies: &'a DependencySnapshot,
        }
        let json = serde_json::to_vec(&Preimage {
            schema,
            phase,
            disposition,
            dependencies,
        })
        .expect("receipt preimage fields are always serializable");
        Digest::of_bytes(&json)
    }

    /// Construct a freshly *executed* receipt for `phase` from `dependencies`
    /// (typically [`DependencySnapshot::for_phase`]'s result).
    pub fn executed(phase: Phase, dependencies: DependencySnapshot) -> EvidenceReceipt {
        let disposition = EvidenceDisposition::Executed;
        let id = Self::compute_id(RECEIPT_SCHEMA, phase, &disposition, &dependencies);
        EvidenceReceipt {
            id,
            schema: RECEIPT_SCHEMA,
            phase,
            disposition,
            dependencies,
        }
    }

    /// Construct a flattened `Reused` receipt pointing at `origin`'s
    /// executed origin. If `origin` is itself `Reused`, the new receipt
    /// still points directly at the original executed receipt — reuse
    /// chains are always flattened, never nested (design.md "chains are
    /// flattened").
    pub fn reused_from(origin: &EvidenceReceipt) -> EvidenceReceipt {
        let source_receipt = match &origin.disposition {
            EvidenceDisposition::Executed => origin.id,
            EvidenceDisposition::Reused { source_receipt } => *source_receipt,
        };
        let disposition = EvidenceDisposition::Reused { source_receipt };
        let dependencies = origin.dependencies.clone();
        let id = Self::compute_id(RECEIPT_SCHEMA, origin.phase, &disposition, &dependencies);
        EvidenceReceipt {
            id,
            schema: RECEIPT_SCHEMA,
            phase: origin.phase,
            disposition,
            dependencies,
        }
    }
}

// =====================================================================
// HermeticReusePolicy validation
// =====================================================================

/// Case-insensitive substrings that make an environment-variable name
/// "secret-shaped" and therefore refused from a [`HermeticReusePolicy`]'s
/// `environment` allowlist (security-plan.md "Reject secret-shaped
/// environment names"). Intentionally over-inclusive: a false positive here
/// only means a legitimate-but-oddly-named variable can't be hermetically
/// bound (safe direction); a false negative could leak a value's presence
/// into a digest an attacker can correlate.
const SECRET_SHAPED_ENV_SUBSTRINGS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "APIKEY",
    "API_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AUTH",
    "ACCESS_KEY",
    "CLIENT_SECRET",
];

/// Whether `name` looks like it holds a secret value by name alone.
pub fn is_secret_shaped_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_SHAPED_ENV_SUBSTRINGS
        .iter()
        .any(|needle| upper.contains(needle))
}

/// A safe POSIX-style environment-variable name: non-empty, bounded,
/// `[A-Za-z_][A-Za-z0-9_]*`.
fn valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    !name.is_empty() && name.len() <= 200 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One problem with a [`HermeticReusePolicy`] declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HermeticPolicyIssue {
    /// `schema` is not a version this build understands.
    UnknownVersion(u32),
    /// An `environment` entry looks secret-shaped by name and is refused.
    SecretShapedEnvironmentName(String),
    /// An `environment` entry is not a safe variable-name token.
    UnsafeEnvironmentName(String),
    /// An `input_paths` entry is not a safe canonical relative path.
    UnsafeInputPath(String),
}

impl fmt::Display for HermeticPolicyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HermeticPolicyIssue::UnknownVersion(v) => {
                write!(f, "unknown hermetic policy version {v}")
            }
            HermeticPolicyIssue::SecretShapedEnvironmentName(n) => {
                write!(f, "refusing secret-shaped environment name: {n:?}")
            }
            HermeticPolicyIssue::UnsafeEnvironmentName(n) => {
                write!(f, "unsafe environment variable name: {n:?}")
            }
            HermeticPolicyIssue::UnsafeInputPath(p) => write!(f, "unsafe input path: {p:?}"),
        }
    }
}

impl std::error::Error for HermeticPolicyIssue {}

impl HermeticReusePolicy {
    /// Every problem with this declared policy (empty ⇒ safe to treat as a
    /// complete opt-in). Never partially trusts a policy with any issue —
    /// callers must treat a non-empty result as "no hermetic opt-in exists".
    pub fn validate(&self) -> Vec<HermeticPolicyIssue> {
        let mut issues = Vec::new();
        if self.schema != HERMETIC_POLICY_SCHEMA {
            issues.push(HermeticPolicyIssue::UnknownVersion(self.schema));
        }
        for name in &self.environment {
            if is_secret_shaped_env_name(name) {
                issues.push(HermeticPolicyIssue::SecretShapedEnvironmentName(
                    name.clone(),
                ));
            } else if !valid_env_var_name(name) {
                issues.push(HermeticPolicyIssue::UnsafeEnvironmentName(name.clone()));
            }
        }
        for path in &self.input_paths {
            if digest::validate_canonical_path(path).is_err() {
                issues.push(HermeticPolicyIssue::UnsafeInputPath(path.clone()));
            }
        }
        issues
    }

    /// Whether this policy declaration is syntactically complete/safe.
    pub fn is_complete(&self) -> bool {
        self.validate().is_empty()
    }
}

// =====================================================================
// Live dependency capture used by CLI gate/status/reuse
// =====================================================================

/// Derive the explicit MPD-owned scope for an active change. Archive planning
/// may add merged-spec and documentation targets at closeout; the active gate
/// snapshot intentionally binds the change tree and ledger now and the dated
/// archive path as a named future system path.
pub fn active_system_scope(_root: &Path, change: &str) -> SystemScope {
    SystemScope {
        change_dir: format!("openspec/changes/{change}"),
        ledger_path: format!(".mpd/state/{change}.json"),
        merged_spec_targets: Vec::new(),
        doc_target: None,
        archive_target: format!(
            "openspec/changes/archive/{}-{change}",
            openspec_core::date::today_utc()
        ),
    }
}

fn digest_named_bytes(domain: &str, items: &[(&str, Vec<u8>)]) -> Result<Digest, String> {
    let mut entries = Vec::with_capacity(items.len());
    for (name, bytes) in items {
        entries.push(
            digest::Entry::file(
                (*name).to_string(),
                0o100644,
                bytes.len() as u64,
                Digest::of_bytes(bytes),
            )
            .map_err(|e| e.to_string())?,
        );
    }
    digest::canonical_digest(domain, 1, entries).map_err(|e| e.to_string())
}

/// Digest a phase persona's **effective instructions** — its config tuning
/// (`personas[tuning_key(phase)]`) plus its resolved base-directive text (both
/// parts for the composite Doc-Validation persona). Bound by the governed phases
/// so a persona directive change (config append OR directive-file edit) stales a
/// reused receipt, while an unrelated config edit does not (design.md D5 §1). The
/// directive read is symlink-refusing (`for_persona`), so the digest is
/// deterministic given disk state and never reads through a redirected target.
fn persona_tuning_digest(
    root: &Path,
    config: &crate::config::Config,
    phase: Phase,
) -> Result<Digest, String> {
    let cfg_bytes = config
        .persona_tuning(phase.tuning_key())
        .map(|t| serde_json::to_vec(t).unwrap_or_default())
        .unwrap_or_default();
    let mut directive = Vec::new();
    for name in phase.tuning_personas() {
        if let Some(d) = crate::directives::for_persona(root, name) {
            directive.extend_from_slice(name.as_bytes());
            directive.push(0);
            directive.extend_from_slice(d.text.as_bytes());
            directive.push(0);
        }
    }
    digest_named_bytes(
        "persona-tuning",
        &[("config", cfg_bytes), ("directive", directive)],
    )
}

fn source_digest(
    root: &Path,
    manifest: &ChangeManifest,
    system: &SystemScope,
) -> Result<Digest, String> {
    let mut paths = git::ls_files(root).map_err(|e| e.to_string())?;
    for status in git::status_v2(root).map_err(|e| e.to_string())? {
        match status {
            git::StatusEntry::Untracked { path } => paths.push(path),
            git::StatusEntry::Unmerged { path, .. } => {
                return Err(format!("unmerged path blocks evidence capture: {path:?}"));
            }
            _ => {}
        }
    }
    paths.sort();
    paths.dedup();
    // The change's own process artifacts are each bound by a *dedicated*
    // dependency key (proposal/design/tasks.md -> DesignArtifacts;
    // documentation.md -> Documentation), so they must not ALSO fold into the
    // Source digest. documentation.md is written at the Documentation phase
    // (after Build/Test/SecurityCode); folding it into Source would let that
    // later-phase output retroactively stale an earlier receipt — the
    // phase-causality violation design.md:398-401 forbids (Security-code
    // finding source-includes-later-phase-output). Spec deltas under the
    // change dir have no dedicated key and stay bound by Source.
    let change_process_artifacts: [String; 11] = [
        format!("{}/proposal.md", system.change_dir),
        format!("{}/design.md", system.change_dir),
        format!("{}/tasks.md", system.change_dir),
        format!("{}/documentation.md", system.change_dir),
        format!("{}/design-mock.md", system.change_dir),
        format!("{}/design-review.md", system.change_dir),
        format!("{}/security-plan.md", system.change_dir),
        format!("{}/security-code.md", system.change_dir),
        format!("{}/design-signoff.md", system.change_dir),
        format!("{}/test.md", system.change_dir),
        format!("{}/doc-validation.md", system.change_dir),
    ];
    let mut entries = Vec::new();
    for path in paths {
        // Receipt-bearing ledgers and local caches are deliberately excluded:
        // otherwise recording a receipt would immediately mutate its own
        // Source dependency and make it stale by self-reference.
        if path.starts_with(".mpd/")
            || change_process_artifacts.contains(&path)
            || !manifest.covers(&path, system)
        {
            continue;
        }
        digest::validate_canonical_path(&path).map_err(|e| e.to_string())?;
        let full = root.join(&path);
        match std::fs::symlink_metadata(&full) {
            Ok(md) if md.file_type().is_symlink() => {
                let target = std::fs::read_link(&full).map_err(|e| e.to_string())?;
                let target = target
                    .to_str()
                    .ok_or_else(|| format!("non-UTF-8 symlink target at {path:?}"))?;
                entries.push(digest::Entry::symlink(path, target).map_err(|e| e.to_string())?);
            }
            Ok(md) if md.is_file() => {
                let content = digest::hash_file_non_following(&full).map_err(|e| e.to_string())?;
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    if md.permissions().mode() & 0o111 != 0 {
                        0o100755
                    } else {
                        0o100644
                    }
                };
                #[cfg(not(unix))]
                let mode = 0o100644;
                entries.push(
                    digest::Entry::file(path, mode, content.length, content.digest)
                        .map_err(|e| e.to_string())?,
                );
            }
            Ok(md) if md.is_dir() => {
                let oid = git::gitlink_oid(root, &path)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| {
                        format!("directory in source scope is not a gitlink: {path:?}")
                    })?;
                entries.push(digest::Entry::gitlink(path, &oid).map_err(|e| e.to_string())?);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                entries.push(digest::Entry::deleted(path).map_err(|e| e.to_string())?);
            }
            Ok(_) => return Err(format!("special file blocks evidence capture: {path:?}")),
            Err(e) => return Err(e.to_string()),
        }
    }
    digest::canonical_digest("source", 1, entries).map_err(|e| e.to_string())
}

fn read_optional(root: &Path, rel: &str) -> Vec<u8> {
    openspec_core::read_capped(&root.join(rel))
        .unwrap_or_default()
        .into_bytes()
}

/// Capture every current dependency value needed by `phase`. Values are
/// phase-filtered by `DependencySnapshot::for_phase`; this function may
/// compute a superset without accidentally binding later-phase outputs.
pub fn capture_dependency_values(
    root: &Path,
    change: &str,
    ledger: &crate::ledger::Ledger,
    config: &crate::config::Config,
    phase: Phase,
) -> Result<DependencyValues, String> {
    let manifest = load_manifest(root, change).map_err(|e| e.to_string())?;
    let issues: Vec<_> = manifest
        .validate()
        .into_iter()
        .filter(|issue| !matches!(issue, ManifestIssue::NoDeclaredScope))
        .collect();
    if !issues.is_empty() {
        return Err(format!(
            "change manifest is not ready: {}",
            issues
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    let system = active_system_scope(root, change);
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    let scope = digest_named_bytes(
        "scope",
        &[
            ("manifest.json", manifest_bytes),
            (
                "system-scope.json",
                serde_json::to_vec(&system.paths()).map_err(|e| e.to_string())?,
            ),
        ],
    )?;
    let source = source_digest(root, &manifest, &system)?;
    let design_mock = digest_named_bytes(
        "design-mock-artifact",
        &[(
            "design-mock.md",
            read_optional(root, &format!("openspec/changes/{change}/design-mock.md")),
        )],
    )?;
    let task_bytes = match Project::new(root).task_plan(change) {
        Ok(plan) if plan.strict => plan.normalized_progress_record().into_bytes(),
        Ok(_) => read_optional(root, &format!("openspec/changes/{change}/tasks.md")),
        Err(error) => {
            return Err(format!(
                "invalid tasks.md for Architecture receipt: {error}"
            ))
        }
    };
    let architecture_plan = digest_named_bytes(
        "architecture-plan",
        &[
            (
                "proposal.md",
                read_optional(root, &format!("openspec/changes/{change}/proposal.md")),
            ),
            (
                "design.md",
                read_optional(root, &format!("openspec/changes/{change}/design.md")),
            ),
            ("tasks.md-normalized", task_bytes),
        ],
    )?;
    let risk = classify_effective_risk(&manifest, config, ledger.governance.risk);
    // Reconciliations authorize another attempt; they do not change the
    // approved threat model. Including them would make `mpd resolve` stale
    // Architecture immediately after recording the authorization. The stable
    // governance dependency is the requested risk, threat profile, and the
    // current versioned classifier result.
    let governance = match phase {
        // Risk shapes Architecture. Threat-profile changes are independently
        // governed by Security(plan), so do not make them masquerade as an
        // architecture-plan change.
        Phase::SecurityPlan | Phase::SecurityCode => Digest::of_bytes(
            &serde_json::to_vec(&(
                ledger.governance.risk,
                &ledger.governance.threat_profile,
                &risk,
            ))
            .map_err(|e| e.to_string())?,
        ),
        _ => Digest::of_bytes(
            &serde_json::to_vec(&(ledger.governance.risk, &risk)).map_err(|e| e.to_string())?,
        ),
    };
    let test_command = Digest::of_bytes(config.test.as_deref().unwrap_or("").as_bytes());
    let deploy_command = Digest::of_bytes(config.deploy.as_deref().unwrap_or("").as_bytes());
    let toolchain_text = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| o.stdout)
        .unwrap_or_default();
    let toolchain = Digest::of_bytes(&toolchain_text);
    let documentation = Digest::of_bytes(&read_optional(
        root,
        &format!("openspec/changes/{change}/documentation.md"),
    ));
    let scanner_identity = Digest::of_bytes(b"builtin+available-external-scanners-v1");
    let allowlist = Digest::of_bytes(&read_optional(root, ".mpd/secret-allowlist.json"));
    let persona_tuning = persona_tuning_digest(root, config, phase)?;

    let mut values = DependencyValues::new()
        .with(DependencyKey::Scope, scope)
        .with(DependencyKey::Source, source)
        .with(DependencyKey::Governance, governance)
        .with(
            DependencyKey::Config,
            Digest::of_bytes(&serde_json::to_vec(config).map_err(|e| e.to_string())?),
        )
        .with(DependencyKey::DesignArtifacts, architecture_plan)
        .with(DependencyKey::DesignMockArtifact, design_mock)
        .with(DependencyKey::ArchitecturePlan, architecture_plan)
        .with(DependencyKey::TestCommand, test_command)
        .with(DependencyKey::Toolchain, toolchain)
        .with(DependencyKey::ProducedArtifact, source)
        .with(DependencyKey::ScannerIdentity, scanner_identity)
        .with(DependencyKey::AllowlistDigest, allowlist)
        .with(DependencyKey::DeployCommand, deploy_command)
        .with(DependencyKey::ShippedBehavior, source)
        .with(DependencyKey::Documentation, documentation)
        .with(DependencyKey::PersonaTuning, persona_tuning);

    if execution_bearing(phase) {
        if let Some(policy) = config.hermetic_reuse_policy().filter(|p| p.is_complete()) {
            let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
            values.set(
                DependencyKey::HermeticPlatform,
                Digest::of_bytes(platform.as_bytes()),
            );
            if let Ok(exe) =
                std::env::current_exe().and_then(|p| digest::hash_file_non_following(&p))
            {
                values.set(DependencyKey::HermeticExecutable, exe.digest);
            }
            let env_pairs: Vec<(String, String)> = policy
                .environment
                .iter()
                .map(|name| (name.clone(), std::env::var(name).unwrap_or_default()))
                .collect();
            values.set(
                DependencyKey::HermeticEnvironment,
                Digest::of_bytes(&serde_json::to_vec(&env_pairs).map_err(|e| e.to_string())?),
            );
            let mut inputs = Vec::new();
            for rel in &policy.input_paths {
                let content =
                    digest::hash_file_non_following(&root.join(rel)).map_err(|e| e.to_string())?;
                inputs.push(
                    digest::Entry::file(rel.clone(), 0o100644, content.length, content.digest)
                        .map_err(|e| e.to_string())?,
                );
            }
            values.set(
                DependencyKey::HermeticInput,
                digest::canonical_digest("hermetic-input", 1, inputs).map_err(|e| e.to_string())?,
            );
        }
    }
    Ok(values)
}

fn allowed(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pattern| {
        glob_match(pattern, path)
            || path_is_within(pattern.trim_end_matches("/**"), path)
            || path_is_within(path, pattern.trim_end_matches("/**"))
    })
}

/// Freeze `patterns` (the declared, possibly-glob manifest scope) into a
/// concrete path list by enumerating every currently tracked/untracked
/// repository path that matches, then union it with the already-concrete
/// `system_paths` (kept verbatim, including directory-prefix entries such as
/// the archive target, so paths this archive is about to create — which
/// don't exist yet at snapshot time — are still covered by prefix once they
/// do). Called exactly once, at `archive --yes` time, *before* the
/// transaction mutates anything, to populate
/// [`ArchiveClosure::system_paths`]. Deliberately never re-called afterward:
/// a live re-resolution is what would let a later, unrelated file silently
/// re-enter "in scope" through a leftover wildcard pattern.
pub fn resolve_scope_snapshot(
    root: &Path,
    patterns: &[String],
    system_paths: &[String],
) -> Result<Vec<String>, String> {
    let mut paths = git::ls_files(root).map_err(|e| e.to_string())?;
    for status in git::status_v2(root).map_err(|e| e.to_string())? {
        if let git::StatusEntry::Untracked { path } = status {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    let mut resolved: Vec<String> = paths.into_iter().filter(|p| allowed(patterns, p)).collect();
    resolved.extend(system_paths.iter().cloned());
    resolved.sort();
    resolved.dedup();
    Ok(resolved)
}

/// Hash every current tracked/untracked regular file in `patterns`. This is
/// used after archive, where manifest.json has moved into the archive and the
/// closure record's immutable allowed-path list is authoritative.
pub fn scoped_digest_for_patterns(root: &Path, patterns: &[String]) -> Result<Digest, String> {
    let mut paths = git::ls_files(root).map_err(|e| e.to_string())?;
    for status in git::status_v2(root).map_err(|e| e.to_string())? {
        match status {
            git::StatusEntry::Untracked { path } => paths.push(path),
            git::StatusEntry::Unmerged { path, .. } if allowed(patterns, &path) => {
                return Err(format!("unmerged path blocks closure digest: {path:?}"));
            }
            _ => {}
        }
    }
    paths.sort();
    paths.dedup();
    let mut entries = Vec::new();
    for path in paths
        .into_iter()
        .filter(|p| allowed(patterns, p) && !p.starts_with(".mpd/state/"))
    {
        let full = root.join(&path);
        let md = match std::fs::symlink_metadata(&full) {
            Ok(md) => md,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                entries.push(digest::Entry::deleted(path).map_err(|e| e.to_string())?);
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        if md.file_type().is_symlink() {
            let target = std::fs::read_link(&full).map_err(|e| e.to_string())?;
            let target = target.to_str().ok_or("non-UTF-8 symlink target")?;
            entries.push(digest::Entry::symlink(path, target).map_err(|e| e.to_string())?);
        } else if md.is_file() {
            let content = digest::hash_file_non_following(&full).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                if md.permissions().mode() & 0o111 != 0 {
                    0o100755
                } else {
                    0o100644
                }
            };
            #[cfg(not(unix))]
            let mode = 0o100644;
            entries.push(
                digest::Entry::file(path, mode, content.length, content.digest)
                    .map_err(|e| e.to_string())?,
            );
        } else if md.is_dir() {
            let oid = git::gitlink_oid(root, &path)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("directory in closure scope is not a gitlink: {path:?}"))?;
            entries.push(digest::Entry::gitlink(path, &oid).map_err(|e| e.to_string())?);
        } else {
            return Err(format!("special file in closure scope: {path:?}"));
        }
    }
    digest::canonical_digest("archive-scope", 1, entries).map_err(|e| e.to_string())
}

/// Compute the post-archive scoped digest without mutating the repository.
/// `overrides` supplies exact ordinary target postimages; the active change
/// tree is virtually renamed to `archive_prefix`. Ledger bytes are excluded
/// to avoid self-reference, matching `ArchiveTransactionPlan`'s contract.
pub fn planned_archive_digest(
    root: &Path,
    patterns: &[String],
    active_prefix: &str,
    archive_prefix: &str,
    overrides: &BTreeMap<String, Vec<u8>>,
) -> Result<Digest, String> {
    let mut paths = git::ls_files(root).map_err(|e| e.to_string())?;
    for status in git::status_v2(root).map_err(|e| e.to_string())? {
        if let git::StatusEntry::Untracked { path } = status {
            paths.push(path);
        }
    }
    paths.extend(overrides.keys().cloned());
    paths.sort();
    paths.dedup();
    let mut entries = Vec::new();
    for original in paths {
        let path = if original == active_prefix {
            archive_prefix.to_string()
        } else if let Some(suffix) = original.strip_prefix(&format!("{active_prefix}/")) {
            format!("{archive_prefix}/{suffix}")
        } else {
            original.clone()
        };
        if !allowed(patterns, &path) || path.starts_with(".mpd/state/") {
            continue;
        }
        if let Some(bytes) = overrides.get(&original).or_else(|| overrides.get(&path)) {
            entries.push(
                digest::Entry::file(path, 0o100644, bytes.len() as u64, Digest::of_bytes(bytes))
                    .map_err(|e| e.to_string())?,
            );
            continue;
        }
        let full = root.join(&original);
        let md = match std::fs::symlink_metadata(&full) {
            Ok(md) => md,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.to_string()),
        };
        if md.file_type().is_symlink() {
            let target = std::fs::read_link(&full).map_err(|e| e.to_string())?;
            entries.push(
                digest::Entry::symlink(path, target.to_str().ok_or("non-UTF-8 symlink target")?)
                    .map_err(|e| e.to_string())?,
            );
        } else if md.is_file() {
            let content = digest::hash_file_non_following(&full).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                if md.permissions().mode() & 0o111 != 0 {
                    0o100755
                } else {
                    0o100644
                }
            };
            #[cfg(not(unix))]
            let mode = 0o100644;
            entries.push(
                digest::Entry::file(path, mode, content.length, content.digest)
                    .map_err(|e| e.to_string())?,
            );
        } else if md.is_dir() {
            let oid = git::gitlink_oid(root, &original)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| {
                    format!("directory in planned scope is not a gitlink: {original:?}")
                })?;
            entries.push(digest::Entry::gitlink(path, &oid).map_err(|e| e.to_string())?);
        }
    }
    digest::canonical_digest("archive-scope", 1, entries).map_err(|e| e.to_string())
}

/// Prove the post-archive commit range is linear, contains no out-of-scope
/// path at any intermediate commit, is clean in included scope, and still
/// matches the archived scoped digest.
pub fn verify_commit_coherence(
    root: &Path,
    closure: &ArchiveClosure,
) -> Result<CommitCoherence, String> {
    let mut blockers = Vec::new();
    let head = git::head_commit(root).map_err(|e| e.to_string())?;
    let Some(head_oid) = head.clone() else {
        return Ok(CommitCoherence {
            coherent: false,
            head,
            blockers: vec!["repository has no commit".into()],
        });
    };
    let commits = match git::rev_list_reverse(root, &closure.base_commit, &head_oid) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            blockers.push("archived result has not been committed".into());
            Vec::new()
        }
        Err(_) => {
            blockers.push("HEAD is not a readable descendant of the archive base".into());
            Vec::new()
        }
    };
    for commit in &commits {
        match git::single_parent(root, commit).map_err(|e| e.to_string())? {
            Some(parent) => {
                for entry in
                    git::diff_tree_name_status(root, &parent, commit).map_err(|e| e.to_string())?
                {
                    for path in entry.orig_path.iter().chain(std::iter::once(&entry.path)) {
                        if !allowed(&closure.allowed_paths, path) {
                            blockers.push(format!(
                                "commit {} touches out-of-scope path {path:?}",
                                &commit[..12]
                            ));
                        }
                    }
                }
            }
            None => blockers.push(format!("commit {} has no single parent", &commit[..12])),
        }
    }
    for status in git::status_v2(root).map_err(|e| e.to_string())? {
        let paths: Vec<&str> = match &status {
            git::StatusEntry::Ordinary { path, .. }
            | git::StatusEntry::Unmerged { path, .. }
            | git::StatusEntry::Untracked { path }
            | git::StatusEntry::Ignored { path } => vec![path],
            git::StatusEntry::RenamedOrCopied {
                path, orig_path, ..
            } => vec![path, orig_path],
        };
        if !matches!(status, git::StatusEntry::Ignored { .. })
            && paths.iter().any(|p| allowed(&closure.allowed_paths, p))
        {
            blockers.push(format!("included scope is dirty at {:?}", paths[0]));
        }
    }
    let digest = scoped_digest_for_patterns(root, &closure.allowed_paths)?;
    if digest != closure.post_archive_digest {
        blockers.push("current scoped content differs from the archived postimage".into());
    }
    if let Some(candidate_id) = &closure.candidate_id {
        match load_candidate_closure_plan(root, &closure.transaction_id.to_hex()) {
            Ok(plan) => {
                if plan.candidate_id != *candidate_id
                    || plan.candidate_base_commit != closure.base_commit
                    || plan.archive_path != closure.archive_path
                    || plan.archive_transaction_id != closure.transaction_id.to_hex()
                {
                    blockers.push(
                        "Candidate closure plan binding differs from the archive record".into(),
                    );
                } else {
                    match verify_candidate_commit_equivalence(root, &head_oid, &plan) {
                        Ok(equivalence) if equivalence.equivalent => {}
                        Ok(equivalence) => blockers.extend(
                            equivalence
                                .blockers
                                .into_iter()
                                .map(|blocker| format!("Candidate closure mismatch: {blocker}")),
                        ),
                        Err(error) => blockers.push(format!(
                            "Candidate closure comparison is unavailable: {error}"
                        )),
                    }
                }
            }
            Err(error) => blockers.push(format!("Candidate closure plan is unavailable: {error}")),
        }
    }
    blockers.sort();
    blockers.dedup();
    Ok(CommitCoherence {
        coherent: blockers.is_empty(),
        head,
        blockers,
    })
}

/// Whether every currently `status --porcelain=v2`-reported change (staged
/// or unstaged, ordinary or renamed, never `!` ignored) overlaps `allowed`.
/// The scoped digest already reflects worktree byte content, but this
/// separately answers "is any *tracked-by-Git* state dirty" — the
/// [`LocalSnapshot::included_clean`] field design.md's "Archive and commit
/// lifecycle"/"Remote observation" sections name.
fn scope_is_clean(root: &Path, allowed_paths: &[String]) -> Result<bool, String> {
    for status in git::status_v2(root).map_err(|e| e.to_string())? {
        let paths: Vec<&str> = match &status {
            git::StatusEntry::Ordinary { path, .. }
            | git::StatusEntry::Unmerged { path, .. }
            | git::StatusEntry::Untracked { path } => vec![path],
            git::StatusEntry::RenamedOrCopied {
                path, orig_path, ..
            } => vec![path, orig_path],
            git::StatusEntry::Ignored { .. } => continue,
        };
        if paths.iter().any(|p| allowed(allowed_paths, p)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One [`LocalSnapshot`]: HEAD OID, index identity, scoped content digest,
/// and included-scope cleanliness, captured together so the four values can
/// never be silently attributed to different repository moments — the local
/// half of the TOCTOU fix design.md's "Remote observation" section requires
/// (security-plan.md MEDIUM). Used both to detect movement between the two
/// paired observations `verify_remote_parity` takes per attempt and, via its
/// derived equality, to require every one of HEAD/index/scope/cleanliness to
/// match before treating two observations as the same repository state.
fn capture_local_snapshot(root: &Path, allowed_paths: &[String]) -> Result<LocalSnapshot, String> {
    let head = git::head_commit(root)
        .map_err(|e| e.to_string())?
        .ok_or("repository has no HEAD")?;
    let index = git::index_identity(root).map_err(|e| e.to_string())?;
    let scoped = scoped_digest_for_patterns(root, allowed_paths)?;
    let included_clean = scope_is_clean(root, allowed_paths)?;
    Ok(LocalSnapshot {
        head,
        index,
        scoped,
        included_clean,
    })
}

pub fn parity_cache_path(root: &Path) -> PathBuf {
    root.join(".mpd/parity-observations.json")
}

pub fn load_parity_cache(root: &Path) -> Option<ParityObservation> {
    let path = parity_cache_path(root);
    let text = openspec_core::read_capped(&path).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_parity_cache(root: &Path, observation: &ParityObservation) -> Result<(), String> {
    let path = parity_cache_path(root);
    openspec_core::assert_contained(root, &path).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(observation).map_err(|e| e.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("parity cache exceeds size limit".into());
    }
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

fn classify_oid_difference(root: &Path, local: &str, remote: &str) -> Result<ParityState, String> {
    let remote_is_ancestor = git::is_ancestor(root, remote, local).map_err(|e| e.to_string())?;
    let local_is_ancestor = git::is_ancestor(root, local, remote).map_err(|e| e.to_string())?;
    Ok(classify_ancestry(remote_is_ancestor, local_is_ancestor))
}

fn classify_ancestry(
    remote_is_ancestor: Option<bool>,
    local_is_ancestor: Option<bool>,
) -> ParityState {
    match (remote_is_ancestor, local_is_ancestor) {
        (None, _) | (_, None) => ParityState::AncestryUnavailable,
        (Some(true), Some(false)) => ParityState::Ahead,
        (Some(false), Some(true)) => ParityState::Behind,
        (Some(false), Some(false)) => ParityState::Diverged,
        (Some(true), Some(true)) => ParityState::NotVerified,
    }
}

/// Fresh, non-pushing, non-fetching parity verification with a stable
/// local/remote/local/remote observation. Exactly one retry is permitted when
/// either side moves; a second movement returns UNSTABLE and writes no cache.
pub fn verify_remote_parity(
    root: &Path,
    change: &str,
    target: &PublishTarget,
    closure: &ArchiveClosure,
    remote_timeout_secs: u64,
) -> Result<ParityObservation, String> {
    verify_remote_parity_with_probe(
        root,
        change,
        target,
        closure,
        remote_timeout_secs,
        &mut |_attempt| {},
    )
}

/// As [`verify_remote_parity`], with a test-only injection point invoked once
/// per attempt, immediately after the first (local1/index1/scope1/remote1)
/// observation and before the recheck (local2/index2/scope2/remote2) that
/// same attempt compares against. Production code always passes a no-op
/// closure via [`verify_remote_parity`]; tests use `probe` to deterministically
/// mutate local/remote repository state exactly inside the TOCTOU window this
/// function is proving closed — see security-plan.md MEDIUM "Add
/// deterministic race fixtures" — rather than relying on timing-sensitive
/// background threads.
pub fn verify_remote_parity_with_probe(
    root: &Path,
    change: &str,
    target: &PublishTarget,
    closure: &ArchiveClosure,
    remote_timeout_secs: u64,
    probe: &mut dyn FnMut(usize),
) -> Result<ParityObservation, String> {
    if !git::configured_remote_names(root)
        .map_err(|e| e.to_string())?
        .contains(&target.remote)
    {
        return Err(format!(
            "publish remote {:?} is not a configured remote name",
            target.remote
        ));
    }
    let coherence = verify_commit_coherence(root, closure)?;
    if !coherence.coherent {
        return Err(format!(
            "closure commit is not coherent: {}",
            coherence.blockers.join("; ")
        ));
    }
    // The coherence proof above (linear in-scope history, scoped == archived
    // postimage, included scope clean) was computed on the HEAD read *before*
    // this observation loop. Bind it to the head we ultimately call VERIFIED:
    // if HEAD/scoped/cleanliness drifted between the coherence proof and a
    // stable observation — even a concurrent `git reset --hard` that then held
    // steady, so snapshot1 == snapshot2 — the observed head was never
    // coherence-proven and MUST NOT be reported VERIFIED (Security-code
    // finding coherence-observation-head-unbound; specs/remote-parity/spec.md
    // "Local or remote snapshot moves during verification").
    let coherent_head = coherence.head;
    for attempt in 0..2 {
        let snapshot1 = capture_local_snapshot(root, &closure.allowed_paths)?;
        let remote1 = git::ls_remote_with_timeout(
            root,
            &target.remote,
            &target.reference,
            remote_timeout_secs,
        )
        .map_err(|_| "remote observation failed (offline)".to_string())?;
        probe(attempt);
        let snapshot2 = capture_local_snapshot(root, &closure.allowed_paths)?;
        let remote2 = git::ls_remote_with_timeout(
            root,
            &target.remote,
            &target.reference,
            remote_timeout_secs,
        )
        .map_err(|_| "remote observation failed (offline)".to_string())?;
        // Re-assert the coherence binding on this observation (see above): the
        // stable head must be the coherence-checked head, its scoped content
        // must still equal the archived postimage, and included scope must be
        // clean. Any drift is treated as movement — one retry, then UNSTABLE —
        // so a head move into the coherence->observation window can never be
        // reported VERIFIED.
        let observation_matches_coherence = coherent_head.as_deref()
            == Some(snapshot2.head.as_str())
            && snapshot2.scoped == closure.post_archive_digest
            && snapshot2.included_clean;
        if snapshot1 != snapshot2 || remote1 != remote2 || !observation_matches_coherence {
            if attempt == 0 {
                continue;
            }
            return Ok(ParityObservation {
                schema: 1,
                change: change.into(),
                remote: target.remote.clone(),
                reference: target.reference.clone(),
                local_oid: snapshot2.head,
                remote_oid: remote2,
                state: ParityState::Unstable,
                observed_at_epoch_secs: crate::ledger::now_epoch_secs(),
            });
        }
        let local2 = snapshot2.head;
        let state = match remote2.as_deref() {
            Some(remote) if remote == local2 => ParityState::Verified,
            Some(remote) => {
                let mut state = classify_oid_difference(root, &local2, remote)?;
                // Only a prior VERIFIED observation for *this same* change /
                // remote / ref may drive rewrite classification. Without the
                // key match, an unrelated target's cached observation (the
                // parity cache is a single global file) would supply a foreign
                // old_oid and mislabel this target (Security-code finding
                // rewritten-cache-not-keyed; security-plan.md cache-binding).
                if let Some(old) = load_parity_cache(root).filter(|o| {
                    o.state == ParityState::Verified
                        && o.change == change
                        && o.remote == target.remote
                        && o.reference == target.reference
                }) {
                    if let Some(old_oid) = old.remote_oid {
                        if old_oid != remote
                            && git::is_ancestor(root, &old_oid, remote)
                                .map_err(|e| e.to_string())?
                                == Some(false)
                        {
                            state = ParityState::Rewritten;
                        }
                    }
                }
                state
            }
            None => ParityState::Unavailable,
        };
        let observation = ParityObservation {
            schema: 1,
            change: change.into(),
            remote: target.remote.clone(),
            reference: target.reference.clone(),
            local_oid: local2,
            remote_oid: remote2,
            state,
            observed_at_epoch_secs: crate::ledger::now_epoch_secs(),
        };
        if observation.state != ParityState::Unstable {
            save_parity_cache(root, &observation)?;
        }
        return Ok(observation);
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestry_classification_covers_ahead_behind_diverged_and_unavailable() {
        assert_eq!(
            classify_ancestry(Some(true), Some(false)),
            ParityState::Ahead
        );
        assert_eq!(
            classify_ancestry(Some(false), Some(true)),
            ParityState::Behind
        );
        assert_eq!(
            classify_ancestry(Some(false), Some(false)),
            ParityState::Diverged
        );
        assert_eq!(
            classify_ancestry(None, Some(false)),
            ParityState::AncestryUnavailable
        );
        assert_eq!(
            classify_ancestry(Some(false), None),
            ParityState::AncestryUnavailable
        );
    }

    fn sample_snapshot() -> DependencySnapshot {
        let mut values = BTreeMap::new();
        values.insert(DependencyKey::Scope, Digest::of_bytes(b"scope"));
        values.insert(DependencyKey::Source, Digest::of_bytes(b"source"));
        DependencySnapshot {
            schema: RECEIPT_SCHEMA,
            values,
        }
    }

    fn sample_receipt() -> EvidenceReceipt {
        EvidenceReceipt {
            id: Digest::of_bytes(b"receipt id"),
            schema: RECEIPT_SCHEMA,
            phase: Phase::Build,
            disposition: EvidenceDisposition::Executed,
            dependencies: sample_snapshot(),
        }
    }

    #[test]
    fn dependency_key_serializes_as_kebab_case_map_key() {
        // BTreeMap<DependencyKey, Digest> must serialize with the enum
        // variant as a plain string JSON key (not a nested object), so a
        // receipt's dependency snapshot is human-diffable in the ledger.
        let snapshot = sample_snapshot();
        let json = serde_json::to_value(&snapshot).unwrap();
        assert!(json["values"].get("scope").is_some());
        assert!(json["values"].get("source").is_some());
        let back: DependencySnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(back, snapshot);
    }

    #[test]
    fn dependency_snapshot_key_order_is_stable() {
        // A BTreeMap always serializes in key order regardless of insertion
        // order, so two snapshots built differently but logically identical
        // produce byte-identical JSON (load-bearing for receipt-id hashing
        // in a later stage).
        let mut a = BTreeMap::new();
        a.insert(DependencyKey::Source, Digest::of_bytes(b"s"));
        a.insert(DependencyKey::Scope, Digest::of_bytes(b"c"));
        let mut b = BTreeMap::new();
        b.insert(DependencyKey::Scope, Digest::of_bytes(b"c"));
        b.insert(DependencyKey::Source, Digest::of_bytes(b"s"));
        let snap_a = DependencySnapshot {
            schema: 1,
            values: a,
        };
        let snap_b = DependencySnapshot {
            schema: 1,
            values: b,
        };
        assert_eq!(
            serde_json::to_string(&snap_a).unwrap(),
            serde_json::to_string(&snap_b).unwrap()
        );
    }

    #[test]
    fn evidence_disposition_tags_are_distinct() {
        let executed = serde_json::to_value(EvidenceDisposition::Executed).unwrap();
        assert_eq!(executed["kind"], "executed");
        let reused = EvidenceDisposition::Reused {
            source_receipt: Digest::of_bytes(b"origin"),
        };
        let reused_json = serde_json::to_value(&reused).unwrap();
        assert_eq!(reused_json["kind"], "reused");
        assert_ne!(executed, reused_json);
    }

    #[test]
    fn evidence_receipt_round_trips_through_json() {
        let receipt = sample_receipt();
        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let back: EvidenceReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn hermetic_policy_requires_the_closed_no_external_state_tag() {
        let ok = r#"{"schema":1,"external_state":"none","environment":[],"input_paths":[]}"#;
        let policy: HermeticReusePolicy = serde_json::from_str(ok).unwrap();
        assert_eq!(policy.external_state, NoExternalState::None);
        // Any other value must fail closed rather than silently coerce.
        let bad = r#"{"schema":1,"external_state":"partial","environment":[],"input_paths":[]}"#;
        assert!(serde_json::from_str::<HermeticReusePolicy>(bad).is_err());
    }

    #[test]
    fn hermetic_policy_environment_and_input_paths_default_empty() {
        let minimal = r#"{"schema":1,"external_state":"none"}"#;
        let policy: HermeticReusePolicy = serde_json::from_str(minimal).unwrap();
        assert!(policy.environment.is_empty());
        assert!(policy.input_paths.is_empty());
    }

    #[test]
    fn archive_closure_round_trips() {
        let closure = ArchiveClosure {
            base_commit: "a".repeat(40),
            archive_path: "openspec/changes/archive/2026-07-16-add-thing".to_string(),
            transaction_id: Digest::of_bytes(b"txn"),
            candidate_id: None,
            allowed_paths: vec!["crates/mpd/**".to_string()],
            system_paths: vec!["openspec/changes/archive/2026-07-16-add-thing".to_string()],
            post_archive_digest: Digest::of_bytes(b"post"),
            archived_at: 1_752_000_000,
        };
        let json = serde_json::to_string(&closure).unwrap();
        let back: ArchiveClosure = serde_json::from_str(&json).unwrap();
        assert_eq!(closure, back);
    }

    /// A pre-`system_paths` archive-closure record (schema drift within this
    /// unreleased feature, or a hand-crafted legacy fixture) must still parse
    /// — `system_paths` degrades to empty rather than failing to load.
    #[test]
    fn archive_closure_without_system_paths_field_defaults_empty() {
        let legacy = r#"{"base_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "archive_path":"openspec/changes/archive/2026-07-16-add-thing",
            "transaction_id":"#
            .to_string()
            + &serde_json::to_string(&Digest::of_bytes(b"txn")).unwrap()
            + r#","allowed_paths":["crates/mpd/**"],
            "post_archive_digest":"#
            + &serde_json::to_string(&Digest::of_bytes(b"post")).unwrap()
            + r#","archived_at":1752000000}"#;
        let closure: ArchiveClosure = serde_json::from_str(&legacy).unwrap();
        assert!(closure.system_paths.is_empty());
    }

    #[test]
    fn pending_closure_pointer_round_trips_and_carries_transaction_state() {
        let pointer = PendingClosurePointer {
            version: PENDING_POINTER_SCHEMA,
            transaction_id: openspec_core::digest::Digest::of_bytes(b"txn"),
            change: "add-thing".to_string(),
            stage: openspec_core::TransactionState::AwaitingCommit,
        };
        let json = serde_json::to_string(&pointer).unwrap();
        assert!(json.contains("\"awaiting-commit\""));
        let back: PendingClosurePointer = serde_json::from_str(&json).unwrap();
        assert_eq!(pointer, back);
    }

    #[test]
    fn local_snapshot_round_trips() {
        let snap = LocalSnapshot {
            head: "b".repeat(40),
            index: Digest::of_bytes(b"index"),
            scoped: Digest::of_bytes(b"scoped"),
            included_clean: true,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: LocalSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn every_dependency_key_round_trips_through_its_kebab_case_slug() {
        // Exhaustive match (no wildcard arm) — adding a new variant without
        // a test update fails to compile, keeping the allowlist genuinely
        // closed as design.md requires.
        let all = [
            DependencyKey::Scope,
            DependencyKey::Source,
            DependencyKey::Governance,
            DependencyKey::Config,
            DependencyKey::DesignArtifacts,
            DependencyKey::DesignMockArtifact,
            DependencyKey::ArchitecturePlan,
            DependencyKey::TestCommand,
            DependencyKey::Toolchain,
            DependencyKey::ProducedArtifact,
            DependencyKey::ScannerIdentity,
            DependencyKey::AllowlistDigest,
            DependencyKey::DeployCommand,
            DependencyKey::ShippedBehavior,
            DependencyKey::Documentation,
            DependencyKey::HermeticPlatform,
            DependencyKey::HermeticExecutable,
            DependencyKey::HermeticEnvironment,
            DependencyKey::HermeticInput,
            DependencyKey::PersonaTuning,
        ];
        for key in all {
            let json = serde_json::to_string(&key).unwrap();
            let back: DependencyKey = serde_json::from_str(&json).unwrap();
            assert_eq!(back, key);
            match key {
                DependencyKey::Scope
                | DependencyKey::Source
                | DependencyKey::Governance
                | DependencyKey::Config
                | DependencyKey::DesignArtifacts
                | DependencyKey::DesignMockArtifact
                | DependencyKey::ArchitecturePlan
                | DependencyKey::TestCommand
                | DependencyKey::Toolchain
                | DependencyKey::ProducedArtifact
                | DependencyKey::ScannerIdentity
                | DependencyKey::AllowlistDigest
                | DependencyKey::DeployCommand
                | DependencyKey::ShippedBehavior
                | DependencyKey::Documentation
                | DependencyKey::HermeticPlatform
                | DependencyKey::HermeticExecutable
                | DependencyKey::HermeticEnvironment
                | DependencyKey::HermeticInput
                | DependencyKey::PersonaTuning => {}
            }
        }
    }

    #[test]
    fn dependency_key_label_matches_its_serde_tag() {
        // Keeps error/status text and the wire format from silently drifting
        // apart: `label()` must equal the quoted serde tag for every variant.
        for key in [
            DependencyKey::Scope,
            DependencyKey::Source,
            DependencyKey::Governance,
            DependencyKey::Config,
            DependencyKey::DesignArtifacts,
            DependencyKey::DesignMockArtifact,
            DependencyKey::ArchitecturePlan,
            DependencyKey::TestCommand,
            DependencyKey::Toolchain,
            DependencyKey::ProducedArtifact,
            DependencyKey::ScannerIdentity,
            DependencyKey::AllowlistDigest,
            DependencyKey::DeployCommand,
            DependencyKey::ShippedBehavior,
            DependencyKey::Documentation,
            DependencyKey::HermeticPlatform,
            DependencyKey::HermeticExecutable,
            DependencyKey::HermeticEnvironment,
            DependencyKey::HermeticInput,
            DependencyKey::PersonaTuning,
        ] {
            let tag = serde_json::to_string(&key).unwrap();
            assert_eq!(tag, format!("\"{}\"", key.label()));
            assert_eq!(key.to_string(), key.label());
        }
    }
}

// =====================================================================
// Manifest tests
// =====================================================================

#[cfg(test)]
mod manifest_tests {
    use super::*;

    fn ready_manifest() -> ChangeManifest {
        ChangeManifest {
            version: MANIFEST_SCHEMA,
            paths: vec!["crates/mpd/**".to_string()],
            shared_paths: vec!["README.md".to_string()],
            publish: Some(PublishTarget {
                remote: "origin".to_string(),
                reference: "refs/heads/main".to_string(),
            }),
        }
    }

    #[test]
    fn seed_has_no_declared_scope_and_round_trips() {
        let seed = ChangeManifest::seed();
        assert_eq!(seed.version, MANIFEST_SCHEMA);
        assert!(seed.paths.is_empty());
        assert!(seed.publish.is_none());
        assert_eq!(
            seed.validate(),
            vec![ManifestIssue::NoDeclaredScope],
            "an empty-scope seed is the ONLY expected issue"
        );
        assert!(!seed.is_ready());

        let json = ChangeManifest::seed_json();
        assert!(json.ends_with('\n'));
        let back: ChangeManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, seed);
    }

    #[test]
    fn ready_manifest_matches_design_doc_example_shape_and_validates_clean() {
        let manifest = ready_manifest();
        assert!(manifest.validate().is_empty(), "{:?}", manifest.validate());
        assert!(manifest.is_ready());
        // The exact JSON shape from design.md "Durable schemas".
        let json: serde_json::Value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["paths"][0], "crates/mpd/**");
        assert_eq!(json["publish"]["remote"], "origin");
        assert_eq!(json["publish"]["ref"], "refs/heads/main");
    }

    #[test]
    fn unknown_version_is_reported() {
        let mut manifest = ready_manifest();
        manifest.version = 2;
        assert!(manifest
            .validate()
            .contains(&ManifestIssue::UnknownVersion(2)));
    }

    #[test]
    fn unsafe_path_patterns_are_reported_for_both_fields() {
        for bad in ["/abs", "a/../b", "a/./b", "a\\b", "a\0b", "", ".."] {
            let mut manifest = ready_manifest();
            manifest.paths = vec![bad.to_string()];
            assert!(
                manifest.validate().iter().any(|i| matches!(
                    i,
                    ManifestIssue::UnsafePathPattern { field: "paths", pattern } if pattern == bad
                )),
                "expected {bad:?} to be reported unsafe in paths"
            );

            let mut manifest = ready_manifest();
            manifest.shared_paths = vec![bad.to_string()];
            assert!(manifest.validate().iter().any(|i| matches!(
                i,
                ManifestIssue::UnsafePathPattern { field: "shared_paths", pattern } if pattern == bad
            )));
        }
    }

    #[test]
    fn glob_patterns_with_wildcards_are_safe_patterns() {
        let mut manifest = ready_manifest();
        manifest.paths = vec!["**/spec.md".to_string(), "src/*.rs".to_string()];
        assert!(manifest.validate().is_empty(), "{:?}", manifest.validate());
    }

    #[test]
    fn too_many_patterns_is_reported() {
        let mut manifest = ready_manifest();
        manifest.paths = (0..MAX_MANIFEST_PATTERNS + 1)
            .map(|i| format!("p{i}"))
            .collect();
        assert!(manifest
            .validate()
            .iter()
            .any(|i| matches!(i, ManifestIssue::TooManyPatterns(_))));
    }

    #[test]
    fn unsafe_publish_remote_and_ref_are_reported_independently() {
        let mut manifest = ready_manifest();
        manifest.publish = Some(PublishTarget {
            remote: ".".to_string(),
            reference: "refs/heads/main".to_string(),
        });
        assert_eq!(
            manifest.validate(),
            vec![ManifestIssue::UnsafeRemoteName(".".to_string())]
        );

        let mut manifest = ready_manifest();
        manifest.publish = Some(PublishTarget {
            remote: "origin".to_string(),
            reference: "refs/tags/v1".to_string(),
        });
        assert_eq!(
            manifest.validate(),
            vec![ManifestIssue::UnsafeRef("refs/tags/v1".to_string())]
        );

        let mut manifest = ready_manifest();
        manifest.publish = Some(PublishTarget {
            remote: "--upload-pack=x".to_string(),
            reference: "-rf".to_string(),
        });
        let issues = manifest.validate();
        assert!(issues.contains(&ManifestIssue::UnsafeRemoteName(
            "--upload-pack=x".to_string()
        )));
        assert!(issues.contains(&ManifestIssue::UnsafeRef("-rf".to_string())));
    }

    #[test]
    fn publish_field_absent_means_no_publish_related_issues() {
        let manifest = ready_manifest();
        assert!(manifest.publish.is_some());
        let mut no_publish = manifest.clone();
        no_publish.publish = None;
        assert!(no_publish.validate().is_empty());
    }

    #[test]
    fn covers_matches_declared_shared_and_system_paths_only() {
        let manifest = ready_manifest();
        let system = SystemScope {
            change_dir: "openspec/changes/add-thing".to_string(),
            ledger_path: ".mpd/state/add-thing.json".to_string(),
            merged_spec_targets: vec!["openspec/specs/thing/spec.md".to_string()],
            doc_target: Some("docs/add-thing.md".to_string()),
            archive_target: "openspec/changes/archive/2026-07-16-add-thing".to_string(),
        };
        assert!(
            manifest.covers("crates/mpd/src/cli.rs", &system),
            "declared pattern"
        );
        assert!(manifest.covers("README.md", &system), "shared path");
        assert!(
            manifest.covers("openspec/changes/add-thing/proposal.md", &system),
            "nested under system change dir"
        );
        assert!(
            manifest.covers(".mpd/state/add-thing.json", &system),
            "exact ledger path"
        );
        assert!(manifest.covers("docs/add-thing.md", &system), "doc target");
        assert!(!manifest.covers("openspec/changes/other-thing/x", &system));
        assert!(
            !manifest.covers("openspec/changes/add-thing-evil/x", &system),
            "must not string-prefix-match a sibling directory"
        );
        assert!(!manifest.covers("random/unrelated.rs", &system));
    }
}

// =====================================================================
// SystemScope tests
// =====================================================================

#[cfg(test)]
mod system_scope_tests {
    use super::*;

    #[test]
    fn paths_are_sorted_and_deduplicated() {
        let scope = SystemScope {
            change_dir: "openspec/changes/z-change".to_string(),
            ledger_path: ".mpd/state/z-change.json".to_string(),
            merged_spec_targets: vec![
                "openspec/specs/b/spec.md".to_string(),
                "openspec/specs/a/spec.md".to_string(),
            ],
            doc_target: None,
            archive_target: "openspec/changes/archive/2026-07-16-z-change".to_string(),
        };
        let paths = scope.paths();
        let mut expected = paths.clone();
        expected.sort();
        expected.dedup();
        assert_eq!(paths, expected, "already sorted+deduped");
        assert_eq!(paths.len(), 5, "no doc target ⇒ 5 distinct entries");
        assert!(!paths.contains(&String::new()));
    }

    #[test]
    fn a_coincidental_duplicate_path_is_counted_once() {
        let scope = SystemScope {
            change_dir: "same/path".to_string(),
            ledger_path: ".mpd/state/x.json".to_string(),
            merged_spec_targets: vec!["same/path".to_string()],
            doc_target: Some(".mpd/state/x.json".to_string()),
            archive_target: "archive/x".to_string(),
        };
        let paths = scope.paths();
        assert_eq!(
            paths.len(),
            3,
            "duplicates of change_dir and ledger_path collapse"
        );
    }
}

// =====================================================================
// DependencyPolicy tests (golden table + phase-causality)
// =====================================================================

#[cfg(test)]
mod risk_classifier_tests {
    use super::*;

    fn manifest(path: &str) -> ChangeManifest {
        ChangeManifest {
            version: MANIFEST_SCHEMA,
            paths: vec![path.into()],
            shared_paths: vec![],
            publish: None,
        }
    }

    #[test]
    fn representative_sensitive_signals_and_unknown_sensitive_paths_are_high() {
        for path in [
            "src/auth/token.rs",
            "src/parser/decode.rs",
            "src/network/client.rs",
            "src/process/exec.rs",
            ".githooks/pre-push",
            "src/persistence/store.rs",
            "src/sandbox/profile.rs",
            "src/crypto/signature.rs",
            "src/deploy/install.rs",
            "security/unclassified-policy.data",
        ] {
            let result = classify_effective_risk(
                &manifest(path),
                &crate::config::Config::default(),
                RiskLevel::Low,
            );
            assert_eq!(result.derived, RiskLevel::High, "{path}");
            assert_eq!(result.effective, RiskLevel::High, "{path}");
            assert!(!result.reasons.is_empty(), "{path}");
            assert_eq!(result.signal_digest.len(), 64);
        }
    }

    #[test]
    fn candidate_config_and_deploy_signals_cannot_lower_requested_risk() {
        let config = crate::config::Config {
            deploy: Some("install reviewed artifact".into()),
            ..Default::default()
        };
        let result =
            classify_effective_risk(&manifest(".mpd/config.json"), &config, RiskLevel::Low);
        assert_eq!(result.requested, RiskLevel::Low);
        assert_eq!(result.derived, RiskLevel::High);
        assert_eq!(result.effective, RiskLevel::High);
    }

    #[test]
    fn source_is_not_a_security_plan_dependency() {
        assert!(!DependencyPolicy::for_phase(Phase::SecurityPlan).contains(&DependencyKey::Source));
        assert!(DependencyPolicy::for_phase(Phase::SecurityCode).contains(&DependencyKey::Source));
    }
}

#[cfg(test)]
mod dependency_policy_tests {
    use super::*;

    #[test]
    fn golden_dependency_policy_table() {
        use DependencyKey::*;
        assert_eq!(
            DependencyPolicy::for_phase(Phase::DesignMock),
            &[Scope, DesignMockArtifact, Governance]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::Architecture),
            &[Scope, ArchitecturePlan, Governance]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::DesignReview),
            &[Scope, DesignMockArtifact, ArchitecturePlan, Governance]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::SecurityPlan),
            &[Scope, ArchitecturePlan, Governance, PersonaTuning]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::Build),
            &[
                Scope,
                Source,
                TestCommand,
                Toolchain,
                ProducedArtifact,
                HermeticPlatform,
                HermeticExecutable,
                HermeticEnvironment,
                HermeticInput
            ]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::Test),
            &[
                Scope,
                Source,
                TestCommand,
                Toolchain,
                ProducedArtifact,
                PersonaTuning,
                HermeticPlatform,
                HermeticExecutable,
                HermeticEnvironment,
                HermeticInput
            ],
            "Test shares Build's shape plus PersonaTuning (governed set)"
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::SecurityCode),
            &[
                Scope,
                ArchitecturePlan,
                Governance,
                Source,
                ScannerIdentity,
                AllowlistDigest,
                PersonaTuning,
                HermeticPlatform,
                HermeticExecutable,
                HermeticEnvironment,
                HermeticInput
            ]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::DesignSignoff),
            &[Scope, DesignMockArtifact, ArchitecturePlan, Governance]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::Documentation),
            &[Scope, ShippedBehavior, Documentation]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::Deploy),
            &[Scope, Source, ProducedArtifact, DeployCommand]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::DocValidation),
            &[Scope, ShippedBehavior, Documentation, PersonaTuning]
        );
        assert_eq!(
            DependencyPolicy::for_phase(Phase::Done),
            &[] as &[DependencyKey]
        );
    }

    /// The earliest phase (inclusive) at which a [`DependencyKey`]'s content
    /// exists at all — an independent, hand-maintained oracle used only to
    /// mechanically prove no phase's policy binds a key that phase could not
    /// yet have seen (design.md "no receipt binds an output first created by
    /// a later phase"). Config/toolchain/deploy-command are configuration
    /// values (available from the start, not phase outputs); `ProducedArtifact`
    /// is first produced *by* Build itself (binding it within Build's own
    /// receipt is binding the phase's own just-created output, not a later
    /// phase's).
    fn earliest_available(key: DependencyKey) -> Phase {
        use DependencyKey::*;
        match key {
            // Config-like / directive inputs available from the start.
            Scope | Source | Governance | Config | DesignArtifacts | DesignMockArtifact
            | ArchitecturePlan | TestCommand | Toolchain | DeployCommand | PersonaTuning
            | HermeticPlatform | HermeticExecutable | HermeticEnvironment | HermeticInput => {
                Phase::DesignMock
            }
            ProducedArtifact => Phase::Build,
            ScannerIdentity | AllowlistDigest => Phase::SecurityCode,
            ShippedBehavior => Phase::Test,
            Documentation => Phase::Documentation,
        }
    }

    #[test]
    fn persona_tuning_digest_is_narrow_to_the_persona_not_the_whole_config() {
        // R6b / round-2 F3: the PersonaTuning digest covers only THIS persona's
        // effective directive (config tuning + base directive text), so an
        // unrelated config edit (test command) does NOT stale it, while a change to
        // the persona's tuning DOES.
        let dir = std::env::temp_dir().join(format!("mpd-ptd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let base = crate::config::Config {
            test: Some("cargo test".to_string()),
            ..Default::default()
        };
        let unrelated = crate::config::Config {
            test: Some("a totally different command".to_string()),
            ..base.clone()
        };
        let d_base = persona_tuning_digest(&dir, &base, Phase::SecurityCode).unwrap();
        assert_eq!(
            d_base,
            persona_tuning_digest(&dir, &unrelated, Phase::SecurityCode).unwrap(),
            "an unrelated config edit must NOT stale the persona-tuning digest"
        );

        let mut tuned = base.clone();
        tuned.personas.insert(
            "Security".to_string(),
            crate::config::PersonaTuning {
                directive_append: Some("also check IMAP cleartext".to_string()),
                ..Default::default()
            },
        );
        assert_ne!(
            d_base,
            persona_tuning_digest(&dir, &tuned, Phase::SecurityCode).unwrap(),
            "a Security tuning change MUST stale the persona-tuning digest"
        );
        // But that Security tuning does NOT stale a DIFFERENT persona's digest.
        assert_eq!(
            persona_tuning_digest(&dir, &base, Phase::Test).unwrap(),
            persona_tuning_digest(&dir, &tuned, Phase::Test).unwrap(),
            "tuning Security must not stale the Tester's digest"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_policy_binds_an_output_first_created_by_a_later_phase() {
        use crate::phase::PIPELINE;
        for &phase in PIPELINE.iter().chain(std::iter::once(&Phase::Done)) {
            for &key in DependencyPolicy::for_phase(phase) {
                assert!(
                    earliest_available(key) <= phase,
                    "{phase:?}'s policy binds {key:?}, first available only at \
                     {:?} — phase-causality violation",
                    earliest_available(key)
                );
            }
        }
    }

    #[test]
    fn mutating_the_documentation_dependency_key_does_not_stale_a_build_receipt() {
        // POLICY-KEY-LEVEL guarantee only: the abstract `Documentation` key is
        // not in Build's dependency policy, so mutating it never stales a Build
        // receipt. This uses hand-built DependencyValues with distinct keys and
        // deliberately does NOT exercise the concrete `source_digest` capture —
        // the production coupling where documentation.md could leak into the
        // Source key is regression-tested by
        // `source_digest_excludes_change_process_artifacts_so_a_doc_edit_does_not_stale_source`
        // (Security-code finding source-includes-later-phase-output).
        let build_values = DependencyValues::new()
            .with(DependencyKey::Scope, Digest::of_bytes(b"scope-v1"))
            .with(DependencyKey::Source, Digest::of_bytes(b"src-v1"))
            .with(DependencyKey::TestCommand, Digest::of_bytes(b"cargo test"))
            .with(DependencyKey::Toolchain, Digest::of_bytes(b"rustc-1.80"))
            .with(DependencyKey::ProducedArtifact, Digest::of_bytes(b"bin-v1"));
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &build_values).unwrap();
        let receipt = EvidenceReceipt::executed(Phase::Build, snapshot);

        let mut later_values = build_values.clone();
        later_values.set(DependencyKey::Documentation, Digest::of_bytes(b"doc-v1"));
        assert_eq!(
            evidence_validity(Some(&receipt), &later_values),
            EvidenceValidity::Valid
        );

        // Mutate the "later" Documentation digest again — still irrelevant.
        later_values.set(
            DependencyKey::Documentation,
            Digest::of_bytes(b"doc-v2-edited"),
        );
        assert_eq!(
            evidence_validity(Some(&receipt), &later_values),
            EvidenceValidity::Valid,
            "Documentation edits after Build must never stale the Build receipt"
        );
    }
}

// =====================================================================
// Evidence validity tests
// =====================================================================

#[cfg(test)]
mod evidence_validity_tests {
    use super::*;

    fn build_values(source: &[u8]) -> DependencyValues {
        DependencyValues::new()
            .with(DependencyKey::Scope, Digest::of_bytes(b"scope-v1"))
            .with(DependencyKey::Source, Digest::of_bytes(source))
            .with(DependencyKey::TestCommand, Digest::of_bytes(b"cargo test"))
            .with(DependencyKey::Toolchain, Digest::of_bytes(b"rustc-1.80"))
            .with(DependencyKey::ProducedArtifact, Digest::of_bytes(b"bin-v1"))
    }

    #[test]
    fn legacy_absent_receipt_is_absent() {
        assert_eq!(
            evidence_validity(None, &DependencyValues::new()),
            EvidenceValidity::Absent
        );
    }

    #[test]
    fn unchanged_dependencies_are_valid() {
        let values = build_values(b"src-v1");
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &values).unwrap();
        let receipt = EvidenceReceipt::executed(Phase::Build, snapshot);
        assert_eq!(
            evidence_validity(Some(&receipt), &values),
            EvidenceValidity::Valid
        );
    }

    #[test]
    fn mutating_each_dependency_independently_yields_stale_naming_exactly_that_key() {
        let baseline = build_values(b"src-v1");
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &baseline).unwrap();
        let receipt = EvidenceReceipt::executed(Phase::Build, snapshot);

        let mutations: &[(DependencyKey, &[u8])] = &[
            (DependencyKey::Source, b"src-v2-MUTATED"),
            (DependencyKey::TestCommand, b"cargo test --release-MUTATED"),
            (DependencyKey::Toolchain, b"rustc-1.81-MUTATED"),
            (DependencyKey::ProducedArtifact, b"bin-v2-MUTATED"),
        ];
        for &(key, mutated_bytes) in mutations {
            let mut current = baseline.clone();
            current.set(key, Digest::of_bytes(mutated_bytes));
            let validity = evidence_validity(Some(&receipt), &current);
            match validity {
                EvidenceValidity::Stale(reasons) => {
                    assert_eq!(
                        reasons,
                        vec![StaleReason::DependencyChanged(key)],
                        "mutating only {key:?} must report exactly that one changed class"
                    );
                }
                other => panic!("expected Stale for mutated {key:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn schema_mismatch_is_stale() {
        let values = build_values(b"src-v1");
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &values).unwrap();
        let mut receipt = EvidenceReceipt::executed(Phase::Build, snapshot);
        receipt.schema = RECEIPT_SCHEMA + 1;
        match evidence_validity(Some(&receipt), &values) {
            EvidenceValidity::Stale(reasons) => assert!(reasons
                .iter()
                .any(|r| matches!(r, StaleReason::SchemaChanged { .. }))),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn hermetic_key_absent_in_both_receipt_and_current_is_not_stale() {
        let values = build_values(b"src-v1");
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &values).unwrap();
        let receipt = EvidenceReceipt::executed(Phase::Build, snapshot);
        // Neither the receipt nor `values` binds any Hermetic* key.
        assert_eq!(
            evidence_validity(Some(&receipt), &values),
            EvidenceValidity::Valid
        );
    }

    #[test]
    fn hermetic_key_newly_available_does_not_retroactively_stale() {
        let values = build_values(b"src-v1");
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &values).unwrap();
        let receipt = EvidenceReceipt::executed(Phase::Build, snapshot);
        let mut with_hermetic = values.clone();
        with_hermetic.set(
            DependencyKey::HermeticPlatform,
            Digest::of_bytes(b"macos-arm64"),
        );
        assert_eq!(
            evidence_validity(Some(&receipt), &with_hermetic),
            EvidenceValidity::Valid,
            "a hermetic key only current has (not the old receipt) doesn't invalidate content"
        );
    }

    #[test]
    fn losing_a_previously_bound_hermetic_value_is_stale() {
        let mut values = build_values(b"src-v1");
        values.set(
            DependencyKey::HermeticPlatform,
            Digest::of_bytes(b"macos-arm64"),
        );
        values.set(
            DependencyKey::HermeticExecutable,
            Digest::of_bytes(b"rustc-bytes"),
        );
        values.set(
            DependencyKey::HermeticEnvironment,
            Digest::of_bytes(b"env-digest"),
        );
        values.set(
            DependencyKey::HermeticInput,
            Digest::of_bytes(b"input-digest"),
        );
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &values).unwrap();
        let receipt = EvidenceReceipt::executed(Phase::Build, snapshot);

        let mut without_hermetic = values.clone();
        without_hermetic.0.remove(&DependencyKey::HermeticPlatform);
        match evidence_validity(Some(&receipt), &without_hermetic) {
            EvidenceValidity::Stale(reasons) => assert_eq!(
                reasons,
                vec![StaleReason::DependencyChanged(
                    DependencyKey::HermeticPlatform
                )]
            ),
            other => panic!("expected Stale, got {other:?}"),
        }
    }
}

// =====================================================================
// Reuse eligibility + decision tests
// =====================================================================

#[cfg(test)]
mod reuse_tests {
    use super::*;

    fn judgment_snapshot() -> DependencySnapshot {
        let values = DependencyValues::new()
            .with(DependencyKey::Scope, Digest::of_bytes(b"scope-v1"))
            .with(
                DependencyKey::DesignArtifacts,
                Digest::of_bytes(b"design-v1"),
            )
            .with(
                DependencyKey::Governance,
                Digest::of_bytes(b"governance-v1"),
            );
        DependencySnapshot::for_phase(Phase::Architecture, &values).unwrap()
    }

    fn build_snapshot(hermetic: bool) -> DependencySnapshot {
        let mut values = DependencyValues::new()
            .with(DependencyKey::Scope, Digest::of_bytes(b"scope-v1"))
            .with(DependencyKey::Source, Digest::of_bytes(b"src-v1"))
            .with(DependencyKey::TestCommand, Digest::of_bytes(b"cargo test"))
            .with(DependencyKey::Toolchain, Digest::of_bytes(b"rustc-1.80"))
            .with(DependencyKey::ProducedArtifact, Digest::of_bytes(b"bin-v1"));
        if hermetic {
            values.set(
                DependencyKey::HermeticPlatform,
                Digest::of_bytes(b"macos-arm64"),
            );
            values.set(
                DependencyKey::HermeticExecutable,
                Digest::of_bytes(b"rustc-bytes"),
            );
            values.set(
                DependencyKey::HermeticEnvironment,
                Digest::of_bytes(b"env-digest"),
            );
            values.set(
                DependencyKey::HermeticInput,
                Digest::of_bytes(b"input-digest"),
            );
        }
        DependencySnapshot::for_phase(Phase::Build, &values).unwrap()
    }

    #[test]
    fn deploy_is_never_reusable_regardless_of_validity() {
        assert_eq!(
            reuse_offer(Phase::Deploy, Verdict::Pass, &EvidenceValidity::Valid, None),
            ReuseOffer::NeverReusable
        );
        let receipt = EvidenceReceipt::executed(
            Phase::Deploy,
            DependencySnapshot::for_phase(
                Phase::Deploy,
                &DependencyValues::new()
                    .with(DependencyKey::Scope, Digest::of_bytes(b"scope-v1"))
                    .with(DependencyKey::Source, Digest::of_bytes(b"s"))
                    .with(DependencyKey::ProducedArtifact, Digest::of_bytes(b"a"))
                    .with(DependencyKey::DeployCommand, Digest::of_bytes(b"d")),
            )
            .unwrap(),
        );
        assert_eq!(
            evaluate_reuse(
                Phase::Deploy,
                Verdict::Pass,
                &receipt,
                &EvidenceValidity::Valid
            ),
            Err(ReuseRefusal::DeployNeverReusable)
        );
    }

    #[test]
    fn not_valid_evidence_is_never_offered() {
        assert_eq!(
            reuse_offer(
                Phase::Architecture,
                Verdict::Pass,
                &EvidenceValidity::Absent,
                None
            ),
            ReuseOffer::NotOffered
        );
        assert_eq!(
            reuse_offer(
                Phase::Architecture,
                Verdict::Pass,
                &EvidenceValidity::Stale(vec![]),
                None
            ),
            ReuseOffer::NotOffered
        );
    }

    #[test]
    fn fail_origin_is_never_offered() {
        assert_eq!(
            reuse_offer(
                Phase::Architecture,
                Verdict::Fail,
                &EvidenceValidity::Valid,
                None
            ),
            ReuseOffer::NotOffered
        );
    }

    #[test]
    fn conditional_pass_is_refused_even_though_content_is_valid() {
        assert_eq!(
            reuse_offer(
                Phase::Architecture,
                Verdict::ConditionalPass,
                &EvidenceValidity::Valid,
                None
            ),
            ReuseOffer::ConditionalRefused
        );
    }

    #[test]
    fn conditional_receipt_reuse_is_refused_even_after_the_condition_later_closed() {
        // A closed `Condition` (ledger.rs) never rewrites a GateRecord's own
        // recorded Verdict — the origin verdict stays ConditionalPass
        // forever, so this refusal is structurally permanent regardless of
        // condition-closing state (evidence-reuse/spec.md "Conditional
        // approval was later resolved").
        let origin = EvidenceReceipt::executed(Phase::Architecture, judgment_snapshot());
        let validity = evidence_validity(
            Some(&origin),
            &DependencyValues::new()
                .with(DependencyKey::Scope, Digest::of_bytes(b"scope-v1"))
                .with(
                    DependencyKey::DesignArtifacts,
                    Digest::of_bytes(b"design-v1"),
                )
                .with(
                    DependencyKey::Governance,
                    Digest::of_bytes(b"governance-v1"),
                ),
        );
        assert_eq!(validity, EvidenceValidity::Valid);
        assert_eq!(
            evaluate_reuse(
                Phase::Architecture,
                Verdict::ConditionalPass,
                &origin,
                &validity
            ),
            Err(ReuseRefusal::OriginWasConditional),
            "must refuse regardless of whether the original condition was later closed"
        );
    }

    #[test]
    fn judgment_phase_valid_pass_is_eligible() {
        assert_eq!(
            reuse_offer(
                Phase::Architecture,
                Verdict::Pass,
                &EvidenceValidity::Valid,
                None
            ),
            ReuseOffer::Eligible
        );
    }

    #[test]
    fn execution_phase_without_hermetic_policy_always_executes() {
        let snapshot = build_snapshot(false);
        assert_eq!(
            reuse_offer(
                Phase::Build,
                Verdict::Pass,
                &EvidenceValidity::Valid,
                Some(&snapshot)
            ),
            ReuseOffer::AlwaysExecutes
        );
        assert!(!hermetic_complete(&snapshot));
    }

    #[test]
    fn hermetic_incomplete_snapshot_is_non_reusable() {
        // Three of four hermetic keys bound — still incomplete.
        let values = DependencyValues::new()
            .with(DependencyKey::Scope, Digest::of_bytes(b"scope-v1"))
            .with(DependencyKey::Source, Digest::of_bytes(b"src-v1"))
            .with(DependencyKey::TestCommand, Digest::of_bytes(b"cargo test"))
            .with(DependencyKey::Toolchain, Digest::of_bytes(b"rustc-1.80"))
            .with(DependencyKey::ProducedArtifact, Digest::of_bytes(b"bin-v1"))
            .with(
                DependencyKey::HermeticPlatform,
                Digest::of_bytes(b"macos-arm64"),
            )
            .with(
                DependencyKey::HermeticExecutable,
                Digest::of_bytes(b"rustc-bytes"),
            )
            .with(
                DependencyKey::HermeticEnvironment,
                Digest::of_bytes(b"env-digest"),
            );
        let snapshot = DependencySnapshot::for_phase(Phase::Build, &values).unwrap();
        assert!(!hermetic_complete(&snapshot), "missing HermeticInput");
        assert_eq!(
            reuse_offer(
                Phase::Build,
                Verdict::Pass,
                &EvidenceValidity::Valid,
                Some(&snapshot)
            ),
            ReuseOffer::AlwaysExecutes
        );
        let origin = EvidenceReceipt::executed(Phase::Build, snapshot);
        assert_eq!(
            evaluate_reuse(
                Phase::Build,
                Verdict::Pass,
                &origin,
                &EvidenceValidity::Valid
            ),
            Err(ReuseRefusal::AlwaysExecutes)
        );
    }

    #[test]
    fn hermetic_complete_snapshot_is_eligible_and_reusable() {
        let snapshot = build_snapshot(true);
        assert!(hermetic_complete(&snapshot));
        assert_eq!(
            reuse_offer(
                Phase::Build,
                Verdict::Pass,
                &EvidenceValidity::Valid,
                Some(&snapshot)
            ),
            ReuseOffer::HermeticEligible
        );
        let origin = EvidenceReceipt::executed(Phase::Build, snapshot);
        assert_eq!(
            evaluate_reuse(
                Phase::Build,
                Verdict::Pass,
                &origin,
                &EvidenceValidity::Valid
            ),
            Ok(())
        );
    }

    #[test]
    fn reused_receipt_flattens_to_the_executed_origin_and_appends_no_new_check() {
        let origin = EvidenceReceipt::executed(Phase::Architecture, judgment_snapshot());
        let reused = EvidenceReceipt::reused_from(&origin);
        assert_eq!(
            reused.disposition,
            EvidenceDisposition::Reused {
                source_receipt: origin.id
            }
        );
        assert_eq!(reused.dependencies, origin.dependencies);
        assert_eq!(reused.phase, origin.phase);
        assert_ne!(reused.id, origin.id, "disposition differs ⇒ different id");

        // Reusing an already-reused receipt still points at the ORIGINAL
        // executed receipt, never chaining through the intermediate one.
        let doubly_reused = EvidenceReceipt::reused_from(&reused);
        assert_eq!(
            doubly_reused.disposition,
            EvidenceDisposition::Reused {
                source_receipt: origin.id
            }
        );
    }

    #[test]
    fn evaluate_reuse_refuses_a_reused_candidate_as_its_own_origin() {
        let origin = EvidenceReceipt::executed(Phase::Architecture, judgment_snapshot());
        let reused = EvidenceReceipt::reused_from(&origin);
        assert_eq!(
            evaluate_reuse(
                Phase::Architecture,
                Verdict::Pass,
                &reused,
                &EvidenceValidity::Valid
            ),
            Err(ReuseRefusal::NotAnExecutedOrigin)
        );
    }

    #[test]
    fn evaluate_reuse_refuses_stale_and_fail_origins() {
        let origin = EvidenceReceipt::executed(Phase::Architecture, judgment_snapshot());
        assert_eq!(
            evaluate_reuse(
                Phase::Architecture,
                Verdict::Pass,
                &origin,
                &EvidenceValidity::Stale(vec![StaleReason::DependencyChanged(
                    DependencyKey::Governance
                )])
            ),
            Err(ReuseRefusal::NotValid)
        );
        assert_eq!(
            evaluate_reuse(
                Phase::Architecture,
                Verdict::Fail,
                &origin,
                &EvidenceValidity::Valid
            ),
            Err(ReuseRefusal::OriginWasFail)
        );
    }
}

// =====================================================================
// HermeticReusePolicy validation tests
// =====================================================================

#[cfg(test)]
mod hermetic_policy_tests {
    use super::*;

    fn policy(environment: &[&str], input_paths: &[&str]) -> HermeticReusePolicy {
        HermeticReusePolicy {
            schema: HERMETIC_POLICY_SCHEMA,
            external_state: NoExternalState::None,
            environment: environment.iter().map(|s| s.to_string()).collect(),
            input_paths: input_paths.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn empty_policy_is_complete() {
        let p = policy(&[], &[]);
        assert!(p.is_complete(), "{:?}", p.validate());
    }

    #[test]
    fn safe_environment_names_and_paths_are_complete() {
        let p = policy(&["CI", "RUSTFLAGS", "LANG"], &["crates/mpd/build.rs"]);
        assert!(p.is_complete(), "{:?}", p.validate());
    }

    #[test]
    fn secret_shaped_environment_names_are_rejected() {
        for bad in [
            "GITHUB_TOKEN",
            "API_KEY",
            "DB_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "CLIENT_SECRET",
            "SSH_AUTH_SOCK",
        ] {
            let p = policy(&[bad], &[]);
            assert!(
                p.validate()
                    .contains(&HermeticPolicyIssue::SecretShapedEnvironmentName(
                        bad.to_string()
                    )),
                "expected {bad:?} to be rejected as secret-shaped: {:?}",
                p.validate()
            );
            assert!(is_secret_shaped_env_name(bad));
        }
    }

    #[test]
    fn unsafe_environment_variable_syntax_is_rejected() {
        for bad in ["1BAD", "has space", "", "has-dash", "has.dot"] {
            let p = policy(&[bad], &[]);
            assert!(
                p.validate().iter().any(
                    |i| matches!(i, HermeticPolicyIssue::UnsafeEnvironmentName(n) if n == bad)
                ),
                "expected {bad:?} rejected: {:?}",
                p.validate()
            );
        }
    }

    #[test]
    fn unsafe_input_paths_are_rejected() {
        for bad in ["../secret", "/abs/path", "a\\b"] {
            let p = policy(&[], &[bad]);
            assert!(p
                .validate()
                .contains(&HermeticPolicyIssue::UnsafeInputPath(bad.to_string())));
        }
    }

    #[test]
    fn unknown_schema_version_is_rejected() {
        let mut p = policy(&[], &[]);
        p.schema = HERMETIC_POLICY_SCHEMA + 1;
        assert!(p.validate().contains(&HermeticPolicyIssue::UnknownVersion(
            HERMETIC_POLICY_SCHEMA + 1
        )));
    }
}

// =====================================================================
// Manifest file I/O tests
// =====================================================================

#[cfg(test)]
mod manifest_io_tests {
    use super::*;
    use std::fs;

    fn unique_root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mpd-closure-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("openspec").join("changes").join("add-thing")).unwrap();
        dir
    }

    #[test]
    fn missing_manifest_is_not_found() {
        let root = unique_root("missing");
        assert_eq!(
            load_manifest(&root, "add-thing"),
            Err(ManifestLoadError::NotFound)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_change_name_is_rejected_before_any_read() {
        let root = unique_root("badname");
        match load_manifest(&root, "../escape") {
            Err(ManifestLoadError::InvalidChangeName(_)) => {}
            other => panic!("expected InvalidChangeName, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn save_then_load_round_trips() {
        let root = unique_root("roundtrip");
        let manifest = ChangeManifest {
            version: MANIFEST_SCHEMA,
            paths: vec!["crates/mpd/**".to_string()],
            shared_paths: vec![],
            publish: None,
        };
        save_manifest(&root, "add-thing", &manifest).unwrap();
        let loaded = load_manifest(&root, "add-thing").unwrap();
        assert_eq!(loaded, manifest);
        // Written file matches the exact durable-JSON convention (pretty,
        // trailing newline).
        let path = manifest_path(&root, "add-thing").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_json_fails_closed() {
        let root = unique_root("malformed");
        let path = manifest_path(&root, "add-thing").unwrap();
        fs::write(&path, "{ not json").unwrap();
        match load_manifest(&root, "add-thing") {
            Err(ManifestLoadError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_symlinked_manifest() {
        use std::os::unix::fs::symlink;
        let root = unique_root("symlink-load");
        let outside = root.join("outside-manifest.json");
        fs::write(
            &outside,
            r#"{"version":1,"paths":["EXFIL/**"],"shared_paths":[]}"#,
        )
        .unwrap();
        let target = manifest_path(&root, "add-thing").unwrap();
        symlink(&outside, &target).unwrap();
        match load_manifest(&root, "add-thing") {
            Err(ManifestLoadError::Unsafe(_)) => {}
            other => panic!("expected Unsafe (symlink refused), got {other:?}"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_a_symlinked_manifest_target() {
        use std::os::unix::fs::symlink;
        let root = unique_root("symlink-save");
        let outside = root.join("outside-manifest.json");
        fs::write(&outside, "stale").unwrap();
        let target = manifest_path(&root, "add-thing").unwrap();
        symlink(&outside, &target).unwrap();
        let manifest = ChangeManifest::seed();
        assert!(save_manifest(&root, "add-thing", &manifest).is_err());
        // The outside file must be untouched.
        assert_eq!(fs::read_to_string(&outside).unwrap(), "stale");
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod candidate_closure_tests {
    use super::*;
    use std::fs;
    use std::process::Command as StdCommand;

    fn tree_entry(path: &str, mode: u32, bytes: &[u8]) -> ClosureTreeEntry {
        ClosureTreeEntry {
            path: path.into(),
            mode,
            byte_len: bytes.len() as u64,
            sha256: Digest::of_bytes(bytes).to_hex(),
        }
    }

    fn plan(entries: Vec<ClosureTreeEntry>, base: &str) -> CandidateClosurePlan {
        CandidateClosurePlan {
            schema: CANDIDATE_CLOSURE_SCHEMA,
            candidate_id: "a".repeat(64),
            candidate_base_commit: base.into(),
            archive_path: "openspec/changes/archive/2026-07-19-change".into(),
            archive_transaction_id: "b".repeat(64),
            overlay_digest: "c".repeat(64),
            expected_tree_digest: closure_tree_digest(&entries).unwrap(),
            entries,
        }
    }

    #[test]
    fn exact_tree_keeps_candidate_and_commit_subjects_separate() {
        let entries = vec![tree_entry("src/main.rs", 0o100644, b"fn main() {}\n")];
        let proof = compare_candidate_closure_entries(
            &plan(entries.clone(), &"1".repeat(40)),
            &"2".repeat(40),
            &entries,
        )
        .unwrap();
        assert!(proof.equivalent, "{:?}", proof.blockers);
        assert_eq!(proof.candidate_id, "a".repeat(64));
        assert_eq!(proof.commit_oid, "2".repeat(40));
        assert_ne!(proof.candidate_id, proof.commit_oid);
    }

    #[test]
    fn full_tree_comparison_rejects_every_required_mismatch_family() {
        let expected = vec![
            tree_entry("config/app.json", 0o100644, b"{}\n"),
            tree_entry("scripts/check.sh", 0o100755, b"#!/bin/sh\n"),
            tree_entry("src/main.rs", 0o100644, b"source\n"),
            tree_entry(
                "openspec/changes/archive/2026-07-19-change/tasks.md",
                0o100644,
                b"- [x] done\n",
            ),
            tree_entry(
                "openspec/changes/archive/2026-07-19-change/test.md",
                0o100644,
                b"fresh overlay\n",
            ),
        ];
        let expected_plan = plan(expected.clone(), &"1".repeat(40));
        let cases = [
            (
                "extra",
                {
                    let mut v = expected.clone();
                    v.push(tree_entry("extra.txt", 0o100644, b"extra"));
                    v.sort_by(|a, b| a.path.cmp(&b.path));
                    v
                },
                "extra path",
            ),
            ("missing", expected[1..].to_vec(), "missing path"),
            (
                "source",
                replace(&expected, "src/main.rs", 0o100644, b"changed\n"),
                "content digest mismatch",
            ),
            (
                "config",
                replace(
                    &expected,
                    "config/app.json",
                    0o100644,
                    b"{\"lowered\":true}\n",
                ),
                "content digest mismatch",
            ),
            (
                "script",
                replace(
                    &expected,
                    "scripts/check.sh",
                    0o100755,
                    b"#!/bin/sh\nexit 0\n",
                ),
                "content digest mismatch",
            ),
            (
                "task",
                replace(
                    &expected,
                    "openspec/changes/archive/2026-07-19-change/tasks.md",
                    0o100644,
                    b"- [ ] reopened\n",
                ),
                "content digest mismatch",
            ),
            (
                "mode",
                replace(&expected, "scripts/check.sh", 0o100644, b"#!/bin/sh\n"),
                "mode mismatch",
            ),
            (
                "rename",
                {
                    let mut v = expected.clone();
                    v.retain(|entry| entry.path != "src/main.rs");
                    v.push(tree_entry("src/renamed.rs", 0o100644, b"source\n"));
                    v.sort_by(|a, b| a.path.cmp(&b.path));
                    v
                },
                "missing path",
            ),
            (
                "deletion",
                expected[..expected.len() - 1].to_vec(),
                "missing path",
            ),
            (
                "stale-overlay",
                replace(
                    &expected,
                    "openspec/changes/archive/2026-07-19-change/test.md",
                    0o100644,
                    b"stale overlay\n",
                ),
                "content digest mismatch",
            ),
        ];
        for (label, observed, blocker) in cases {
            let proof =
                compare_candidate_closure_entries(&expected_plan, &"2".repeat(40), &observed)
                    .unwrap();
            assert!(!proof.equivalent, "{label} unexpectedly passed");
            assert!(
                proof.blockers.iter().any(|value| value.contains(blocker)),
                "{label}: {:?}",
                proof.blockers
            );
        }
    }

    fn replace(
        entries: &[ClosureTreeEntry],
        path: &str,
        mode: u32,
        bytes: &[u8],
    ) -> Vec<ClosureTreeEntry> {
        entries
            .iter()
            .map(|entry| {
                if entry.path == path {
                    tree_entry(path, mode, bytes)
                } else {
                    entry.clone()
                }
            })
            .collect()
    }

    #[test]
    fn direct_commit_materialization_is_compared_by_path_mode_and_sha256() {
        let root = std::env::temp_dir().join(format!(
            "mpd-candidate-closure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        run_git(&root, &["init", "--quiet", "--initial-branch=main"]);
        fs::write(root.join("src/main.rs"), b"fn main() {}\n").unwrap();
        run_git(&root, &["add", "src/main.rs"]);
        run_git(&root, &["commit", "--quiet", "-m", "closure"]);
        let commit = git::head_commit(&root).unwrap().unwrap();
        let entries = vec![tree_entry("src/main.rs", 0o100644, b"fn main() {}\n")];
        let proof =
            verify_candidate_commit_equivalence(&root, &commit, &plan(entries, &commit)).unwrap();
        assert!(proof.equivalent, "{:?}", proof.blockers);
        assert_eq!(proof.commit_oid, commit);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn modern_commit_coherence_requires_the_saved_candidate_closure_plan() {
        let root = std::env::temp_dir().join(format!(
            "mpd-candidate-coherence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        run_git(&root, &["init", "--quiet", "--initial-branch=main"]);
        fs::write(root.join("README.md"), b"base\n").unwrap();
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "--quiet", "-m", "base"]);
        let base = git::head_commit(&root).unwrap().unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), b"fn main() {}\n").unwrap();
        run_git(&root, &["add", "src/main.rs"]);
        run_git(&root, &["commit", "--quiet", "-m", "closure"]);

        let entries = vec![
            tree_entry("README.md", 0o100644, b"base\n"),
            tree_entry("src/main.rs", 0o100644, b"fn main() {}\n"),
        ];
        let candidate_plan = plan(entries, &base);
        save_candidate_closure_plan(&root, &candidate_plan).unwrap();
        let allowed_paths = vec!["**".to_string()];
        let closure = ArchiveClosure {
            base_commit: base,
            archive_path: candidate_plan.archive_path.clone(),
            transaction_id: Digest::from_hex(&candidate_plan.archive_transaction_id).unwrap(),
            candidate_id: Some(candidate_plan.candidate_id.clone()),
            allowed_paths: allowed_paths.clone(),
            system_paths: Vec::new(),
            post_archive_digest: scoped_digest_for_patterns(&root, &allowed_paths).unwrap(),
            archived_at: 1,
        };
        let coherent = verify_commit_coherence(&root, &closure).unwrap();
        assert!(coherent.coherent, "{:?}", coherent.blockers);

        fs::remove_file(
            candidate_closure_plan_directory(&root, false)
                .unwrap()
                .join(format!("{}.json", candidate_plan.archive_transaction_id)),
        )
        .unwrap();
        let missing = verify_commit_coherence(&root, &closure).unwrap();
        assert!(!missing.coherent);
        assert!(missing
            .blockers
            .iter()
            .any(|blocker| blocker.contains("plan is unavailable")));
        fs::remove_dir_all(root).unwrap();
    }

    fn run_git(root: &Path, args: &[&str]) {
        let status = StdCommand::new("git")
            .args(args)
            .current_dir(root)
            .env("GIT_AUTHOR_NAME", "Closure Test")
            .env("GIT_AUTHOR_EMAIL", "closure@example.com")
            .env("GIT_COMMITTER_NAME", "Closure Test")
            .env("GIT_COMMITTER_EMAIL", "closure@example.com")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }
}

// =====================================================================
// Commit-coherence + remote-parity tests (real Git repositories)
// =====================================================================
//
// These drive `verify_commit_coherence` and `verify_remote_parity` against
// real temporary Git repositories and local bare remotes — the exact fixture
// class design.md's risk-to-test map and security-plan.md require ("Hidden
// intermediate path", "Remote misclassification", "TOCTOU/resource/privacy").
// Every fixture git invocation here is test-only setup, never production
// code — production Git calls all go through `crate::git`'s argument-array
// plumbing adapters.
#[cfg(test)]
mod remote_parity_tests {
    use super::*;
    use std::fs;
    use std::process::Command as StdCommand;

    /// A guaranteed-unique temp directory, even when two tests race to call
    /// this within the same clock tick under parallel `cargo test` execution
    /// (an earlier version keyed only on `label` + pid + nanoseconds, which
    /// let two concurrently running tests compute the *same* path and
    /// `remove_dir_all` out from under each other's in-flight repository —
    /// the process-wide atomic counter closes that race unconditionally).
    fn unique_dir(label: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "mpd-closure-parity-{label}-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Run a real `git` subcommand for test-fixture setup. `init` retries
    /// briefly: its hook-template copy has a known transient race under
    /// heavy parallel test execution (mirrors `git.rs`'s own test helper),
    /// an environmental flake rather than a production-code defect.
    fn run_git(dir: &Path, args: &[&str]) {
        let is_init = args.first() == Some(&"init");
        let attempts = if is_init { 5 } else { 1 };
        let mut last_status = None;
        for attempt in 0..attempts {
            let status = StdCommand::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .env("GIT_PAGER", "cat")
                .env("GIT_TERMINAL_PROMPT", "0")
                .status()
                .expect("git available on PATH");
            if status.success() {
                return;
            }
            last_status = Some(status);
            if attempt + 1 < attempts {
                std::thread::sleep(std::time::Duration::from_millis(20 * (attempt as u64 + 1)));
            }
        }
        panic!(
            "git {args:?} failed in {} (status: {:?})",
            dir.display(),
            last_status
        );
    }

    /// As [`run_git`], returning trimmed stdout — used for the plumbing
    /// (`rev-parse`, `commit-tree`) fixtures need their own output back.
    fn run_git_capture(dir: &Path, args: &[&str]) -> String {
        let output = StdCommand::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .env("GIT_PAGER", "cat")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git available on PATH");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output is UTF-8")
            .trim()
            .to_string()
    }

    fn init_repo_labeled(label: &str) -> PathBuf {
        let dir = unique_dir(label);
        run_git(&dir, &["init", "--quiet", "--initial-branch=main"]);
        // `save_parity_cache` writes `.mpd/parity-observations.json` under
        // the project root without creating missing parent directories — in
        // a real project `.mpd/` always exists by the time `publish
        // --verify` can run (created at `mpd init`), so these bare test
        // fixtures need to provide the same precondition explicitly.
        fs::create_dir_all(dir.join(".mpd")).unwrap();
        dir
    }

    fn init_repo() -> PathBuf {
        init_repo_labeled("repo")
    }

    fn init_bare(label: &str) -> PathBuf {
        let dir = unique_dir(label);
        run_git(&dir, &["init", "--quiet", "--bare"]);
        dir
    }

    fn write_file(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn commit_all(dir: &Path, message: &str) {
        run_git(dir, &["add", "-A"]);
        run_git(dir, &["commit", "--quiet", "-m", message]);
    }

    fn head(dir: &Path) -> String {
        git::head_commit(dir).unwrap().unwrap()
    }

    fn closure_for(base: &str, allowed: &[&str], digest: Digest) -> ArchiveClosure {
        ArchiveClosure {
            base_commit: base.to_string(),
            archive_path: "openspec/changes/archive/2026-01-01-test".into(),
            transaction_id: Digest::of_bytes(b"test-transaction"),
            candidate_id: None,
            allowed_paths: allowed.iter().map(|s| s.to_string()).collect(),
            system_paths: Vec::new(),
            post_archive_digest: digest,
            archived_at: 0,
        }
    }

    /// A repo with two commits: `base` (`keep/a.txt`), then the "archived"
    /// state HEAD (`keep/a.txt` + `keep/b.txt`), plus a matching, currently
    /// coherent [`ArchiveClosure`] scoped to `keep/**`.
    fn setup_base_repo(label: &str) -> (PathBuf, String, ArchiveClosure) {
        let dir = init_repo_labeled(label);
        write_file(&dir, "keep/a.txt", "a");
        commit_all(&dir, "base");
        let base = head(&dir);
        write_file(&dir, "keep/b.txt", "b");
        commit_all(&dir, "official state");
        let allowed = vec!["keep/**".to_string()];
        let digest = scoped_digest_for_patterns(&dir, &allowed).unwrap();
        let closure = closure_for(&base, &["keep/**"], digest);
        (dir, base, closure)
    }

    // --- verify_commit_coherence: the per-commit union / hidden-path risk ---

    #[test]
    fn commit_coherence_accepts_a_clean_in_scope_history() {
        let (dir, _base, closure) = setup_base_repo("clean-history");
        let coherence = verify_commit_coherence(&dir, &closure).unwrap();
        assert!(coherence.coherent, "blockers: {:?}", coherence.blockers);
        assert_eq!(coherence.head.as_deref(), Some(head(&dir).as_str()));
    }

    #[test]
    fn commit_coherence_rejects_an_intermediate_out_of_scope_add_then_delete() {
        // security-plan.md HIGH finding: an endpoint diff of base..HEAD hides
        // a path that was added and removed entirely between the two — here
        // `leak/secret.txt` never appears in the final tree, so a naive
        // endpoint-only check would see nothing wrong. The per-commit union
        // must still catch it.
        let dir = init_repo();
        write_file(&dir, "keep/a.txt", "a");
        commit_all(&dir, "base");
        let base = head(&dir);

        write_file(&dir, "keep/b.txt", "b");
        write_file(&dir, "leak/secret.txt", "top secret");
        commit_all(&dir, "add b and a leaked secret");

        fs::remove_file(dir.join("leak/secret.txt")).unwrap();
        commit_all(&dir, "delete the leaked secret");

        let allowed = vec!["keep/**".to_string()];
        let digest = scoped_digest_for_patterns(&dir, &allowed).unwrap();
        let closure = closure_for(&base, &["keep/**"], digest);

        let coherence = verify_commit_coherence(&dir, &closure).unwrap();
        assert!(
            !coherence.coherent,
            "endpoint diff would show only keep/b.txt added; the transient \
             out-of-scope leak/secret.txt must still block coherence"
        );
        assert!(
            coherence
                .blockers
                .iter()
                .any(|b| b.contains("leak/secret.txt") && b.contains("out-of-scope")),
            "blockers: {:?}",
            coherence.blockers
        );
    }

    #[test]
    fn commit_coherence_reports_no_commit_on_an_unborn_branch() {
        let dir = init_repo();
        let closure = closure_for(&"0".repeat(40), &["**"], Digest::of_bytes(b"unused"));
        let coherence = verify_commit_coherence(&dir, &closure).unwrap();
        assert!(!coherence.coherent);
        assert_eq!(coherence.head, None);
        assert!(coherence.blockers.iter().any(|b| b.contains("no commit")));
    }

    // --- verify_remote_parity: remote-name resolution -----------------------

    #[test]
    fn verify_remote_parity_resolves_only_the_exact_configured_remote_name() {
        let (dir, _base, closure) = setup_base_repo("resolution");
        let bare = init_bare("resolution-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]);

        let good = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        assert_eq!(
            verify_remote_parity(&dir, "resolution-change", &good, &closure, 15)
                .unwrap()
                .state,
            ParityState::Verified
        );

        // security-plan.md HIGH finding: the bare remote's own real,
        // reachable filesystem path is syntactically a legal remote-name
        // *token* (see `git::valid_remote_name`'s doc comment) but was never
        // `git remote add`ed under that literal string — it must be refused
        // rather than letting Git fall back to interpreting it as a local
        // repository path and falsely claiming remote publication.
        let path_impostor = PublishTarget {
            remote: bare.to_str().unwrap().to_string(),
            reference: "refs/heads/main".into(),
        };
        let err = verify_remote_parity(&dir, "resolution-change", &path_impostor, &closure, 15)
            .unwrap_err();
        assert!(err.contains("not a configured remote name"), "{err}");

        let unconfigured = PublishTarget {
            remote: "not-a-real-remote".into(),
            reference: "refs/heads/main".into(),
        };
        let err2 = verify_remote_parity(&dir, "resolution-change", &unconfigured, &closure, 15)
            .unwrap_err();
        assert!(err2.contains("not a configured remote name"), "{err2}");

        let _ = fs::remove_dir_all(&bare);
    }

    // --- verify_remote_parity: state classification -------------------------

    #[test]
    fn verify_remote_parity_is_verified_on_exact_oid_match_and_writes_a_cache() {
        let (dir, _base, closure) = setup_base_repo("exact");
        let bare = init_bare("exact-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let obs = verify_remote_parity(&dir, "exact-change", &target, &closure, 15).unwrap();
        assert_eq!(obs.state, ParityState::Verified);
        assert_eq!(obs.remote_oid.as_deref(), Some(obs.local_oid.as_str()));
        let cached = load_parity_cache(&dir).expect("verified observation is cached");
        assert_eq!(cached.state, ParityState::Verified);
        assert_eq!(cached.local_oid, obs.local_oid);
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_reports_offline_when_the_remote_is_unreachable() {
        let (dir, _base, closure) = setup_base_repo("offline");
        let bare = init_bare("offline-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        // The name stays "configured" (present in `git config`) but is now
        // unreachable — offline, not divergence, and no crash.
        fs::remove_dir_all(&bare).unwrap();
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let err = verify_remote_parity(&dir, "offline-change", &target, &closure, 5).unwrap_err();
        assert!(err.contains("offline"), "{err}");
    }

    #[test]
    fn verify_remote_parity_classifies_ahead_when_local_has_unshared_commits() {
        let dir = init_repo();
        write_file(&dir, "keep/a.txt", "a");
        commit_all(&dir, "base");
        let base = head(&dir);
        write_file(&dir, "keep/b.txt", "b");
        commit_all(&dir, "official state");
        let b = head(&dir);
        let bare = init_bare("ahead-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]); // remote = B
        write_file(&dir, "keep/c.txt", "c");
        commit_all(&dir, "local-only follow-up"); // HEAD = C, remote stays B

        let allowed = vec!["keep/**".to_string()];
        let digest = scoped_digest_for_patterns(&dir, &allowed).unwrap();
        let closure = closure_for(&base, &["keep/**"], digest);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let obs = verify_remote_parity(&dir, "ahead-change", &target, &closure, 15).unwrap();
        assert_eq!(obs.state, ParityState::Ahead);
        assert_eq!(obs.remote_oid.as_deref(), Some(b.as_str()));
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_classifies_behind_when_the_remote_object_is_locally_reachable() {
        let dir = init_repo();
        write_file(&dir, "keep/a.txt", "a");
        commit_all(&dir, "base");
        let base = head(&dir);
        write_file(&dir, "keep/b.txt", "b");
        commit_all(&dir, "official state");
        let b = head(&dir);
        write_file(&dir, "keep/d.txt", "d");
        commit_all(&dir, "future commit"); // HEAD = D (child of B)
        let bare = init_bare("behind-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]); // remote = D
        let d = head(&dir);
        // Move the local branch back to B; D's object stays in the local odb
        // (created here, never pruned) even though HEAD no longer reaches it
        // — the "object already exists locally, no fetch needed" case
        // `is_ancestor` depends on (design.md: MPD never fetches).
        run_git(&dir, &["reset", "--hard", &b]);
        assert_eq!(head(&dir), b);

        let allowed = vec!["keep/**".to_string()];
        let digest = scoped_digest_for_patterns(&dir, &allowed).unwrap();
        let closure = closure_for(&base, &["keep/**"], digest);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let obs = verify_remote_parity(&dir, "behind-change", &target, &closure, 15).unwrap();
        assert_eq!(obs.state, ParityState::Behind);
        assert_eq!(obs.remote_oid.as_deref(), Some(d.as_str()));
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_classifies_diverged_when_neither_side_contains_the_other() {
        let dir = init_repo();
        write_file(&dir, "keep/a.txt", "a");
        commit_all(&dir, "base");
        let base = head(&dir);
        write_file(&dir, "keep/b.txt", "b");
        commit_all(&dir, "official state");
        let b = head(&dir);
        write_file(&dir, "keep/remote-only.txt", "remote-only");
        commit_all(&dir, "remote sibling"); // D, child of B
        let bare = init_bare("diverged-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]); // remote = D
        let d = head(&dir);
        run_git(&dir, &["reset", "--hard", &b]);
        write_file(&dir, "keep/local-only.txt", "local-only");
        commit_all(&dir, "local sibling"); // HEAD = C, also a child of B
        let c = head(&dir);
        assert_ne!(c, d);

        let allowed = vec!["keep/**".to_string()];
        let digest = scoped_digest_for_patterns(&dir, &allowed).unwrap();
        let closure = closure_for(&base, &["keep/**"], digest);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let obs = verify_remote_parity(&dir, "diverged-change", &target, &closure, 15).unwrap();
        assert_eq!(obs.state, ParityState::Diverged);
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_reports_ancestry_unavailable_without_fetching_a_foreign_object() {
        let (dir, _base, closure) = setup_base_repo("unavailable-ancestry");
        // A second, completely independent repository whose commit history
        // shares nothing with `dir` — its OID is guaranteed absent from
        // `dir`'s object database, and MPD never fetches to find out.
        let foreign = init_repo();
        write_file(&foreign, "unrelated.txt", "unrelated");
        commit_all(&foreign, "unrelated root");
        let bare = init_bare("unavailable-ancestry-bare");
        run_git(
            &foreign,
            &["remote", "add", "origin", bare.to_str().unwrap()],
        );
        run_git(&foreign, &["push", "-q", "origin", "HEAD:refs/heads/main"]);

        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let obs = verify_remote_parity(&dir, "unavailable-ancestry-change", &target, &closure, 15)
            .unwrap();
        assert_eq!(obs.state, ParityState::AncestryUnavailable);
        let _ = fs::remove_dir_all(&foreign);
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_reports_unavailable_when_the_ref_is_missing_on_the_remote() {
        let (dir, _base, closure) = setup_base_repo("missing-ref");
        let bare = init_bare("missing-ref-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/other"]);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let obs = verify_remote_parity(&dir, "missing-ref-change", &target, &closure, 15).unwrap();
        assert_eq!(obs.state, ParityState::Unavailable);
        assert_eq!(obs.remote_oid, None);
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_classifies_rewritten_when_verified_history_is_replaced() {
        let (dir, _base, closure) = setup_base_repo("rewritten");
        let bare = init_bare("rewritten-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        let first = verify_remote_parity(&dir, "rewritten-change", &target, &closure, 15).unwrap();
        assert_eq!(first.state, ParityState::Verified);

        // A brand-new, parentless commit object (same tree, no shared
        // ancestry) built purely via plumbing — this never touches `dir`'s
        // index/working tree — then force-pushed over the remote ref: a
        // genuine history rewrite the previously verified remote OID is not
        // an ancestor of.
        let tree = run_git_capture(&dir, &["rev-parse", "HEAD^{tree}"]);
        let orphan = run_git_capture(&dir, &["commit-tree", &tree, "-m", "orphan rewrite"]);
        run_git(
            &dir,
            &[
                "push",
                "-q",
                "--force",
                "origin",
                &format!("{orphan}:refs/heads/main"),
            ],
        );

        let second = verify_remote_parity(&dir, "rewritten-change", &target, &closure, 15).unwrap();
        assert_eq!(second.state, ParityState::Rewritten);
        assert_eq!(second.remote_oid.as_deref(), Some(orphan.as_str()));
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_ignores_a_foreign_targets_cache_for_rewrite_detection() {
        // Security-code finding rewritten-cache-not-keyed: the Rewritten check
        // reads the single global parity cache. A prior VERIFIED observation
        // for a DIFFERENT change/remote/ref must NOT supply the old_oid
        // baseline for this target — otherwise an unrelated cache entry
        // mislabels an honest divergence as a history rewrite. NON-VACUOUS:
        // reverting the change/remote/ref filter makes this observe Rewritten
        // and the test fails.
        let (dir, _base, closure) = setup_base_repo("foreign-cache");
        let bare = init_bare("foreign-cache-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };

        // Put this target's remote at an orphan (no shared ancestry with local
        // HEAD) so remote != local and the honest classification is Diverged.
        let tree = run_git_capture(&dir, &["rev-parse", "HEAD^{tree}"]);
        let orphan = run_git_capture(&dir, &["commit-tree", &tree, "-m", "orphan on remote"]);
        run_git(
            &dir,
            &[
                "push",
                "-q",
                "--force",
                "origin",
                &format!("{orphan}:refs/heads/main"),
            ],
        );

        // Seed the global cache with a VERIFIED observation for a DIFFERENT
        // change, whose remote_oid (local HEAD) is NOT an ancestor of the
        // orphan now on the remote — exactly the shape that would drive a
        // spurious Rewritten if the cache read weren't keyed to this target.
        let foreign_oid = head(&dir);
        save_parity_cache(
            &dir,
            &ParityObservation {
                schema: 1,
                change: "a-totally-different-change".into(),
                remote: "origin".into(),
                reference: "refs/heads/main".into(),
                local_oid: foreign_oid.clone(),
                remote_oid: Some(foreign_oid),
                state: ParityState::Verified,
                observed_at_epoch_secs: 0,
            },
        )
        .unwrap();

        let obs =
            verify_remote_parity(&dir, "foreign-cache-change", &target, &closure, 15).unwrap();
        assert_ne!(
            obs.state,
            ParityState::Rewritten,
            "a foreign change's cached observation must not drive rewrite detection for this target"
        );
        assert_eq!(
            obs.state,
            ParityState::Diverged,
            "local HEAD and the orphan remote share no ancestry -> the honest label is Diverged"
        );
        let _ = fs::remove_dir_all(&bare);
    }

    // --- verify_remote_parity: TOCTOU / movement races (deterministic) -----

    #[test]
    fn verify_remote_parity_is_unstable_and_writes_no_cache_when_head_moves_twice() {
        let (dir, _base, closure) = setup_base_repo("unstable");
        let bare = init_bare("unstable-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };
        assert!(load_parity_cache(&dir).is_none());

        let mut moves = 0u32;
        // The probe fires once per attempt, exactly inside the
        // first-observation/recheck window `verify_remote_parity` is proving
        // closed (security-plan.md MEDIUM "Add deterministic race
        // fixtures"). Moving HEAD on *both* attempts forces two consecutive
        // movements — the documented UNSTABLE case — deterministically,
        // rather than racing real background threads against subprocess
        // timing.
        let obs = verify_remote_parity_with_probe(
            &dir,
            "unstable-change",
            &target,
            &closure,
            15,
            &mut |_attempt| {
                moves += 1;
                write_file(&dir, "keep/race.txt", &format!("race-{moves}"));
                commit_all(&dir, &format!("race commit {moves}"));
            },
        )
        .unwrap();

        assert_eq!(obs.state, ParityState::Unstable);
        assert_eq!(moves, 2, "both attempts should have observed a probe call");
        assert!(
            load_parity_cache(&dir).is_none(),
            "an unstable observation must never write a cache"
        );
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_recovers_via_the_single_permitted_retry() {
        // A single *remote* movement on the first attempt must recover to
        // VERIFIED via the one permitted retry (design.md "Remote
        // observation"). The flap is on the remote — local HEAD never leaves
        // the coherence-checked archived commit — so the recovered VERIFIED is
        // honest (contrast the head-move case below, which must NOT recover:
        // Security-code finding coherence-observation-head-unbound).
        let (dir, _base, closure) = setup_base_repo("single-retry");
        let bare = init_bare("single-retry-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        // The remote ref is absent for the first observation.
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };

        let mut flapped = false;
        let obs = verify_remote_parity_with_probe(
            &dir,
            "single-retry-change",
            &target,
            &closure,
            15,
            &mut |attempt| {
                if attempt == 0 && !flapped {
                    flapped = true;
                    // Publish the local (coherent) HEAD to the ref between the
                    // first attempt's paired observations: remote1 (absent) !=
                    // remote2 (present) forces exactly one retry, and the
                    // second attempt is stable with remote == the coherent
                    // local HEAD.
                    run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
                }
            },
        )
        .unwrap();

        assert_eq!(
            obs.state,
            ParityState::Verified,
            "a single remote movement must recover via the permitted retry"
        );
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn verify_remote_parity_refuses_verified_when_head_moved_off_the_coherence_checked_commit() {
        // Security-code finding coherence-observation-head-unbound (MEDIUM):
        // coherence is proven once on the pre-loop HEAD. A concurrent move of
        // local HEAD onto a *different* commit that happens to equal the remote
        // OID must NOT be reported VERIFIED — that commit's coherence (no
        // out-of-scope path anywhere in its history) was never proven. Here the
        // divergent commit keeps the scoped digest byte-identical (it touches
        // only an out-of-scope path), so ONLY the head<->coherence binding —
        // not the scoped-postimage re-check — can catch it, proving that
        // binding is load-bearing.
        let (dir, _base, closure) = setup_base_repo("coherence-window");
        let archived_head = head(&dir); // coherent; == closure.post_archive_digest
        let bare = init_bare("coherence-window-bare");
        run_git(&dir, &["remote", "add", "origin", bare.to_str().unwrap()]);
        let target = PublishTarget {
            remote: "origin".into(),
            reference: "refs/heads/main".into(),
        };

        // A divergent commit that leaves keep/** (the scoped paths) unchanged
        // but touches an out-of-scope path, so its scoped digest still equals
        // the archived postimage while its history is NOT coherent.
        write_file(&dir, "out/of/scope.txt", "not in keep/**");
        commit_all(&dir, "divergent out-of-scope commit");
        let divergent = head(&dir);
        run_git(&dir, &["push", "-q", "origin", "HEAD:refs/heads/main"]); // remote = divergent
                                                                          // Restore HEAD to the coherent archived commit so pre-loop coherence
                                                                          // passes; the probe then simulates the concurrent reset landing inside
                                                                          // the coherence->observation window.
        run_git(&dir, &["reset", "--hard", archived_head.as_str()]);

        let mut reset_once = false;
        let obs = verify_remote_parity_with_probe(
            &dir,
            "coherence-window-change",
            &target,
            &closure,
            15,
            &mut |_attempt| {
                if !reset_once {
                    reset_once = true;
                    run_git(&dir, &["reset", "--hard", divergent.as_str()]);
                }
            },
        )
        .unwrap();

        assert_eq!(
            obs.state,
            ParityState::Unstable,
            "a HEAD move onto a commit never coherence-checked must be UNSTABLE, not VERIFIED"
        );
        assert!(
            load_parity_cache(&dir).is_none(),
            "an unstable observation must never write a verified cache"
        );
        let _ = fs::remove_dir_all(&bare);
    }

    #[test]
    fn source_digest_excludes_change_process_artifacts_so_a_doc_edit_does_not_stale_source() {
        // Security-code finding source-includes-later-phase-output: the
        // change's documentation.md is a Documentation-phase output. It must
        // NOT fold into the Source digest, or a later doc edit would stale an
        // earlier Build/Test/SecurityCode receipt (design.md:398-401
        // phase-causality). Drives the REAL source_digest capture path, unlike
        // the abstract-key policy test in dependency_policy_tests.
        let dir = init_repo();
        let change = "cargo-doc-decouple";
        let change_dir = format!("openspec/changes/{change}");
        write_file(&dir, "crates/x/src/lib.rs", "pub fn f() {}\n");
        write_file(
            &dir,
            &format!("{change_dir}/documentation.md"),
            "# Docs v1\n",
        );
        write_file(&dir, &format!("{change_dir}/design.md"), "# Design v1\n");
        commit_all(&dir, "seed source + process artifacts");

        let manifest = ChangeManifest {
            version: 1,
            paths: vec!["crates/x/**".to_string()],
            shared_paths: Vec::new(),
            publish: None,
        };
        let system = active_system_scope(&dir, change);
        let before = source_digest(&dir, &manifest, &system).unwrap();

        // Editing the later-phase documentation artifact must NOT move Source.
        write_file(
            &dir,
            &format!("{change_dir}/documentation.md"),
            "# Docs v2 rewritten\n",
        );
        commit_all(&dir, "documentation phase output");
        assert_eq!(
            source_digest(&dir, &manifest, &system).unwrap(),
            before,
            "editing documentation.md must not change the Source digest"
        );

        // ...nor editing design.md (bound by DesignArtifacts, not Source).
        write_file(&dir, &format!("{change_dir}/design.md"), "# Design v2\n");
        commit_all(&dir, "design edit");
        assert_eq!(
            source_digest(&dir, &manifest, &system).unwrap(),
            before,
            "editing design.md must not change the Source digest"
        );

        // Sanity: a genuine in-scope source edit DOES move it.
        write_file(&dir, "crates/x/src/lib.rs", "pub fn f() { let _ = 1; }\n");
        commit_all(&dir, "real source change");
        assert_ne!(
            source_digest(&dir, &manifest, &system).unwrap(),
            before,
            "editing real in-scope source must change the Source digest"
        );
    }

    /// Deterministic printable-ASCII pseudo-random content (xorshift64,
    /// seeded per file) — always valid UTF-8 (so it round-trips through
    /// `write_file`'s `&str` signature) while still exercising real,
    /// non-degenerate per-byte hashing work rather than an all-zero page.
    fn pseudo_random_ascii(seed: u64, len: usize) -> String {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        let mut s = String::with_capacity(len);
        while s.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let byte = (state % 95) as u8 + 32; // printable ASCII 0x20..=0x7e
            s.push(byte as char);
        }
        s
    }

    /// Risk-to-test map (design.md): "Performance | seeded 10k-path/100MB
    /// benchmark with byte-count and wall-time reporting." Builds a real
    /// Git-tracked repository with 10,000 files totalling ~100MB of
    /// deterministic content (spread across 100 subdirectories so no single
    /// directory holds an unrealistic 10k-entry fan-out), then times the
    /// exact production hot path — `scoped_digest_for_patterns`'s `git
    /// ls-files` + `git status --porcelain=v2` + one non-following streamed
    /// hash per file — that backs `mpd status`/archive/publish scoped
    /// digests (design.md "Config, migration, and performance": "Hash each
    /// included byte once per command with streaming I/O"). Reports the
    /// actual byte count and wall time to stderr (visible even under
    /// `cargo test`'s stdout capture) instead of asserting a specific
    /// number, since hardware varies; it still fails on a gross regression
    /// far outside any sane per-request budget. `#[ignore]`d by default —
    /// like any real benchmark, it is expensive (writes ~100MB, one `git
    /// add`/`commit` over 10k files) and is meant to be run deliberately via
    /// `cargo test --release -- --ignored scoped_digest_throughput
    /// --nocapture`, not on every default `cargo test`.
    #[test]
    #[ignore]
    fn scoped_digest_throughput_over_10k_paths_100mb() {
        const FILE_COUNT: usize = 10_000;
        const FILE_BYTES: usize = 10_000; // 10_000 * 10_000 = 100_000_000 bytes (~100MB)
        const SUBDIRS: usize = 100;

        let dir = init_repo_labeled("perf-10k");
        let write_start = std::time::Instant::now();
        for i in 0..FILE_COUNT {
            let sub = i % SUBDIRS;
            let content = pseudo_random_ascii(i as u64, FILE_BYTES);
            write_file(&dir, &format!("perf/{sub:03}/f{i:05}.bin"), &content);
        }
        let write_elapsed = write_start.elapsed();
        commit_all(&dir, "perf: 10k paths / 100MB");

        let patterns = vec!["perf/**".to_string()];
        let hash_start = std::time::Instant::now();
        let digest = scoped_digest_for_patterns(&dir, &patterns).unwrap();
        let hash_elapsed = hash_start.elapsed();

        let total_bytes = FILE_COUNT * FILE_BYTES;
        eprintln!(
            "scoped_digest_throughput_over_10k_paths_100mb: {FILE_COUNT} paths, \
             {total_bytes} bytes written in {write_elapsed:?}, scoped_digest_for_patterns \
             completed in {hash_elapsed:?} (digest {digest}) — \
             {throughput:.1} MB/s",
            throughput = (total_bytes as f64 / (1024.0 * 1024.0))
                / hash_elapsed.as_secs_f64().max(0.000_001)
        );
        assert_eq!(digest.to_hex().len(), 64);
        // A generous ceiling, not a tight performance assertion: this test's
        // job is to prove the hot path completes and to report real numbers,
        // not to gate CI on absolute hardware speed. 60s for 100MB across
        // 10k files is far beyond any expected streaming-hash workload and
        // only catches a true algorithmic regression (e.g. re-reading a file
        // per pattern, or buffering the whole tree in memory).
        assert!(
            hash_elapsed.as_secs() < 60,
            "scoped_digest_for_patterns took {hash_elapsed:?} for {FILE_COUNT} paths / \
             {total_bytes} bytes — investigate a possible performance regression"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
