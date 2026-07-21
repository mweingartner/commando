//! The gate ledger: durable per-change record of phase verdicts and evidence.
//!
//! OpenSpec tracks whether an artifact *exists*; the ledger tracks whether an
//! adversarial persona *signed off* on it, with evidence. It lives at
//! `.mpd/state/<change>.json` so it survives session death — the piece the
//! in-session pipeline lacked.

use crate::candidate::CandidateCapture;
use crate::closure::{ArchiveClosure, EvidenceReceipt};
use crate::phase::{Applicability, Phase};
use openspec_core::{
    atomic_write_contained_classified, validate_change_name, AtomicWriteOutcome, TaskEntry,
    TaskPlan,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// The current ledger schema format this binary writes and fully understands
/// (D5). Bump this in future changes whenever a new enum variant or
/// semantics-bearing field would make older readers fail — the
/// `design-mock-artifact` receipt-kind era is retroactively "format 2" from
/// this change onward.
pub const LEDGER_FORMAT: u32 = 2;

/// Default for ledgers written before the `format` field existed — every
/// pre-existing ledger decodes as format 1.
fn ledger_format_v1() -> u32 {
    1
}

macro_rules! string_enum {
    ($name:ident, $default:ident, { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name { $(#[doc = $text] $variant,)+ }
        impl $name {
            pub fn label(self) -> &'static str { match self { $(Self::$variant => $text,)+ } }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.label()) }
        }
        impl FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s { $($text => Ok(Self::$variant),)+ _ => Err(format!("unsupported {} {s:?}", stringify!($name))) }
            }
        }
        impl Default for $name { fn default() -> Self { Self::$default } }
    };
}

string_enum!(RiskLevel, Medium, { Low => "low", Medium => "medium", High => "high" });
string_enum!(ThreatProfile, LocalTrustedUser, {
    LocalTrustedUser => "local-trusted-user", LocalUntrustedInput => "local-untrusted-input",
    NetworkClient => "network-client", NetworkServer => "network-server",
    CredentialBearing => "credential-bearing", HighAssurance => "high-assurance"
});
string_enum!(FailureClass, Product, {
    Product => "product", Test => "test", Infrastructure => "infrastructure",
    Environment => "environment", Policy => "policy"
});
// Per-persona tuning knobs (persona-tuning). Both are strengthen-only ordinals:
// the lowest term is the baseline no-op, and there is deliberately no sub-baseline
// term, so a user cannot dial a persona weaker through the menus (design.md D2).
string_enum!(Rigor, Standard, {
    Standard => "standard", Deep => "deep", Paranoid => "paranoid"
});
string_enum!(Depth, Examples, {
    Examples => "examples", Property => "property", Fuzz => "fuzz"
});

impl Rigor {
    /// Total order over rigor (`standard` < `deep` < `paranoid`). Manual, like
    /// [`RiskLevel::rank`] — `string_enum!` does NOT generate a `rank()`. Used to
    /// keep composition strengthen-only (a monotonic `max`), never a string
    /// comparison (design.md Cond 3).
    pub fn rank(self) -> u8 {
        match self {
            Self::Standard => 0,
            Self::Deep => 1,
            Self::Paranoid => 2,
        }
    }
}

impl Depth {
    /// Total order over Tester depth (`examples` < `property` < `fuzz`). Manual,
    /// like [`RiskLevel::rank`]. Strengthen-only emphasis (design.md D2/Cond 3).
    pub fn rank(self) -> u8 {
        match self {
            Self::Examples => 0,
            Self::Property => 1,
            Self::Fuzz => 2,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn max_rigor(a: Option<Rigor>, b: Option<Rigor>) -> Option<Rigor> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if x.rank() >= y.rank() { x } else { y }),
        (Some(x), None) => Some(x),
        (None, y) => y,
    }
}

fn max_depth(a: Option<Depth>, b: Option<Depth>) -> Option<Depth> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if x.rank() >= y.rank() { x } else { y }),
        (Some(x), None) => Some(x),
        (None, y) => y,
    }
}

/// The persona tuning that was in force for a brief/gate — the durable, auditable
/// record that a tuned persona's PASS is not indistinguishable from a full-rigor
/// PASS (design.md D5). `weakened` is true iff an un-rankable vector was present
/// (a free-text `directive_append` OR a `modified:true` base directive) — the one
/// thing mpd cannot prove rigor-preserving, so it is recorded, never blocked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonaTuningRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rigor: Option<Rigor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<Depth>,
    /// A sanitized config `directive_append` was carried in the brief.
    #[serde(default, skip_serializing_if = "is_false")]
    pub had_append: bool,
    /// The base directive file for this persona differed from the bundled default.
    #[serde(default, skip_serializing_if = "is_false")]
    pub base_modified: bool,
    /// `had_append || base_modified` — the un-rankable weakening flag.
    #[serde(default, skip_serializing_if = "is_false")]
    pub weakened: bool,
}

impl PersonaTuningRecord {
    /// Whether this record carries nothing worth recording (the baseline no-op):
    /// no above-baseline rigor/depth, no append, no modified base. `next` writes a
    /// `brief_tuning` slot only when this is false (design.md Cond 11 — inertness).
    pub fn is_baseline(&self) -> bool {
        self.rigor.map_or(0, Rigor::rank) == 0
            && self.depth.map_or(0, Depth::rank) == 0
            && !self.had_append
            && !self.base_modified
    }

    /// Merge `other` in the weakest-seen (strengthen-only) direction: booleans OR,
    /// ordinals `max`. Once `weakened`/`base_modified`/`had_append` is set for an
    /// attempt, a later non-weakened re-brief can never clear it (design.md Cond 11,
    /// round-3 F2) — the anti-laundering property.
    pub fn merge_weakest_seen(&mut self, other: &PersonaTuningRecord) {
        self.had_append |= other.had_append;
        self.base_modified |= other.base_modified;
        self.weakened |= other.weakened;
        self.rigor = max_rigor(self.rigor, other.rigor);
        self.depth = max_depth(self.depth, other.depth);
    }
}

/// The brief-time tuning `mpd next` recorded for a `(phase, attempt)`, consumed by
/// `mpd gate` to stamp the receipt from what the brief actually carried — closing
/// the `next`→`gate` TOCTOU (design.md D5 §2). Inert to every dependency/brief
/// digest; it gates nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BriefTuning {
    pub attempt: usize,
    pub record: PersonaTuningRecord,
}

impl RiskLevel {
    pub fn attempt_limit(self) -> usize {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
    /// A total order over rigor (Low < Medium < High), used to distinguish a
    /// risk *upgrade* from a *downgrade* under `--autonomous` reconcile — a
    /// downgrade weakens rigor and must halt for a human (design.md D7 / Cond
    /// 12). Deliberately a method (not a `PartialOrd` derive) so the ordering is
    /// an explicit, named rigor axis rather than an implicit enum-declaration
    /// artifact.
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }
    pub fn max(self, other: RiskLevel) -> RiskLevel {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
    pub fn page_limit(self) -> Option<usize> {
        match self {
            Self::Low => Some(2),
            Self::Medium => Some(8),
            Self::High => None,
        }
    }
}

/// Versioned, content-bound risk classification for the current change inputs.
/// `Governance::risk` remains the requested value for backward compatibility;
/// all enforcement uses `effective` once an assessment has been computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub classifier_version: u32,
    pub requested: RiskLevel,
    pub derived: RiskLevel,
    pub effective: RiskLevel,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub signal_digest: String,
}

/// One append-only record that stale current evidence forced a causal rewind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessInvalidationEvent {
    pub schema: u32,
    pub stored_phase: Phase,
    pub rewind_phase: Phase,
    pub stale_phases: Vec<Phase>,
    pub reasons: Vec<String>,
    pub at_epoch_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Governance {
    pub risk: RiskLevel,
    pub threat_profile: ThreatProfile,
    #[serde(default)]
    pub reconciliations: Vec<Reconciliation>,
}
impl Default for Governance {
    fn default() -> Self {
        Self {
            risk: RiskLevel::Medium,
            threat_profile: ThreatProfile::LocalTrustedUser,
            reconciliations: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exploitability {
    pub attacker: String,
    pub capability: String,
    pub boundary: String,
    pub harm: String,
    pub fix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReconciliationKind {
    Continue,
    Narrow,
    Risk,
    ThreatProfile,
}

impl ReconciliationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Narrow => "narrow",
            Self::Risk => "risk",
            Self::ThreatProfile => "threat-profile",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reconciliation {
    pub kind: ReconciliationKind,
    pub reason: String,
    pub phase: Phase,
    pub authorized_attempt: usize,
    pub at_epoch_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
    #[serde(default)]
    pub consumed: bool,
}

/// Legacy decoding shape for artifact waivers produced by older MPD releases.
/// Current Commando policy never creates or honors these records; their presence
/// on a strict ledger is a blocker until the affected gates are rewound and rerun.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiver {
    /// The judgment phase whose artifact check was waived.
    pub phase: Phase,
    /// Why the artifact was waived (bounded, terminal-safe).
    pub reason: String,
    /// The attempt this waiver authorizes — it applies to no other.
    pub attempt: usize,
    /// When it was recorded (epoch seconds).
    pub at_epoch_secs: u64,
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn bounded_text(value: &str, field: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} must not be blank"));
    }
    if value.chars().count() > 500 {
        return Err(format!("{field} must be at most 500 characters"));
    }
    Ok(value.to_string())
}

#[allow(dead_code)] // exercised by the reserved, non-CLI restart state below
fn validate_full_oid(value: &str, field: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be a full lowercase object id"));
    }
    Ok(())
}

#[allow(dead_code)] // exercised by the reserved, non-CLI restart state below
fn validate_sha256(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be a lowercase sha256 digest"));
    }
    Ok(())
}

#[allow(dead_code)] // exercised by the reserved, non-CLI restart state below
fn validate_first_adoption_restart(event: &FirstAdoptionRestartV1) -> Result<(), String> {
    if event.schema != 1 {
        return Err(format!(
            "unsupported first-adoption restart schema {}",
            event.schema
        ));
    }
    validate_full_oid(&event.superseded_checkpoint_oid, "superseded checkpoint")?;
    if let Some(proof) = &event.superseded_proof_digest {
        validate_sha256(proof, "superseded proof digest")?;
    }
    if let Some(replacement) = &event.replacement_tip_oid {
        validate_full_oid(replacement, "replacement tip")?;
        if replacement == &event.superseded_checkpoint_oid {
            return Err("replacement tip must differ from superseded checkpoint".into());
        }
    } else if matches!(event.stage, FirstAdoptionRestartStage::Pretrust) {
        return Err("pretrust restart requires a replacement checkpoint tip".into());
    }
    validate_sha256(&event.evidence_digest, "restart evidence digest")?;
    for (field, value) in [
        ("restart actor", &event.actor),
        ("restart reason", &event.reason),
    ] {
        if value.chars().any(char::is_control) || bounded_text(value, field)? != *value {
            return Err(format!("{field} must be trimmed and terminal-safe"));
        }
    }
    if event.at_epoch_secs == 0 {
        return Err("first-adoption restart timestamp must be nonzero".into());
    }
    Ok(())
}

fn invalid(e: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e)
}

/// The kind of change. It informs review depth and reporting, but never skips
/// Documentation or Doc Validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    /// A feature or enhancement that changes functional behavior. Documented.
    #[default]
    Feature,
    /// A defect fix.
    Fix,
    /// A non-functional change (refactor, tooling, perf, deps).
    Chore,
}

impl ChangeKind {
    /// Whether a change of this kind runs the Documentation phases. All kinds
    /// do; retained as an API boundary for older callers.
    pub fn documents(self) -> bool {
        true
    }

    /// A short human label.
    pub fn label(self) -> &'static str {
        match self {
            ChangeKind::Feature => "feature",
            ChangeKind::Fix => "fix",
            ChangeKind::Chore => "chore",
        }
    }
}

/// A gate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// The gate passed unconditionally.
    Pass,
    /// The gate passed with open conditions that must close before archive.
    ConditionalPass,
    /// The gate failed; the pipeline cannot advance.
    Fail,
}

impl Verdict {
    /// The canonical artifact token for this verdict.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::ConditionalPass => "CONDITIONAL PASS",
            Self::Fail => "FAIL",
        }
    }

    /// Whether this verdict permits advancing to the next phase.
    pub fn advances(self) -> bool {
        matches!(self, Verdict::Pass)
    }
}

/// Deterministic-check evidence attached to a gate (never contains raw tool
/// output — only summarized, non-secret results).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckSummary {
    /// Number of tests observed to pass, when a count could be parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests_passed: Option<usize>,
    /// Whether the secret scan came back clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_clean: Option<bool>,
    /// Which scanner(s) actually backed the secret result (e.g. `builtin`,
    /// `builtin+gitleaks`) — recorded so a later audit of the ledger knows the
    /// provenance of the PASS, not merely current tool availability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner: Option<String>,
    /// The command that produced the result (for audit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// A recorded gate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRecord {
    /// The outcome.
    pub verdict: Verdict,
    /// Who recorded it (persona name).
    pub by: String,
    /// A pointer to evidence (e.g. `design.md#conditions`). Never raw output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Deterministic-check summary, when the phase ran checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<CheckSummary>,
    /// When it was recorded (`YYYY-MM-DD`).
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<FailureClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploitability: Option<Exploitability>,
    #[serde(default)]
    pub attempt: usize,
    #[serde(default)]
    pub started_at_epoch_secs: u64,
    #[serde(default)]
    pub completed_at_epoch_secs: u64,
    /// Content-bound evidence for this verdict, when the phase's gate ran
    /// under the content-addressed release-closure model. Absent on every
    /// pre-existing (legacy) gate record — legacy evidence is `absent`,
    /// never `valid`, per design.md "Legacy gate has no receipt".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<EvidenceReceipt>,
    /// The persona tuning in force when this gate was recorded, stamped from the
    /// brief's recorded determination (design.md D5). Absent on every baseline
    /// (untuned) gate and every legacy record — a tuned PASS is then no longer
    /// indistinguishable in the ledger from a full-rigor PASS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona_tuning: Option<PersonaTuningRecord>,
    /// Exact worktree candidate used by an objective candidate gate. Legacy,
    /// planning, Commit-validation, and manual records intentionally decode as
    /// absent rather than being mistaken for candidate evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<CandidateCapture>,
    /// The only artifact identity allowed to flow from an objective Build to
    /// Deploy. Legacy/provisional Build attempts intentionally have no value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_output: Option<BuildOutputV1>,
    /// Truth produced by a typed Deploy.  Legacy/manual deployment keeps this
    /// absent and therefore cannot masquerade as verified local installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_result: Option<DeployResultV1>,
    /// Bounded structured-validation receipt for an exact Candidate gate.
    /// It carries result metadata and digests, never raw child output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_receipt: Option<crate::local_validation::ValidationReceiptV1>,
}

/// Versioned identity of one release file observed through an opened,
/// no-follow regular file. It is data, not an executable recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildOutputV1 {
    pub schema: u32,
    /// Named contract selected by the Build profile. Empty is legacy data and
    /// cannot satisfy a strict Deploy configuration.
    #[serde(default)]
    pub name: String,
    pub path: String,
    /// Build contract limits copied into the receipt so Deploy can reapply them
    /// before its first install effect.
    #[serde(default)]
    pub max_bytes: u64,
    #[serde(default)]
    pub required_mode: u32,
    pub size: u64,
    pub mode: u32,
    /// Opened-file identity at Build time. Legacy/non-Unix records decode as
    /// zero and cannot satisfy strict Deploy revalidation.
    #[serde(default)]
    pub device: u64,
    #[serde(default)]
    pub inode: u64,
    pub sha256: String,
    /// Candidate identity whose read-only projection produced these bytes.
    /// Legacy/manual Build outputs remain explicitly unbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_id: Option<String>,
}

/// Bounded Deploy evidence. Definition and result digests preserve what was
/// copied and parent-verified without persisting artifact bytes. `probe_executed`
/// is an explicit negative assertion for execute and readiness modes: production
/// Deploy must never launch the installed candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployResultV1 {
    pub schema: u32,
    pub mode: String,
    pub target: String,
    pub definition_digest: String,
    pub result_digest: String,
    pub install_executed: bool,
    pub probe_executed: bool,
    pub verified: bool,
}

impl GateRecord {
    pub fn duration_secs(&self) -> u64 {
        self.completed_at_epoch_secs
            .saturating_sub(self.started_at_epoch_secs)
    }
}

/// A condition event is append-only evidence about one condition's lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConditionEvent {
    Opened {
        by: String,
        at_epoch_secs: u64,
        evidence: String,
        evidence_digest: String,
    },
    Resolved {
        by: String,
        at_epoch_secs: u64,
        evidence: String,
        evidence_digest: String,
    },
    Reopened {
        at_epoch_secs: u64,
        reason: String,
        rewind_phase: Phase,
    },
}

/// An evidence-bearing obligation opened by a CONDITIONAL PASS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// Stable display identifier, assigned at creation and never reused.
    #[serde(default)]
    pub id: String,
    /// The phase/attempt that opened this obligation.
    #[serde(default = "legacy_condition_phase")]
    pub phase: Phase,
    #[serde(default)]
    pub attempt: usize,
    /// What must be done.
    pub text: String,
    /// Who owns closing it.
    pub owner: String,
    /// Legacy boolean state.  New records derive closure from `events`; retaining
    /// this field makes old ledgers readable so they can be explicitly repaired.
    pub closed: bool,
    #[serde(default)]
    pub opened_at_epoch_secs: u64,
    #[serde(default)]
    pub events: Vec<ConditionEvent>,
}

impl Condition {
    pub fn is_open(&self) -> bool {
        if self.events.is_empty() {
            return !self.closed;
        }
        !matches!(self.events.last(), Some(ConditionEvent::Resolved { .. }))
    }
}

/// Append-only disposition history for an explicitly deferred Builder task.
/// The task's ID alone is never an authority: each event is bound to the
/// normalized full-record digest from the current task plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TaskDeferralEvent {
    Deferred {
        owner: String,
        reason: String,
        evidence: String,
        evidence_digest: String,
        at_epoch_secs: u64,
    },
    Revoked {
        reason: String,
        at_epoch_secs: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDeferral {
    pub task_id: String,
    pub record_digest: String,
    #[serde(default)]
    pub events: Vec<TaskDeferralEvent>,
}

impl TaskDeferral {
    pub(crate) fn is_active(&self) -> bool {
        matches!(self.events.last(), Some(TaskDeferralEvent::Deferred { .. }))
    }
}

/// A compatibility repair is an append-only reconciliation, never a fabricated
/// PASS or an archive rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyRepairEvent {
    pub reason: String,
    pub rewind_phase: Phase,
    /// Exact ledger image observed before the repair was applied.
    #[serde(default)]
    pub ledger_before_digest: String,
    pub at_epoch_secs: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskAccounting {
    pub done: usize,
    pub deferred: usize,
    pub open: Vec<String>,
    pub stale: Vec<String>,
    pub total: usize,
}

impl TaskAccounting {
    pub fn accounted(&self) -> bool {
        self.open.is_empty() && self.stale.is_empty() && self.done + self.deferred == self.total
    }
}

fn legacy_condition_phase() -> Phase {
    // Old condition records did not carry a source phase.  They remain readable,
    // but higher-level migration/strict checks can surface that ambiguity.
    Phase::Architecture
}

/// One recorded gate verdict, preserved in the append-only history. The `gates`
/// map keeps only the *latest* verdict per phase (which drives advancement and
/// readiness); `history` keeps the full ordered trail, so a catch-then-fix
/// (FAIL → PASS) survives in the audit record instead of being overwritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvent {
    /// The phase that was recorded.
    pub phase: Phase,
    /// The verdict record at that moment.
    pub record: GateRecord,
}

/// The durable state of one change's trip through the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// The ledger schema format (D5, `LEDGER_FORMAT`). Additive and
    /// defaulted to 1 for every ledger written before this field existed;
    /// `save` always writes the current constant regardless of what was
    /// loaded, so every ledger this binary touches is stamped current.
    #[serde(default = "ledger_format_v1")]
    pub format: u32,
    /// The change name.
    pub change: String,
    /// The schema the change was created under.
    pub schema: String,
    /// Whether the change has a UI/UX surface (governs design-phase skipping).
    pub ui: bool,
    /// The kind of change (governs documentation-phase skipping).
    #[serde(default)]
    pub kind: ChangeKind,
    /// The current phase.
    pub phase: Phase,
    /// Recorded gate verdicts, keyed by phase.
    pub gates: BTreeMap<Phase, GateRecord>,
    /// Open/closed conditions from conditional passes.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Append-only task deferral/revocation history.  An event with a stale
    /// record digest is visible as stale and cannot account for a current task.
    #[serde(default)]
    pub task_deferrals: Vec<TaskDeferral>,
    /// Append-only log of every gate verdict ever recorded, in order. Preserves
    /// the full audit trail (incl. a FAIL that was later re-recorded PASS) that
    /// the latest-per-phase `gates` map would otherwise overwrite. Additive and
    /// optional so pre-existing ledgers deserialize with an empty history.
    #[serde(default)]
    pub history: Vec<GateEvent>,
    #[serde(default)]
    pub governance: Governance,
    /// Most recent mutating-command risk assessment. Status recomputes a
    /// read-only projection and never trusts this cache as current authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_assessment: Option<RiskAssessment>,
    /// Whether this change runs under the strict (self-enforcing) tier. Write-once
    /// and monotonic: set true by `conduct`/`begin --strict` via
    /// [`Ledger::set_strict`] and NEVER reset to false by any code path (design.md
    /// D1/D7, Cond 14), so a resumed harness keeps the strictness it opted into.
    /// Additive and `#[serde(default)]` so a legacy ledger loads as `strict=false`
    /// — the manual tier, byte-identical to today.
    #[serde(default)]
    pub strict: bool,
    /// Legacy artifact-waiver records. Additive/defaulted for compatibility;
    /// current strict ledgers block when this collection is nonempty.
    #[serde(default)]
    pub waivers: Vec<Waiver>,
    #[serde(default)]
    pub phase_started_at_epoch_secs: u64,
    /// The content-addressed record of this change's completed archive
    /// closure, once `archive --yes` has fully applied and been verified
    /// (see `archive-transaction.md`). Absent for every change archived
    /// before this schema existed and for any change not yet archived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_closure: Option<ArchiveClosure>,
    /// Per-phase brief-time persona tuning `mpd next` recorded, keyed by phase with
    /// the attempt carried inside. Written only when a non-baseline tuning was in
    /// force (so an untuned ledger is byte-identical), and consumed by `mpd gate`
    /// to stamp the receipt from what the brief carried (design.md D5 §2 / Cond 11).
    /// Additive + `#[serde(default)]`; inert to every digest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub brief_tuning: BTreeMap<Phase, BriefTuning>,
    /// One-time adoption events are append-only and intentionally distinct
    /// from generic governance reconciliation. They preserve provisional Build
    /// history while making it ineligible for readiness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub first_adoption_reconciliations: Vec<FirstAdoptionReconciliationV1>,
    /// Append-only corrections around the one-time trust transition. These
    /// records never manufacture a gate result; they only supersede checkpoint
    /// eligibility while preserving the old checkpoint as chain history.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub first_adoption_restarts: Vec<FirstAdoptionRestartV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_repairs: Vec<LegacyRepairEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub freshness_invalidations: Vec<FreshnessInvalidationEvent>,
    /// D8 defect-escape provenance: the archived change this one was opened
    /// to fix a defect that escaped from (`mpd conduct --fix --introduced-by
    /// <archived-change>`). Write-once at begin — no mutation verb edits it
    /// afterward — and additive/absent on every ledger that doesn't use the
    /// flag. Display/measurement data only: no readiness, gate, scope, or
    /// verification decision may read it (Cond 19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstAdoptionReconciliationV1 {
    pub schema: u32,
    pub checkpoint_oid: String,
    pub policy_object_oid: String,
    pub pretrust_proof_digest: String,
    pub security_evidence: String,
    pub reason: String,
    pub at_epoch_secs: u64,
    /// Immutable posttrust bindings retained with the one Build rewind. Empty
    /// values are readable only for ledgers written before this schema addition.
    #[serde(default)]
    pub checkpoint_scope_digest: String,
    #[serde(default)]
    pub security_evidence_digest: String,
    #[serde(default)]
    pub bootstrap_nonce_digest: String,
    #[serde(default)]
    pub trusted_policy_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirstAdoptionRestartStage {
    Pretrust,
    Posttrust,
}

/// A bounded, append-only correction to first-adoption checkpoint eligibility.
/// `replacement_tip_oid` is mandatory before trust exists; after trust exists,
/// an activation-only recovery may retain the same source tip by leaving it
/// absent. The event invalidates, rather than upgrades, an older proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstAdoptionRestartV1 {
    pub schema: u32,
    pub stage: FirstAdoptionRestartStage,
    pub superseded_checkpoint_oid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_proof_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_tip_oid: Option<String>,
    pub actor: String,
    pub reason: String,
    pub evidence_digest: String,
    pub at_epoch_secs: u64,
}

impl FirstAdoptionRestartV1 {
    fn same_intent(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.stage == other.stage
            && self.superseded_checkpoint_oid == other.superseded_checkpoint_oid
            && self.superseded_proof_digest == other.superseded_proof_digest
            && self.replacement_tip_oid == other.replacement_tip_oid
            && self.actor == other.actor
            && self.reason == other.reason
            && self.evidence_digest == other.evidence_digest
    }
}

/// Derived state used by reconciliation/final gates to bind the last eligible
/// checkpoint and current evidence without rewriting any earlier event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // persisted codec is implemented before a mutation CLI is authorized
pub struct FirstAdoptionEligibilityV1 {
    pub schema: u32,
    pub latest_eligible_checkpoint_oid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_eligible_proof_digest: Option<String>,
    pub latest_evidence_digest: String,
    pub checkpoint_chain_digest: String,
    pub restart_count: usize,
}

impl Ledger {
    /// A fresh ledger positioned at the first applicable phase.
    #[cfg(test)]
    pub fn new(
        change: impl Into<String>,
        schema: impl Into<String>,
        ui: bool,
        kind: ChangeKind,
    ) -> Ledger {
        Self::new_with_governance(change, schema, ui, kind, Governance::default())
    }

    pub fn new_with_governance(
        change: impl Into<String>,
        schema: impl Into<String>,
        ui: bool,
        kind: ChangeKind,
        governance: Governance,
    ) -> Ledger {
        let applicability = Applicability {
            ui,
            docs: kind.documents(),
        };
        Ledger {
            format: LEDGER_FORMAT,
            change: change.into(),
            schema: schema.into(),
            ui,
            kind,
            phase: Phase::first(applicability),
            gates: BTreeMap::new(),
            conditions: Vec::new(),
            task_deferrals: Vec::new(),
            history: Vec::new(),
            governance,
            risk_assessment: None,
            strict: false,
            waivers: Vec::new(),
            phase_started_at_epoch_secs: now_epoch_secs(),
            archive_closure: None,
            brief_tuning: BTreeMap::new(),
            first_adoption_reconciliations: Vec::new(),
            first_adoption_restarts: Vec::new(),
            legacy_repairs: Vec::new(),
            freshness_invalidations: Vec::new(),
            introduced_by: None,
        }
    }

    pub fn effective_risk(&self) -> RiskLevel {
        self.risk_assessment
            .as_ref()
            .map(|assessment| assessment.effective)
            .unwrap_or(self.governance.risk)
    }

    /// Apply one causal freshness rewind. Latest downstream approvals stop
    /// driving state, while the append-only verdict history and conditions are
    /// retained. Closed downstream obligations are explicitly reopened.
    pub fn invalidate_for_freshness(
        &mut self,
        rewind_phase: Phase,
        stale_phases: Vec<Phase>,
        reasons: Vec<String>,
    ) -> Result<(), String> {
        if self.archive_closure.is_some() {
            return Err("freshness rewind refuses archived state".into());
        }
        if rewind_phase >= self.phase {
            return Err(format!(
                "freshness rewind target {} is not earlier than stored phase {}",
                rewind_phase.label(),
                self.phase.label()
            ));
        }
        let stored_phase = self.phase;
        for phase in Phase::applicable(self.applicability()) {
            if phase >= rewind_phase {
                self.gates.remove(&phase);
                self.brief_tuning.remove(&phase);
            }
        }
        self.waivers.retain(|waiver| waiver.phase < rewind_phase);
        self.reopen_conditions_from(rewind_phase, "stale evidence rewind");
        self.phase = rewind_phase;
        self.phase_started_at_epoch_secs = now_epoch_secs();
        self.freshness_invalidations
            .push(FreshnessInvalidationEvent {
                schema: 1,
                stored_phase,
                rewind_phase,
                stale_phases,
                reasons,
                at_epoch_secs: now_epoch_secs(),
            });
        Ok(())
    }

    /// Record the brief-time tuning `next` computed for `phase` at `attempt`,
    /// monotonic weakest-seen: a record for the SAME attempt is MERGED (never
    /// downgraded — design.md Cond 11, round-3 F2); a different attempt replaces.
    /// Callers write only when `record.is_baseline()` is false (inertness).
    pub fn record_brief_tuning(
        &mut self,
        phase: Phase,
        attempt: usize,
        record: PersonaTuningRecord,
    ) {
        match self.brief_tuning.get_mut(&phase) {
            Some(existing) if existing.attempt == attempt => {
                existing.record.merge_weakest_seen(&record);
            }
            _ => {
                self.brief_tuning
                    .insert(phase, BriefTuning { attempt, record });
            }
        }
    }

    /// The brief-time tuning recorded for `phase` iff it matches `attempt` — the
    /// gate consumes it only on an exact `(phase, attempt)` match, falling back to
    /// a live determination otherwise so a stale superseded record can never mask
    /// (design.md Cond 11, round-3 F4).
    pub fn brief_tuning_for(&self, phase: Phase, attempt: usize) -> Option<&PersonaTuningRecord> {
        self.brief_tuning
            .get(&phase)
            .filter(|bt| bt.attempt == attempt)
            .map(|bt| &bt.record)
    }

    /// Turn on the strict (self-enforcing) tier. Write-once / monotonic: this is
    /// the ONLY path that mutates `strict`, and it only ever sets it true — there
    /// is deliberately no true→false setter (design.md Cond 14), the linchpin the
    /// whole enforcement hangs on.
    // Consumed by the `conduct` / `begin --strict` bit-setter (a later stage);
    // exercised now by the monotonicity test.
    #[allow(dead_code)]
    pub fn set_strict(&mut self) {
        self.strict = true;
    }

    pub fn attempts_for(&self, phase: Phase) -> usize {
        self.history.iter().filter(|e| e.phase == phase).count()
    }
    pub fn next_attempt(&self, phase: Phase) -> usize {
        next_attempt_after(self.attempts_for(phase))
    }
    pub fn attempt_authorized(&self, phase: Phase) -> bool {
        let next = self.next_attempt(phase);
        next <= self.effective_risk().attempt_limit()
            || self
                .governance
                .reconciliations
                .iter()
                .any(|r| !r.consumed && r.phase == phase && r.authorized_attempt == next)
    }

    /// The one-shot reconciliation authorizing the next excess attempt, if any.
    pub fn attempt_authorization(&self, phase: Phase) -> Option<&Reconciliation> {
        let next = self.next_attempt(phase);
        (next > self.effective_risk().attempt_limit())
            .then(|| {
                self.governance
                    .reconciliations
                    .iter()
                    .find(|r| !r.consumed && r.phase == phase && r.authorized_attempt == next)
            })
            .flatten()
    }
    pub fn reconcile(
        &mut self,
        kind: ReconciliationKind,
        reason: String,
        new_value: Option<String>,
    ) -> Result<(), String> {
        let reason = bounded_text(&reason, "reason")?;
        let phase = self.phase;
        let mut prior = None;
        let mut new = None;
        match kind {
            ReconciliationKind::Risk => {
                let value: RiskLevel = new_value.ok_or("--risk requires a value")?.parse()?;
                prior = Some(self.governance.risk.to_string());
                new = Some(value.to_string());
                self.governance.risk = value;
                self.invalidate_from_security();
            }
            ReconciliationKind::ThreatProfile => {
                let value: ThreatProfile = new_value
                    .ok_or("--threat-profile requires a value")?
                    .parse()?;
                prior = Some(self.governance.threat_profile.to_string());
                new = Some(value.to_string());
                self.governance.threat_profile = value;
                self.invalidate_from_security();
            }
            _ => {}
        }
        let phase = if matches!(
            kind,
            ReconciliationKind::Risk | ReconciliationKind::ThreatProfile
        ) {
            self.phase
        } else {
            phase
        };
        let authorized_attempt = self.next_attempt(phase);
        self.governance.reconciliations.push(Reconciliation {
            kind,
            reason,
            phase,
            authorized_attempt,
            at_epoch_secs: now_epoch_secs(),
            prior,
            new,
            consumed: false,
        });
        Ok(())
    }
    fn invalidate_from_security(&mut self) {
        for p in Phase::applicable(self.applicability()) {
            if p >= Phase::SecurityPlan {
                self.gates.remove(&p);
            }
        }
        // Drop strict waivers for the rewound phases, exactly as their gate
        // records are dropped: a waiver recorded for Security/downstream on a
        // prior attempt must not silently suppress the artifact gate on the
        // re-run under the changed threat profile (design.md D7 / B1).
        self.waivers.retain(|w| w.phase < Phase::SecurityPlan);
        self.reopen_conditions_from(Phase::SecurityPlan, "governance rewind");
        // Rewind-only, never advance: a governance change while the change is still
        // BEFORE Security (e.g. at Architecture) must stay put — jumping forward to
        // SecurityPlan would skip the ungated intervening phase(s). Downstream
        // (phase > SecurityPlan) still rewinds to force a fresh Security review.
        if self.phase > Phase::SecurityPlan {
            self.phase = Phase::SecurityPlan;
            self.phase_started_at_epoch_secs = now_epoch_secs();
        }
    }

    /// Record the sole posttrust adoption transition and rewind to Build
    /// without erasing any provisional gate events. An exact replay is a no-op;
    /// a conflicting transition is refused rather than laundering history.
    #[cfg(test)]
    pub fn reconcile_first_adoption(
        &mut self,
        event: FirstAdoptionReconciliationV1,
    ) -> Result<bool, String> {
        if let Some(existing) = self.first_adoption_reconciliations.first() {
            if existing == &event {
                return Ok(false);
            }
            return Err("conflicting first-adoption reconciliation already exists".into());
        }
        self.first_adoption_reconciliations.push(event);
        for phase in Phase::applicable(self.applicability()) {
            if phase >= Phase::Build {
                self.gates.remove(&phase);
            }
        }
        self.waivers.retain(|w| w.phase < Phase::Build);
        self.reopen_conditions_from(Phase::Build, "first-adoption reconciliation rewind");
        if self.phase > Phase::Build {
            self.phase = Phase::Build;
            self.phase_started_at_epoch_secs = now_epoch_secs();
        }
        Ok(true)
    }

    /// Append a first-adoption correction without deleting or editing any
    /// earlier checkpoint/proof record. An exact response-loss replay is a
    /// no-op; every other attempt to supersede an already-consumed checkpoint
    /// is a conflict.
    #[allow(dead_code)] // no live mutation command is authorized in this slice
    pub fn append_first_adoption_restart(
        &mut self,
        event: FirstAdoptionRestartV1,
    ) -> Result<bool, String> {
        validate_first_adoption_restart(&event)?;
        let reconciled = !self.first_adoption_reconciliations.is_empty();
        match event.stage {
            FirstAdoptionRestartStage::Pretrust if reconciled => {
                return Err("pretrust restart refused after first-adoption reconciliation".into());
            }
            FirstAdoptionRestartStage::Posttrust if !reconciled => {
                return Err("posttrust restart requires first-adoption reconciliation".into());
            }
            _ => {}
        }
        if self
            .first_adoption_restarts
            .iter()
            .any(|prior| prior.same_intent(&event))
        {
            return Ok(false);
        }
        if self.first_adoption_restarts.len() >= 64 {
            return Err("first-adoption restart history exceeds 64 events".into());
        }
        if self
            .first_adoption_restarts
            .iter()
            .any(|prior| prior.superseded_checkpoint_oid == event.superseded_checkpoint_oid)
        {
            return Err("first-adoption checkpoint was already superseded".into());
        }
        if let Some(previous) = self.first_adoption_restarts.last() {
            let latest = previous
                .replacement_tip_oid
                .as_deref()
                .unwrap_or(&previous.superseded_checkpoint_oid);
            if event.superseded_checkpoint_oid != latest {
                return Err(
                    "first-adoption restart does not extend the latest eligible checkpoint".into(),
                );
            }
        } else if matches!(event.stage, FirstAdoptionRestartStage::Posttrust) {
            let checkpoint = &self.first_adoption_reconciliations[0].checkpoint_oid;
            if event.superseded_checkpoint_oid != *checkpoint {
                return Err(
                    "posttrust restart does not supersede the reconciled checkpoint".into(),
                );
            }
        }
        self.first_adoption_restarts.push(event);
        Ok(true)
    }

    /// Fold restart history into the single checkpoint/evidence state eligible
    /// for reconciliation and final gates. Any restart invalidates the proof
    /// bound to its superseded checkpoint; a fresh proof must therefore be
    /// supplied and verified separately for the replacement tip.
    #[allow(dead_code)] // consumed by tests and the future reviewed restart command
    pub fn first_adoption_eligibility(
        &self,
        initial_checkpoint_oid: &str,
        initial_proof_digest: Option<&str>,
        initial_evidence_digest: &str,
    ) -> Result<FirstAdoptionEligibilityV1, String> {
        validate_full_oid(initial_checkpoint_oid, "initial checkpoint")?;
        if let Some(proof) = initial_proof_digest {
            validate_sha256(proof, "initial proof digest")?;
        }
        validate_sha256(initial_evidence_digest, "initial evidence digest")?;

        let mut latest = initial_checkpoint_oid.to_string();
        let mut proof = initial_proof_digest.map(str::to_string);
        let mut evidence = initial_evidence_digest.to_string();
        let mut chain = format!("mpd:first-adoption-checkpoint-chain:v1\0{latest}\0{evidence}");
        for event in &self.first_adoption_restarts {
            validate_first_adoption_restart(event)?;
            if event.superseded_checkpoint_oid != latest {
                return Err(
                    "first-adoption restart history is not a contiguous checkpoint chain".into(),
                );
            }
            if let (Some(expected), Some(superseded)) =
                (proof.as_deref(), event.superseded_proof_digest.as_deref())
            {
                if superseded != expected {
                    return Err("first-adoption restart supersedes a different proof".into());
                }
            }
            latest = event
                .replacement_tip_oid
                .clone()
                .unwrap_or_else(|| event.superseded_checkpoint_oid.clone());
            proof = None;
            evidence.clone_from(&event.evidence_digest);
            chain.push('\0');
            chain.push_str(match event.stage {
                FirstAdoptionRestartStage::Pretrust => "pretrust",
                FirstAdoptionRestartStage::Posttrust => "posttrust",
            });
            chain.push('\0');
            chain.push_str(&event.superseded_checkpoint_oid);
            chain.push('\0');
            chain.push_str(event.superseded_proof_digest.as_deref().unwrap_or("-"));
            chain.push('\0');
            chain.push_str(event.replacement_tip_oid.as_deref().unwrap_or("-"));
            chain.push('\0');
            chain.push_str(&event.evidence_digest);
        }
        Ok(FirstAdoptionEligibilityV1 {
            schema: 1,
            latest_eligible_checkpoint_oid: latest,
            latest_eligible_proof_digest: proof,
            latest_evidence_digest: evidence,
            checkpoint_chain_digest: crate::digest::Digest::of_bytes(chain.as_bytes()).to_hex(),
            restart_count: self.first_adoption_restarts.len(),
        })
    }

    /// The change's phase applicability (which optional phase groups run).
    pub fn applicability(&self) -> Applicability {
        Applicability {
            ui: self.ui,
            docs: self.kind.documents(),
        }
    }

    fn reopen_conditions_from(&mut self, rewind_phase: Phase, reason: &str) {
        let at_epoch_secs = now_epoch_secs();
        for condition in &mut self.conditions {
            if condition.phase >= rewind_phase {
                condition.events.push(ConditionEvent::Reopened {
                    at_epoch_secs,
                    reason: reason.to_string(),
                    rewind_phase,
                });
                condition.closed = false;
            }
        }
    }

    /// Record a verdict for `phase`. If it advances and is the current phase,
    /// move to the next applicable phase.
    pub fn record(&mut self, phase: Phase, record: GateRecord) -> Result<(), String> {
        if self.phase == Phase::Done {
            return Err("all phases are complete; no further gate can be recorded".into());
        }
        if !phase.is_active(self.applicability()) {
            return Err(format!(
                "{} is not applicable to this change",
                phase.label()
            ));
        }
        if phase != self.phase {
            return Err(format!(
                "cannot record {} while current phase is {}; run `mpd gate {}`",
                phase.label(),
                self.phase.label(),
                self.phase.slug()
            ));
        }
        let advances = record.verdict.advances();
        // Preserve the full audit trail: a later PASS must not erase an earlier
        // FAIL/CONDITIONAL for the same phase. `gates` keeps the latest verdict
        // (drives advancement + readiness); `history` keeps every verdict.
        self.history.push(GateEvent {
            phase,
            record: record.clone(),
        });
        self.gates.insert(phase, record);
        if let Some(r) = self.governance.reconciliations.iter_mut().find(|r| {
            !r.consumed
                && r.phase == phase
                && r.authorized_attempt
                    == self.history.last().map(|e| e.record.attempt).unwrap_or(0)
        }) {
            r.consumed = true;
        }
        if advances && phase == self.phase {
            self.phase = phase.next(self.applicability());
            self.phase_started_at_epoch_secs = now_epoch_secs();
        }
        Ok(())
    }

    /// Reasons the change cannot be archived yet (empty ⇒ ready). Every
    /// applicable phase must have an unconditional PASS, the terminal phase must
    /// be Done, and no evidence-bearing condition may remain open.
    pub fn blocking_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.strict {
            reasons.extend(self.integrity_blockers());
            if !self.waivers.is_empty() {
                reasons.push(
                    "legacy artifact waivers are present; current Commando policy denies waivers"
                        .into(),
                );
            }
        }
        for phase in Phase::applicable(self.applicability()) {
            match self.gates.get(&phase) {
                None => reasons.push(format!("{} gate not recorded", phase.label())),
                Some(rec) if rec.verdict != Verdict::Pass => {
                    reasons.push(format!(
                        "{} gate is not an unconditional PASS",
                        phase.label()
                    ));
                }
                Some(_) => {}
            }
        }
        for (i, cond) in self.conditions.iter().enumerate() {
            if cond.is_open() {
                reasons.push(format!(
                    "open condition {}: {}",
                    if cond.id.is_empty() {
                        (i + 1).to_string()
                    } else {
                        cond.id.clone()
                    },
                    cond.text
                ));
            }
        }
        if self.phase != Phase::Done {
            reasons.push(format!("current phase is {}, not Done", self.phase.label()));
        }
        reasons
    }

    /// Whether the change is ready to archive.
    pub fn ready_to_archive(&self) -> bool {
        self.blocking_reasons().is_empty()
    }

    /// Return the active deferral for this exact normalized task record. A
    /// matching ID with another digest is deliberately *not* reused: editing a
    /// task contract makes its previous deferral stale rather than retargeting
    /// it to new work.
    pub fn active_task_deferral(&self, task: &TaskEntry) -> Option<&TaskDeferral> {
        self.task_deferrals.iter().rev().find(|deferral| {
            deferral.task_id == task.id
                && deferral.record_digest == task.record_digest
                && deferral.is_active()
        })
    }

    /// Deterministic Builder-task accounting for Test/archive. `done` and a
    /// current evidence-backed deferral are distinct truths; stale deferrals
    /// are blockers, never silent waivers.
    pub fn task_accounting(&self, plan: &TaskPlan) -> TaskAccounting {
        let mut accounting = TaskAccounting {
            total: plan.entries.len(),
            ..TaskAccounting::default()
        };
        for task in &plan.entries {
            if task.done {
                accounting.done += 1;
            } else if self.active_task_deferral(task).is_some() {
                accounting.deferred += 1;
            } else {
                accounting.open.push(task.id.clone());
            }
        }
        for deferral in &self.task_deferrals {
            if !deferral.is_active() {
                continue;
            }
            if plan.entries.iter().any(|task| {
                task.id == deferral.task_id && task.record_digest != deferral.record_digest
            }) || !plan.entries.iter().any(|task| task.id == deferral.task_id)
            {
                accounting.stale.push(deferral.task_id.clone());
            }
        }
        accounting.stale.sort();
        accounting.stale.dedup();
        accounting
    }

    pub fn defer_task(
        &mut self,
        task: &TaskEntry,
        owner: &str,
        reason: &str,
        evidence: String,
        evidence_digest: String,
    ) -> Result<(), String> {
        let owner = bounded_text(owner, "task deferral owner")?;
        let reason = bounded_text(reason, "task deferral reason")?;
        if task.done {
            return Err(format!("task {} is already checked", task.id));
        }
        let event = TaskDeferralEvent::Deferred {
            owner,
            reason,
            evidence,
            evidence_digest,
            at_epoch_secs: now_epoch_secs(),
        };
        if let Some(existing) = self.task_deferrals.iter_mut().rev().find(|deferral| {
            deferral.task_id == task.id && deferral.record_digest == task.record_digest
        }) {
            existing.events.push(event);
        } else {
            self.task_deferrals.push(TaskDeferral {
                task_id: task.id.clone(),
                record_digest: task.record_digest.clone(),
                events: vec![event],
            });
        }
        Ok(())
    }

    pub fn revoke_task_deferral(&mut self, task: &TaskEntry, reason: &str) -> Result<(), String> {
        let reason = bounded_text(reason, "task deferral revocation reason")?;
        let Some(existing) = self.task_deferrals.iter_mut().rev().find(|deferral| {
            deferral.task_id == task.id
                && deferral.record_digest == task.record_digest
                && deferral.is_active()
        }) else {
            return Err(format!("task {} has no current deferral", task.id));
        };
        existing.events.push(TaskDeferralEvent::Revoked {
            reason,
            at_epoch_secs: now_epoch_secs(),
        });
        Ok(())
    }

    /// Validate a requested compatibility rewind without mutating the ledger.
    /// Returns `true` when the exact rewind already exists and is the current
    /// state, making command replay idempotent.
    pub fn repair_state_preview(&self, rewind: Phase, reason: &str) -> Result<bool, String> {
        let reason = bounded_text(reason, "repair reason")?;
        if self.archive_closure.is_some() {
            return Err("repair-state refuses archived state; archives are immutable".into());
        }
        if rewind == Phase::Done {
            return Err("repair-state --to must name a pipeline phase, not done".into());
        }
        let already_exists = self.phase == rewind
            && self
                .legacy_repairs
                .last()
                .is_some_and(|event| event.rewind_phase == rewind && event.reason == reason);
        if already_exists {
            return Ok(true);
        }
        if rewind >= self.phase {
            return Err(format!(
                "repair-state only rewinds: {} is not earlier than current phase {}",
                rewind.label(),
                self.phase.label()
            ));
        }
        Ok(false)
    }

    /// Compatibility repair can only rewind and append an explicit event. It
    /// removes current downstream approvals while retaining the complete gate
    /// history, and cannot synthesize PASS or edit archive history. Returns
    /// `false` for an idempotent replay that was already applied.
    pub fn repair_state_to(
        &mut self,
        rewind: Phase,
        reason: &str,
        ledger_before_digest: &str,
    ) -> Result<bool, String> {
        if self.repair_state_preview(rewind, reason)? {
            return Ok(false);
        }
        let reason = bounded_text(reason, "repair reason")?;
        if ledger_before_digest.len() != 64
            || !ledger_before_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("observed ledger digest must be a 64-character hex digest".into());
        }
        for phase in Phase::applicable(self.applicability()) {
            if phase >= rewind {
                self.gates.remove(&phase);
                self.brief_tuning.remove(&phase);
            }
        }
        for condition in &mut self.conditions {
            if condition.phase >= rewind && !condition.is_open() {
                condition.events.push(ConditionEvent::Reopened {
                    at_epoch_secs: now_epoch_secs(),
                    reason: reason.clone(),
                    rewind_phase: rewind,
                });
                condition.closed = false;
            }
        }
        self.phase = rewind;
        self.phase_started_at_epoch_secs = now_epoch_secs();
        self.legacy_repairs.push(LegacyRepairEvent {
            reason,
            rewind_phase: rewind,
            ledger_before_digest: ledger_before_digest.to_ascii_lowercase(),
            at_epoch_secs: now_epoch_secs(),
        });
        Ok(true)
    }

    /// Strict ledger integrity blockers. Legacy state stays readable but does
    /// not become archive-ready merely because an old boolean happened to be
    /// true.
    pub fn integrity_blockers(&self) -> Vec<String> {
        let mut blockers = Vec::new();
        for condition in &self.conditions {
            if condition.events.is_empty() {
                blockers.push(format!("condition {} is legacy-unscoped", condition.id));
            }
        }
        blockers
    }

    /// Close the 1-based condition (as numbered by `blocking_reasons` /
    /// `mpd status`). Errors if the index is out of range.
    pub fn close_condition(
        &mut self,
        index_1based: usize,
        by: &str,
        evidence: String,
        evidence_digest: String,
    ) -> Result<(), String> {
        let i = index_1based
            .checked_sub(1)
            .ok_or_else(|| "condition numbers are 1-based".to_string())?;
        let len = self.conditions.len();
        let cond = self.conditions.get_mut(i).ok_or_else(|| {
            format!(
                "no condition #{index_1based} (there {} {})",
                if len == 1 { "is" } else { "are" },
                len
            )
        })?;
        let by = bounded_text(by, "condition closer")?;
        cond.events.push(ConditionEvent::Resolved {
            by,
            at_epoch_secs: now_epoch_secs(),
            evidence,
            evidence_digest,
        });
        cond.closed = true;
        Ok(())
    }

    /// Close every open condition; returns how many were newly closed.
    pub fn close_all_conditions(
        &mut self,
        by: &str,
        evidence: String,
        evidence_digest: String,
    ) -> Result<usize, String> {
        let by = bounded_text(by, "condition closer")?;
        let mut n = 0;
        for c in self.conditions.iter_mut() {
            if c.is_open() {
                c.events.push(ConditionEvent::Resolved {
                    by: by.clone(),
                    at_epoch_secs: now_epoch_secs(),
                    evidence: evidence.clone(),
                    evidence_digest: evidence_digest.clone(),
                });
                c.closed = true;
                n += 1;
            }
        }
        Ok(n)
    }
}

fn next_attempt_after(prior_attempts: usize) -> usize {
    prior_attempts.saturating_add(1)
}

/// `<root>/.mpd`.
pub fn mpd_dir(root: &Path) -> PathBuf {
    root.join(".mpd")
}

/// Path to a change's ledger file.
pub fn state_path(root: &Path, change: &str) -> PathBuf {
    mpd_dir(root).join("state").join(format!("{change}.json"))
}

/// Path to the "current change" pointer.
pub fn current_path(root: &Path) -> PathBuf {
    mpd_dir(root).join("current")
}

/// Load a change's ledger.
pub fn load(root: &Path, change: &str) -> io::Result<Ledger> {
    validate_change_name(change).map_err(invalid)?;
    let path = state_path(root, change);
    let text = openspec_core::read_contained_capped(root, &path, openspec_core::DEFAULT_MAX_BYTES)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    serde_json::from_str(&text).map_err(|error| ledger_version_probe(&path, &text, error))
}

/// D5: when full deserialization has already failed, probe-parse the same
/// bytes as a bare `serde_json::Value` to give an honest, diagnosable error —
/// never consulted on the happy path, so a ledger that parses is returned
/// identically to today. `format` is read as an unsigned integer ONLY (Cond
/// 15): a string, float, negative, or otherwise non-`u32` value is treated as
/// absent, never a panic or a version claim.
fn ledger_version_probe(path: &Path, text: &str, original: serde_json::Error) -> io::Error {
    let original = io::Error::new(io::ErrorKind::InvalidData, original);
    let Ok(probe) = serde_json::from_str::<serde_json::Value>(text) else {
        // Not even JSON: the original serde error is preserved unchanged.
        return original;
    };
    let format = probe
        .get("format")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let path = path.display();
    match format {
        Some(found) if found > LEDGER_FORMAT => {
            // Bounded like every other disk-derived string this binary
            // surfaces (Cond 15/17 discipline) — a hostile/future ledger's
            // `change` field is not trusted to be short.
            const MAX_CHANGE_HINT_CHARS: usize = 200;
            let change_hint = probe
                .get("change")
                .and_then(serde_json::Value::as_str)
                .map(crate::harness::terminal_safe)
                .map(|value| {
                    if value.chars().count() > MAX_CHANGE_HINT_CHARS {
                        value
                            .chars()
                            .take(MAX_CHANGE_HINT_CHARS)
                            .collect::<String>()
                            + "…"
                    } else {
                        value
                    }
                });
            let message = match change_hint {
                Some(change) => format!(
                    "{path}: ledger for change {change:?} requires a newer mpd \
                     (ledger format {found}, this binary supports up to {LEDGER_FORMAT})"
                ),
                None => format!(
                    "{path}: this ledger requires a newer mpd \
                     (ledger format {found}, this binary supports up to {LEDGER_FORMAT})"
                ),
            };
            io::Error::new(io::ErrorKind::InvalidData, message)
        }
        // `format` parses but is <= LEDGER_FORMAT, or is absent entirely: we
        // cannot distinguish corruption from forward-skew for pre-format
        // ledgers, so the original serde error is kept, only given path
        // context and an honest hint.
        _ => io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{path}: {original}\n  hint: this ledger may have been written by a newer or \
                 different mpd"
            ),
        ),
    }
}

/// Load a ledger together with the digest of the exact observed file image.
pub fn load_observed(root: &Path, change: &str) -> io::Result<(Ledger, String)> {
    let (ledger, observed) = load_observed_exact(root, change)?;
    Ok((ledger, observed.digest))
}

/// Exact file image paired with a parsed ledger for compare-and-swap writes.
#[derive(Debug, Clone)]
pub struct LedgerObservation {
    exact: String,
    digest: String,
}

impl LedgerObservation {
    /// Digest used by audit records and human-readable previews.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Load a ledger together with the exact bytes required by a later CAS save.
pub fn load_observed_exact(root: &Path, change: &str) -> io::Result<(Ledger, LedgerObservation)> {
    validate_change_name(change).map_err(invalid)?;
    let path = state_path(root, change);
    let text = openspec_core::read_contained_capped(root, &path, openspec_core::DEFAULT_MAX_BYTES)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let digest = openspec_core::digest::Digest::of_bytes(text.as_bytes()).to_hex();
    let ledger =
        serde_json::from_str(&text).map_err(|error| ledger_version_probe(&path, &text, error))?;
    Ok((
        ledger,
        LedgerObservation {
            exact: text,
            digest,
        },
    ))
}

/// Persist a change's ledger (pretty JSON, trailing newline).
pub fn save(root: &Path, ledger: &Ledger) -> io::Result<()> {
    validate_change_name(&ledger.change).map_err(invalid)?;
    let _lock = acquire_ledger_lock(root, &ledger.change)?;
    let path = state_path(root, &ledger.change);
    let json = serialized_ledger(ledger)?;
    classified_into_io(atomic_write_contained_classified(
        root,
        &path,
        json.as_bytes(),
    ))
}

/// Persist only if the ledger still has the exact image observed by the caller.
/// The final replacement uses the same contained atomic writer as [`save`].
pub fn save_if_observed(root: &Path, ledger: &Ledger, observed: &str) -> io::Result<()> {
    validate_change_name(&ledger.change).map_err(invalid)?;
    let _lock = acquire_ledger_lock(root, &ledger.change)?;
    let path = state_path(root, &ledger.change);
    let current =
        openspec_core::read_contained_capped(root, &path, openspec_core::DEFAULT_MAX_BYTES)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let current_digest = openspec_core::digest::Digest::of_bytes(current.as_bytes()).to_hex();
    if current_digest != observed {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "ledger changed after preview; refusing stale repair",
        ));
    }
    let json = serialized_ledger(ledger)?;
    classified_into_io(atomic_write_contained_classified(
        root,
        &path,
        json.as_bytes(),
    ))
}

/// Exact CAS result for a ledger mutation that may transfer external resource
/// ownership after the durable binding wins.
#[derive(Debug)]
pub enum ExactSaveOutcome {
    /// Rename and parent-directory sync completed normally.
    Committed,
    /// Rename installed the exact expected bytes, but a later sync/reporting
    /// operation failed. Exact readback under the ledger lock confirmed the win.
    CommittedAfterRename { error: String },
    /// This invocation did not replace the ledger.
    NotCommitted(io::Error),
    /// Rename occurred, but exact readback could not confirm the expected bytes.
    UncertainAfterRename(io::Error),
}

/// Persist one exact observed-ledger mutation while serializing every MPD
/// ledger writer through the same descriptor-held advisory lock.
pub fn save_exact_observed(
    root: &Path,
    ledger: &Ledger,
    observed: &LedgerObservation,
) -> ExactSaveOutcome {
    save_exact_observed_with(root, ledger, observed, |root, path, bytes| {
        atomic_write_contained_classified(root, path, bytes)
    })
}

fn save_exact_observed_with<F>(
    root: &Path,
    ledger: &Ledger,
    observed: &LedgerObservation,
    writer: F,
) -> ExactSaveOutcome
where
    F: FnOnce(&Path, &Path, &[u8]) -> AtomicWriteOutcome,
{
    if let Err(error) = validate_change_name(&ledger.change).map_err(invalid) {
        return ExactSaveOutcome::NotCommitted(error);
    }
    let _lock = match acquire_ledger_lock(root, &ledger.change) {
        Ok(lock) => lock,
        Err(error) => return ExactSaveOutcome::NotCommitted(error),
    };
    let path = state_path(root, &ledger.change);
    let current =
        match openspec_core::read_contained_capped(root, &path, openspec_core::DEFAULT_MAX_BYTES) {
            Ok(current) => current,
            Err(error) => {
                return ExactSaveOutcome::NotCommitted(io::Error::other(error.to_string()))
            }
        };
    if current != observed.exact {
        return ExactSaveOutcome::NotCommitted(io::Error::new(
            io::ErrorKind::WouldBlock,
            "ledger changed after observation; refusing stale gate write",
        ));
    }
    let expected = match serialized_ledger(ledger) {
        Ok(expected) => expected,
        Err(error) => return ExactSaveOutcome::NotCommitted(error),
    };
    match writer(root, &path, expected.as_bytes()) {
        AtomicWriteOutcome::Committed => ExactSaveOutcome::Committed,
        AtomicWriteOutcome::FailedBeforeRename(error) => {
            ExactSaveOutcome::NotCommitted(io::Error::other(error.to_string()))
        }
        AtomicWriteOutcome::FailedAfterRename(error) => {
            let readback =
                openspec_core::read_contained_capped(root, &path, openspec_core::DEFAULT_MAX_BYTES);
            match readback {
                Ok(current) if current == expected => ExactSaveOutcome::CommittedAfterRename {
                    error: error.to_string(),
                },
                Ok(_) => ExactSaveOutcome::UncertainAfterRename(io::Error::other(format!(
                    "ledger replacement reported a post-rename failure and exact readback differed: {error}"
                ))),
                Err(readback) => ExactSaveOutcome::UncertainAfterRename(io::Error::other(format!(
                    "ledger replacement reported a post-rename failure and exact readback failed: {error}; {readback}"
                ))),
            }
        }
    }
}

fn serialized_ledger(ledger: &Ledger) -> io::Result<String> {
    // D5: every durable write stamps the current format, regardless of what
    // was loaded (a legacy ledger's defaulted `format: 1` never survives a
    // resave under this binary).
    let stamped = if ledger.format == LEDGER_FORMAT {
        None
    } else {
        let mut stamped = ledger.clone();
        stamped.format = LEDGER_FORMAT;
        Some(stamped)
    };
    let mut json = serde_json::to_string_pretty(stamped.as_ref().unwrap_or(ledger))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    json.push('\n');
    Ok(json)
}

fn classified_into_io(outcome: AtomicWriteOutcome) -> io::Result<()> {
    match outcome {
        AtomicWriteOutcome::Committed => Ok(()),
        AtomicWriteOutcome::FailedBeforeRename(error)
        | AtomicWriteOutcome::FailedAfterRename(error) => Err(io::Error::other(error.to_string())),
    }
}

struct LedgerFileLock {
    _file: File,
}

fn acquire_ledger_lock(root: &Path, change: &str) -> io::Result<LedgerFileLock> {
    validate_change_name(change).map_err(invalid)?;
    // The lock is process authority, not product state. Keeping a persistent
    // lock beside the manifest-visible ledger made an otherwise clean archive
    // dirty and let pre-commit mistake the lock for candidate content. Resolve
    // it below Git's clone-private common directory instead; linked worktrees
    // therefore serialize on the same lock without adding a worktree path.
    let common = crate::local_validation::git_common_dir(root).map_err(io::Error::other)?;
    let private = common.join("mpd");
    let locks = private.join("ledger-locks");
    ensure_owner_private_lock_dir(&private)?;
    ensure_owner_private_lock_dir(&locks)?;
    let path = locks.join(format!("{change}.lock"));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options.open(&path)?;
    file.lock()?;
    let descriptor = file.metadata()?;
    let named = fs::symlink_metadata(&path)?;
    if descriptor.file_type().is_symlink()
        || !descriptor.is_file()
        || named.file_type().is_symlink()
        || !named.is_file()
    {
        return Err(io::Error::other("ledger lock is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = fs::metadata(root)?.uid();
        if descriptor.dev() != named.dev()
            || descriptor.ino() != named.ino()
            || descriptor.nlink() != 1
            || descriptor.uid() != owner
            || descriptor.mode() & 0o077 != 0
            || descriptor.mode() & 0o600 != 0o600
        {
            return Err(io::Error::other(
                "ledger lock identity or owner-only permissions are invalid",
            ));
        }
    }
    Ok(LedgerFileLock { _file: file })
}

fn ensure_owner_private_lock_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
        }
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(
            "ledger lock directory is not a no-follow directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = fs::metadata(
            path.ancestors()
                .find(|ancestor| ancestor.file_name().is_some_and(|name| name == ".git"))
                .unwrap_or(path),
        )?
        .uid();
        if metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "ledger lock directory is not owner-private",
            ));
        }
    }
    Ok(())
}

/// Read the current-change pointer, if set. A value that is not a valid change
/// name (e.g. a tampered, git-tracked `.mpd/current` carrying `../../`) is
/// treated as unset rather than trusted into a path.
pub fn current(root: &Path) -> Option<String> {
    openspec_core::read_contained_capped(root, &current_path(root), 1024)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .filter(|s| validate_change_name(s).is_ok())
}

/// Set the current-change pointer.
pub fn set_current(root: &Path, change: &str) -> io::Result<()> {
    validate_change_name(change).map_err(invalid)?;
    let path = current_path(root);
    openspec_core::atomic_write_contained(root, &path, format!("{change}\n").as_bytes())
        .map_err(|e| io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn init_locking_fixture(root: &Path) {
        std::fs::create_dir_all(root.join(".mpd/state")).unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
    }

    fn pass(by: &str) -> GateRecord {
        GateRecord {
            verdict: Verdict::Pass,
            by: by.to_string(),
            evidence: None,
            checks: None,
            at: "2026-07-11".to_string(),
            failure_class: None,
            exploitability: None,
            attempt: 1,
            started_at_epoch_secs: 0,
            completed_at_epoch_secs: 0,
            receipt: None,
            persona_tuning: None,
            candidate: None,
            build_output: None,
            deploy_result: None,
            validation_receipt: None,
        }
    }

    /// Walk the execution phases through Test, before mandatory documentation.
    fn walk_core(l: &mut Ledger) {
        for phase in [
            Phase::Architecture,
            Phase::SecurityPlan,
            Phase::Build,
            Phase::SecurityCode,
            Phase::Test,
        ] {
            l.record(phase, pass(phase.persona().name)).unwrap();
        }
    }

    fn walk_to_deploy(l: &mut Ledger) {
        walk_core(l);
        l.record(Phase::Documentation, pass("Documenter")).unwrap();
        l.record(Phase::DocValidation, pass("Architect & Designer"))
            .unwrap();
    }

    #[test]
    fn passing_current_phase_advances() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Feature);
        assert_eq!(l.phase, Phase::Architecture);
        l.record(Phase::Architecture, pass("Architect")).unwrap();
        assert_eq!(l.phase, Phase::SecurityPlan);
    }

    #[test]
    fn documentation_doctrine_covers_feature_fix_and_all_chore_subtypes() {
        for kind in [ChangeKind::Feature, ChangeKind::Fix, ChangeKind::Chore] {
            assert!(kind.documents(), "{} must run documentation", kind.label());
            let ledger = Ledger::new("doctrine", "mpd", false, kind);
            let phases = Phase::applicable(ledger.applicability());
            assert!(phases.contains(&Phase::Documentation));
            assert!(phases.contains(&Phase::DocValidation));
            assert_eq!(phases.last(), Some(&Phase::Deploy));
        }
        // Configuration, dependency, and tooling changes are represented by
        // Chore and therefore follow the same mandatory phase matrix.
    }

    #[test]
    fn first_adoption_reconciliation_preserves_history_and_rewinds_build_once() {
        let mut l = Ledger::new("adoption", "mpd", false, ChangeKind::Feature);
        for phase in [
            Phase::Architecture,
            Phase::SecurityPlan,
            Phase::Build,
            Phase::SecurityCode,
        ] {
            l.record(phase, pass("tester")).unwrap();
        }
        let event = FirstAdoptionReconciliationV1 {
            schema: 1,
            checkpoint_oid: "a".repeat(40),
            policy_object_oid: "b".repeat(40),
            pretrust_proof_digest: "c".repeat(64),
            security_evidence: "security-code.md".into(),
            reason: "reviewed transition".into(),
            at_epoch_secs: 1,
            checkpoint_scope_digest: "d".repeat(64),
            security_evidence_digest: "e".repeat(64),
            bootstrap_nonce_digest: "f".repeat(64),
            trusted_policy_digest: "0".repeat(64),
        };
        assert!(l.reconcile_first_adoption(event.clone()).unwrap());
        assert_eq!(l.phase, Phase::Build);
        assert!(!l.gates.contains_key(&Phase::Build));
        assert_eq!(
            l.history.iter().filter(|e| e.phase == Phase::Build).count(),
            1
        );
        assert!(!l.reconcile_first_adoption(event).unwrap());
        let mut conflicting_replay = l.first_adoption_reconciliations[0].clone();
        conflicting_replay.bootstrap_nonce_digest = "1".repeat(64);
        assert!(l.reconcile_first_adoption(conflicting_replay).is_err());
        assert_eq!(l.first_adoption_reconciliations.len(), 1);
        assert_eq!(l.phase, Phase::Build);
        assert_eq!(
            l.history.iter().filter(|e| e.phase == Phase::Build).count(),
            1
        );
    }

    fn pretrust_restart(
        superseded: char,
        replacement: char,
        evidence: char,
    ) -> FirstAdoptionRestartV1 {
        FirstAdoptionRestartV1 {
            schema: 1,
            stage: FirstAdoptionRestartStage::Pretrust,
            superseded_checkpoint_oid: superseded.to_string().repeat(40),
            superseded_proof_digest: Some("c".repeat(64)),
            replacement_tip_oid: Some(replacement.to_string().repeat(40)),
            actor: "independent Security reviewer".into(),
            reason: "material correction retained as a descendant".into(),
            evidence_digest: evidence.to_string().repeat(64),
            at_epoch_secs: 1,
        }
    }

    #[test]
    fn first_adoption_restart_is_bounded_append_only_and_derives_latest_eligibility() {
        let mut ledger = Ledger::new("adoption", "mpd", false, ChangeKind::Feature);
        let history_before = ledger.history.clone();
        let first = pretrust_restart('a', 'b', 'd');
        assert!(ledger.append_first_adoption_restart(first.clone()).unwrap());
        assert!(!ledger.append_first_adoption_restart(first).unwrap());
        assert_eq!(
            ledger.history, history_before,
            "restart must not create PASS"
        );

        let eligibility = ledger
            .first_adoption_eligibility(&"a".repeat(40), Some(&"c".repeat(64)), &"e".repeat(64))
            .unwrap();
        assert_eq!(eligibility.latest_eligible_checkpoint_oid, "b".repeat(40));
        assert_eq!(eligibility.latest_eligible_proof_digest, None);
        assert_eq!(eligibility.latest_evidence_digest, "d".repeat(64));
        assert_eq!(eligibility.restart_count, 1);
        assert_eq!(eligibility.checkpoint_chain_digest.len(), 64);

        let mut conflicting = pretrust_restart('a', 'f', 'e');
        conflicting.reason = "different correction".into();
        assert!(ledger.append_first_adoption_restart(conflicting).is_err());
        assert_eq!(ledger.first_adoption_restarts.len(), 1);

        let second = pretrust_restart('b', 'f', 'e');
        assert!(ledger.append_first_adoption_restart(second).unwrap());
        let eligibility = ledger
            .first_adoption_eligibility(&"a".repeat(40), Some(&"c".repeat(64)), &"e".repeat(64))
            .unwrap();
        assert_eq!(eligibility.latest_eligible_checkpoint_oid, "f".repeat(40));
        assert_eq!(eligibility.latest_evidence_digest, "e".repeat(64));
        assert_eq!(eligibility.restart_count, 2);
    }

    #[test]
    fn first_adoption_restart_rejects_wrong_stage_malformed_codec_and_non_chain_event() {
        let mut ledger = Ledger::new("adoption", "mpd", false, ChangeKind::Feature);
        let mut posttrust = pretrust_restart('a', 'b', 'd');
        posttrust.stage = FirstAdoptionRestartStage::Posttrust;
        assert!(ledger.append_first_adoption_restart(posttrust).is_err());

        let mut malformed = pretrust_restart('a', 'b', 'd');
        malformed.actor = "unsafe\nactor".into();
        assert!(ledger.append_first_adoption_restart(malformed).is_err());
        assert!(serde_json::from_str::<FirstAdoptionRestartV1>(
            r#"{"schema":1,"stage":"pretrust","superseded_checkpoint_oid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","replacement_tip_oid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","actor":"reviewer","reason":"fix","evidence_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","at_epoch_secs":1,"unknown":true}"#
        )
        .is_err());

        assert!(ledger
            .append_first_adoption_restart(pretrust_restart('a', 'b', 'd'))
            .unwrap());
        assert!(ledger
            .append_first_adoption_restart(pretrust_restart('f', '0', 'e'))
            .is_err());
        assert_eq!(ledger.first_adoption_restarts.len(), 1);
    }

    #[test]
    fn fail_does_not_advance() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Feature);
        let mut rec = pass("Security");
        rec.verdict = Verdict::Fail;
        l.record(Phase::Architecture, rec).unwrap();
        assert_eq!(l.phase, Phase::Architecture);
        assert!(!l.ready_to_archive());
    }

    #[test]
    fn record_preserves_verdict_history() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        l.record(Phase::Architecture, pass("Architect")).unwrap();
        l.record(Phase::SecurityPlan, pass("Security")).unwrap();
        l.record(Phase::Build, pass("Builder")).unwrap();
        // Security (code) FAILs, then is fixed and re-recorded PASS.
        let mut fail = pass("Security");
        fail.verdict = Verdict::Fail;
        l.record(Phase::SecurityCode, fail).unwrap();
        assert_eq!(l.phase, Phase::SecurityCode, "FAIL does not advance");
        l.record(Phase::SecurityCode, pass("Security")).unwrap();
        // Latest-per-phase shows PASS (and advances); history keeps FAIL *and* PASS.
        assert_eq!(l.gates[&Phase::SecurityCode].verdict, Verdict::Pass);
        assert_eq!(l.phase, Phase::Test);
        let sc: Vec<_> = l
            .history
            .iter()
            .filter(|e| e.phase == Phase::SecurityCode)
            .map(|e| e.record.verdict)
            .collect();
        assert_eq!(
            sc,
            vec![Verdict::Fail, Verdict::Pass],
            "catch-then-fix must survive in the audit trail"
        );
    }

    #[test]
    fn old_ledger_without_history_deserializes() {
        // A ledger serialized before `history` existed (field absent) must load
        // with an empty history via #[serde(default)] and round-trip forward.
        let json = r#"{
            "change": "c", "schema": "mpd", "ui": false, "kind": "fix",
            "phase": "build",
            "gates": { "architecture": { "verdict": "pass", "by": "Architect", "at": "2026-07-11" } },
            "conditions": []
        }"#;
        let l: Ledger = serde_json::from_str(json).unwrap();
        assert!(l.history.is_empty());
        assert_eq!(l.phase, Phase::Build);
        assert_eq!(l.governance, Governance::default());
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn legacy_ledger_and_gate_record_default_receipt_and_closure_to_absent() {
        // A ledger serialized before the content-addressed release-closure
        // schema existed (no `receipt` on any gate, no top-level
        // `archive_closure`) must still load unchanged via #[serde(default)],
        // with both new fields defaulting to `None` — never a false `valid`
        // or a false completed closure (design.md "Legacy gate has no
        // receipt").
        let json = r#"{
            "change": "c", "schema": "mpd", "ui": false, "kind": "fix",
            "phase": "build",
            "gates": { "architecture": { "verdict": "pass", "by": "Architect", "at": "2026-07-11" } },
            "conditions": []
        }"#;
        let l: Ledger = serde_json::from_str(json).unwrap();
        assert_eq!(l.archive_closure, None);
        assert_eq!(l.gates[&Phase::Architecture].receipt, None);
        assert_eq!(l.gates[&Phase::Architecture].candidate, None);
        // Round-trips forward without inventing either field.
        let json_out = serde_json::to_string(&l).unwrap();
        assert!(!json_out.contains("receipt"));
        assert!(!json_out.contains("archive_closure"));
        assert!(!json_out.contains("\"candidate\""));
        let back: Ledger = serde_json::from_str(&json_out).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn typed_governance_parsing_is_closed_and_bounded() {
        assert_eq!("low".parse::<RiskLevel>().unwrap(), RiskLevel::Low);
        assert_eq!(
            "network-server".parse::<ThreatProfile>().unwrap(),
            ThreatProfile::NetworkServer
        );
        assert_eq!(
            "environment".parse::<FailureClass>().unwrap(),
            FailureClass::Environment
        );
        assert!("LOW".parse::<RiskLevel>().is_err());
        assert!("unknown".parse::<ThreatProfile>().is_err());
        assert!(bounded_text("  reason  ", "reason").is_ok());
        assert!(bounded_text(" ", "reason").is_err());
        assert!(bounded_text(&"x".repeat(501), "reason").is_err());
    }

    #[test]
    fn low_risk_retry_requires_and_consumes_one_reconciliation() {
        let governance = Governance {
            risk: RiskLevel::Low,
            threat_profile: ThreatProfile::LocalTrustedUser,
            reconciliations: vec![],
        };
        let mut l = Ledger::new_with_governance("c", "mpd", false, ChangeKind::Fix, governance);
        let mut failed = pass("Architect");
        failed.verdict = Verdict::Fail;
        failed.failure_class = Some(FailureClass::Product);
        failed.attempt = 1;
        l.record(Phase::Architecture, failed).unwrap();
        assert!(!l.attempt_authorized(Phase::Architecture));
        l.reconcile(ReconciliationKind::Continue, "fix is ready".into(), None)
            .unwrap();
        assert!(l.attempt_authorized(Phase::Architecture));
        let mut retried = pass("Architect");
        retried.attempt = 2;
        l.record(Phase::Architecture, retried).unwrap();
        assert!(l.governance.reconciliations[0].consumed);
    }

    #[test]
    fn governance_change_retains_history_and_rewinds_only_security_and_downstream() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        l.record(Phase::Architecture, pass("Architect")).unwrap();
        l.record(Phase::SecurityPlan, pass("Security")).unwrap();
        l.record(Phase::Build, pass("Builder")).unwrap();
        let history_len = l.history.len();
        l.reconcile(
            ReconciliationKind::ThreatProfile,
            "input is now untrusted".into(),
            Some("local-untrusted-input".into()),
        )
        .unwrap();
        assert_eq!(l.phase, Phase::SecurityPlan);
        assert!(l.gates.contains_key(&Phase::Architecture));
        assert!(!l.gates.contains_key(&Phase::SecurityPlan));
        assert!(!l.gates.contains_key(&Phase::Build));
        assert_eq!(l.history.len(), history_len);
        assert_eq!(
            l.governance.threat_profile,
            ThreatProfile::LocalUntrustedInput
        );
    }

    #[test]
    fn backward_clock_duration_clamps_to_zero() {
        let mut rec = pass("Tester");
        rec.started_at_epoch_secs = 20;
        rec.completed_at_epoch_secs = 10;
        assert_eq!(rec.duration_secs(), 0);
    }

    #[test]
    fn next_attempt_saturates_at_usize_max() {
        assert_eq!(next_attempt_after(usize::MAX), usize::MAX);
        assert_eq!(next_attempt_after(0), 1);
    }

    #[test]
    fn fix_requires_documentation_validation_then_final_deploy() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        walk_core(&mut l);
        assert_eq!(l.phase, Phase::Documentation);
        l.record(Phase::Documentation, pass("Documenter")).unwrap();
        assert_eq!(l.phase, Phase::DocValidation);
        l.record(Phase::DocValidation, pass("Architect & Designer"))
            .unwrap();
        assert_eq!(l.phase, Phase::Deploy);
        assert!(!l.ready_to_archive(), "{:?}", l.blocking_reasons());
        assert_eq!(l.phase, Phase::Deploy);
        l.record(Phase::Deploy, pass("main-session")).unwrap();
        assert!(l.ready_to_archive(), "{:?}", l.blocking_reasons());
    }

    #[test]
    fn feature_requires_documentation_validation_then_final_deploy() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Feature);
        walk_core(&mut l);
        // Documentation is required before archive.
        assert_eq!(l.phase, Phase::Documentation);
        assert!(!l.ready_to_archive());
        l.record(Phase::Documentation, pass("Documenter")).unwrap();
        assert_eq!(l.phase, Phase::DocValidation);
        // Doc Validation is required before final Deploy.
        assert!(!l.ready_to_archive());
        l.record(Phase::DocValidation, pass("Architect & Designer"))
            .unwrap();
        assert_eq!(l.phase, Phase::Deploy);
        assert!(!l.ready_to_archive());
        l.record(Phase::Deploy, pass("main-session")).unwrap();
        assert!(l.ready_to_archive(), "{:?}", l.blocking_reasons());
    }

    #[test]
    fn open_condition_blocks_archive() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        walk_to_deploy(&mut l);
        l.conditions.push(Condition {
            id: "security-code.1".into(),
            phase: Phase::SecurityCode,
            attempt: 1,
            text: "close the audit item".into(),
            owner: "Security".into(),
            closed: false,
            opened_at_epoch_secs: 0,
            events: Vec::new(),
        });
        assert!(!l.ready_to_archive());
        l.conditions[0].closed = true;
        l.record(Phase::Deploy, pass("main-session")).unwrap();
        assert!(l.ready_to_archive());
    }

    #[test]
    fn close_condition_by_index_and_all() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        walk_to_deploy(&mut l);
        for t in ["a", "b"] {
            l.conditions.push(Condition {
                id: format!("security-code.{t}"),
                phase: Phase::SecurityCode,
                attempt: 1,
                text: t.into(),
                owner: "Security".into(),
                closed: false,
                opened_at_epoch_secs: 0,
                events: Vec::new(),
            });
        }
        assert!(l
            .close_condition(3, "Security", "test.md".into(), "digest".into())
            .is_err()); // out of range
        assert!(l
            .close_condition(0, "Security", "test.md".into(), "digest".into())
            .is_err()); // not 1-based
        l.close_condition(1, "Security", "test.md".into(), "digest".into())
            .unwrap();
        assert!(!l.ready_to_archive()); // #2 still open
        assert_eq!(
            l.close_all_conditions("Security", "test.md".into(), "digest".into())
                .unwrap(),
            1
        ); // only #2 remained
        l.record(Phase::Deploy, pass("main-session")).unwrap();
        assert!(l.ready_to_archive());
    }

    #[test]
    fn explicit_repair_rewinds_only_and_is_idempotent_without_fabricating_verdicts() {
        let mut l = Ledger::new("legacy", "mpd", false, ChangeKind::Fix);
        l.set_strict();
        l.record(Phase::Architecture, pass("Architect")).unwrap();
        l.record(Phase::SecurityPlan, pass("Security")).unwrap();
        let history_before = l.history.clone();
        l.conditions.push(Condition {
            id: "security-plan.1".into(),
            phase: Phase::SecurityPlan,
            attempt: 1,
            text: "legacy unscoped condition".into(),
            owner: "Security".into(),
            // This is the exact legacy ambiguity: a closed boolean but no
            // evidence-bearing event history.
            closed: true,
            opened_at_epoch_secs: 0,
            events: Vec::new(),
        });

        assert!(l.integrity_blockers()[0].contains("legacy-unscoped"));
        assert!(!l
            .repair_state_preview(Phase::SecurityPlan, "explicit migration")
            .unwrap());
        assert!(l
            .repair_state_to(Phase::SecurityPlan, "explicit migration", &"a".repeat(64))
            .unwrap());

        assert_eq!(l.phase, Phase::SecurityPlan);
        assert_eq!(
            l.history, history_before,
            "repair must not synthesize a PASS"
        );
        assert!(!l.gates.contains_key(&Phase::SecurityPlan));
        assert!(
            l.archive_closure.is_none(),
            "repair must not rewrite/archive state"
        );
        assert!(matches!(
            l.conditions[0].events.as_slice(),
            [ConditionEvent::Reopened {
                rewind_phase: Phase::SecurityPlan,
                ..
            }]
        ));
        assert!(l.conditions[0].is_open());
        assert_eq!(l.legacy_repairs.len(), 1);
        assert_eq!(l.legacy_repairs[0].ledger_before_digest, "a".repeat(64));
        assert!(l
            .repair_state_preview(Phase::SecurityPlan, "explicit migration")
            .unwrap());
        assert!(!l
            .repair_state_to(Phase::SecurityPlan, "explicit migration", &"b".repeat(64))
            .unwrap());
        assert_eq!(l.legacy_repairs.len(), 1, "replay must be a no-op");
        assert!(l
            .repair_state_preview(Phase::Build, "wrong direction")
            .is_err());

        l.archive_closure = Some(ArchiveClosure {
            base_commit: "0".repeat(40),
            archive_path: "openspec/changes/archive/legacy".into(),
            transaction_id: crate::digest::Digest::of_bytes(b"transaction"),
            candidate_id: None,
            allowed_paths: vec![],
            system_paths: vec![],
            post_archive_digest: crate::digest::Digest::of_bytes(b"postimage"),
            archived_at: 1,
        });
        let archived = l
            .repair_state_preview(Phase::Architecture, "immutable archive")
            .unwrap_err();
        assert!(archived.contains("archives are immutable"));
    }

    #[test]
    fn repair_save_refuses_a_concurrently_changed_observed_ledger() {
        let root = std::env::temp_dir().join(format!(
            "mpd-repair-observed-{}-{}",
            std::process::id(),
            now_epoch_secs()
        ));
        init_locking_fixture(&root);
        let mut ledger = Ledger::new("repair-race", "mpd", false, ChangeKind::Fix);
        ledger
            .record(Phase::Architecture, pass("Architect"))
            .unwrap();
        save(&root, &ledger).unwrap();

        let (mut loaded, observed) = load_observed(&root, "repair-race").unwrap();
        loaded
            .repair_state_to(Phase::Architecture, "operator rewind", &observed)
            .unwrap();

        let path = state_path(&root, "repair-race");
        let mut concurrent = std::fs::read(&path).unwrap();
        concurrent.extend_from_slice(b" ");
        std::fs::write(&path, &concurrent).unwrap();
        let error = save_if_observed(&root, &loaded, &observed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(std::fs::read(&path).unwrap(), concurrent);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_observed_saves_serialize_and_only_one_concurrent_writer_wins() {
        use std::sync::{Arc, Barrier};

        let root = std::env::temp_dir().join(format!(
            "mpd-ledger-cas-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        init_locking_fixture(&root);
        let ledger = Ledger::new("cas-race", "mpd", false, ChangeKind::Fix);
        save(&root, &ledger).unwrap();
        let (observed_ledger, observation) = load_observed_exact(&root, "cas-race").unwrap();
        let mut first = observed_ledger.clone();
        first.phase_started_at_epoch_secs = 11;
        let mut second = observed_ledger;
        second.phase_started_at_epoch_secs = 22;

        let barrier = Arc::new(Barrier::new(2));
        let spawn = |proposed: Ledger| {
            let root = root.clone();
            let observation = observation.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                save_exact_observed(&root, &proposed, &observation)
            })
        };
        let left = spawn(first.clone());
        let right = spawn(second.clone());
        let outcomes = [left.join().unwrap(), right.join().unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ExactSaveOutcome::Committed))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    ExactSaveOutcome::NotCommitted(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                ))
                .count(),
            1
        );
        let durable = load(&root, "cas-race").unwrap();
        assert!(durable == first || durable == second);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_save_resolves_post_rename_failure_by_exact_readback() {
        let root = std::env::temp_dir().join(format!(
            "mpd-ledger-post-rename-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        init_locking_fixture(&root);
        let ledger = Ledger::new("post-rename", "mpd", false, ChangeKind::Fix);
        save(&root, &ledger).unwrap();
        let (mut proposed, observation) = load_observed_exact(&root, "post-rename").unwrap();
        proposed.phase_started_at_epoch_secs = 99;

        let outcome =
            save_exact_observed_with(&root, &proposed, &observation, |root, path, bytes| {
                openspec_core::atomic_write_contained(root, path, bytes).unwrap();
                AtomicWriteOutcome::FailedAfterRename(openspec_core::CoreError::Io(
                    "injected parent-directory sync failure".into(),
                ))
            });
        assert!(matches!(
            outcome,
            ExactSaveOutcome::CommittedAfterRename { ref error }
                if error.contains("injected parent-directory sync failure")
        ));
        assert_eq!(load(&root, "post-rename").unwrap(), proposed);

        let (mut stale, second_observation) = load_observed_exact(&root, "post-rename").unwrap();
        stale.phase_started_at_epoch_secs = 100;
        let prior = second_observation.exact.clone();
        let outcome =
            save_exact_observed_with(&root, &stale, &second_observation, |root, path, _| {
                openspec_core::atomic_write_contained(root, path, prior.as_bytes()).unwrap();
                AtomicWriteOutcome::FailedAfterRename(openspec_core::CoreError::Io(
                    "injected post-rename replacement".into(),
                ))
            });
        assert!(matches!(outcome, ExactSaveOutcome::UncertainAfterRename(_)));
        assert_eq!(load(&root, "post-rename").unwrap(), proposed);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn roundtrips_through_json() {
        let mut l = Ledger::new("c", "mpd", true, ChangeKind::Feature);
        l.record(Phase::DesignMock, pass("Designer")).unwrap();
        let json = serde_json::to_string(&l).unwrap();
        let back: Ledger = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }

    // D5: ledger version-skew guardrail.

    #[test]
    fn legacy_ledger_without_a_format_field_defaults_to_format_one() {
        let json = r#"{
            "change": "c", "schema": "mpd", "ui": false, "kind": "fix",
            "phase": "build",
            "gates": { "architecture": { "verdict": "pass", "by": "Architect", "at": "2026-07-11" } },
            "conditions": []
        }"#;
        let l: Ledger = serde_json::from_str(json).unwrap();
        assert_eq!(l.format, 1);
    }

    #[test]
    fn new_ledger_is_stamped_with_the_current_format() {
        let l = Ledger::new("c", "mpd", false, ChangeKind::Chore);
        assert_eq!(l.format, LEDGER_FORMAT);
    }

    #[test]
    fn save_always_stamps_the_current_format_even_over_a_legacy_in_memory_value() {
        let root = std::env::temp_dir().join(format!(
            "mpd-ledger-format-stamp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        init_locking_fixture(&root);
        let mut ledger = Ledger::new("format-stamp", "mpd", false, ChangeKind::Chore);
        // Simulate a ledger loaded from a pre-format-field file (defaulted to
        // 1) that is now being resaved by this binary.
        ledger.format = 1;
        save(&root, &ledger).unwrap();
        let raw = std::fs::read_to_string(state_path(&root, "format-stamp")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["format"], LEDGER_FORMAT);
        // The in-memory value the caller holds is untouched — only the
        // durable bytes are stamped.
        assert_eq!(ledger.format, 1);
        let reloaded = load(&root, "format-stamp").unwrap();
        assert_eq!(reloaded.format, LEDGER_FORMAT);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_ledger_that_parses_is_returned_identically_regardless_of_format() {
        // Cond 6: the probe runs ONLY on the failure path. A ledger that
        // deserializes successfully — whatever its `format` value — must be
        // returned exactly as today.
        let root = std::env::temp_dir().join(format!(
            "mpd-ledger-format-happy-path-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        init_locking_fixture(&root);
        let ledger = Ledger::new("happy-path", "mpd", false, ChangeKind::Fix);
        save(&root, &ledger).unwrap();
        assert_eq!(load(&root, "happy-path").unwrap(), ledger);
        let (observed_ledger, _) = load_observed(&root, "happy-path").unwrap();
        assert_eq!(observed_ledger, ledger);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn format_exceeding_this_binary_produces_the_newer_mpd_message() {
        // A future format introduces a genuinely incompatible shape (here:
        // `phase`/`gates` are missing) — deserialization fails, and the
        // probe sees `format: 99 > LEDGER_FORMAT`.
        let json = r#"{"format": 99, "change": "future-thing", "schema": "mpd", "ui": false, "kind": "fix"}"#;
        let error = serde_json::from_str::<Ledger>(json).unwrap_err();
        let wrapped =
            ledger_version_probe(Path::new("/repo/.mpd/state/future-thing.json"), json, error);
        let message = wrapped.to_string();
        assert!(
            message.contains("requires a newer mpd"),
            "message={message}"
        );
        assert!(message.contains("ledger format 99"), "message={message}");
        assert!(
            message.contains(&format!("up to {LEDGER_FORMAT}")),
            "message={message}"
        );
        assert!(message.contains("future-thing"), "message={message}");
        assert!(
            message.contains("/repo/.mpd/state/future-thing.json"),
            "message={message}"
        );
    }

    #[test]
    fn format_at_or_below_current_keeps_the_original_error_with_a_hint() {
        for format_value in ["1", "2", &LEDGER_FORMAT.to_string()] {
            let json = format!(
                r#"{{"format": {format_value}, "change": "c", "schema": "mpd", "ui": false}}"#
            );
            let error = serde_json::from_str::<Ledger>(&json).unwrap_err();
            let original_message = error.to_string();
            let wrapped = ledger_version_probe(Path::new("/repo/.mpd/state/c.json"), &json, error);
            let message = wrapped.to_string();
            assert!(
                !message.contains("requires a newer mpd"),
                "message={message}"
            );
            assert!(message.contains(&original_message), "message={message}");
            assert!(
                message.contains("newer or different mpd"),
                "message={message}"
            );
            assert!(
                message.contains("/repo/.mpd/state/c.json"),
                "message={message}"
            );
        }
    }

    #[test]
    fn absent_format_keeps_the_original_error_with_a_hint() {
        let json = r#"{"change": "c", "schema": "mpd", "ui": false}"#;
        let error = serde_json::from_str::<Ledger>(json).unwrap_err();
        let original_message = error.to_string();
        let wrapped = ledger_version_probe(Path::new("/repo/.mpd/state/c.json"), json, error);
        let message = wrapped.to_string();
        assert!(
            !message.contains("requires a newer mpd"),
            "message={message}"
        );
        assert!(message.contains(&original_message), "message={message}");
        assert!(
            message.contains("newer or different mpd"),
            "message={message}"
        );
    }

    #[test]
    fn non_u32_format_values_are_treated_as_absent() {
        // Cond 15: a string, float, or negative `format` must never be read
        // as a version claim — it degrades to the original-error path.
        for bad_format in [r#""5""#, "5.5", "-1", "true", "null"] {
            let json = format!(
                r#"{{"format": {bad_format}, "change": "c", "schema": "mpd", "ui": false}}"#
            );
            let error = serde_json::from_str::<Ledger>(&json).unwrap_err();
            let wrapped = ledger_version_probe(Path::new("/repo/.mpd/state/c.json"), &json, error);
            let message = wrapped.to_string();
            assert!(
                !message.contains("requires a newer mpd"),
                "format={bad_format}: message={message}"
            );
        }
    }

    #[test]
    fn probe_failure_on_non_json_leaves_the_original_error_unchanged() {
        let text = "not json at all";
        let error = serde_json::from_str::<Ledger>(text).unwrap_err();
        let original_message = error.to_string();
        let wrapped = ledger_version_probe(Path::new("/repo/.mpd/state/c.json"), text, error);
        assert_eq!(wrapped.to_string(), original_message);
    }

    #[test]
    fn candidate_gate_and_build_output_codecs_are_compact_and_legacy_safe() {
        let capture = crate::candidate::CandidateCapture {
            subject: crate::candidate::CandidateSubject {
                version: 1,
                change: "c".into(),
                base_commit: "a".repeat(40),
                base_tree: "b".repeat(40),
                manifest_digest: "c".repeat(64),
                entries_digest: "d".repeat(64),
                policy_digest: "e".repeat(64),
                source_digest: "f".repeat(64),
                id: "1".repeat(64),
            },
            clone_private_root: "/private/candidate".into(),
            storage: crate::candidate::CandidateStorageBinding {
                record_path: "/private/record.json".into(),
                record_sha256: "2".repeat(64),
                root_device: 1,
                root_inode: 2,
                record_device: 1,
                record_inode: 3,
            },
            counts: crate::candidate::CandidateCounts {
                entries: 100_000,
                included_dirty: 2,
                deleted: 1,
                untracked: 1,
                executable: 1,
                excluded_dirty: 100_000,
            },
            excluded_dirty_digest: "3".repeat(64),
            excluded_dirty_sample: Vec::new(),
            declared_status_digest: "4".repeat(64),
            captured_at_epoch_secs: 1,
        };
        let mut ledger = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        let mut record = pass("Architect");
        record.candidate = Some(capture.clone());
        ledger.record(Phase::Architecture, record).unwrap();
        let encoded = serde_json::to_string(&ledger).unwrap();
        let encoded_value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert!(encoded_value["gates"]["architecture"]["candidate"]
            .get("entries")
            .is_none());
        let decoded: Ledger = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.gates[&Phase::Architecture].candidate, Some(capture));

        let legacy = r#"{"schema":1,"name":"mpd","path":"out/mpd","max_bytes":10,"required_mode":493,"size":5,"mode":493,"device":1,"inode":2,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let legacy: BuildOutputV1 = serde_json::from_str(legacy).unwrap();
        assert_eq!(legacy.candidate_id, None);
        let mut bound = legacy;
        bound.candidate_id = Some("b".repeat(64));
        let roundtrip: BuildOutputV1 =
            serde_json::from_str(&serde_json::to_string(&bound).unwrap()).unwrap();
        assert_eq!(roundtrip, bound);
    }

    #[test]
    fn legacy_ledger_defaults_strict_false_and_no_waivers() {
        // A ledger serialized before the strict tier existed (no `strict`, no
        // `waivers`) must load as the manual tier — strict=false, no waivers —
        // via #[serde(default)], and round-trip forward cleanly (design.md
        // "Legacy ledger breakage").
        let json = r#"{
            "change": "c", "schema": "mpd", "ui": false, "kind": "fix",
            "phase": "build",
            "gates": { "architecture": { "verdict": "pass", "by": "Architect", "at": "2026-07-11" } },
            "conditions": []
        }"#;
        let l: Ledger = serde_json::from_str(json).unwrap();
        assert!(!l.strict, "a legacy ledger is the manual tier");
        assert!(l.waivers.is_empty());
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(l, back);
    }

    #[test]
    fn strict_is_write_once_and_monotonic() {
        // `set_strict` only ever turns strict ON; there is deliberately no
        // true→false path (design.md Cond 14) — the linchpin of enforcement.
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        assert!(!l.strict, "a fresh ledger defaults to the manual tier");
        l.set_strict();
        assert!(l.strict);
        // Idempotent: calling again keeps it on, never flips it off.
        l.set_strict();
        assert!(l.strict);
    }

    #[test]
    fn persona_tuning_record_is_baseline_and_merges_weakest_seen() {
        // is_baseline: nothing above baseline ⇒ true.
        assert!(PersonaTuningRecord::default().is_baseline());
        assert!(PersonaTuningRecord {
            rigor: Some(Rigor::Standard),
            depth: Some(Depth::Examples),
            ..Default::default()
        }
        .is_baseline());
        assert!(!PersonaTuningRecord {
            rigor: Some(Rigor::Deep),
            ..Default::default()
        }
        .is_baseline());
        assert!(!PersonaTuningRecord {
            had_append: true,
            weakened: true,
            ..Default::default()
        }
        .is_baseline());

        // merge_weakest_seen: a later clean record can NEVER downgrade a recorded
        // weakening (round-3 F2 anti-laundering) — booleans OR, ordinals max.
        let mut weakened = PersonaTuningRecord {
            rigor: Some(Rigor::Deep),
            had_append: true,
            base_modified: true,
            weakened: true,
            ..Default::default()
        };
        let clean = PersonaTuningRecord {
            rigor: Some(Rigor::Standard),
            ..Default::default()
        };
        weakened.merge_weakest_seen(&clean);
        assert!(weakened.weakened, "a clean merge cannot clear weakened");
        assert!(weakened.had_append && weakened.base_modified);
        assert_eq!(
            weakened.rigor,
            Some(Rigor::Deep),
            "rigor is max, never lowered"
        );

        // A stronger later record raises the ordinal.
        let mut base = PersonaTuningRecord {
            rigor: Some(Rigor::Deep),
            ..Default::default()
        };
        base.merge_weakest_seen(&PersonaTuningRecord {
            rigor: Some(Rigor::Paranoid),
            ..Default::default()
        });
        assert_eq!(base.rigor, Some(Rigor::Paranoid));
    }

    #[test]
    fn record_brief_tuning_merges_same_attempt_replaces_other() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        let weak = PersonaTuningRecord {
            had_append: true,
            weakened: true,
            ..Default::default()
        };
        l.record_brief_tuning(Phase::SecurityCode, 1, weak);
        // A later non-baseline-but-non-weakened re-brief at the SAME attempt merges
        // (weakest-seen) — it must NOT downgrade the recorded weakened (round-3 F2).
        l.record_brief_tuning(
            Phase::SecurityCode,
            1,
            PersonaTuningRecord {
                rigor: Some(Rigor::Deep),
                ..Default::default()
            },
        );
        let rec = l.brief_tuning_for(Phase::SecurityCode, 1).unwrap();
        assert!(rec.weakened, "same-attempt merge preserves weakened");
        assert_eq!(rec.rigor, Some(Rigor::Deep));
        // A DIFFERENT attempt replaces (a fresh attempt starts clean).
        l.record_brief_tuning(
            Phase::SecurityCode,
            2,
            PersonaTuningRecord {
                rigor: Some(Rigor::Deep),
                ..Default::default()
            },
        );
        assert!(
            !l.brief_tuning_for(Phase::SecurityCode, 2).unwrap().weakened,
            "a new attempt replaces the slot"
        );
        // The gate consumes the record ONLY on an exact (phase, attempt) match.
        assert!(l.brief_tuning_for(Phase::SecurityCode, 99).is_none());
        assert!(l.brief_tuning_for(Phase::Test, 1).is_none());
    }

    #[test]
    fn legacy_ledger_defaults_empty_brief_tuning_and_gate_no_persona_tuning() {
        let json = r#"{
            "change": "c", "schema": "mpd", "ui": false, "kind": "fix",
            "phase": "build",
            "gates": { "architecture": { "verdict": "pass", "by": "Architect", "at": "2026-07-11" } },
            "conditions": []
        }"#;
        let l: Ledger = serde_json::from_str(json).unwrap();
        assert!(l.brief_tuning.is_empty());
        assert_eq!(l.gates[&Phase::Architecture].persona_tuning, None);
        // An empty brief_tuning + None stamp never serialize (byte-identical).
        let out = serde_json::to_string(&l).unwrap();
        assert!(!out.contains("brief_tuning"));
        assert!(!out.contains("persona_tuning"));
    }

    #[test]
    fn governance_change_before_security_stays_put_and_does_not_advance() {
        // A reconcile (risk OR threat-profile) while the change is still BEFORE
        // Security (at Architecture) must NOT jump forward to security-plan — that
        // would skip the ungated Architecture phase (reconcile-phase-skip fix). The
        // downstream rewind (current > SecurityPlan) is covered by
        // `governance_change_retains_history_and_rewinds_only_security_and_downstream`.
        for (kind, value) in [
            (ReconciliationKind::Risk, "high"),
            (ReconciliationKind::ThreatProfile, "network-server"),
        ] {
            let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
            assert_eq!(l.phase, Phase::Architecture);
            l.reconcile(kind, "novel surface".into(), Some(value.into()))
                .unwrap();
            assert_eq!(
                l.phase,
                Phase::Architecture,
                "a pre-Security {kind:?} reconcile must stay at Architecture, not advance to security-plan"
            );
            assert_eq!(l.governance.reconciliations.len(), 1);
        }
    }

    #[test]
    fn security_rewind_drops_strict_waivers_for_rewound_phases() {
        // A waiver recorded for a phase at/after Security (plan) is dropped when
        // a governance change rewinds to Security (plan) — exactly as the gate
        // records are — so a stale waiver can never suppress the artifact gate on
        // the re-run (design.md D7 / B1). An upstream (Architecture) waiver
        // survives, since that phase is not rewound.
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        l.record(Phase::Architecture, pass("Architect")).unwrap();
        l.record(Phase::SecurityPlan, pass("Security")).unwrap();
        l.record(Phase::Build, pass("Builder")).unwrap();
        l.waivers.push(Waiver {
            phase: Phase::Architecture,
            reason: "design.md already carries the conditions".into(),
            attempt: 1,
            at_epoch_secs: 0,
        });
        l.waivers.push(Waiver {
            phase: Phase::SecurityCode,
            reason: "stale attempt-1 waiver".into(),
            attempt: 1,
            at_epoch_secs: 0,
        });
        l.reconcile(
            ReconciliationKind::ThreatProfile,
            "input is now untrusted".into(),
            Some("local-untrusted-input".into()),
        )
        .unwrap();
        assert_eq!(l.phase, Phase::SecurityPlan);
        let phases: Vec<_> = l.waivers.iter().map(|w| w.phase).collect();
        assert_eq!(
            phases,
            vec![Phase::Architecture],
            "only the upstream (non-rewound) waiver survives the rewind"
        );
    }

    // -----------------------------------------------------------------
    // Anti-laundering property (design.md Cond 11, round-3 F2): for ANY two
    // `PersonaTuningRecord`s, `merge_weakest_seen` never clears a set
    // `weakened`/`had_append`/`base_modified` flag and never lowers a
    // rigor/depth ordinal — the weakest-seen-monotonicity guarantee the hand-
    // written example test (`persona_tuning_record_is_baseline_and_merges_weakest_seen`)
    // only samples a few fixed points of.
    // -----------------------------------------------------------------

    fn arb_pt_rigor() -> impl Strategy<Value = Option<Rigor>> {
        prop_oneof![
            Just(None),
            Just(Some(Rigor::Standard)),
            Just(Some(Rigor::Deep)),
            Just(Some(Rigor::Paranoid)),
        ]
    }

    fn arb_pt_depth() -> impl Strategy<Value = Option<Depth>> {
        prop_oneof![
            Just(None),
            Just(Some(Depth::Examples)),
            Just(Some(Depth::Property)),
            Just(Some(Depth::Fuzz)),
        ]
    }

    fn arb_persona_tuning_record() -> impl Strategy<Value = PersonaTuningRecord> {
        (
            arb_pt_rigor(),
            arb_pt_depth(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(rigor, depth, had_append, base_modified, weakened)| {
                PersonaTuningRecord {
                    rigor,
                    depth,
                    had_append,
                    base_modified,
                    weakened,
                }
            })
    }

    proptest! {
        #[test]
        fn effective_risk_max_law(requested in 0u8..3, derived in 0u8..3) {
            let levels = [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High];
            let requested = levels[requested as usize];
            let derived = levels[derived as usize];
            let effective = requested.max(derived);
            prop_assert!(effective.rank() >= requested.rank());
            prop_assert!(effective.rank() >= derived.rank());
            prop_assert_eq!(effective.rank(), requested.rank().max(derived.rank()));
        }

        /// Independent small reference model for the phase transition kernel.
        /// It deliberately does not call `Ledger::record` to compute the
        /// expected state: arbitrary seeded action sequences must not advance
        /// on FAIL/CONDITIONAL, accept a future phase, or become archive-ready
        /// without Deploy and Done.
        #[test]
        fn seeded_phase_reference_model_preserves_gate_truth(actions in proptest::collection::vec(any::<u8>(), 1..240)) {
            let mut ledger = Ledger::new("model", "mpd", false, ChangeKind::Fix);
            let mut reference = ledger.phase;
            let mut condition_phase: Option<Phase> = None;
            let mut condition_open = false;
            let mut task = TaskEntry {
                id: "1.1".into(),
                done: false,
                text: "model task".into(),
                normalized_record: "- [ ] 1.1 model task".into(),
                record_digest: "a".repeat(64),
                source_line: 1,
            };
            let mut task_state = 0u8; // 0=open, 1=deferred, 2=done, 3=stale
            let mut deferred_record_digest: Option<String> = None;
            for action in actions {
                match action % 10 {
                    0 if reference != Phase::Done => {
                        let phase = reference;
                        ledger.record(phase, pass("reference")).unwrap();
                        reference = phase.next(ledger.applicability());
                    }
                    1 if reference != Phase::Done => {
                        let phase = reference;
                        let mut record = pass("reference");
                        record.verdict = Verdict::Fail;
                        ledger.record(phase, record).unwrap();
                    }
                    2 if reference != Phase::Done => {
                        let phase = reference;
                        let mut record = pass("reference");
                        record.verdict = Verdict::ConditionalPass;
                        ledger.record(phase, record).unwrap();
                        // CLI owns opening, but the model exercises the same
                        // append-only ledger shape independently of CLI parsing.
                        if condition_phase.is_none() && phase >= Phase::SecurityPlan {
                            ledger.conditions.push(Condition {
                                id: format!("{}.1", phase.slug()),
                                phase,
                                attempt: 1,
                                text: "model obligation".into(),
                                owner: "Security".into(),
                                closed: false,
                                opened_at_epoch_secs: 1,
                                events: vec![ConditionEvent::Opened {
                                    by: "Security".into(),
                                    at_epoch_secs: 1,
                                    evidence: "security-plan.md".into(),
                                    evidence_digest: "e".repeat(64),
                                }],
                            });
                            condition_phase = Some(phase);
                            condition_open = true;
                        }
                    }
                    3 if reference != Phase::Done => {
                        let future = if reference == Phase::Deploy { Phase::Architecture } else { Phase::Deploy };
                        prop_assert!(ledger.record(future, pass("future")).is_err());
                    }
                    4 if reference > Phase::SecurityPlan => {
                        ledger.reconcile(ReconciliationKind::Risk, "seeded rewind".into(), Some("high".into())).unwrap();
                        reference = Phase::SecurityPlan;
                        if condition_phase.is_some_and(|phase| phase >= Phase::SecurityPlan) {
                            condition_open = true;
                        }
                    }
                    5 if condition_open => {
                        ledger.close_all_conditions("Security", "security-plan.md".into(), "d".repeat(64)).unwrap();
                        condition_open = false;
                    }
                    6 if task_state == 0 => {
                        ledger.defer_task(&task, "Builder", "bounded model deferral", "tasks.md".into(), "f".repeat(64)).unwrap();
                        deferred_record_digest = Some(task.record_digest.clone());
                        task_state = 1;
                    }
                    7 if task_state == 1 => {
                        ledger.revoke_task_deferral(&task, "model revoke").unwrap();
                        deferred_record_digest = None;
                        task_state = 0;
                    }
                    8 if matches!(task_state, 0 | 1) => {
                        task.done = true;
                        task_state = 2;
                    }
                    9 if task_state != 2 => {
                        task.record_digest = if task.record_digest.starts_with('a') { "b".repeat(64) } else { "a".repeat(64) };
                        if matches!(task_state, 1 | 3) {
                            task_state = if deferred_record_digest.as_deref() == Some(&task.record_digest) {
                                1
                            } else {
                                3
                            };
                        }
                    }
                    _ => {}
                }
                prop_assert_eq!(ledger.phase, reference);
                prop_assert_eq!(ledger.conditions.iter().any(Condition::is_open), condition_open);
                let plan = TaskPlan { strict: true, entries: vec![task.clone()] };
                let accounting = ledger.task_accounting(&plan);
                match task_state {
                    0 => prop_assert_eq!(&accounting.open, &vec!["1.1".to_string()]),
                    1 => prop_assert_eq!(accounting.deferred, 1),
                    2 => prop_assert_eq!(accounting.done, 1),
                    3 => prop_assert_eq!(&accounting.stale, &vec!["1.1".to_string()]),
                    _ => unreachable!(),
                }
                let archive_ready = ledger.ready_to_archive() && accounting.accounted();
                if condition_open || matches!(task_state, 0 | 3) {
                    prop_assert!(!archive_ready, "open/reopened conditions and open/stale tasks block archive");
                }
                if archive_ready {
                    prop_assert_eq!(ledger.phase, Phase::Done);
                    prop_assert_eq!(ledger.gates.get(&Phase::Deploy).map(|r| r.verdict), Some(Verdict::Pass));
                }
            }
        }

        /// `merge_weakest_seen` is monotone in every field, for arbitrary record
        /// pairs: each boolean can only ever become MORE true (OR, never AND or
        /// overwrite), and each ordinal can only ever rise to the max of the two
        /// inputs, never fall below either side. This is the property that makes
        /// laundering ("re-brief clean to erase a recorded weakening")
        /// impossible regardless of which two records are merged, generalizing
        /// the hand-picked example in
        /// `persona_tuning_record_is_baseline_and_merges_weakest_seen`.
        ///
        /// Non-vacuity (Tester, verified by revert→red→restore): changing
        /// `self.had_append |= other.had_append` to `self.had_append =
        /// other.had_append` (a blind overwrite, one field) reddens this test
        /// immediately with a minimal counterexample
        /// (`a.had_append=true, b.had_append=false` → merged `false`).
        #[test]
        fn merge_weakest_seen_never_downgrades_either_input(
            mut a in arb_persona_tuning_record(),
            b in arb_persona_tuning_record(),
        ) {
            let before = a.clone();
            a.merge_weakest_seen(&b);

            // Booleans: the merged value is exactly the OR of both inputs — it
            // can never be false when either input was true.
            prop_assert_eq!(a.had_append, before.had_append || b.had_append);
            prop_assert_eq!(a.base_modified, before.base_modified || b.base_modified);
            prop_assert_eq!(a.weakened, before.weakened || b.weakened);

            // Ordinals: the merged rank is >= both inputs' ranks (a true max,
            // never a blind overwrite by whichever side happened to be `other`).
            let a_rigor_rank = a.rigor.map_or(0, Rigor::rank);
            prop_assert!(a_rigor_rank >= before.rigor.map_or(0, Rigor::rank));
            prop_assert!(a_rigor_rank >= b.rigor.map_or(0, Rigor::rank));
            let a_depth_rank = a.depth.map_or(0, Depth::rank);
            prop_assert!(a_depth_rank >= before.depth.map_or(0, Depth::rank));
            prop_assert!(a_depth_rank >= b.depth.map_or(0, Depth::rank));
        }
    }
}
