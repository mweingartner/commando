//! The gate ledger: durable per-change record of phase verdicts and evidence.
//!
//! OpenSpec tracks whether an artifact *exists*; the ledger tracks whether an
//! adversarial persona *signed off* on it, with evidence. It lives at
//! `.mpd/state/<change>.json` so it survives session death — the piece the
//! in-session pipeline lacked.

use crate::closure::{ArchiveClosure, EvidenceReceipt};
use crate::phase::{Applicability, Phase};
use openspec_core::validate_change_name;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub fn page_limit(self) -> Option<usize> {
        match self {
            Self::Low => Some(2),
            Self::Medium => Some(8),
            Self::High => None,
        }
    }
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

/// A recorded escape from a strict-tier judgment-artifact gate: the persona
/// signed off but the structural artifact check was waived with a reason. A
/// waiver never bypasses an objective gate and never converts a FAIL (design.md
/// D5). It is **attempt-scoped** (mirroring [`Reconciliation`]): it applies only
/// to the attempt it was recorded for, so a stale attempt-1 waiver cannot
/// silently suppress the artifact gate on a re-run under a changed threat
/// profile (design.md D7 / B1). `invalidate_from_security` drops waivers for the
/// rewound phases, exactly as it drops their gate records.
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

fn invalid(e: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e)
}

/// The kind of change, which governs whether the Documentation phases run.
/// Only a feature (a change that alters functional behavior) is documented;
/// defect fixes and non-functional chores skip the Documentation and Doc
/// Validation phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    /// A feature or enhancement that changes functional behavior. Documented.
    #[default]
    Feature,
    /// A defect fix. Not documented.
    Fix,
    /// A non-functional change (refactor, tooling, perf, deps). Not documented.
    Chore,
}

impl ChangeKind {
    /// Whether a change of this kind runs the Documentation phases.
    pub fn documents(self) -> bool {
        matches!(self, ChangeKind::Feature)
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
    /// Whether this verdict permits advancing to the next phase.
    pub fn advances(self) -> bool {
        matches!(self, Verdict::Pass | Verdict::ConditionalPass)
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
}

impl GateRecord {
    pub fn duration_secs(&self) -> u64 {
        self.completed_at_epoch_secs
            .saturating_sub(self.started_at_epoch_secs)
    }
}

/// An open condition from a CONDITIONAL PASS that blocks archive until closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// What must be done.
    pub text: String,
    /// Who owns closing it.
    pub owner: String,
    /// Whether it has been closed.
    pub closed: bool,
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
    /// Append-only log of every gate verdict ever recorded, in order. Preserves
    /// the full audit trail (incl. a FAIL that was later re-recorded PASS) that
    /// the latest-per-phase `gates` map would otherwise overwrite. Additive and
    /// optional so pre-existing ledgers deserialize with an empty history.
    #[serde(default)]
    pub history: Vec<GateEvent>,
    #[serde(default)]
    pub governance: Governance,
    /// Whether this change runs under the strict (self-enforcing) tier. Write-once
    /// and monotonic: set true by `conduct`/`begin --strict` via
    /// [`Ledger::set_strict`] and NEVER reset to false by any code path (design.md
    /// D1/D7, Cond 14), so a resumed harness keeps the strictness it opted into.
    /// Additive and `#[serde(default)]` so a legacy ledger loads as `strict=false`
    /// — the manual tier, byte-identical to today.
    #[serde(default)]
    pub strict: bool,
    /// Append-only, attempt-scoped waivers of the strict judgment-artifact gate.
    /// A waiver is surfaced loudly in status and counted in the archive audit
    /// summary; it never bypasses an objective gate or converts a FAIL (design.md
    /// D5/D7). Additive and `#[serde(default)]` so a legacy ledger loads with none.
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
            change: change.into(),
            schema: schema.into(),
            ui,
            kind,
            phase: Phase::first(applicability),
            gates: BTreeMap::new(),
            conditions: Vec::new(),
            history: Vec::new(),
            governance,
            strict: false,
            waivers: Vec::new(),
            phase_started_at_epoch_secs: now_epoch_secs(),
            archive_closure: None,
            brief_tuning: BTreeMap::new(),
        }
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
        next <= self.governance.risk.attempt_limit()
            || self
                .governance
                .reconciliations
                .iter()
                .any(|r| !r.consumed && r.phase == phase && r.authorized_attempt == next)
    }

    /// The one-shot reconciliation authorizing the next excess attempt, if any.
    pub fn attempt_authorization(&self, phase: Phase) -> Option<&Reconciliation> {
        let next = self.next_attempt(phase);
        (next > self.governance.risk.attempt_limit())
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
        // Rewind-only, never advance: a governance change while the change is still
        // BEFORE Security (e.g. at Architecture) must stay put — jumping forward to
        // SecurityPlan would skip the ungated intervening phase(s). Downstream
        // (phase > SecurityPlan) still rewinds to force a fresh Security review.
        if self.phase > Phase::SecurityPlan {
            self.phase = Phase::SecurityPlan;
            self.phase_started_at_epoch_secs = now_epoch_secs();
        }
    }

    /// The change's phase applicability (which optional phase groups run).
    pub fn applicability(&self) -> Applicability {
        Applicability {
            ui: self.ui,
            docs: self.kind.documents(),
        }
    }

    /// Record a verdict for `phase`. If it advances and is the current phase,
    /// move to the next applicable phase.
    pub fn record(&mut self, phase: Phase, record: GateRecord) {
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
    }

    /// Reasons the change cannot be archived yet (empty ⇒ ready). Every
    /// applicable phase before Deploy must have a non-Fail verdict, and no
    /// condition may remain open.
    pub fn blocking_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        for phase in Phase::applicable(self.applicability()) {
            if phase == Phase::Deploy {
                continue;
            }
            match self.gates.get(&phase) {
                None => reasons.push(format!("{} gate not recorded", phase.label())),
                Some(rec) if rec.verdict == Verdict::Fail => {
                    reasons.push(format!("{} gate is FAIL", phase.label()));
                }
                Some(_) => {}
            }
        }
        for (i, cond) in self.conditions.iter().enumerate() {
            if !cond.closed {
                reasons.push(format!("open condition #{}: {}", i + 1, cond.text));
            }
        }
        reasons
    }

    /// Whether the change is ready to archive.
    pub fn ready_to_archive(&self) -> bool {
        self.blocking_reasons().is_empty()
    }

    /// Close the 1-based condition (as numbered by `blocking_reasons` /
    /// `mpd status`). Errors if the index is out of range.
    pub fn close_condition(&mut self, index_1based: usize) -> Result<(), String> {
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
        cond.closed = true;
        Ok(())
    }

    /// Close every open condition; returns how many were newly closed.
    pub fn close_all_conditions(&mut self) -> usize {
        let mut n = 0;
        for c in self.conditions.iter_mut() {
            if !c.closed {
                c.closed = true;
                n += 1;
            }
        }
        n
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
    let text = std::fs::read_to_string(state_path(root, change))?;
    serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Persist a change's ledger (pretty JSON, trailing newline).
pub fn save(root: &Path, ledger: &Ledger) -> io::Result<()> {
    validate_change_name(&ledger.change).map_err(invalid)?;
    let path = state_path(root, &ledger.change);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut json = serde_json::to_string_pretty(ledger)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    json.push('\n');
    std::fs::write(path, json)
}

/// Read the current-change pointer, if set. A value that is not a valid change
/// name (e.g. a tampered, git-tracked `.mpd/current` carrying `../../`) is
/// treated as unset rather than trusted into a path.
pub fn current(root: &Path) -> Option<String> {
    std::fs::read_to_string(current_path(root))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .filter(|s| validate_change_name(s).is_ok())
}

/// Set the current-change pointer.
pub fn set_current(root: &Path, change: &str) -> io::Result<()> {
    validate_change_name(change).map_err(invalid)?;
    let path = current_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{change}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        }
    }

    /// Walk the execution phases common to every change (design/doc skipped).
    fn walk_core(l: &mut Ledger) {
        for phase in [
            Phase::Architecture,
            Phase::SecurityPlan,
            Phase::Build,
            Phase::SecurityCode,
            Phase::Test,
        ] {
            l.record(phase, pass(phase.persona().name));
        }
    }

    #[test]
    fn passing_current_phase_advances() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Feature);
        assert_eq!(l.phase, Phase::Architecture);
        l.record(Phase::Architecture, pass("Architect"));
        assert_eq!(l.phase, Phase::SecurityPlan);
    }

    #[test]
    fn fail_does_not_advance() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Feature);
        let mut rec = pass("Security");
        rec.verdict = Verdict::Fail;
        l.record(Phase::Architecture, rec);
        assert_eq!(l.phase, Phase::Architecture);
        assert!(!l.ready_to_archive());
    }

    #[test]
    fn record_preserves_verdict_history() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        l.record(Phase::Architecture, pass("Architect"));
        l.record(Phase::SecurityPlan, pass("Security"));
        l.record(Phase::Build, pass("Builder"));
        // Security (code) FAILs, then is fixed and re-recorded PASS.
        let mut fail = pass("Security");
        fail.verdict = Verdict::Fail;
        l.record(Phase::SecurityCode, fail);
        assert_eq!(l.phase, Phase::SecurityCode, "FAIL does not advance");
        l.record(Phase::SecurityCode, pass("Security"));
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
        // Round-trips forward without inventing either field.
        let json_out = serde_json::to_string(&l).unwrap();
        assert!(!json_out.contains("receipt"));
        assert!(!json_out.contains("archive_closure"));
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
        l.record(Phase::Architecture, failed);
        assert!(!l.attempt_authorized(Phase::Architecture));
        l.reconcile(ReconciliationKind::Continue, "fix is ready".into(), None)
            .unwrap();
        assert!(l.attempt_authorized(Phase::Architecture));
        let mut retried = pass("Architect");
        retried.attempt = 2;
        l.record(Phase::Architecture, retried);
        assert!(l.governance.reconciliations[0].consumed);
    }

    #[test]
    fn governance_change_retains_history_and_rewinds_only_security_and_downstream() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        l.record(Phase::Architecture, pass("Architect"));
        l.record(Phase::SecurityPlan, pass("Security"));
        l.record(Phase::Build, pass("Builder"));
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
    fn fix_ready_after_core_gates_skipping_docs() {
        // A fix skips the Documentation phases: Test → Deploy → ready.
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        walk_core(&mut l);
        assert_eq!(l.phase, Phase::Deploy);
        assert!(l.ready_to_archive(), "{:?}", l.blocking_reasons());
    }

    #[test]
    fn feature_requires_documentation_and_validation() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Feature);
        walk_core(&mut l);
        // Documentation is required before archive.
        assert_eq!(l.phase, Phase::Documentation);
        assert!(!l.ready_to_archive());
        l.record(Phase::Documentation, pass("Documenter"));
        assert_eq!(l.phase, Phase::Deploy);
        // Doc Validation (after Deploy) is still required.
        assert!(!l.ready_to_archive());
        l.record(Phase::Deploy, pass("main-session"));
        assert_eq!(l.phase, Phase::DocValidation);
        assert!(!l.ready_to_archive());
        l.record(Phase::DocValidation, pass("Architect & Designer"));
        assert!(l.ready_to_archive(), "{:?}", l.blocking_reasons());
    }

    #[test]
    fn open_condition_blocks_archive() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        walk_core(&mut l);
        l.conditions.push(Condition {
            text: "close the audit item".into(),
            owner: "Security".into(),
            closed: false,
        });
        assert!(!l.ready_to_archive());
        l.conditions[0].closed = true;
        assert!(l.ready_to_archive());
    }

    #[test]
    fn close_condition_by_index_and_all() {
        let mut l = Ledger::new("c", "mpd", false, ChangeKind::Fix);
        walk_core(&mut l);
        for t in ["a", "b"] {
            l.conditions.push(Condition {
                text: t.into(),
                owner: "Security".into(),
                closed: false,
            });
        }
        assert!(l.close_condition(3).is_err()); // out of range
        assert!(l.close_condition(0).is_err()); // not 1-based
        l.close_condition(1).unwrap();
        assert!(!l.ready_to_archive()); // #2 still open
        assert_eq!(l.close_all_conditions(), 1); // only #2 remained
        assert!(l.ready_to_archive());
    }

    #[test]
    fn roundtrips_through_json() {
        let mut l = Ledger::new("c", "mpd", true, ChangeKind::Feature);
        l.record(Phase::DesignMock, pass("Designer"));
        let json = serde_json::to_string(&l).unwrap();
        let back: Ledger = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
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
        l.record(Phase::Architecture, pass("Architect"));
        l.record(Phase::SecurityPlan, pass("Security"));
        l.record(Phase::Build, pass("Builder"));
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
