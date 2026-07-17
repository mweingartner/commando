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

impl RiskLevel {
    pub fn attempt_limit(self) -> usize {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
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
    #[serde(default)]
    pub phase_started_at_epoch_secs: u64,
    /// The content-addressed record of this change's completed archive
    /// closure, once `archive --yes` has fully applied and been verified
    /// (see `archive-transaction.md`). Absent for every change archived
    /// before this schema existed and for any change not yet archived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_closure: Option<ArchiveClosure>,
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
            phase_started_at_epoch_secs: now_epoch_secs(),
            archive_closure: None,
        }
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
        self.phase = Phase::SecurityPlan;
        self.phase_started_at_epoch_secs = now_epoch_secs();
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
}
