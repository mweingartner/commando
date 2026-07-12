//! The gate ledger: durable per-change record of phase verdicts and evidence.
//!
//! OpenSpec tracks whether an artifact *exists*; the ledger tracks whether an
//! adversarial persona *signed off* on it, with evidence. It lives at
//! `.mpd/state/<change>.json` so it survives session death — the piece the
//! in-session pipeline lacked.

use crate::phase::{Applicability, Phase};
use openspec_core::validate_change_name;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

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
}

impl Ledger {
    /// A fresh ledger positioned at the first applicable phase.
    pub fn new(
        change: impl Into<String>,
        schema: impl Into<String>,
        ui: bool,
        kind: ChangeKind,
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
        self.gates.insert(phase, record);
        if advances && phase == self.phase {
            self.phase = phase.next(self.applicability());
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
