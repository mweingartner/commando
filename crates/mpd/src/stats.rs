//! `mpd stats` — read-only outcome measurement over the existing gate ledger
//! fields (D7). This is the first outcome-measurement surface mpd exposes, the
//! groundwork for measuring the pipeline's own quality effect over time.
//! Strictly observational: no file writes, no git subprocess, no
//! network access, no ledger mutation, and no `.mpd/current` resolution side
//! effects. Every measure here is derived from data `mpd gate`/`mpd conduct`
//! already recorded; this module adds no new durable schema (beyond D8's
//! additive `Ledger::introduced_by`, read here, not written).
//!
//! Data source: every regular file under `.mpd/state/*.json` — the ledgers of
//! active AND archived changes alike (an archived ledger persists there with
//! `archive_closure` set; the dated `openspec/changes/archive/` directory
//! carries no ledger of its own). Reads reuse [`crate::ledger::load`]
//! directly, so every bounded/no-follow/version-probe discipline D5 already
//! built is inherited rather than re-implemented: a 16 MiB per-file cap, a
//! rejected symlink/non-regular file, and an honest "requires a newer mpd"
//! diagnostic on format skew all come for free.
//!
//! An unreadable or unparsable ledger is reported as an `unreadable` row
//! carrying a coarse, stable error class — never silently skipped, never
//! fatal to the rest of the report.

use crate::ledger::{self, ChangeKind, Ledger, ReconciliationKind, Verdict};
use crate::phase::Phase;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const STATS_SCHEMA: u32 = 1;

/// Hard cap on how many `.mpd/state/*.json` entries one `mpd stats` run will
/// process. A directory holding more is a read-only reporting concern, not a
/// security boundary, so cap overflow is reported (`aggregate.truncated`),
/// never a hard error.
const MAX_STATS_LEDGERS: usize = 10_000;

/// Length bound for any disk-derived string surfaced in the human table or
/// JSON (change names, failure classes, `introduced_by`, error classes) —
/// Cond 17. Applied after `terminal_safe` strips control/bidi characters.
const MAX_RENDERED_STRING: usize = 200;

/// Bound and sanitize a disk-derived string before it is ever surfaced.
fn safe_string(value: &str) -> String {
    let cleaned = crate::harness::terminal_safe(value);
    if cleaned.chars().count() > MAX_RENDERED_STRING {
        cleaned
            .chars()
            .take(MAX_RENDERED_STRING)
            .collect::<String>()
            + "…"
    } else {
        cleaned
    }
}

/// One change's outcome measures, or a reported load failure. Never both.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ChangeRow {
    Readable(Box<ChangeStats>),
    Unreadable { change: String, error_class: String },
}

impl ChangeRow {
    fn change_name(&self) -> &str {
        match self {
            ChangeRow::Readable(stats) => &stats.change,
            ChangeRow::Unreadable { change, .. } => change,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RewindCounts {
    pub legacy_repairs: usize,
    pub freshness_invalidations: usize,
    pub total: usize,
}

/// Coverage is deliberately distinct from a numeric total: absence is not a
/// zero-cost assertion.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UsageCoverageStats {
    pub applicable_attempts: usize,
    pub reported_attempts: usize,
    pub authenticated_attempts: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeStats {
    pub change: String,
    pub kind: &'static str,
    pub archived: bool,
    pub strict: bool,
    pub risk: &'static str,
    pub threat_profile: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduced_by: Option<String>,
    pub attempts_by_phase: BTreeMap<&'static str, usize>,
    pub wallclock_secs_by_phase: BTreeMap<&'static str, u64>,
    pub reconciliations_by_kind: BTreeMap<&'static str, usize>,
    pub rewinds: RewindCounts,
    pub failure_classes: BTreeMap<String, usize>,
    pub weakened_tuning_incidents: usize,
    pub active_deferrals: usize,
    pub usage_coverage: UsageCoverageStats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AggregateStats {
    pub ledgers_scanned: usize,
    pub readable: usize,
    pub unreadable: usize,
    pub truncated: bool,
    pub attempts_by_phase: BTreeMap<&'static str, usize>,
    pub wallclock_secs_by_phase: BTreeMap<&'static str, u64>,
    pub failure_classes: BTreeMap<String, usize>,
    pub defect_escapes_by_originating_change: BTreeMap<String, usize>,
    pub usage_coverage: UsageCoverageStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsReport {
    pub schema: u32,
    pub changes: Vec<ChangeRow>,
    pub aggregate: AggregateStats,
}

/// Classify a `ledger::load` failure into a small, stable vocabulary — never
/// the raw message verbatim, so a wording change elsewhere can't silently
/// widen what a caller matches against (Cond 17's "error classes").
fn classify_load_error(error: &std::io::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("requires a newer mpd") {
        "unsupported-newer-format"
    } else if message.contains("newer or different mpd") {
        "malformed-or-version-skewed"
    } else if message.contains("byte limit") || message.contains("exceeds") {
        "oversized"
    } else if message.contains("non-regular") {
        "unsafe-file"
    } else if message.contains("invalid") {
        "invalid-change-name"
    } else {
        "malformed"
    }
}

/// Every phase measure this report derives, keyed by phase for the caller to
/// fold into either a per-change row or the aggregate.
struct PhaseMeasures {
    attempts: BTreeMap<&'static str, usize>,
    wallclock_secs: BTreeMap<&'static str, u64>,
}

fn phase_measures(ledger: &Ledger) -> PhaseMeasures {
    let mut attempts = BTreeMap::new();
    let mut wallclock_secs = BTreeMap::new();
    let history_empty_for = |phase: Phase| !ledger.history.iter().any(|event| event.phase == phase);
    for phase in Phase::applicable(ledger.applicability()) {
        let history_max_attempt = ledger
            .history
            .iter()
            .filter(|event| event.phase == phase)
            .map(|event| event.record.attempt)
            .max();
        let history_wallclock: u64 = ledger
            .history
            .iter()
            .filter(|event| event.phase == phase)
            .map(|event| event.record.duration_secs())
            .fold(0u64, |acc, secs| acc.saturating_add(secs));
        if history_empty_for(phase) {
            // Fallback to the single `gates` record (legacy ledgers, or a
            // phase whose history predates this schema).
            if let Some(record) = ledger.gates.get(&phase) {
                attempts.insert(phase.slug(), record.attempt);
                wallclock_secs.insert(phase.slug(), record.duration_secs());
            }
        } else {
            if let Some(attempt) = history_max_attempt {
                attempts.insert(phase.slug(), attempt);
            }
            wallclock_secs.insert(phase.slug(), history_wallclock);
        }
    }
    PhaseMeasures {
        attempts,
        wallclock_secs,
    }
}

fn change_stats(change: String, ledger: &Ledger) -> ChangeStats {
    let measures = phase_measures(ledger);
    let mut reconciliations_by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for reconciliation in &ledger.governance.reconciliations {
        *reconciliations_by_kind
            .entry(reconciliation_kind_label(reconciliation.kind))
            .or_insert(0) += 1;
    }
    let mut failure_classes: BTreeMap<String, usize> = BTreeMap::new();
    for event in &ledger.history {
        if event.record.verdict != Verdict::Fail {
            continue;
        }
        if let Some(class) = event.record.failure_class {
            *failure_classes
                .entry(safe_string(class.label()))
                .or_insert(0) += 1;
        }
    }
    let weakened_history = ledger
        .history
        .iter()
        .filter(|event| {
            event
                .record
                .persona_tuning
                .as_ref()
                .is_some_and(|tuning| tuning.weakened)
        })
        .count();
    let weakened_brief = ledger
        .brief_tuning
        .values()
        .filter(|tuning| tuning.record.weakened)
        .count();
    let active_deferrals = ledger
        .task_deferrals
        .iter()
        .filter(|deferral| deferral.is_active())
        .count();
    let applicable_attempts = ledger.history.len().max(ledger.gates.len());
    let usage_coverage = UsageCoverageStats {
        applicable_attempts,
        reported_attempts: ledger.usage_records.len(),
        authenticated_attempts: ledger
            .provenance_records
            .values()
            .filter(|record| {
                matches!(
                    record.state.state,
                    crate::attestation::AttestationVerifierState::Locked
                )
            })
            .count(),
    };
    ChangeStats {
        change: safe_string(&change),
        kind: change_kind_label(ledger.kind),
        archived: ledger.archive_closure.is_some(),
        strict: ledger.strict,
        risk: risk_label(ledger.effective_risk()),
        threat_profile: threat_profile_label(ledger.governance.threat_profile),
        introduced_by: ledger.introduced_by.as_deref().map(safe_string),
        attempts_by_phase: measures.attempts,
        wallclock_secs_by_phase: measures.wallclock_secs,
        reconciliations_by_kind,
        rewinds: RewindCounts {
            legacy_repairs: ledger.legacy_repairs.len(),
            freshness_invalidations: ledger.freshness_invalidations.len(),
            total: ledger
                .legacy_repairs
                .len()
                .saturating_add(ledger.freshness_invalidations.len()),
        },
        failure_classes,
        weakened_tuning_incidents: weakened_history.saturating_add(weakened_brief),
        active_deferrals,
        usage_coverage,
    }
}

// `string_enum!`-generated types don't carry a `'static` label accessor
// beyond `.label()` (which already returns `&'static str`); these thin
// wrappers exist only to keep call sites in `change_stats` uniform.
fn change_kind_label(kind: ChangeKind) -> &'static str {
    kind.label()
}
fn risk_label(risk: crate::ledger::RiskLevel) -> &'static str {
    risk.label()
}
fn threat_profile_label(profile: crate::ledger::ThreatProfile) -> &'static str {
    profile.label()
}
fn reconciliation_kind_label(kind: ReconciliationKind) -> &'static str {
    kind.label()
}

/// Enumerate `.mpd/state/*.json` filenames (not their content), bounded and
/// sorted. Non-`.json` entries and non-regular files are skipped here at the
/// listing stage only when detectable without a follow (`file_name` alone);
/// the actual load path re-validates via `symlink_metadata`.
fn list_ledger_stems(root: &Path) -> (Vec<String>, bool) {
    let state_dir = root.join(".mpd").join("state");
    let Ok(entries) = std::fs::read_dir(&state_dir) else {
        return (Vec::new(), false);
    };
    let mut stems: Vec<String> = Vec::new();
    let mut truncated = false;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if stems.len() >= MAX_STATS_LEDGERS {
            truncated = true;
            break;
        }
        stems.push(stem.to_string());
    }
    stems.sort();
    (stems, truncated)
}

/// Load and classify exactly one ledger by its filename stem. `stem` is the
/// literal filename-derived text — NOT yet validated — so an unsafe/invalid
/// name is reported as an `Unreadable` row under its own sanitized text
/// rather than ever being passed to a path-sensitive operation.
fn load_row(root: &Path, stem: &str) -> ChangeRow {
    if openspec_core::validate_change_name(stem).is_err() {
        return ChangeRow::Unreadable {
            change: safe_string(stem),
            error_class: "invalid-change-name".to_string(),
        };
    }
    match ledger::load(root, stem) {
        Ok(loaded) => {
            // Cond 17: change identity must come from the validated `change`
            // field or the filename stem; a mismatch is itself an anomaly,
            // reported rather than silently trusting either side alone.
            if loaded.change != stem {
                return ChangeRow::Unreadable {
                    change: safe_string(stem),
                    error_class: "change-identity-mismatch".to_string(),
                };
            }
            ChangeRow::Readable(Box::new(change_stats(stem.to_string(), &loaded)))
        }
        Err(error) => ChangeRow::Unreadable {
            change: safe_string(stem),
            error_class: classify_load_error(&error).to_string(),
        },
    }
}

/// Collect the full report. `change_filter`, when given, restricts collection
/// to exactly that one ledger (already-validated by the caller is not
/// required — an invalid/absent name simply yields a single unreadable row).
/// Strictly read-only: only `read_dir`/`symlink_metadata`/regular-file reads
/// occur, no write, no git subprocess, no network, and `.mpd/current` is
/// never consulted.
pub fn collect(root: &Path, change_filter: Option<&str>) -> StatsReport {
    let (stems, truncated) = match change_filter {
        Some(change) => (vec![change.to_string()], false),
        None => list_ledger_stems(root),
    };
    let mut changes: Vec<ChangeRow> = stems.iter().map(|stem| load_row(root, stem)).collect();
    changes.sort_by(|a, b| a.change_name().cmp(b.change_name()));

    let mut aggregate = AggregateStats {
        ledgers_scanned: changes.len(),
        truncated,
        ..AggregateStats::default()
    };
    for row in &changes {
        match row {
            ChangeRow::Readable(stats) => {
                aggregate.readable = aggregate.readable.saturating_add(1);
                for (phase, attempt) in &stats.attempts_by_phase {
                    *aggregate.attempts_by_phase.entry(phase).or_insert(0) = aggregate
                        .attempts_by_phase
                        .get(phase)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(*attempt);
                }
                for (phase, secs) in &stats.wallclock_secs_by_phase {
                    let slot = aggregate.wallclock_secs_by_phase.entry(phase).or_insert(0);
                    *slot = slot.saturating_add(*secs);
                }
                for (class, count) in &stats.failure_classes {
                    *aggregate.failure_classes.entry(class.clone()).or_insert(0) = aggregate
                        .failure_classes
                        .get(class)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(*count);
                }
                if let Some(origin) = &stats.introduced_by {
                    *aggregate
                        .defect_escapes_by_originating_change
                        .entry(origin.clone())
                        .or_insert(0) += 1;
                }
                aggregate.usage_coverage.applicable_attempts = aggregate
                    .usage_coverage
                    .applicable_attempts
                    .saturating_add(stats.usage_coverage.applicable_attempts);
                aggregate.usage_coverage.reported_attempts = aggregate
                    .usage_coverage
                    .reported_attempts
                    .saturating_add(stats.usage_coverage.reported_attempts);
                aggregate.usage_coverage.authenticated_attempts = aggregate
                    .usage_coverage
                    .authenticated_attempts
                    .saturating_add(stats.usage_coverage.authenticated_attempts);
            }
            ChangeRow::Unreadable { .. } => {
                aggregate.unreadable = aggregate.unreadable.saturating_add(1);
            }
        }
    }
    StatsReport {
        schema: STATS_SCHEMA,
        changes,
        aggregate,
    }
}

/// Render the bounded, terminal-safe human table. Every disk-derived string
/// already passed through `safe_string` at collection time; this only lays
/// out the (already-sanitized) values.
pub fn render_human(report: &StatsReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "mpd stats (schema {}): {} ledger(s) scanned, {} readable, {} unreadable{}\n",
        report.schema,
        report.aggregate.ledgers_scanned,
        report.aggregate.readable,
        report.aggregate.unreadable,
        if report.aggregate.truncated {
            " (TRUNCATED at the ledger cap)"
        } else {
            ""
        }
    ));
    for row in &report.changes {
        match row {
            ChangeRow::Readable(stats) => {
                out.push_str(&format!(
                    "\n{} [{}{}{}] risk={} threat={}\n",
                    stats.change,
                    stats.kind,
                    if stats.archived { " archived" } else { "" },
                    if stats.strict { " strict" } else { "" },
                    stats.risk,
                    stats.threat_profile,
                ));
                if let Some(origin) = &stats.introduced_by {
                    out.push_str(&format!("  introduced-by: {origin}\n"));
                }
                if !stats.attempts_by_phase.is_empty() {
                    let phases = stats
                        .attempts_by_phase
                        .iter()
                        .map(|(phase, attempt)| format!("{phase}={attempt}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("  attempts: {phases}\n"));
                }
                if !stats.wallclock_secs_by_phase.is_empty() {
                    let phases = stats
                        .wallclock_secs_by_phase
                        .iter()
                        .map(|(phase, secs)| format!("{phase}={secs}s"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("  wall-clock: {phases}\n"));
                }
                if !stats.reconciliations_by_kind.is_empty() {
                    let kinds = stats
                        .reconciliations_by_kind
                        .iter()
                        .map(|(kind, count)| format!("{kind}={count}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("  reconciliations: {kinds}\n"));
                }
                if stats.rewinds.total > 0 {
                    out.push_str(&format!(
                        "  rewinds: {} (legacy-repairs={}, freshness-invalidations={})\n",
                        stats.rewinds.total,
                        stats.rewinds.legacy_repairs,
                        stats.rewinds.freshness_invalidations
                    ));
                }
                if !stats.failure_classes.is_empty() {
                    let classes = stats
                        .failure_classes
                        .iter()
                        .map(|(class, count)| format!("{class}={count}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("  failure classes: {classes}\n"));
                }
                if stats.weakened_tuning_incidents > 0 {
                    out.push_str(&format!(
                        "  weakened-tuning incidents: {}\n",
                        stats.weakened_tuning_incidents
                    ));
                }
                if stats.active_deferrals > 0 {
                    out.push_str(&format!("  active deferrals: {}\n", stats.active_deferrals));
                }
                out.push_str(&format!(
                    "  usage coverage: {}/{} reported, {} authenticated\n",
                    stats.usage_coverage.reported_attempts,
                    stats.usage_coverage.applicable_attempts,
                    stats.usage_coverage.authenticated_attempts
                ));
            }
            ChangeRow::Unreadable {
                change,
                error_class,
            } => {
                out.push_str(&format!("\n{change} [unreadable: {error_class}]\n"));
            }
        }
    }
    out.push_str("\naggregate:\n");
    if !report.aggregate.attempts_by_phase.is_empty() {
        let phases = report
            .aggregate
            .attempts_by_phase
            .iter()
            .map(|(phase, attempt)| format!("{phase}={attempt}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("  total attempts: {phases}\n"));
    }
    if !report.aggregate.wallclock_secs_by_phase.is_empty() {
        let phases = report
            .aggregate
            .wallclock_secs_by_phase
            .iter()
            .map(|(phase, secs)| format!("{phase}={secs}s"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("  total wall-clock: {phases}\n"));
    }
    if !report.aggregate.failure_classes.is_empty() {
        let classes = report
            .aggregate
            .failure_classes
            .iter()
            .map(|(class, count)| format!("{class}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("  failure classes: {classes}\n"));
    }
    out.push_str(&format!(
        "  usage coverage: {}/{} reported, {} authenticated\n",
        report.aggregate.usage_coverage.reported_attempts,
        report.aggregate.usage_coverage.applicable_attempts,
        report.aggregate.usage_coverage.authenticated_attempts
    ));
    if !report
        .aggregate
        .defect_escapes_by_originating_change
        .is_empty()
    {
        let escapes = report
            .aggregate
            .defect_escapes_by_originating_change
            .iter()
            .map(|(change, count)| format!("{change}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "  defect escapes by originating change: {escapes}\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{
        BriefTuning, GateEvent, GateRecord, PersonaTuningRecord, Reconciliation, TaskDeferral,
        TaskDeferralEvent,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-stats-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join(".mpd/state")).unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        root
    }

    fn gate_record(by: &str, attempt: usize, started: u64, completed: u64) -> GateRecord {
        GateRecord {
            verdict: Verdict::Pass,
            by: by.into(),
            evidence: None,
            checks: None,
            at: "2026-01-01".into(),
            failure_class: None,
            exploitability: None,
            attempt,
            started_at_epoch_secs: started,
            completed_at_epoch_secs: completed,
            receipt: None,
            persona_tuning: None,
            candidate: None,
            build_output: None,
            deploy_result: None,
            validation_receipt: None,
            judgment_artifact_sha256: None,
        }
    }

    /// Full byte-content + mtime snapshot of every entry under `.mpd`,
    /// keyed by path. Any write, truncate, rewrite-with-identical-length, or
    /// touch by a stats run changes this snapshot.
    fn mpd_tree_snapshot(root: &std::path::Path) -> Vec<(String, SystemTime, Vec<u8>)> {
        let mut snapshot = Vec::new();
        let mut pending = vec![root.join(".mpd")];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    pending.push(path);
                    continue;
                }
                let bytes = if metadata.is_file() {
                    std::fs::read(&path).unwrap()
                } else {
                    Vec::new() // symlink: identity only, never followed
                };
                snapshot.push((
                    path.to_string_lossy().into_owned(),
                    metadata.modified().unwrap(),
                    bytes,
                ));
            }
        }
        snapshot.sort_by(|a, b| a.0.cmp(&b.0));
        snapshot
    }

    #[test]
    fn collect_is_strictly_read_only() {
        let root = test_root("read-only");
        let mut ledger = Ledger::new("watched", "mpd", false, ChangeKind::Chore);
        ledger
            .record(Phase::Architecture, gate_record("Architect", 1, 10, 20))
            .unwrap();
        ledger::save(&root, &ledger).unwrap();
        // A malformed ledger must ALSO stay byte-identical: reporting an
        // unreadable row must never trigger any repair/rewrite attempt.
        std::fs::write(root.join(".mpd/state/broken.json"), "{ not json").unwrap();

        let before = mpd_tree_snapshot(&root);
        assert!(!root.join(".mpd/current").exists());
        let _ = collect(&root, None);
        let _ = collect(&root, Some("watched"));
        let _ = collect(&root, Some("broken"));
        assert!(
            !root.join(".mpd/current").exists(),
            "stats must never resolve/create a current-change pointer"
        );
        let after = mpd_tree_snapshot(&root);
        assert_eq!(
            before, after,
            "collect must not change the content or mtime of any state file"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attempts_fall_back_to_gates_record_when_history_is_empty() {
        let root = test_root("fallback");
        let mut ledger = Ledger::new("legacy-shape", "mpd", false, ChangeKind::Fix);
        ledger
            .gates
            .insert(Phase::Architecture, gate_record("Architect", 3, 5, 15));
        // No `history` entries at all — the legacy shape.
        ledger::save(&root, &ledger).unwrap();

        let report = collect(&root, None);
        let ChangeRow::Readable(stats) = &report.changes[0] else {
            panic!("expected a readable row");
        };
        assert_eq!(
            stats.attempts_by_phase.get(Phase::Architecture.slug()),
            Some(&3)
        );
        assert_eq!(
            stats
                .wallclock_secs_by_phase
                .get(Phase::Architecture.slug()),
            Some(&10)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attempts_and_wallclock_aggregate_over_history_when_present() {
        let root = test_root("history-max");
        let mut ledger = Ledger::new("history-shape", "mpd", false, ChangeKind::Fix);
        ledger.history.push(GateEvent {
            phase: Phase::Architecture,
            record: gate_record("Architect", 1, 0, 5),
        });
        ledger.history.push(GateEvent {
            phase: Phase::Architecture,
            record: gate_record("Architect", 2, 5, 12),
        });
        ledger
            .gates
            .insert(Phase::Architecture, gate_record("Architect", 2, 5, 12));
        ledger::save(&root, &ledger).unwrap();

        let report = collect(&root, None);
        let ChangeRow::Readable(stats) = &report.changes[0] else {
            panic!("expected a readable row");
        };
        // Max attempt over history, not the gates-record fallback.
        assert_eq!(
            stats.attempts_by_phase.get(Phase::Architecture.slug()),
            Some(&2)
        );
        // Sum of history durations: (5-0) + (12-5) = 12.
        assert_eq!(
            stats
                .wallclock_secs_by_phase
                .get(Phase::Architecture.slug()),
            Some(&12)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciliations_rewinds_failure_classes_and_weakened_tuning_are_counted() {
        let root = test_root("measures");
        let mut ledger = Ledger::new("measured", "mpd", false, ChangeKind::Feature);
        ledger.governance.reconciliations.push(Reconciliation {
            kind: ReconciliationKind::Risk,
            reason: "widened".into(),
            phase: Phase::Architecture,
            authorized_attempt: 2,
            at_epoch_secs: 1,
            prior: None,
            new: None,
            consumed: true,
        });
        ledger.governance.reconciliations.push(Reconciliation {
            kind: ReconciliationKind::Risk,
            reason: "widened again".into(),
            phase: Phase::Architecture,
            authorized_attempt: 3,
            at_epoch_secs: 2,
            prior: None,
            new: None,
            consumed: true,
        });
        ledger
            .legacy_repairs
            .push(crate::ledger::LegacyRepairEvent {
                reason: "repair".into(),
                rewind_phase: Phase::Build,
                ledger_before_digest: String::new(),
                at_epoch_secs: 1,
            });
        let mut failed = gate_record("Security", 1, 0, 1);
        failed.verdict = Verdict::Fail;
        failed.failure_class = Some(crate::ledger::FailureClass::Product);
        ledger.history.push(GateEvent {
            phase: Phase::SecurityCode,
            record: failed,
        });
        let mut weakened_gate = gate_record("Tester", 1, 0, 1);
        weakened_gate.persona_tuning = Some(PersonaTuningRecord {
            weakened: true,
            ..Default::default()
        });
        ledger.history.push(GateEvent {
            phase: Phase::Test,
            record: weakened_gate,
        });
        ledger.brief_tuning.insert(
            Phase::Build,
            BriefTuning {
                attempt: 1,
                record: PersonaTuningRecord {
                    weakened: true,
                    ..Default::default()
                },
            },
        );
        ledger.task_deferrals.push(TaskDeferral {
            task_id: "t1".into(),
            record_digest: "d".repeat(64),
            events: vec![TaskDeferralEvent::Deferred {
                owner: "Builder".into(),
                reason: "later".into(),
                evidence: "e".into(),
                evidence_digest: "f".repeat(64),
                at_epoch_secs: 1,
            }],
        });
        ledger::save(&root, &ledger).unwrap();

        let report = collect(&root, None);
        let ChangeRow::Readable(stats) = &report.changes[0] else {
            panic!("expected a readable row");
        };
        assert_eq!(stats.reconciliations_by_kind.get("risk"), Some(&2));
        assert_eq!(stats.rewinds.legacy_repairs, 1);
        assert_eq!(stats.rewinds.freshness_invalidations, 0);
        assert_eq!(stats.rewinds.total, 1);
        assert_eq!(stats.failure_classes.get("product"), Some(&1));
        assert_eq!(stats.weakened_tuning_incidents, 2);
        assert_eq!(stats.active_deferrals, 1);
        assert_eq!(report.aggregate.failure_classes.get("product"), Some(&1));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unreadable_ledgers_are_reported_not_skipped() {
        let root = test_root("unreadable");
        // Malformed JSON.
        std::fs::write(root.join(".mpd/state/broken.json"), "{ not json").unwrap();
        // A valid ledger for comparison.
        let ledger = Ledger::new("healthy", "mpd", false, ChangeKind::Chore);
        ledger::save(&root, &ledger).unwrap();
        // A ledger whose internal `change` field doesn't match its filename.
        let mut mismatched = Ledger::new("elsewhere", "mpd", false, ChangeKind::Chore);
        mismatched.change = "elsewhere".into();
        std::fs::write(
            root.join(".mpd/state/mismatch.json"),
            serde_json::to_string(&mismatched).unwrap(),
        )
        .unwrap();

        let report = collect(&root, None);
        assert_eq!(report.aggregate.ledgers_scanned, 3);
        assert_eq!(report.aggregate.readable, 1);
        assert_eq!(report.aggregate.unreadable, 2);
        let broken = report
            .changes
            .iter()
            .find(|row| row.change_name() == "broken")
            .unwrap();
        assert!(matches!(broken, ChangeRow::Unreadable { .. }));
        let mismatch = report
            .changes
            .iter()
            .find(|row| row.change_name() == "mismatch")
            .unwrap();
        match mismatch {
            ChangeRow::Unreadable { error_class, .. } => {
                assert_eq!(error_class, "change-identity-mismatch");
            }
            ChangeRow::Readable(_) => panic!("a change-identity mismatch must not be trusted"),
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_state_file_is_reported_not_followed() {
        use std::os::unix::fs::symlink;
        let root = test_root("symlink");
        let outside = root.join("outside.json");
        let ledger = Ledger::new("outside", "mpd", false, ChangeKind::Chore);
        std::fs::write(&outside, serde_json::to_string(&ledger).unwrap()).unwrap();
        symlink(&outside, root.join(".mpd/state/linked.json")).unwrap();

        let report = collect(&root, None);
        let row = report
            .changes
            .iter()
            .find(|row| row.change_name() == "linked")
            .unwrap();
        assert!(
            matches!(row, ChangeRow::Unreadable { .. }),
            "a symlinked state file must never be followed"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn introduced_by_is_surfaced_and_grouped_in_the_aggregate() {
        let root = test_root("introduced-by");
        let mut ledger = Ledger::new("fix-the-bug", "mpd", false, ChangeKind::Fix);
        ledger.introduced_by = Some("original-feature".into());
        ledger::save(&root, &ledger).unwrap();
        let mut second = Ledger::new("fix-the-bug-2", "mpd", false, ChangeKind::Fix);
        second.introduced_by = Some("original-feature".into());
        ledger::save(&root, &second).unwrap();

        let report = collect(&root, None);
        assert_eq!(
            report
                .aggregate
                .defect_escapes_by_originating_change
                .get("original-feature"),
            Some(&2)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn change_filter_scopes_collection_to_exactly_one_ledger() {
        let root = test_root("filter");
        let a = Ledger::new("a", "mpd", false, ChangeKind::Chore);
        let b = Ledger::new("b", "mpd", false, ChangeKind::Chore);
        ledger::save(&root, &a).unwrap();
        ledger::save(&root, &b).unwrap();

        let report = collect(&root, Some("a"));
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].change_name(), "a");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn json_output_is_deterministic_and_sorted_by_change_name() {
        let root = test_root("json-sort");
        for name in ["zeta", "alpha", "mike"] {
            let ledger = Ledger::new(name, "mpd", false, ChangeKind::Chore);
            ledger::save(&root, &ledger).unwrap();
        }
        let report = collect(&root, None);
        let names: Vec<&str> = report.changes.iter().map(|row| row.change_name()).collect();
        assert_eq!(names, vec!["alpha", "mike", "zeta"]);
        let json_first = serde_json::to_string(&report).unwrap();
        let json_second = serde_json::to_string(&collect(&root, None)).unwrap();
        assert_eq!(json_first, json_second, "collection must be deterministic");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn render_human_never_panics_on_a_full_report() {
        let root = test_root("render");
        let ledger = Ledger::new("renderable", "mpd", false, ChangeKind::Feature);
        ledger::save(&root, &ledger).unwrap();
        std::fs::write(root.join(".mpd/state/broken.json"), "not json").unwrap();
        let report = collect(&root, None);
        let text = render_human(&report);
        assert!(text.contains("renderable"));
        assert!(text.contains("broken"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn usage_coverage_distinguishes_missing_from_explicit_zero_and_locked_provenance() {
        let root = test_root("usage-coverage");
        let mut ledger = Ledger::new("observed", "mpd", false, ChangeKind::Feature);
        ledger.history.push(GateEvent {
            phase: Phase::Architecture,
            record: gate_record("Architect", 1, 0, 1),
        });
        ledger.history.push(GateEvent {
            phase: Phase::Architecture,
            record: gate_record("Architect", 2, 1, 2),
        });
        let digest = "a".repeat(64);
        ledger.usage_records.insert(
            Ledger::attempt_key(Phase::Architecture, 1),
            crate::attestation::UsageRecord {
                schema: 1,
                evidence_digest: digest.clone(),
                input_tokens: 0,
                output_tokens: 0,
                cached_tokens: 0,
                active_millis: 0,
                currency: None,
                cost_micros: None,
                reported: true,
            },
        );
        ledger.provenance_records.insert(
            Ledger::attempt_key(Phase::Architecture, 1),
            crate::attestation::ProvenanceRecord {
                schema: 1,
                evidence_digest: digest,
                issuer: "external".into(),
                key_id: "key".into(),
                session_id_digest: "b".repeat(64),
                state: crate::attestation::AttestationState {
                    state: crate::attestation::AttestationVerifierState::Locked,
                    code: None,
                },
            },
        );
        ledger::save(&root, &ledger).unwrap();

        let report = collect(&root, None);
        let ChangeRow::Readable(row) = &report.changes[0] else {
            panic!("expected readable stats row");
        };
        assert_eq!(row.usage_coverage.applicable_attempts, 2);
        assert_eq!(row.usage_coverage.reported_attempts, 1);
        assert_eq!(row.usage_coverage.authenticated_attempts, 1);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["changes"][0]["usage_coverage"]["reported_attempts"], 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
