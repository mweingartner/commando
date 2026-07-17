//! The `mpd` command surface: thin verbs over the phase machine, gate ledger,
//! deterministic checks, and the OpenSpec-format engine.

use crate::checks::{self, tests_runner};
use crate::config::Config;
use crate::ledger::{
    self, bounded_text, ChangeKind, CheckSummary, Condition, Exploitability, FailureClass,
    GateRecord, Governance, ReconciliationKind, RiskLevel, ThreatProfile, Verdict, Waiver,
};
use crate::phase::Phase;
use crate::{closure, digest, git, githooks, harness, scaffold};
use clap::{Parser, Subcommand};
use closure::ArchiveClosure;
use openspec_core::{date, Project};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// mpd — an adversarial-gate overlay over the OpenSpec format.
#[derive(Debug, Parser)]
#[command(name = "mpd", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize an OpenSpec+mpd project in the current directory.
    Init {
        /// The test command used to verify Build/Test gates (e.g. "cargo test").
        #[arg(long)]
        test: Option<String>,
    },
    /// Create a new change and seed its pipeline ledger.
    Begin {
        /// Change name (lowercase kebab-case).
        name: String,
        /// Mark the change as having a UI/UX surface (enables design phases).
        #[arg(long)]
        ui: bool,
        /// A defect fix — skips the Documentation phases.
        #[arg(long)]
        fix: bool,
        /// A non-functional chore (refactor/tooling/perf) — skips Documentation.
        #[arg(long)]
        chore: bool,
        /// Review rigor (`low`, `medium`, or `high`).
        #[arg(long)]
        risk: Option<String>,
        /// Credible threat boundary for this change.
        #[arg(long = "threat-profile")]
        threat_profile: Option<String>,
        /// Run under the strict (self-enforcing) tier — the same bit `conduct`
        /// sets. Gate-enforces judgment artifacts; survives session death.
        #[arg(long)]
        strict: bool,
    },
    /// Begin a change under the strict tier: begin + strict + a seeded judgment
    /// stub + the harness call-loop contract. The way a harness drives mpd.
    Conduct {
        /// Change name (lowercase kebab-case).
        name: String,
        /// Mark the change as having a UI/UX surface (enables design phases).
        #[arg(long)]
        ui: bool,
        /// A defect fix — skips the Documentation phases.
        #[arg(long)]
        fix: bool,
        /// A non-functional chore (refactor/tooling/perf) — skips Documentation.
        #[arg(long)]
        chore: bool,
        /// Review rigor (`low`, `medium`, or `high`).
        #[arg(long)]
        risk: Option<String>,
        /// Credible threat boundary for this change.
        #[arg(long = "threat-profile")]
        threat_profile: Option<String>,
    },
    /// Scaffold a phase's judgment-artifact template into the change dir (the
    /// strict-mode escape path — fills a stub you then author).
    Brief {
        /// Phase slug (e.g. `security-code`, `test`, `design-review`).
        phase: String,
        /// Change (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
    },
    /// Show the current phase, gate verdicts, and readiness.
    Status {
        /// Change to inspect (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Print a compact one-block summary (phase, governance, readiness, next
        /// command) instead of the full report. `--json` is unaffected.
        #[arg(long)]
        brief: bool,
    },
    /// Emit the next persona's brief for the current phase.
    Next {
        /// Change to advance (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
        /// Rendering: `generic`, `claude-code`, or `codex`.
        #[arg(long, default_value = "generic")]
        harness: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Inline the persona's full directive (from `.mpd/directives/`, else the
        /// bundled default) so the brief is self-sufficient.
        #[arg(long)]
        full: bool,
        /// Emit only the phase slice — the active persona directive, the change's
        /// manifest scope, the extracted `## Conditions for Builder` block, and
        /// the upstream artifact pointers — instead of the full brief; `--json`
        /// additionally carries `artifact_path` + the strict `gate_command`. Cuts
        /// harness context load (design.md goal / task 3.2).
        #[arg(long)]
        context: bool,
    },
    /// Record a gate verdict (runs deterministic checks for enforcement phases).
    Gate {
        /// Phase slug (e.g. `architecture`, `security-code`, `test`).
        phase: String,
        /// Change (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
        /// Record a PASS.
        #[arg(long)]
        pass: bool,
        /// Record a CONDITIONAL PASS (optionally with --condition).
        #[arg(long)]
        conditional: bool,
        /// Record a FAIL.
        #[arg(long)]
        fail: bool,
        /// Evidence pointer (e.g. `design.md#conditions`).
        #[arg(long)]
        evidence: Option<String>,
        /// Persona recording the verdict (defaults to the phase's persona).
        #[arg(long)]
        by: Option<String>,
        /// An open condition to attach to a CONDITIONAL PASS (repeatable).
        #[arg(long = "condition")]
        conditions: Vec<String>,
        /// Required classification for FAIL.
        #[arg(long = "class")]
        failure_class: Option<String>,
        #[arg(long)]
        attacker: Option<String>,
        #[arg(long)]
        capability: Option<String>,
        #[arg(long)]
        boundary: Option<String>,
        #[arg(long)]
        harm: Option<String>,
        #[arg(long = "fix")]
        exact_fix: Option<String>,
        /// Explicitly reuse an exact, valid executed evidence receipt.
        #[arg(long)]
        reuse: Option<String>,
        /// Strict tier only: waive this phase's judgment-artifact check with a
        /// bounded reason (audited; never bypasses an objective gate or a FAIL).
        #[arg(long = "waive-artifact")]
        waive_artifact: Option<String>,
        /// Autonomous mode: a `--waive-artifact` on a Security phase is a judgment
        /// call reserved for a human — refuse it (halt-and-report) rather than
        /// self-authorize it (design.md D7 / Cond 12).
        #[arg(long)]
        autonomous: bool,
    },
    /// Record a bounded human decision before an excess review attempt.
    Reconcile {
        #[arg(long = "continue")]
        continue_reason: Option<String>,
        #[arg(long)]
        narrow: Option<String>,
        #[arg(long, value_names = ["LEVEL", "REASON"], num_args = 2)]
        risk: Option<Vec<String>>,
        #[arg(long = "threat-profile", value_names = ["PROFILE", "REASON"], num_args = 2)]
        threat_profile: Option<Vec<String>>,
        #[arg(long)]
        change: Option<String>,
        /// Autonomous mode: proceed on `--continue`/`--narrow`/a `--risk` upgrade,
        /// but refuse (halt-and-report) any threat-profile change or `--risk`
        /// downgrade — those weaken rigor and require a human (Cond 12).
        #[arg(long)]
        autonomous: bool,
    },
    /// Close open conditions from a CONDITIONAL PASS (they block archive).
    Resolve {
        /// Condition number (1-based, as shown by `mpd status`). Omit with --all.
        index: Option<usize>,
        /// Close every open condition.
        #[arg(long)]
        all: bool,
        /// Change (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
    },
    /// Run deterministic checks now (secret scan + optional test run).
    Check {
        /// Scan only staged files (used by the pre-commit hook).
        #[arg(long)]
        staged: bool,
        /// Suppress "everything is fine" output. Never silences allowlist
        /// suppression reporting or failures.
        #[arg(long)]
        quiet: bool,
    },
    /// Fold a completed change's specs into the record and archive it.
    Archive {
        /// Change (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
        /// Skip spec updates (tooling changes).
        #[arg(long = "skip-specs")]
        skip_specs: bool,
        /// Apply the archive (default is a dry-run preview).
        #[arg(long)]
        yes: bool,
    },
    /// Create or inspect the active change manifest.
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Inspect or freshly verify closure commit parity with its configured remote ref.
    Publish {
        #[arg(long)]
        verify: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect or recover an interrupted archive closure transaction.
    Closure {
        #[command(subcommand)]
        command: ClosureCommand,
    },
    /// Point `.mpd/current` at an existing change — recovers a cleared pointer
    /// (e.g. after `mpd closure abandon` or an archive that reset it).
    Use {
        /// Change name to make current (must have a seeded ledger).
        change: String,
    },
    /// Diagnose the project setup.
    Doctor {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Heal a missing/incomplete `.mpd/.gitignore` (add-only; fails closed
        /// on a symlinked/oversized file; never touches config.json).
        #[arg(long)]
        fix: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    /// Seed manifest.json without guessing project scope.
    Init {
        #[arg(long)]
        change: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ClosureCommand {
    Recover {
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    Abandon {
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
}

/// Run the CLI, returning a process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init { test } => cmd_init(test),
        Command::Begin {
            name,
            ui,
            fix,
            chore,
            risk,
            threat_profile,
            strict,
        } => cmd_begin(name, ui, fix, chore, risk, threat_profile, strict),
        Command::Conduct {
            name,
            ui,
            fix,
            chore,
            risk,
            threat_profile,
        } => cmd_conduct(name, ui, fix, chore, risk, threat_profile),
        Command::Brief { phase, change } => cmd_brief(phase, change),
        Command::Status {
            change,
            json,
            brief,
        } => cmd_status(change, json, brief),
        Command::Next {
            change,
            harness,
            json,
            full,
            context,
        } => cmd_next(change, harness, json, full, context),
        Command::Gate {
            phase,
            change,
            pass,
            conditional,
            fail,
            evidence,
            by,
            conditions,
            failure_class,
            attacker,
            capability,
            boundary,
            harm,
            exact_fix,
            reuse,
            waive_artifact,
            autonomous,
        } => cmd_gate(
            phase,
            change,
            pass,
            conditional,
            fail,
            evidence,
            by,
            conditions,
            failure_class,
            attacker,
            capability,
            boundary,
            harm,
            exact_fix,
            reuse,
            waive_artifact,
            autonomous,
        ),
        Command::Reconcile {
            continue_reason,
            narrow,
            risk,
            threat_profile,
            change,
            autonomous,
        } => cmd_reconcile(
            continue_reason,
            narrow,
            risk,
            threat_profile,
            change,
            autonomous,
        ),
        Command::Resolve { index, all, change } => cmd_resolve(index, all, change),
        Command::Check { staged, quiet } => cmd_check(staged, quiet),
        Command::Archive {
            change,
            skip_specs,
            yes,
        } => cmd_archive(change, skip_specs, yes),
        Command::Manifest { command } => cmd_manifest(command),
        Command::Publish { verify, json } => cmd_publish(verify, json),
        Command::Closure { command } => cmd_closure(command),
        Command::Use { change } => cmd_use(change),
        Command::Doctor { json, fix } => cmd_doctor(json, fix),
    };
    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            2
        }
    }
}

type CmdResult = Result<i32, String>;

fn cwd() -> Result<PathBuf, String> {
    std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))
}

fn find_root() -> Result<PathBuf, String> {
    let start = cwd()?;
    Project::discover(&start)
        .map(|p| p.root)
        .ok_or_else(|| "no openspec/ project found (run `mpd init`)".to_string())
}

fn resolve_change(root: &std::path::Path, opt: Option<String>) -> Result<String, String> {
    if let Some(c) = opt {
        // A `--change` value becomes a path component; validate before trusting.
        openspec_core::validate_change_name(&c)?;
        return Ok(c);
    }
    if let Some(current) = ledger::current(root) {
        return Ok(current);
    }
    if let Ok(Some(view)) = openspec_core::inspect(root) {
        return Ok(view.change);
    }
    Err("no change specified and no current or pending closure set; pass --change".to_string())
}

fn cmd_init(test: Option<String>) -> CmdResult {
    let root = cwd()?;
    let report = scaffold::init(&root, test).map_err(|e| e.to_string())?;
    if report.created.is_empty() {
        println!("Project already initialized (nothing to create).");
    } else {
        println!("Initialized mpd project:");
        for c in &report.created {
            println!("  + {c}");
        }
    }
    if let Some(path) = &report.hook_path {
        println!("  + {path} (pre-commit gate installed)");
    } else if let Some(note) = &report.hook_note {
        println!("  ! pre-commit hook: {note}");
    } else {
        println!("  ! not a git repo — run `git init` then `mpd init` to install the commit gate");
    }
    println!("\nNext: mpd begin <change-name>");
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn cmd_begin(
    name: String,
    ui: bool,
    fix: bool,
    chore: bool,
    risk: Option<String>,
    threat_profile: Option<String>,
    strict: bool,
) -> CmdResult {
    let kind = match (fix, chore) {
        (false, false) => ChangeKind::Feature,
        (true, false) => ChangeKind::Fix,
        (false, true) => ChangeKind::Chore,
        (true, true) => return Err("specify at most one of --fix, --chore".into()),
    };
    let root = find_root()?;
    // A pending closure from a prior interrupted archive must be resolved
    // (recovered or abandoned) before starting a new change — otherwise its
    // journal/staged content could be mistaken for this one's.
    if let Some(view) = openspec_core::inspect(&root).map_err(|e| e.to_string())? {
        return Err(format!(
            "cannot begin a new change — a closure for {:?} is still pending (stage: {}); \
             run `mpd closure recover` or `mpd closure abandon` first",
            view.change,
            stage_label(view.stage)
        ));
    }
    let cfg = Config::load(&root);
    let risk = match risk {
        Some(v) => v.parse::<RiskLevel>()?,
        None => cfg
            .governance
            .as_ref()
            .and_then(|g| g.risk)
            .unwrap_or(if ui {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            }),
    };
    let threat_profile = match threat_profile {
        Some(v) => v.parse::<ThreatProfile>()?,
        None => cfg
            .governance
            .as_ref()
            .and_then(|g| g.threat_profile)
            .unwrap_or_default(),
    };
    let governance = Governance {
        risk,
        threat_profile,
        reconciliations: vec![],
    };
    let mut ledger =
        scaffold::begin(&root, &name, ui, kind, governance).map_err(|e| e.to_string())?;
    println!(
        "Started change {:?} (kind: {}, ui: {}). Current phase: {}.",
        name,
        kind.label(),
        ui,
        ledger.phase.label()
    );
    println!(
        "Governance: risk {}, threat profile {}.",
        risk, threat_profile
    );
    if !kind.documents() {
        println!(
            "  (Documentation phases skipped for a {} change.)",
            kind.label()
        );
    }
    // The strict tier is a durable, per-change bit (`conduct` and `begin --strict`
    // are the only setters). Turn it on, persist it, and seed the current phase's
    // judgment stub so the very first gate has an artifact to author.
    if strict {
        ledger.set_strict();
        ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
        if let Some(created) = scaffold::seed_judgment_template(&root, &name, ledger.phase)
            .map_err(|e| e.to_string())?
        {
            println!(
                "  + {created} (seeded {} judgment stub)",
                ledger.phase.label()
            );
        }
        println!(
            "Strict tier ON: judgment artifacts are gate-enforced. \
             Escape: `mpd brief <phase>` scaffolds a stub; \
             `mpd gate <phase> --pass --waive-artifact \"reason\"` waives (audited)."
        );
    }
    println!("Next: mpd next");
    Ok(0)
}

/// `mpd conduct` — the harness entry point: `begin` under the strict tier, plus
/// the call-loop contract so an orchestrator knows the exact verb sequence.
fn cmd_conduct(
    name: String,
    ui: bool,
    fix: bool,
    chore: bool,
    risk: Option<String>,
    threat_profile: Option<String>,
) -> CmdResult {
    let name_for_contract = name.clone();
    let code = cmd_begin(name, ui, fix, chore, risk, threat_profile, true)?;
    print_conduct_contract(&name_for_contract);
    Ok(code)
}

/// Print the harness call-loop contract (design.md D2): the fixed `next → spawn →
/// gate` motion over the unchanged verbs, so a dropped call never silently
/// degrades a strict run.
fn print_conduct_contract(name: &str) {
    println!("\nStrict harness call-loop (drive mpd with the unchanged verbs):");
    println!("  loop:");
    println!(
        "    brief=$(mpd next --harness claude-code --context --json)  \
         # slice + persona + model + artifact_path + gate_command"
    );
    println!("    break if brief.phase == \"done\"");
    println!("    # spawn the persona at brief.model, fill brief.artifact_path, do the work");
    println!(
        "    mpd gate <phase> --pass --evidence <artifact_path>        \
         # strict checks auto-apply from ledger.strict"
    );
    println!("  mpd archive --yes");
    println!("\nStarted {name:?} under the strict tier. Next: mpd next");
}

/// `mpd brief <phase>` — scaffold a phase's judgment-artifact template into the
/// change dir if absent (the strict-mode escape path; never overwrites authored
/// content). Universal: works in both tiers.
fn cmd_brief(phase: String, change: Option<String>) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let phase = Phase::from_slug(&phase).ok_or_else(|| format!("unknown phase {phase:?}"))?;
    if phase.judgment_artifact().is_none() {
        return Err(format!(
            "phase {:?} has no judgment artifact to scaffold",
            phase.slug()
        ));
    }
    match scaffold::seed_judgment_template(&root, &change, phase).map_err(|e| e.to_string())? {
        Some(created) => println!("  + {created} (seeded {} judgment stub)", phase.label()),
        None => println!(
            "{}'s judgment artifact already exists — left untouched.",
            phase.label()
        ),
    }
    Ok(0)
}

#[derive(Debug, serde::Serialize)]
struct ManifestView {
    state: &'static str,
    scope: Vec<String>,
    included_staged: Vec<String>,
    unrelated_staged: Vec<String>,
    blockers: Vec<String>,
}

/// `manifest_view`'s scope-classification authority: either the active,
/// still-open change's declared manifest patterns plus live system scope, or
/// — once archived and pending commit — the closure's own concrete, realized
/// footprint. These are deliberately different authorities (see
/// `ArchiveClosure::system_paths`), never a shared glob-matching path.
fn scope_covers(
    manifest: &closure::ChangeManifest,
    system: &closure::SystemScope,
    path: &str,
) -> bool {
    manifest.covers(path, system)
}

/// A boxed "is this path in scope" predicate — either branch of
/// `manifest_view`'s active/archived authority split, type-erased so both
/// arms can share one binding.
type ScopeCoverage = Box<dyn Fn(&str) -> bool>;

fn manifest_view(root: &Path, change: &str) -> ManifestView {
    let active = closure::load_manifest(root, change);
    let (mut scope, mut blockers, covers): (Vec<String>, Vec<String>, ScopeCoverage) = match active
    {
        Ok(manifest) => {
            let system = closure::active_system_scope(root, change);
            let mut scope = manifest.paths.clone();
            scope.extend(manifest.shared_paths.clone());
            scope.extend(system.paths());
            let blockers = manifest
                .validate()
                .into_iter()
                .map(|e| e.to_string())
                .collect();
            (
                scope,
                blockers,
                Box::new(move |path: &str| scope_covers(&manifest, &system, path)),
            )
        }
        Err(active_error) => {
            let Some(record) = ledger::load(root, change)
                .ok()
                .and_then(|ledger| ledger.archive_closure)
            else {
                return ManifestView {
                    state: "incomplete",
                    scope: vec![],
                    included_staged: vec![],
                    unrelated_staged: vec![],
                    blockers: vec![active_error.to_string()],
                };
            };
            // A change that reached `AwaitingCommit` has already exhausted
            // its declared (possibly wildcard, e.g. legacy `**`) scope —
            // the operator's only remaining job is "commit the exact
            // archived result". `record.system_paths` is the closure's own
            // concrete, non-glob footprint recorded at archive time, and is
            // the sole scope authority here (specs/change-manifest/spec.md
            // "Active change directory has been archived" — "protect its
            // scope"). A legacy/absent record degrades to an empty scope,
            // which fails closed (everything staged is reported unrelated)
            // rather than fail-open.
            let scope_paths = record.system_paths.clone();
            let covers_paths = scope_paths.clone();
            (
                scope_paths,
                Vec::new(),
                Box::new(move |path: &str| closure::covers_concrete_paths(&covers_paths, path)),
            )
        }
    };
    let mut included = Vec::new();
    let mut unrelated = Vec::new();
    match crate::git::diff_cached_name_status(root) {
        Ok(entries) => {
            for entry in entries {
                for path in entry.orig_path.iter().chain(std::iter::once(&entry.path)) {
                    if covers(path) {
                        included.push(path.clone());
                    } else {
                        unrelated.push(path.clone());
                    }
                }
            }
        }
        Err(e) => blockers.push(format!("cannot inspect staged paths: {e}")),
    }
    included.sort();
    included.dedup();
    unrelated.sort();
    unrelated.dedup();
    if !unrelated.is_empty() {
        blockers.push("staged content falls outside this change's declared/system scope".into());
    }
    let state = if !unrelated.is_empty() {
        "blocked"
    } else if blockers.is_empty() {
        "ready"
    } else {
        "incomplete"
    };
    scope.sort();
    scope.dedup();
    ManifestView {
        state,
        scope,
        included_staged: included,
        unrelated_staged: unrelated,
        blockers,
    }
}

fn cmd_status(change: Option<String>, json: bool, brief: bool) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    let project = Project::new(&root);
    let tasks = project.task_status(&change).unwrap_or_default();
    // Readiness = the ledger's gate/condition reasons PLUS unfilled core-artifact
    // stubs (which `mpd archive` also refuses), so status and archive agree.
    let mut reasons = ledger.blocking_reasons();
    reasons.extend(artifact_stub_issues(&project, &change));
    let ready = reasons.is_empty();
    let artifact_budget = artifact_budget(&project, &change, ledger.governance.risk);
    let attempt_authorization = ledger
        .attempt_authorization(ledger.phase)
        .map(|r| r.kind.label().to_string());
    let manifest = manifest_view(&root, &change);
    let evidence: Vec<serde_json::Value> = ledger.gates.iter().map(|(phase, record)| {
        let validity = if project.change_dir(&change).is_dir() {
            closure::capture_dependency_values(&root, &change, &ledger, &Config::load(&root), *phase)
                .ok()
                .map(|values| closure::evidence_validity(record.receipt.as_ref(), &values))
                .unwrap_or(closure::EvidenceValidity::Absent)
        } else if record.receipt.is_some() {
            closure::EvidenceValidity::Valid
        } else {
            closure::EvidenceValidity::Absent
        };
        let offer = closure::reuse_offer(*phase, record.verdict, &validity, record.receipt.as_ref().map(|r| &r.dependencies));
        serde_json::json!({
            "phase": phase.slug(),
            "validity": validity.label(),
            "reasons": match &validity { closure::EvidenceValidity::Stale(v) => v.iter().map(ToString::to_string).collect::<Vec<_>>(), _ => vec![] },
            "reuse": format!("{:?}", offer).to_ascii_lowercase(),
            "receipt": record.receipt.as_ref().map(|r| r.id.to_string()),
        })
    }).collect();
    let coherence = ledger
        .archive_closure
        .as_ref()
        .and_then(|c| closure::verify_commit_coherence(&root, c).ok());
    let parity = closure::load_parity_cache(&root);

    if json {
        let gates: serde_json::Map<String, serde_json::Value> = ledger
            .gates
            .iter()
            .map(|(p, r)| {
                (
                    p.slug().to_string(),
                    serde_json::to_value(r).unwrap_or(serde_json::Value::Null),
                )
            })
            .collect();
        let v = serde_json::json!({
            "change": ledger.change,
            "ui": ledger.ui,
            "phase": ledger.phase.slug(),
            "gates": gates,
            "tasks": { "done": tasks.done, "total": tasks.total },
            "ready_to_archive": ready,
            "blocking_reasons": reasons,
            "history": serde_json::to_value(&ledger.history).unwrap_or(serde_json::Value::Null),
            "governance": ledger.governance,
            "artifact_budget": artifact_budget,
            "current_attempt": ledger.next_attempt(ledger.phase),
            "attempt_limit": ledger.governance.risk.attempt_limit(),
            "reconciliation_required": !ledger.attempt_authorized(ledger.phase),
            "attempt_authorization": attempt_authorization,
            "evidence": evidence,
            "manifest": manifest,
            "commit_coherence": coherence.as_ref().map(|c| serde_json::json!({"coherent":c.coherent,"head":c.head,"blockers":c.blockers})),
            "remote_parity": parity,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(0);
    }

    // `--brief`: a compact one-block summary for a quick glance or a low-context
    // harness poll. `--json` (handled above) is unaffected.
    if brief {
        println!(
            "Change: {}  phase: {}  ({} tier)",
            ledger.change,
            ledger.phase.label(),
            if ledger.strict { "strict" } else { "manual" }
        );
        println!(
            "Governance: risk {}, threat profile {} — review attempt {}/{}",
            ledger.governance.risk,
            ledger.governance.threat_profile,
            ledger.next_attempt(ledger.phase),
            ledger.governance.risk.attempt_limit()
        );
        if ready {
            println!("Ready to archive: yes  →  mpd archive --yes");
        } else {
            println!("Ready to archive: no ({} reason(s))", reasons.len());
            for r in reasons.iter().take(3) {
                println!("  - {r}");
            }
            if reasons.len() > 3 {
                println!("  … {} more (run `mpd status`)", reasons.len() - 3);
            }
            if ledger.phase != Phase::Done {
                println!("→ next: mpd next");
            }
        }
        return Ok(0);
    }

    println!("Change: {}  (ui: {})", ledger.change, ledger.ui);
    println!(
        "Governance: risk {}, threat profile {}",
        ledger.governance.risk, ledger.governance.threat_profile
    );
    println!(
        "Review attempt: {}/{}",
        ledger.next_attempt(ledger.phase),
        ledger.governance.risk.attempt_limit()
    );
    if let Some(kind) = &attempt_authorization {
        println!(
            "Excess attempt {} authorized by {} reconciliation (base limit {}).",
            ledger.next_attempt(ledger.phase),
            kind,
            ledger.governance.risk.attempt_limit()
        );
    }
    if let Some(warning) = &artifact_budget.warning {
        println!("Warning: {warning}");
    }
    println!("Current phase: {}\n", ledger.phase.label());
    println!("Pipeline:");
    for phase in Phase::applicable(ledger.applicability()) {
        let marker = match ledger.gates.get(&phase) {
            Some(r) => match r.verdict {
                Verdict::Pass => "PASS",
                Verdict::ConditionalPass => "COND",
                Verdict::Fail => "FAIL",
            },
            None if phase == ledger.phase => "→   ",
            None => "    ",
        };
        println!("  [{marker}] {}", phase.label());
    }

    // Verdict history: when any phase was recorded more than once (e.g. a FAIL
    // later re-recorded PASS), show the full ordered trail so the catch stays
    // visible instead of being hidden behind the latest green stamp.
    if ledger.history.len() > ledger.gates.len()
        || ledger
            .history
            .iter()
            .any(|e| e.record.verdict == Verdict::Fail)
    {
        println!("\nGate history:");
        // Window to the most recent events so a long-lived change (many retries)
        // does not flood the terminal; the full trail is always in `--json`.
        const HISTORY_WINDOW: usize = 12;
        let total = ledger.history.len();
        let skip = total.saturating_sub(HISTORY_WINDOW);
        if skip > 0 {
            println!("  … {skip} earlier event(s) omitted (see `mpd status --json`)");
        }
        for ev in ledger.history.iter().skip(skip) {
            let v = match ev.record.verdict {
                Verdict::Pass => "PASS",
                Verdict::ConditionalPass => "COND",
                Verdict::Fail => "FAIL",
            };
            let class = ev
                .record
                .failure_class
                .map(|c| format!(", class {c}"))
                .unwrap_or_default();
            println!(
                "  {v}  {}  ({}, attempt {}, {}s{})",
                ev.phase.label(),
                harness::terminal_safe(&ev.record.by),
                ev.record.attempt,
                ev.record.duration_secs(),
                class
            );
        }
    }

    println!("\nTasks: {}/{} complete", tasks.done, tasks.total);
    println!("\nEvidence:");
    for item in &evidence {
        println!(
            "  {:<8} {:<18} {}",
            item["validity"]
                .as_str()
                .unwrap_or("absent")
                .to_ascii_uppercase(),
            item["phase"].as_str().unwrap_or(""),
            item["reuse"].as_str().unwrap_or("")
        );
    }
    println!("\nChange manifest: {}", manifest.state.to_ascii_uppercase());
    println!("  Scope: {} path pattern(s)", manifest.scope.len());
    println!("  Included staged: {}", manifest.included_staged.len());
    if !manifest.unrelated_staged.is_empty() {
        println!(
            "  Unrelated staged: {}",
            manifest
                .unrelated_staged
                .iter()
                .take(5)
                .map(|p| harness::terminal_safe(p))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for blocker in &manifest.blockers {
        println!("  - {blocker}");
    }
    if let Some(c) = &coherence {
        println!(
            "\nCommit coherence: {}",
            if c.coherent { "COHERENT" } else { "BLOCKED" }
        );
        for blocker in &c.blockers {
            println!("  - {blocker}");
        }
    }
    if let Some(p) = &parity {
        println!(
            "\nRemote parity: {} (last observed at {})",
            p.state.label().to_ascii_uppercase(),
            p.observed_at_epoch_secs
        );
    } else {
        println!("\nRemote parity: NOT VERIFIED");
    }
    if ready {
        println!("Ready to archive: yes");
    } else {
        println!("Ready to archive: no");
        for r in &reasons {
            println!("  - {r}");
        }
    }

    // Point the operator at the next command instead of leaving it to be guessed.
    let open_conditions = ledger.conditions.iter().filter(|c| !c.closed).count();
    if let Some(c) = &coherence {
        if !c.coherent {
            println!("\n→ next: commit the exact archived result");
        } else if parity
            .as_ref()
            .is_some_and(|p| p.state == closure::ParityState::Verified)
        {
            println!("\n→ ready: closure is published at exact remote parity");
        } else {
            println!("\n→ next: mpd publish --verify");
        }
    } else if open_conditions > 0 {
        println!("\n→ close open conditions: mpd resolve <n>");
    } else if ledger.phase != Phase::Done {
        println!("\n→ next: mpd next");
    } else if ready {
        println!("\n→ ready: mpd archive --yes");
    }
    Ok(0)
}

/// The compact release-closure facts `mpd next` prepends ahead of the
/// per-phase brief (design.md "Preserve one safe next-command cue"; tasks.md
/// 5.1): reusability/evidence lives in `evidence_hint` already — this adds
/// the change-manifest state (blockers, if any) and, once archived, the
/// pending-closure stage plus its one safe next action, so an operator
/// driving purely off `mpd next` still sees a manifest block or a stalled
/// closure rather than only phase-by-phase task text.
fn release_closure_facts(root: &Path, change: &str, ledger: &ledger::Ledger) -> serde_json::Value {
    let manifest = manifest_view(root, change);
    let pending = openspec_core::inspect(root)
        .ok()
        .flatten()
        .filter(|v| v.change == change);
    serde_json::json!({
        "manifest_state": manifest.state,
        "manifest_blockers": manifest.blockers,
        "pending_closure": pending.as_ref().map(|v| serde_json::json!({
            "stage": stage_label(v.stage),
            "write_eligible": v.write_eligible,
            "next": v.next,
        })),
        "archived": ledger.archive_closure.is_some(),
    })
}

/// Human-readable rendering of [`release_closure_facts`], printed only when
/// there is something worth surfacing (a blocked/incomplete manifest, or a
/// still-pending closure) — a clean change with nothing pending prints
/// nothing extra, so the common case stays exactly as before.
fn print_release_closure_facts(facts: &serde_json::Value) {
    let manifest_state = facts["manifest_state"].as_str().unwrap_or("incomplete");
    if manifest_state != "ready" {
        let blockers: Vec<&str> = facts["manifest_blockers"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        println!(
            "Release closure: manifest {} — {}",
            manifest_state.to_ascii_uppercase(),
            if blockers.is_empty() {
                "no scope declared yet".to_string()
            } else {
                blockers.join("; ")
            }
        );
    }
    if let Some(pending) = facts["pending_closure"].as_object() {
        println!(
            "Release closure: pending ({}) — {}",
            pending
                .get("stage")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            pending
                .get("next")
                .and_then(|v| v.as_str())
                .unwrap_or("run `mpd closure recover`")
        );
    }
}

fn cmd_next(
    change: Option<String>,
    harness_kind: String,
    json: bool,
    full: bool,
    context: bool,
) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    let release_closure = release_closure_facts(&root, &change, &ledger);
    if ledger.phase == Phase::Done {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "change": change,
                    "phase": "done",
                    "archived": ledger.archive_closure.is_some(),
                    "release_closure": release_closure,
                }))
                .unwrap()
            );
            return Ok(0);
        }
        if ledger.archive_closure.is_some() {
            print_release_closure_facts(&release_closure);
            if release_closure["pending_closure"].is_null() {
                println!(
                    "{change:?} is archived and its closure metadata is resolved. Run \
                     `mpd publish --verify` to (re)confirm remote parity."
                );
            }
        } else {
            println!(
                "All phases complete for {change:?}. Run `mpd archive` to fold specs into the record."
            );
        }
        return Ok(0);
    }
    let cfg = Config::load(&root);
    let page_warning =
        artifact_budget(&Project::new(&root), &change, ledger.governance.risk).warning;
    let brief = harness::brief(
        &cfg,
        &change,
        ledger.phase,
        &harness_kind,
        &ledger.governance,
        ledger.strict,
        ledger.next_attempt(ledger.phase),
        !ledger.attempt_authorized(ledger.phase),
        ledger
            .attempt_authorization(ledger.phase)
            .map(|r| r.kind.label().to_string()),
        page_warning,
    );
    let evidence_hint = ledger
        .history
        .iter()
        .rev()
        .find(|event| event.phase == ledger.phase)
        .map(|event| {
            let validity = closure::capture_dependency_values(
                &root,
                &change,
                &ledger,
                &cfg,
                ledger.phase,
            )
            .ok()
            .map(|values| closure::evidence_validity(event.record.receipt.as_ref(), &values))
            .unwrap_or(closure::EvidenceValidity::Absent);
            let offer = closure::reuse_offer(
                ledger.phase,
                event.record.verdict,
                &validity,
                event.record.receipt.as_ref().map(|r| &r.dependencies),
            );
            serde_json::json!({
                "validity": validity.label(),
                "reuse": format!("{:?}", offer).to_ascii_lowercase(),
                "receipt": event.record.receipt.as_ref().map(|r| r.id.to_string()),
                "reasons": match validity { closure::EvidenceValidity::Stale(v) => v.into_iter().map(|r| r.to_string()).collect::<Vec<_>>(), _ => vec![] }
            })
        });

    // With --full, resolve the phase persona's directive(s). A composite persona
    // (Doc Validation = "Architect & Designer") resolves its parts.
    let directives: Vec<(String, crate::directives::Directive)> = if full {
        let names: Vec<&str> = if ledger.phase.is_doc_validation() {
            vec!["Architect", "Designer"]
        } else {
            vec![brief.persona.as_str()]
        };
        names
            .into_iter()
            .filter_map(|n| crate::directives::for_persona(&root, n).map(|d| (n.to_string(), d)))
            .collect()
    } else {
        Vec::new()
    };

    if json {
        let mut v = serde_json::to_value(&brief).unwrap();
        if full {
            let arr: Vec<_> = directives
                .iter()
                .map(|(p, d)| serde_json::json!({"persona": p, "modified": d.modified, "text": d.text}))
                .collect();
            v["directives"] = serde_json::json!(arr);
        }
        // `--context` enriches the machine envelope with the phase's judgment
        // artifact path and the strict `gate_command` (design.md D2 loop): a
        // harness reads `artifact_path`, fills it, then records the exact strict
        // gate. Both are omitted without `--context` so the default envelope is
        // unchanged.
        if context {
            v["artifact_path"] = match ledger.phase.judgment_artifact() {
                Some((f, _)) => serde_json::Value::String(f.to_string()),
                None => serde_json::Value::Null,
            };
            v["gate_command"] = serde_json::Value::String(strict_gate_command(ledger.phase));
        }
        v["evidence"] = evidence_hint.clone().unwrap_or(serde_json::Value::Null);
        v["release_closure"] = release_closure;
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(0);
    }

    // `--context` (text): emit ONLY the phase slice — persona + model, the
    // upstream artifact pointers, the manifest scope, the extracted
    // `## Conditions for Builder` block, and the active persona directive —
    // instead of the full brief, to cut a harness's context load (task 3.2).
    if context {
        render_context_slice(&root, &change, &ledger, &brief);
        return Ok(0);
    }

    // Prepend release-closure facts (manifest block / stalled pending
    // closure) ahead of the phase brief — see `release_closure_facts`. Silent
    // when there's nothing to report, so the common case is unchanged.
    print_release_closure_facts(&release_closure);

    let rendered = match harness_kind.as_str() {
        "claude-code" => harness::render_claude_code(&brief),
        "codex" => harness::render_codex(&brief),
        "generic" => harness::render_generic(&brief),
        other => {
            return Err(format!(
                "unknown harness {other:?} (use generic|claude-code|codex)"
            ))
        }
    };
    print!("{rendered}");
    if let Some(evidence) = evidence_hint {
        println!(
            "Evidence: {} ({}){}",
            evidence["validity"]
                .as_str()
                .unwrap_or("absent")
                .to_ascii_uppercase(),
            evidence["reuse"].as_str().unwrap_or("not offered"),
            evidence["receipt"]
                .as_str()
                .map(|r| format!(" receipt {r}"))
                .unwrap_or_default()
        );
    }
    for (persona, d) in &directives {
        if d.modified {
            println!(
                "\n⚠  project directive for {persona} differs from the bundled default — \
                 review it before trusting it, especially at Security/Build phases."
            );
        }
        println!("\n───── directive: {persona} ─────\n{}", d.text);
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn cmd_gate(
    phase_slug: String,
    change: Option<String>,
    pass: bool,
    conditional: bool,
    fail: bool,
    mut evidence: Option<String>,
    by: Option<String>,
    conditions: Vec<String>,
    failure_class: Option<String>,
    attacker: Option<String>,
    capability: Option<String>,
    boundary: Option<String>,
    harm: Option<String>,
    exact_fix: Option<String>,
    reuse: Option<String>,
    waive_artifact: Option<String>,
    autonomous: bool,
) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let phase =
        Phase::from_slug(&phase_slug).ok_or_else(|| format!("unknown phase {phase_slug:?}"))?;

    let verdict = match (pass, conditional, fail, reuse.is_some()) {
        (true, false, false, _) => Verdict::Pass,
        (false, true, false, false) => Verdict::ConditionalPass,
        (false, false, true, false) => Verdict::Fail,
        _ => {
            return Err(
                "specify exactly one of --pass, --conditional, --fail; --reuse requires --pass"
                    .into(),
            )
        }
    };

    // Strict-tier waiver validation (Cond 17), at the TOP alongside the
    // `--reuse requires --pass` rule above: a waiver never combines with `--reuse`
    // (the reuse seam must not skip the autonomous halt or the artifact check),
    // requires `--pass` (it can never convert a FAIL), and is meaningless on a
    // phase with no judgment artifact. The reason is bounded here so an invalid
    // reason is rejected before it could suppress any check.
    let waiver_reason = match &waive_artifact {
        Some(raw) => {
            if reuse.is_some() {
                return Err("--waive-artifact cannot combine with --reuse".into());
            }
            if !pass {
                return Err("--waive-artifact requires --pass".into());
            }
            if phase.judgment_artifact().is_none() {
                return Err(format!(
                    "--waive-artifact is invalid on {}: it has no judgment artifact to waive",
                    phase.label()
                ));
            }
            // Under --autonomous, waiving a SECURITY phase's artifact is a judgment
            // call reserved for a human — halt-and-report rather than self-waive
            // (design.md D7 / Cond 12). Non-Security judgment phases may still be
            // waived autonomously. Checked here, before any state mutation.
            if autonomous && matches!(phase, Phase::SecurityPlan | Phase::SecurityCode) {
                return Ok(autonomous_halt(&format!(
                    "waiving the {} judgment artifact requires a human decision; \
                     re-run without --autonomous or author it (`mpd brief {}`)",
                    phase.label(),
                    phase.slug()
                )));
            }
            Some(bounded_text(raw, "waiver reason")?)
        }
        None => None,
    };

    let exploit_fields_present = [&attacker, &capability, &boundary, &harm, &exact_fix]
        .iter()
        .any(|v| v.is_some());
    let failure_class = match (verdict, failure_class) {
        (Verdict::Fail, Some(v)) => Some(v.parse::<FailureClass>()?),
        (Verdict::Fail, None) => return Err(
            "--fail requires exactly one --class product|test|infrastructure|environment|policy"
                .into(),
        ),
        (_, Some(_)) => return Err("--class is valid only with --fail".into()),
        (_, None) => None,
    };
    let security = matches!(phase, Phase::SecurityPlan | Phase::SecurityCode);
    let exploitability = if verdict == Verdict::Fail && security {
        Some(Exploitability {
            attacker: bounded_text(attacker.as_deref().unwrap_or(""), "attacker")?,
            capability: bounded_text(capability.as_deref().unwrap_or(""), "capability")?,
            boundary: bounded_text(boundary.as_deref().unwrap_or(""), "boundary")?,
            harm: bounded_text(harm.as_deref().unwrap_or(""), "harm")?,
            fix: bounded_text(exact_fix.as_deref().unwrap_or(""), "fix")?,
        })
    } else if exploit_fields_present {
        return Err("exploitability flags are valid only with a Security --fail".into());
    } else {
        None
    };

    let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    // A waiver only means something in the strict tier — it waives the strict
    // judgment-artifact check. Refuse it on a manual-tier change rather than
    // record a phantom waiver, so the manual tier stays byte-identical (D3/R1).
    if waiver_reason.is_some() && !ledger.strict {
        return Err(
            "--waive-artifact requires the strict tier (start with `mpd conduct` or `mpd begin --strict`)"
                .into(),
        );
    }
    if reuse.is_none() && !ledger.attempt_authorized(phase) {
        return Err(format!("attempt {} exceeds the {}-risk limit; run `mpd reconcile --continue \"reason\"` (or narrow/change governance) first", ledger.next_attempt(phase), ledger.governance.risk));
    }
    let attempt = ledger.next_attempt(phase);
    let completed = ledger::now_epoch_secs();
    let mut checks_summary: Option<CheckSummary> = None;

    if verdict.advances() && phase == Phase::Architecture {
        let view = manifest_view(&root, &change);
        if view.state != "ready" {
            return Ok(gate_blocked(&format!(
                "Architecture gate refused: change manifest is {} ({})",
                view.state,
                view.blockers.join("; ")
            )));
        }
    }

    // Reuse is a distinct append-only gate event. It never runs checks and
    // only accepts the original executed receipt for this exact phase.
    if let Some(receipt_hex) = reuse {
        // Cond 13: the reuse path returns before the `advances()` block, so in
        // strict mode the phase's OWN judgment artifact must still exist and pass
        // the structural check here — otherwise reuse bypasses the anti-evaporation
        // guarantee at gate time. Run it first so an incomplete artifact refuses
        // deterministically, ahead of receipt evaluation. A waiver cannot reach
        // this path (waive + reuse is rejected at the top).
        if ledger.strict {
            if let Some(msg) = strict_artifact_issues(&root, &change, phase, ledger.governance.risk)
            {
                return Ok(gate_blocked(&msg));
            }
        }
        let requested = crate::digest::Digest::from_hex(&receipt_hex)?;
        let origin = ledger
            .history
            .iter()
            .find(|event| {
                event.phase == phase
                    && event
                        .record
                        .receipt
                        .as_ref()
                        .is_some_and(|r| r.id == requested)
            })
            .ok_or_else(|| format!("no receipt {receipt_hex} exists for {}", phase.label()))?;
        let origin_receipt = origin.record.receipt.as_ref().expect("matched receipt");
        let current = closure::capture_dependency_values(
            &root,
            &change,
            &ledger,
            &Config::load(&root),
            phase,
        )?;
        let validity = closure::evidence_validity(Some(origin_receipt), &current);
        closure::evaluate_reuse(phase, origin.record.verdict, origin_receipt, &validity)
            .map_err(|e| format!("cannot reuse {receipt_hex}: {e}"))?;
        let receipt = closure::EvidenceReceipt::reused_from(origin_receipt);
        let completed = ledger::now_epoch_secs();
        ledger.record(
            phase,
            GateRecord {
                verdict: Verdict::Pass,
                by: by.unwrap_or_else(|| phase.persona().name.to_string()),
                evidence: Some(format!("reused from {receipt_hex}")),
                checks: None,
                at: date::today_utc(),
                failure_class: None,
                exploitability: None,
                attempt,
                started_at_epoch_secs: completed,
                completed_at_epoch_secs: completed,
                receipt: Some(receipt),
            },
        );
        ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
        println!(
            "Recorded reused PASS for {} from {receipt_hex}.",
            phase.label()
        );
        return Ok(0);
    }

    // Enforcement: a PASS/CONDITIONAL on a test/secret phase must be backed by
    // a real run — the gate cannot accept the caller's word.
    if verdict.advances() {
        if phase.requires_tests() {
            let cfg = Config::load(&root);
            let cmd = cfg.test.ok_or_else(|| {
                format!(
                    "{} gate requires a test command; set it in .mpd/config.json (\"test\": ...)",
                    phase.label()
                )
            })?;
            println!("Running tests: {cmd}");
            let outcome = tests_runner::run(&cmd, &root);
            if !outcome.verified() {
                // When the command exited 0 but no pass count was recognized, the
                // failure is easy to mistake for a broken gate — spell out the
                // cause so a `"test": "true"` placeholder is diagnosable from
                // stderr alone. A genuine failure (a real count, non-zero exit)
                // keeps the bare summary.
                let hint = if !matches!(outcome.passed, Some(n) if n > 0) {
                    "\n  hint: the runner emitted no recognizable pass count; a \
                     placeholder like `true` always refuses — point \"test\" at a \
                     real suite that prints a pass count."
                } else {
                    ""
                };
                return Ok(gate_blocked(&format!(
                    "{} gate refused: {} (command: {}){hint}",
                    phase.label(),
                    outcome.summary,
                    outcome.command
                )));
            }
            checks_summary = Some(CheckSummary {
                tests_passed: outcome.passed,
                secrets_clean: None,
                scanner: None,
                command: Some(outcome.command),
            });
        }
        if phase.requires_secret_scan() {
            let files = checks::git_tracked_files(&root);
            let report = checks::scan_secrets(&files);
            let scanner = report.scanner;
            let (findings, suppressed) =
                crate::allowlist::Allowlist::load(&root).filter(report.findings, &root);
            if suppressed > 0 {
                println!("  {suppressed} secret finding(s) suppressed by allowlist.");
            }
            if !findings.is_empty() {
                for f in &findings {
                    eprintln!("  secret: {}:{} [{}]", f.path, f.line, f.rule);
                }
                return Ok(gate_blocked(&format!(
                    "{} gate refused: {} secret finding(s) via {}",
                    phase.label(),
                    findings.len(),
                    scanner
                )));
            }
            // Additionally run external best-of-breed scanners when installed
            // (gitleaks / Semgrep). Absent tools are skipped, not treated clean.
            let external = checks::run_external_scanners(&root);
            if !external.failures.is_empty() {
                for msg in &external.failures {
                    eprintln!("  {msg}");
                }
                return Ok(gate_blocked(&format!(
                    "{} gate refused by external scanner(s): {}",
                    phase.label(),
                    external.ran.join(", ")
                )));
            }
            let mut scanners = vec![scanner.to_string()];
            scanners.extend(external.ran.iter().cloned());
            let summary = checks_summary.get_or_insert_with(CheckSummary::default);
            summary.secrets_clean = Some(true);
            summary.scanner = Some(scanners.join("+"));
        }
        // Documentation gate: the doc must exist and cover every required
        // section, with no unfilled placeholders — machine-checked, not the
        // Documenter's word.
        if phase.requires_doc_check() {
            let path = Project::new(&root)
                .change_dir(&change)
                .join("documentation.md");
            // Symlink-refusing, size-capped read (a symlinked doc yields "" and
            // fails the structural check — never exfiltrated).
            let text = read_contained(&root, &path);
            let issues = check_documentation(&text);
            if !issues.is_empty() {
                for issue in &issues {
                    eprintln!("  doc: {issue}");
                }
                return Ok(gate_blocked(&format!(
                    "{} gate refused: documentation.md incomplete ({} issue(s))",
                    phase.label(),
                    issues.len()
                )));
            }
        }
        // Deploy gate: when a deploy command is configured, RUN it (build +
        // install) and refuse PASS if it fails — the machine-enforced
        // end-of-cycle default. Unset ⇒ the gate only records deploy-ready
        // evidence.
        if phase == Phase::Deploy {
            if let Some(cmd) = Config::load(&root).deploy {
                println!("Deploying: {cmd}");
                let outcome = tests_runner::run(&cmd, &root);
                if !outcome.success {
                    return Ok(gate_blocked(&format!(
                        "Deploy gate refused: deploy command failed (command: {})",
                        outcome.command
                    )));
                }
                checks_summary
                    .get_or_insert_with(CheckSummary::default)
                    .command = Some(outcome.command);
            }
        }
        // Strict tier (fires only when `ledger.strict`; the manual tier is inert
        // and byte-identical to today). This runs AFTER every objective gate
        // above, so a waiver can never skip tests/secret/doc/deploy (Cond 5).
        if ledger.strict {
            // `--evidence` must resolve to a real contained file — its OWN
            // artifact for a judgment phase — and defaults to that artifact when
            // omitted. Validation is metadata-only; it never reads content into
            // output (Cond 2).
            evidence = validate_evidence(&root, &change, phase, evidence)?;
            // A validly-scoped waiver for this phase + attempt (recorded by this
            // very invocation, or already on file for this attempt) skips the
            // judgment-artifact structural check — nothing else (Cond 5, Cond 15).
            let waived = waiver_reason.is_some()
                || ledger
                    .waivers
                    .iter()
                    .any(|w| w.phase == phase && w.attempt == attempt);
            if !waived {
                if let Some(msg) =
                    strict_artifact_issues(&root, &change, phase, ledger.governance.risk)
                {
                    return Ok(gate_blocked(&msg));
                }
            }
        }
    }

    // Record an attempt-scoped waiver (append-only) once every objective gate and
    // the strict evidence check have passed. A waiver only reaches here on a
    // PASS (Cond 17), so it can never convert a FAIL; it is surfaced loudly and
    // counted in the archive audit summary, but bypasses no objective gate (Cond 5).
    if let Some(reason) = waiver_reason {
        println!(
            "  ⚠ WAIVED: {} judgment-artifact check waived — {} (attempt {attempt}, audited).",
            phase.label(),
            harness::terminal_safe(&reason)
        );
        ledger.waivers.push(Waiver {
            phase,
            reason,
            attempt,
            at_epoch_secs: completed,
        });
    }

    let by = by.unwrap_or_else(|| phase.persona().name.to_string());
    ledger.record(
        phase,
        GateRecord {
            verdict,
            by,
            evidence,
            checks: checks_summary,
            at: date::today_utc(),
            failure_class,
            exploitability,
            attempt,
            started_at_epoch_secs: if ledger.phase_started_at_epoch_secs == 0 {
                completed
            } else {
                ledger.phase_started_at_epoch_secs.min(completed)
            },
            completed_at_epoch_secs: completed,
            receipt: if verdict.advances() {
                let values = closure::capture_dependency_values(
                    &root,
                    &change,
                    &ledger,
                    &Config::load(&root),
                    phase,
                )?;
                let snapshot = closure::DependencySnapshot::for_phase(phase, &values)
                    .map_err(|e| e.to_string())?;
                Some(closure::EvidenceReceipt::executed(phase, snapshot))
            } else {
                None
            },
        },
    );
    if verdict == Verdict::ConditionalPass {
        for text in conditions {
            ledger.conditions.push(Condition {
                text,
                owner: phase.persona().name.to_string(),
                closed: false,
            });
        }
    }
    ledger::save(&root, &ledger).map_err(|e| e.to_string())?;

    println!(
        "Recorded {} for {} gate. Current phase: {}.",
        match verdict {
            Verdict::Pass => "PASS",
            Verdict::ConditionalPass => "CONDITIONAL PASS",
            Verdict::Fail => "FAIL",
        },
        phase.label(),
        ledger.phase.label()
    );
    Ok(0)
}

fn cmd_reconcile(
    continue_reason: Option<String>,
    narrow: Option<String>,
    risk: Option<Vec<String>>,
    threat_profile: Option<Vec<String>>,
    change: Option<String>,
    autonomous: bool,
) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let choices = usize::from(continue_reason.is_some())
        + usize::from(narrow.is_some())
        + usize::from(risk.is_some())
        + usize::from(threat_profile.is_some());
    if choices != 1 {
        return Err("specify exactly one of --continue, --narrow, --risk <level> <reason>, or --threat-profile <profile> <reason>".into());
    }
    let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    let (kind, reason, value) = if let Some(r) = continue_reason {
        (ReconciliationKind::Continue, r, None)
    } else if let Some(r) = narrow {
        (ReconciliationKind::Narrow, r, None)
    } else if let Some(v) = risk {
        (ReconciliationKind::Risk, v[1].clone(), Some(v[0].clone()))
    } else {
        let v = threat_profile.unwrap();
        (
            ReconciliationKind::ThreatProfile,
            v[1].clone(),
            Some(v[0].clone()),
        )
    };
    // Under --autonomous, only rigor-neutral or rigor-*strengthening* moves may
    // proceed: --continue/--narrow, and a --risk UPGRADE. ANY threat-profile
    // change (the enum is unordered — every change could weaken a boundary) and
    // any --risk DOWNGRADE halt-and-report for a human (design.md D7 / Cond 12).
    // Evaluated before `reconcile` mutates anything.
    if autonomous {
        match kind {
            ReconciliationKind::ThreatProfile => {
                return Ok(autonomous_halt(
                    "a threat-profile change re-frames the security review — a human must decide",
                ));
            }
            ReconciliationKind::Risk => {
                let new: RiskLevel = value.as_deref().ok_or("--risk requires a value")?.parse()?;
                if new.rank() < ledger.governance.risk.rank() {
                    return Ok(autonomous_halt(&format!(
                        "a risk downgrade ({} → {}) weakens rigor — a human must decide",
                        ledger.governance.risk, new
                    )));
                }
            }
            ReconciliationKind::Continue | ReconciliationKind::Narrow => {}
        }
    }
    ledger.reconcile(kind, reason, value)?;
    ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
    println!("Recorded reconciliation for {} attempt {}. Current governance: risk {}, threat profile {}.", ledger.phase.label(), ledger.next_attempt(ledger.phase), ledger.governance.risk, ledger.governance.threat_profile);
    Ok(0)
}

#[derive(Debug, serde::Serialize)]
struct ArtifactBudget {
    approx_pages: Option<usize>,
    page_limit: Option<usize>,
    readable: bool,
    warning: Option<String>,
}

fn artifact_budget(project: &Project, change: &str, risk: RiskLevel) -> ArtifactBudget {
    let mut words = 0usize;
    for name in REQUIRED_ARTIFACTS {
        let p = project.change_dir(change).join(name);
        match openspec_core::assert_contained(&project.root, &p)
            .and_then(|()| openspec_core::read_capped(&p))
        {
            Ok(text) => words = words.saturating_add(text.split_whitespace().count()),
            Err(_) => {
                return ArtifactBudget {
                    approx_pages: None,
                    page_limit: risk.page_limit(),
                    readable: false,
                    warning: Some(format!(
                        "canonical artifact estimate unavailable: {name} is unreadable or exceeds the safe read limit; review it directly before continuing."
                    )),
                };
            }
        }
    }
    let pages = words.div_ceil(500);
    let limit = risk.page_limit();
    ArtifactBudget {
        approx_pages: Some(pages),
        page_limit: limit,
        readable: true,
        warning: limit.filter(|n| pages > *n).map(|n| format!(
            "canonical artifacts are approximately {pages} pages (guidance: {n}); consolidate current state and move superseded prose to history/."
        )),
    }
}

fn gate_blocked(msg: &str) -> i32 {
    eprintln!("{msg}");
    1
}

/// A `--autonomous` halt-and-report (design.md D7 / Cond 12): mpd refuses to make
/// a rigor-weakening decision a human must own, prints why, and exits with a
/// distinct code (3) a harness can branch on — never 1 (a blocked objective gate)
/// or 2 (a usage error).
fn autonomous_halt(msg: &str) -> i32 {
    eprintln!("reconciliation required — human decision: {msg}");
    3
}

/// The durable documentation target `<root>/<docs_dir>/<change>.md`. Validates
/// that `docs_dir` is a project-relative subdirectory (no `..`, not absolute) —
/// docs always live under the project they are for.
fn docs_target(root: &Path, docs_dir: &str, change: &str) -> Result<PathBuf, String> {
    let dir = Path::new(docs_dir);
    if dir.is_absolute() || dir.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "invalid docs_dir {docs_dir:?}: must be a relative project subdirectory"
        ));
    }
    Ok(root.join(dir).join(format!("{change}.md")))
}

/// The sections every `documentation.md` must contain (matched at `##` level,
/// case-insensitively, by heading prefix — so "Functional details" matches).
const REQUIRED_DOC_SECTIONS: &[&str] = &["Purpose", "Value", "Scope", "Functional", "Usage"];

/// Whether `text` still carries an UNFILLED template placeholder (`<!-- … -->`).
/// A `<!--` that appears only inside an inline-code span (backticks) is ignored,
/// so a document that merely *describes* the placeholder convention (like this
/// change's own design/proposal) is not mistaken for an unfilled stub. On each
/// line the even-indexed backtick splits are the spans outside inline code.
fn has_unfilled_placeholder(text: &str) -> bool {
    text.lines()
        .any(|line| line.split('`').step_by(2).any(|seg| seg.contains("<!--")))
}

/// Structural completeness check shared by the documentation gate and the strict
/// judgment-artifact gate. Returns the list of problems (empty ⇒ complete): each
/// required `section` missing (matched at `##` level, case-insensitively, by
/// heading prefix — so "Functional details" matches "Functional"), any unfilled
/// `<!-- … -->` template placeholder, or content shorter than `min_len` trimmed
/// bytes.
fn check_sections(text: &str, sections: &[&str], min_len: usize) -> Vec<String> {
    let mut issues = Vec::new();
    for section in sections {
        let present = text.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("##")
                && trimmed
                    .trim_start_matches('#')
                    .trim()
                    .to_ascii_lowercase()
                    .starts_with(&section.to_ascii_lowercase())
        });
        if !present {
            issues.push(format!("missing section: {section}"));
        }
    }
    if has_unfilled_placeholder(text) {
        issues.push("unfilled template placeholders remain (<!-- … -->)".to_string());
    }
    if text.trim().len() < min_len {
        issues.push("documentation is too short to be meaningful".to_string());
    }
    issues
}

/// Structural completeness check for a `documentation.md` file — the required doc
/// sections and a 120-char floor. A thin, behavior-preserving wrapper over
/// [`check_sections`].
fn check_documentation(text: &str) -> Vec<String> {
    check_sections(text, REQUIRED_DOC_SECTIONS, 120)
}

/// Upper bound on an extracted `--context` section render (Cond 11 — the human
/// slice must be length-bounded). Generous enough to carry a full Conditions for
/// Builder block, small enough to keep a hostile design.md from flooding a
/// terminal; the full artifact is always one `read_capped` away.
const CONTEXT_SECTION_MAX: usize = 8000;

/// The `##`-heading level of a (left-trimmed) line — the count of leading `#`.
fn heading_level(trimmed: &str) -> usize {
    trimmed.chars().take_while(|c| *c == '#').count()
}

/// Extract the body beneath the first `##`-level heading whose title matches
/// `section` (case-insensitive prefix — the same scan as [`check_sections`]),
/// from that heading to the next `#`/`##` boundary (a deeper `###` subheading
/// stays inside). Returns the trimmed body, made `terminal_safe` and truncated to
/// `max_len` bytes with an ellipsis (Cond 11 — new user-controlled text in the
/// human `--context` render must be terminal-safe AND length-bounded). `None`
/// when the section is absent or its body is empty.
fn extract_section(text: &str, section: &str, max_len: usize) -> Option<String> {
    let needle = section.to_ascii_lowercase();
    let mut in_section = false;
    let mut body = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let level = heading_level(trimmed);
        if in_section {
            // A new top-level or level-2 heading ends the section; `###`+ is body.
            if (1..=2).contains(&level) {
                break;
            }
            body.push_str(line);
            body.push('\n');
        } else if level == 2 {
            let title = trimmed.trim_start_matches('#').trim().to_ascii_lowercase();
            if title.starts_with(&needle) {
                in_section = true;
            }
        }
    }
    if !in_section {
        return None;
    }
    let safe = harness::terminal_safe(body.trim());
    if safe.is_empty() {
        return None;
    }
    if safe.len() <= max_len {
        return Some(safe);
    }
    // Truncate at a UTF-8 char boundary at or below max_len.
    let mut end = max_len;
    while end > 0 && !safe.is_char_boundary(end) {
        end -= 1;
    }
    Some(format!("{}…", &safe[..end]))
}

/// The strict-tier gate command for a phase: it records the phase's own judgment
/// artifact as evidence when it has one, else a bare pass. Shared by the
/// `--context` JSON envelope and text slice.
fn strict_gate_command(phase: Phase) -> String {
    match phase.judgment_artifact() {
        Some((filename, _)) => {
            format!("mpd gate {} --pass --evidence {filename}", phase.slug())
        }
        None => format!("mpd gate {} --pass", phase.slug()),
    }
}

/// The upstream judgment artifacts this phase's persona should read, as
/// `(phase label, filename)`. Resolves [`Phase::upstream_context`] to each
/// upstream phase's [`Phase::judgment_artifact`], skipping phases with none and
/// phases the change's applicability excludes (task 3.2).
fn upstream_artifact_pointers(
    phase: Phase,
    applicability: crate::phase::Applicability,
) -> Vec<(&'static str, &'static str)> {
    let applicable = Phase::applicable(applicability);
    phase
        .upstream_context()
        .iter()
        .filter(|p| applicable.contains(p))
        .filter_map(|p| p.judgment_artifact().map(|(f, _)| (p.label(), f)))
        .collect()
}

/// Render the `mpd next --context` phase slice (text): persona + model, the
/// upstream artifact pointers, the change's manifest scope, the extracted
/// `## Conditions for Builder` block from design.md, and the active persona
/// directive — the minimal context a persona needs, in place of the full brief.
fn render_context_slice(
    root: &Path,
    change: &str,
    ledger: &ledger::Ledger,
    brief: &harness::NextBrief,
) {
    println!("▸ {} — {}  [context slice]", brief.label, brief.change);
    let model_line = match &brief.model_note {
        Some(note) => format!("{} ({note})", brief.model),
        None => brief.model.clone(),
    };
    println!("  Persona: {} (model: {})", brief.persona, model_line);
    if brief.deep_tier_bump {
        println!("  risk=high → deep tier");
    }
    if brief.reconciliation_required && ledger.strict {
        println!("  reconciliation required — human decision");
    }

    let pointers = upstream_artifact_pointers(ledger.phase, ledger.applicability());
    if !pointers.is_empty() {
        println!("\n  Read upstream artifacts:");
        for (label, file) in pointers {
            println!("    - {label}: {file}");
        }
    }

    let manifest = manifest_view(root, change);
    println!("\n  Manifest scope ({} pattern(s)):", manifest.scope.len());
    for p in manifest.scope.iter().take(20) {
        println!("    - {}", harness::terminal_safe(p));
    }
    if manifest.scope.len() > 20 {
        println!("    … {} more", manifest.scope.len() - 20);
    }

    let design = read_contained(
        root,
        &Project::new(root).change_dir(change).join("design.md"),
    );
    // The Conditions for Builder are the invariants the persona MUST honor, so
    // the bound is generous (still bounded per Cond 11 — the full file is one
    // `read_capped` away via the artifact pointer if it ever exceeds this).
    match extract_section(&design, "Conditions for Builder", CONTEXT_SECTION_MAX) {
        Some(block) => println!("\n  ## Conditions for Builder\n{block}"),
        None => {
            println!("\n  (no `## Conditions for Builder` section in design.md yet)")
        }
    }

    if let Some(d) = crate::directives::for_persona(root, &brief.persona) {
        if d.modified {
            println!(
                "\n  ⚠ project directive for {} differs from the bundled default — \
                 review it before trusting it.",
                brief.persona
            );
        }
        println!("\n───── directive: {} ─────\n{}", brief.persona, d.text);
    }

    println!("\n  When done: {}", strict_gate_command(ledger.phase));
}

/// The minimum authored-body length for a strict judgment artifact — the same
/// 120-byte floor the documentation gate uses.
const JUDGMENT_MIN_LEN: usize = 120;

/// Read a project file only if it stays within `root` after symlink
/// resolution, else `""`. `read_capped` alone lstat's only the final path
/// component, so an intermediate directory symlink (a symlinked change dir or
/// `.mpd/`) would be followed and read through; `assert_contained` refuses that
/// (Cond 1). A refused path reads as `""` and fails the caller's structural
/// check / reports fail-closed — never followed, never surfaced.
fn read_contained(root: &Path, path: &Path) -> String {
    if openspec_core::assert_contained(root, path).is_ok() {
        openspec_core::read_capped(path).unwrap_or_default()
    } else {
        String::new()
    }
}

/// The strict-tier structural check of `phase`'s judgment artifact. Returns
/// `None` when the artifact is complete (or the phase has none), or the
/// escape-bearing refusal message when it is missing/incomplete (Cond 15). The
/// read goes through [`read_contained`] (containment-checked, symlink-refusing,
/// size-capped): a symlinked change dir / artifact or an oversized file reads as
/// `""` and fails the structural check — never followed, never read through
/// (an intermediate-directory symlink escape is refused too). Artifact content is
/// never surfaced (only the structural issue list). High-risk Security (code)
/// additionally requires the `Independent review` + `Refutation` sections
/// (design.md D6, layered on here rather than in `judgment_artifact`).
fn strict_artifact_issues(
    root: &Path,
    change: &str,
    phase: Phase,
    risk: RiskLevel,
) -> Option<String> {
    let (filename, sections) = phase.judgment_artifact()?;
    let path = Project::new(root).change_dir(change).join(filename);
    let text = read_contained(root, &path);
    let mut required: Vec<&str> = sections.to_vec();
    if phase == Phase::SecurityCode && risk == RiskLevel::High {
        required.push("Independent review");
        required.push("Refutation");
    }
    let issues = check_sections(&text, &required, JUDGMENT_MIN_LEN);
    if issues.is_empty() {
        return None;
    }
    for issue in &issues {
        eprintln!("  artifact: {issue}");
    }
    Some(format!(
        "{} gate refused: {filename} incomplete ({} issue(s)). \
         Author it (`mpd brief {slug}`) or waive it \
         (`mpd gate {slug} --pass --waive-artifact \"reason\"`).",
        phase.label(),
        issues.len(),
        slug = phase.slug(),
    ))
}

/// Validate a strict-mode `--evidence` pointer WITHOUT reading its content into
/// any output (Cond 2). Strips the optional `#anchor` at the FIRST `#`, rejects
/// an absolute path, joins the remainder to the change dir, and runs
/// [`openspec_core::assert_contained`] (which refuses `.`/`..`/empty-component/
/// intermediate-symlink/escape — so ad-hoc absolute checks are not relied on
/// alone). Existence is confirmed via `symlink_metadata` (never following a
/// link) and the target must be a non-empty regular file. For a judgment phase
/// the post-`join` `PathBuf` MUST equal the change dir's own judgment artifact
/// exactly — a planted `subdir/security-code.md` cannot alias. When `--evidence`
/// is omitted it defaults to that exact artifact (or to `None` for a
/// non-judgment phase, which records no evidence). Returns the pointer to record.
fn validate_evidence(
    root: &Path,
    change: &str,
    phase: Phase,
    ev: Option<String>,
) -> Result<Option<String>, String> {
    let change_dir = Project::new(root).change_dir(change);
    let artifact = phase.judgment_artifact();
    // An omitted pointer defaults to the phase's own artifact (a safe constant
    // basename); its existence and completeness are owned by the separate
    // judgment-artifact check, so no path validation is needed here. A
    // non-judgment phase with no pointer records nothing.
    let raw = match ev {
        Some(e) => e,
        None => {
            return Ok(artifact.map(|(filename, _)| filename.to_string()));
        }
    };
    // Strip at the FIRST '#': the anchor is a human pointer, not part of the path.
    let stripped = raw.split('#').next().unwrap_or("").trim();
    if stripped.is_empty() {
        return Err("--evidence must name a file (the path before '#' is empty)".into());
    }
    let stripped_path = Path::new(stripped);
    // Reject an absolute path BEFORE joining — `Path::join` replaces the base on
    // an absolute argument, which would silently escape the change dir.
    if stripped_path.is_absolute() {
        return Err(format!(
            "--evidence path {stripped:?} must be relative to the change directory"
        ));
    }
    let joined = change_dir.join(stripped_path);
    openspec_core::assert_contained(&change_dir, &joined).map_err(|e| e.to_string())?;
    // Existence via symlink_metadata (never follow); must be a non-empty file.
    let md = std::fs::symlink_metadata(&joined).map_err(|_| {
        format!("--evidence file {stripped:?} does not exist in the change directory")
    })?;
    if md.file_type().is_symlink() {
        return Err(format!(
            "--evidence file {stripped:?} is a symlink; refusing to follow it"
        ));
    }
    if !md.is_file() {
        return Err(format!(
            "--evidence path {stripped:?} is not a regular file"
        ));
    }
    if md.len() == 0 {
        return Err(format!("--evidence file {stripped:?} is empty"));
    }
    // For a judgment phase the evidence MUST be that phase's OWN artifact —
    // compare the post-`join` PathBufs, not a basename (Cond 2, kills aliasing).
    if let Some((filename, _)) = artifact {
        let expected = change_dir.join(filename);
        if joined != expected {
            return Err(format!(
                "--evidence for {} must point to its own artifact {filename:?}, not {stripped:?}",
                phase.label()
            ));
        }
    }
    Ok(Some(raw))
}

/// The core OpenSpec artifacts every change must fill before archive.
const REQUIRED_ARTIFACTS: &[&str] = &["proposal.md", "design.md", "tasks.md"];

/// Issues with a change's core artifacts (empty ⇒ all filled): each must exist,
/// carry real content, and have no unfilled `<!-- … -->` template placeholders —
/// the same guarantee the Documentation gate already enforces for
/// `documentation.md`, extended to the core artifacts so a template stub can't be
/// archived. Reads are symlink-refusing and size-capped (`read_capped`): a
/// symlinked or oversized artifact yields "" and is reported as a stub, never
/// followed.
fn artifact_stub_issues(project: &Project, change: &str) -> Vec<String> {
    let dir = project.change_dir(change);
    let mut issues = Vec::new();
    for name in REQUIRED_ARTIFACTS {
        let text = read_contained(&project.root, &dir.join(name));
        if text.trim().is_empty() {
            issues.push(format!("{name} is missing or empty"));
        } else if has_unfilled_placeholder(&text) {
            issues.push(format!(
                "{name} still has unfilled template placeholders (<!-- … -->)"
            ));
        }
    }
    issues
}

/// The archive-time strict re-check (design.md Cond 9 / B2). A change's judgment
/// gates all passed at gate time, but an artifact can still evaporate before the
/// change is folded into the permanent record — the exact CARC hole. Under
/// `ledger.strict`, sweep every APPLICABLE judgment phase and re-run its
/// structural check via [`strict_artifact_issues`], collecting a refusal for any
/// that no longer passes. A phase whose passing gate carried a validly-scoped
/// waiver (a waiver for that phase AND that phase's recorded gate attempt) is
/// treated as satisfied and surfaced WAIVED, never blocking — otherwise a
/// legitimate gate-time waiver would be an un-archivable dead-end. Returns the
/// escape-bearing refusals (empty ⇒ every artifact survived) and the labels of
/// the phases counted WAIVED in the audit summary. Reads go through the same
/// symlink-refusing, size-capped path as the gate (Cond 1); no artifact content
/// is surfaced.
fn strict_archive_recheck(
    root: &Path,
    change: &str,
    ledger: &ledger::Ledger,
) -> (Vec<String>, Vec<&'static str>) {
    let mut refusals = Vec::new();
    let mut waived = Vec::new();
    for phase in Phase::applicable(ledger.applicability()) {
        if phase.judgment_artifact().is_none() {
            continue;
        }
        // The waiver is attempt-scoped to the phase's *recorded* passing gate;
        // a rewind (`invalidate_from_security`) has already dropped waivers for
        // any rewound phase, so a surviving match is for the current attempt.
        let attempt = ledger.gates.get(&phase).map(|r| r.attempt).unwrap_or(0);
        let waived_here = ledger
            .waivers
            .iter()
            .any(|w| w.phase == phase && w.attempt == attempt);
        if waived_here {
            waived.push(phase.label());
            continue;
        }
        if let Some(msg) = strict_artifact_issues(root, change, phase, ledger.governance.risk) {
            refusals.push(msg);
        }
    }
    (refusals, waived)
}

/// The archive transient-path pre-flight (design.md Cond 8). A transient `.mpd/`
/// path (the current-change pointer, scratch tmp, a pending closure, publish
/// parity observations) that exists on disk but is NOT covered by
/// `.mpd/.gitignore` would be swept into the commit/archive. Returns the
/// un-covered transient entries (empty ⇒ clean), demanding exactly the set
/// [`scaffold::TRANSIENT_GITIGNORE_ENTRIES`] that `mpd doctor --fix` heals, so a
/// `--fix` always fully clears what this refuses. The `.mpd/.gitignore` read is
/// symlink-refusing + size-capped (Cond 1): a symlinked/oversized file reads as
/// `""` ⇒ nothing is covered ⇒ every existing transient is reported (fail-closed).
fn uncovered_transient_paths(root: &Path) -> Vec<&'static str> {
    let mpd = ledger::mpd_dir(root);
    let gitignore = read_contained(root, &mpd.join(".gitignore"));
    let covered: std::collections::BTreeSet<&str> = gitignore.lines().map(|l| l.trim()).collect();
    scaffold::TRANSIENT_GITIGNORE_ENTRIES
        .iter()
        .copied()
        .filter(|entry| {
            // Only an existing transient path is "in scope" — a pattern whose
            // target isn't on disk can't leak. `symlink_metadata` never follows
            // a link, so a symlinked transient still counts as present.
            let on_disk = mpd.join(entry.trim_matches('/')).symlink_metadata().is_ok();
            on_disk && !covered.contains(entry)
        })
        .collect()
}

fn cmd_resolve(index: Option<usize>, all: bool, change: Option<String>) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;

    match (index, all) {
        (Some(_), true) => return Err("specify a condition number or --all, not both".into()),
        (None, false) => {
            return Err("specify a condition number (see `mpd status`) or --all".into())
        }
        (Some(i), false) => {
            ledger.close_condition(i)?;
            println!("Closed condition #{i}.");
        }
        (None, true) => {
            let n = ledger.close_all_conditions();
            println!("Closed {n} open condition(s).");
        }
    }
    ledger::save(&root, &ledger).map_err(|e| e.to_string())?;

    let remaining = ledger.conditions.iter().filter(|c| !c.closed).count();
    if remaining == 0 {
        let tail = if ledger.ready_to_archive() {
            " Ready to archive."
        } else {
            ""
        };
        println!("All conditions closed.{tail}");
    } else {
        println!("{remaining} condition(s) still open.");
    }
    Ok(0)
}

fn cmd_check(staged: bool, quiet: bool) -> CmdResult {
    let root = find_root()?;
    let files = if staged {
        checks::git_staged_files(&root)
    } else {
        checks::git_tracked_files(&root)
    };
    let report = checks::scan_secrets(&files);
    let scanner = report.scanner;
    let (findings, suppressed) =
        crate::allowlist::Allowlist::load(&root).filter(report.findings, &root);
    let mut failed = false;
    if staged {
        if let Ok(change) = resolve_change(&root, None) {
            let view = manifest_view(&root, &change);
            if view.state == "blocked" {
                failed = true;
                eprintln!("Change manifest blocked by out-of-scope staged paths:");
                let path_limit = Config::load(&root).human_path_list_limit();
                for path in view.unrelated_staged.iter().take(path_limit) {
                    eprintln!("  {}", harness::terminal_safe(path));
                }
            }
        }
    }

    // Suppression reporting is a security signal — never silenced by --quiet.
    if suppressed > 0 {
        println!("Secret scan: {suppressed} finding(s) suppressed by allowlist.");
    }
    if !findings.is_empty() {
        failed = true;
        eprintln!(
            "Secret scan ({}) found {} finding(s):",
            scanner,
            findings.len()
        );
        for f in &findings {
            let loc = if f.line == 0 {
                f.path.clone()
            } else {
                format!("{}:{}", f.path, f.line)
            };
            eprintln!("  {loc} [{}]", f.rule);
        }
    }

    // The pre-commit hook (`--staged`) does the FAST secret scan only, so it
    // stays cheap on every commit. The heavier external scanners and the test
    // suite run in the full `mpd check` (manual/CI) and at the Build/Test gate.
    if !staged {
        let external = checks::run_external_scanners(&root);
        if !external.failures.is_empty() {
            failed = true;
            for msg in &external.failures {
                eprintln!("{msg}");
            }
        }

        let cfg = Config::load(&root);
        if let Some(cmd) = cfg.test {
            let outcome = tests_runner::run(&cmd, &root);
            if !outcome.success {
                failed = true;
                eprintln!("Tests failed: {} ({})", outcome.summary, outcome.command);
            } else if !quiet {
                println!("Tests: {}", outcome.summary);
            }
        }
    }

    if failed {
        Ok(1)
    } else {
        if !quiet {
            println!("Checks passed (secret scan clean via {}).", report.scanner);
        }
        Ok(0)
    }
}

fn cmd_manifest(command: ManifestCommand) -> CmdResult {
    let root = find_root()?;
    match command {
        ManifestCommand::Init { change } => {
            let change = resolve_change(&root, change)?;
            let path = closure::manifest_path(&root, &change)?;
            if path.exists() {
                return Err(format!(
                    "{} already exists; refusing to overwrite declared scope",
                    path.display()
                ));
            }
            closure::save_manifest(&root, &change, &closure::ChangeManifest::seed())
                .map_err(|e| e.to_string())?;
            println!(
                "Seeded {}. Declare paths before Architecture PASS.",
                path.display()
            );
            Ok(0)
        }
    }
}

fn archived_manifest(
    root: &Path,
    ledger: &ledger::Ledger,
) -> Result<closure::ChangeManifest, String> {
    let closure_record = ledger
        .archive_closure
        .as_ref()
        .ok_or("change has not been archived")?;
    let path = root
        .join(&closure_record.archive_path)
        .join("manifest.json");
    // Contain before read (Cond 1 class): the archive path is ledger-authored but
    // an intermediate symlink would otherwise be followed by read_capped's
    // final-only lstat.
    openspec_core::assert_contained(root, &path).map_err(|e| e.to_string())?;
    let text = openspec_core::read_capped(&path).map_err(|e| e.to_string())?;
    let manifest: closure::ChangeManifest =
        serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let issues = manifest.validate();
    if !issues.is_empty() {
        return Err(format!(
            "archived manifest is invalid: {}",
            issues
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    Ok(manifest)
}

fn resolve_publish_target(
    root: &Path,
    manifest: &closure::ChangeManifest,
    config: &Config,
) -> Result<Option<closure::PublishTarget>, String> {
    if let Some(target) = &manifest.publish {
        return Ok(Some(target.clone()));
    }
    if let Some(defaults) = &config.closure {
        match (&defaults.default_remote, &defaults.default_ref) {
            (Some(remote), Some(reference)) => {
                if !git::valid_remote_name(remote) || !git::valid_branch_ref(reference) {
                    return Err("closure default publication target is invalid".into());
                }
                return Ok(Some(closure::PublishTarget {
                    remote: remote.clone(),
                    reference: reference.clone(),
                }));
            }
            (None, None) => {}
            _ => {
                return Err(
                    "closure default_remote and default_ref must be configured together".into(),
                )
            }
        }
    }
    Ok(git::publication_upstream(root)
        .map_err(|e| e.to_string())?
        .map(|(remote, reference)| closure::PublishTarget { remote, reference }))
}

fn cmd_publish(verify: bool, json: bool) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, None)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    let closure_record = ledger
        .archive_closure
        .as_ref()
        .ok_or("change has no archived closure; run mpd archive first")?;
    let manifest = archived_manifest(&root, &ledger)?;
    let config = Config::load(&root);
    let Some(target) = resolve_publish_target(&root, &manifest, &config)? else {
        if json {
            println!(
                "{}",
                serde_json::json!({"state":"unavailable","reason":"no explicit or configured publication target","next":"configure closure.default_remote and closure.default_ref or a branch upstream"})
            );
        } else {
            println!("Remote parity: UNAVAILABLE\n  no explicit or configured publication target\nNo push or deploy performed.");
        }
        return Ok(1);
    };
    let coherence = closure::verify_commit_coherence(&root, closure_record)?;
    if !verify {
        let cached = closure::load_parity_cache(&root).filter(|p| {
            p.change == change && p.remote == target.remote && p.reference == target.reference
        });
        if json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "change": change,
                "remote": target.remote,
                "ref": target.reference,
                "commit_coherence": {"coherent": coherence.coherent, "head": coherence.head, "blockers": coherence.blockers},
                "last_observation": cached,
                "next": if coherence.coherent { "mpd publish --verify" } else { "commit the exact archived result" }
            })).unwrap());
        } else {
            println!(
                "Publish readiness: {}",
                if coherence.coherent {
                    "READY"
                } else {
                    "BLOCKED"
                }
            );
            println!(
                "  target: {}/{}",
                harness::terminal_safe(&target.remote),
                harness::terminal_safe(&target.reference)
            );
            for blocker in &coherence.blockers {
                println!("  - {blocker}");
            }
            if let Some(cached) = cached {
                println!(
                    "  last observation: {} at {}",
                    cached.state.label(),
                    cached.observed_at_epoch_secs
                );
            }
            println!("No push or deploy performed.");
            println!(
                "\n→ next: {}",
                if coherence.coherent {
                    "mpd publish --verify"
                } else {
                    "commit the exact archived result"
                }
            );
        }
        return Ok(if coherence.coherent { 0 } else { 1 });
    }
    if !coherence.coherent {
        return Err(format!(
            "closure commit is not coherent: {}",
            coherence.blockers.join("; ")
        ));
    }
    match closure::verify_remote_parity(
        &root,
        &change,
        &target,
        closure_record,
        config.remote_timeout_secs(),
    ) {
        Ok(observation) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&observation).unwrap());
            } else {
                println!(
                    "Remote parity: {}",
                    observation.state.label().to_ascii_uppercase()
                );
                println!("  local:  {}", observation.local_oid);
                println!(
                    "  remote: {}",
                    observation.remote_oid.as_deref().unwrap_or("(missing)")
                );
                println!("No push or deploy performed.");
            }
            if observation.state == closure::ParityState::Verified {
                // The closure is complete. Remove only its ignored transaction
                // metadata; committed repository bytes remain untouched. A
                // prior successful `publish --verify` may have already
                // cleaned this up (the pending closure is gone) — re-running
                // verification is idempotent, not an error, so only clean up
                // when a pending closure still exists.
                if openspec_core::inspect(&root)
                    .map_err(|e| e.to_string())?
                    .is_some()
                {
                    openspec_core::abandon_apply(&root).map_err(|e| e.to_string())?;
                }
                Ok(0)
            } else {
                Ok(1)
            }
        }
        Err(e) if e.contains("offline") || e.contains("remote observation failed") => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"state":"offline","error":"remote observation failed","next":"retry mpd publish --verify when connectivity is restored"})
                );
            } else {
                println!("Remote parity: OFFLINE\n  remote observation failed; local evidence remains intact.\nNo push or deploy performed.");
            }
            Ok(1)
        }
        Err(e) => Err(e),
    }
}

/// A repository-relative, `/`-separated path, validated against `root`. Used
/// to translate `Project`/`Config` filesystem paths into the
/// `openspec_core::transaction::RelativePath` the archive-transaction
/// executor operates on.
fn relative_to_root(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| format!("{} is not inside the project root", path.display()))?;
    let s = rel
        .to_str()
        .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))?;
    Ok(s.replace('\\', "/"))
}

/// A stable, lowercase-kebab label for a transaction stage — matches its
/// serde wire tag so text and JSON never disagree on vocabulary.
fn stage_label(stage: openspec_core::TransactionState) -> &'static str {
    use openspec_core::TransactionState::*;
    match stage {
        Preparing => "preparing",
        Prepared => "prepared",
        Applying => "applying",
        Renaming => "renaming",
        RecordingClosure => "recording-closure",
        AwaitingCommit => "awaiting-commit",
    }
}

fn stepclass_label(class: openspec_core::StepClass) -> &'static str {
    use openspec_core::StepClass::*;
    match class {
        AlreadyComplete => "DONE   ",
        Pending => "PENDING",
        ThirdState => "BLOCKED",
    }
}

/// Render a [`openspec_core::TransactionView`] in the shared human/JSON form
/// `mpd closure recover` and `mpd closure abandon` both use for their
/// preview.
fn render_transaction_view(view: &openspec_core::TransactionView, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(view).unwrap());
        return;
    }
    println!("Pending closure: {}", view.change);
    println!("  transaction: {}", view.transaction_id.to_hex());
    println!("  stage:       {}", stage_label(view.stage));
    println!(
        "  affected paths: {}{}",
        view.affected_path_count,
        if view.truncated {
            " (list truncated below)"
        } else {
            ""
        }
    );
    for c in &view.classifications {
        println!("  [{}] {}: {}", stepclass_label(c.class), c.path, c.detail);
    }
    println!("  write eligible: {}", view.write_eligible);
    if !view.blockers.is_empty() {
        println!("  blockers:");
        for b in &view.blockers {
            println!("    - {b}");
        }
    }
    println!("  {}", view.durability_note);
    println!("\n→ next: {}", view.next);
}

fn cmd_closure(command: ClosureCommand) -> CmdResult {
    let root = find_root()?;
    match command {
        ClosureCommand::Recover { yes, json } => cmd_closure_recover(&root, yes, json),
        ClosureCommand::Abandon { yes, json } => cmd_closure_abandon(&root, yes, json),
    }
}

fn closure_preview(root: &Path, json: bool) -> CmdResult {
    match openspec_core::inspect(root).map_err(|e| e.to_string())? {
        None => {
            if json {
                println!("{}", serde_json::json!({"pending": false}));
            } else {
                println!("No pending closure.");
            }
            Ok(0)
        }
        Some(view) => {
            render_transaction_view(&view, json);
            Ok(0)
        }
    }
}

fn cmd_closure_recover(root: &Path, yes: bool, json: bool) -> CmdResult {
    if !yes {
        return closure_preview(root, json);
    }
    match openspec_core::recover_apply(root) {
        Ok(view) => {
            render_transaction_view(&view, json);
            Ok(0)
        }
        Err(e) => {
            eprintln!("Recovery refused: {e}");
            Ok(1)
        }
    }
}

fn cmd_closure_abandon(root: &Path, yes: bool, json: bool) -> CmdResult {
    if !yes {
        return closure_preview(root, json);
    }
    match openspec_core::abandon_apply(root) {
        Ok(()) => {
            if json {
                println!("{}", serde_json::json!({"abandoned": true}));
            } else {
                println!(
                    "Abandoned the pending closure (removed only its own ignored metadata; \
                     repository targets are untouched)."
                );
            }
            Ok(0)
        }
        Err(e) => {
            eprintln!("Abandon refused: {e}");
            Ok(1)
        }
    }
}

fn cmd_archive(change: Option<String>, skip_specs: bool, yes: bool) -> CmdResult {
    let root = find_root()?;

    // A pending closure from a prior interrupted archive (of this or another
    // change) must be resolved before starting a new one — see
    // archive-transaction.md "Pending closure remains discoverable... begin/
    // another archive refuse."
    if let Some(view) = openspec_core::inspect(&root).map_err(|e| e.to_string())? {
        eprintln!(
            "Cannot archive — a closure for {:?} is already pending (stage: {}).",
            view.change,
            stage_label(view.stage)
        );
        eprintln!("Run `mpd closure recover` or `mpd closure abandon` first.");
        return Ok(1);
    }

    let change = resolve_change(&root, change)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;

    // Irreversibility guard: never archive over an unmet gate or open condition.
    let reasons = ledger.blocking_reasons();
    if !reasons.is_empty() {
        eprintln!("Cannot archive {change:?} — unmet gates/conditions:");
        for r in &reasons {
            eprintln!("  - {r}");
        }
        return Ok(1);
    }

    let project = Project::new(&root);
    let manifest = closure::load_manifest(&root, &change).map_err(|e| e.to_string())?;
    let manifest_check = manifest_view(&root, &change);
    if manifest_check.state != "ready" {
        eprintln!(
            "Cannot archive {change:?} — change manifest is {}:",
            manifest_check.state
        );
        for reason in &manifest_check.blockers {
            eprintln!("  - {reason}");
        }
        return Ok(1);
    }

    // Irreversibility guard #2: never archive a change whose core artifacts are
    // still unfilled template stubs. The Documentation gate already blocks a stub
    // documentation.md; extend the same guarantee to proposal/design/tasks so an
    // empty template can't be folded into the permanent record.
    let stub_issues = artifact_stub_issues(&project, &change);
    if !stub_issues.is_empty() {
        eprintln!("Cannot archive {change:?} — core artifacts are incomplete:");
        for i in &stub_issues {
            eprintln!("  - {i}");
        }
        return Ok(1);
    }

    // Irreversibility guard #3 (strict tier only): the judgment artifacts that
    // passed at gate time must still be present and complete now — a re-check
    // against the exact evaporation this change fixes (design.md Cond 9 / B2).
    // A validly-scoped waiver for an applicable phase is surfaced WAIVED, never
    // blocking. Inert when `strict=false`, so the manual tier is unchanged.
    if ledger.strict {
        let (refusals, waived) = strict_archive_recheck(&root, &change, &ledger);
        for label in &waived {
            println!("  ⚠ WAIVED: {label} judgment artifact (audited, not re-checked).");
        }
        if !refusals.is_empty() {
            eprintln!(
                "Cannot archive {change:?} — judgment artifacts evaporated after their gate:"
            );
            for msg in &refusals {
                eprintln!("  - {msg}");
            }
            return Ok(1);
        }
    }

    // Transient-path pre-flight (design.md Cond 8): an un-gitignored transient
    // `.mpd/` file would be swept into the permanent record. Warn on a dry-run;
    // fail-closed on `--yes`. `mpd doctor --fix` heals exactly this set.
    let uncovered = uncovered_transient_paths(&root);
    if !uncovered.is_empty() {
        eprintln!(
            "Transient .mpd/ path(s) are not covered by .mpd/.gitignore and would be committed:"
        );
        for entry in &uncovered {
            eprintln!("  - .mpd{entry}");
        }
        if yes {
            eprintln!("Refusing to archive. Run `mpd doctor --fix` then re-archive.");
            return Ok(1);
        }
        eprintln!("Warning: run `mpd doctor --fix` before archiving with --yes.");
    }

    let plan = project
        .plan_archive(&change, skip_specs)
        .map_err(|e| e.to_string())?;

    // Documentation fold-in (feature changes only): read the change's
    // documentation.md now, before the transaction moves the change directory.
    // A *symlinked* documentation.md is treated as absent (not followed).
    let doc_src = project.change_dir(&change).join("documentation.md");
    let doc_is_regular = doc_src
        .symlink_metadata()
        .map(|m| m.file_type().is_file())
        .unwrap_or(false);
    let doc_fold: Option<(PathBuf, String)> = if ledger.kind.documents() && doc_is_regular {
        let target = docs_target(&root, Config::load(&root).docs_dir(), &change)?;
        // Catch a pre-planted symlinked docs dir/target now, before anything is
        // moved or written.
        openspec_core::assert_contained(&root, &target).map_err(|e| e.to_string())?;
        openspec_core::assert_contained(&project.root, &doc_src).map_err(|e| e.to_string())?;
        let content = openspec_core::read_capped(&doc_src).map_err(|e| e.to_string())?;
        Some((target, content))
    } else {
        None
    };

    println!("Archive plan for {change:?}:");
    if plan.skip_specs {
        println!("  (spec updates skipped)");
    } else if plan.updates.is_empty() {
        println!("  (no spec deltas)");
    } else {
        for u in &plan.updates {
            let kind = if u.is_new { "NEW " } else { "UPDATE" };
            println!(
                "  {kind} specs/{}/spec.md  (+{} ~{} -{} →{})",
                u.capability, u.stats.added, u.stats.modified, u.stats.removed, u.stats.renamed
            );
        }
    }
    if let Some((target, _)) = &doc_fold {
        println!("  DOC   {}", target.display());
    }
    println!("  → archive to {}", plan.archive_target.display());

    if !yes {
        println!("\nDry run. Re-run with --yes to apply.");
        return Ok(0);
    }

    // ---- Compose every planned postimage into ONE crash-safe transaction ----
    // (archive-transaction.md; design.md "Archive and commit lifecycle").
    let base_commit = git::head_commit(&root)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "cannot archive: HEAD has no commit yet (unborn branch)".to_string())?;

    let mut writes: Vec<openspec_core::TargetWrite> = Vec::new();
    let mut contents: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for u in &plan.updates {
        let target = relative_to_root(&root, &u.target_path)?;
        let bytes = u.content.clone().into_bytes();
        contents.insert(target.clone(), bytes.clone());
        writes.push(openspec_core::TargetWrite { target, bytes });
    }
    if let Some((target_path, content)) = &doc_fold {
        let target = relative_to_root(&root, target_path)?;
        let bytes = content.clone().into_bytes();
        contents.insert(target.clone(), bytes.clone());
        writes.push(openspec_core::TargetWrite { target, bytes });
    }

    let archive_target_rel = relative_to_root(&root, &plan.archive_target)?;
    let change_dir_rel = relative_to_root(&root, &project.change_dir(&change))?;
    let ledger_path_rel = relative_to_root(&root, &ledger::state_path(&root, &change))?;
    let system = closure::SystemScope {
        change_dir: change_dir_rel.clone(),
        ledger_path: ledger_path_rel.clone(),
        merged_spec_targets: plan
            .updates
            .iter()
            .map(|u| relative_to_root(&root, &u.target_path))
            .collect::<Result<Vec<_>, _>>()?,
        doc_target: doc_fold
            .as_ref()
            .map(|(p, _)| relative_to_root(&root, p))
            .transpose()?,
        archive_target: archive_target_rel.clone(),
    };
    let mut closure_scope = manifest.paths.clone();
    closure_scope.extend(manifest.shared_paths.clone());
    closure_scope.extend(system.paths());
    closure_scope.sort();
    closure_scope.dedup();
    // Freeze the declared (possibly glob) scope into a concrete snapshot now,
    // before the transaction mutates anything — the pending closure's own
    // protected scope (`ArchiveClosure::system_paths`); never re-resolved
    // after this point.
    let mut declared_patterns = manifest.paths.clone();
    declared_patterns.extend(manifest.shared_paths.clone());
    let scope_snapshot =
        closure::resolve_scope_snapshot(&root, &declared_patterns, &system.paths())?;
    let final_scoped_digest = closure::planned_archive_digest(
        &root,
        &closure_scope,
        &change_dir_rel,
        &archive_target_rel,
        &contents,
    )?;
    let final_scoped_digest_oc =
        openspec_core::digest::Digest::from_hex(&final_scoped_digest.to_hex())
            .expect("mpd Digest hex always parses as an openspec_core Digest");

    // The closure record itself can only be built once the transaction id is
    // known. The already-executed Deploy gate is preserved; archive never
    // invents or duplicates deployment evidence.
    let archived_at = ledger::now_epoch_secs();

    let ledger_bytes_out: std::cell::RefCell<Option<Vec<u8>>> = std::cell::RefCell::new(None);
    let plan_txn = openspec_core::build_plan(
        &root,
        &change,
        base_commit.clone(),
        writes,
        openspec_core::DirectoryMoveInput {
            source: change_dir_rel,
            destination: archive_target_rel.clone(),
        },
        final_scoped_digest_oc,
        |transaction_id| {
            let mut lg = ledger.clone();
            lg.archive_closure = Some(ArchiveClosure {
                base_commit: base_commit.clone(),
                archive_path: archive_target_rel.clone(),
                transaction_id: digest::Digest::from_hex(&transaction_id.to_hex())
                    .expect("openspec_core Digest hex always parses as an mpd Digest"),
                allowed_paths: closure_scope.clone(),
                system_paths: scope_snapshot.clone(),
                post_archive_digest: final_scoped_digest,
                archived_at,
            });
            let mut bytes = serde_json::to_string_pretty(&lg)
                .expect("ledger always serializes")
                .into_bytes();
            bytes.push(b'\n');
            *ledger_bytes_out.borrow_mut() = Some(bytes.clone());
            openspec_core::TargetWrite {
                target: ledger_path_rel.clone(),
                bytes,
            }
        },
    )
    .map_err(|e| e.to_string())?;
    contents.insert(
        ledger_path_rel,
        ledger_bytes_out
            .into_inner()
            .expect("the closure_ledger callback always runs inside build_plan"),
    );

    openspec_core::prepare(&root, &plan_txn, &contents).map_err(|e| e.to_string())?;
    match openspec_core::drive(&root).map_err(|e| e.to_string())? {
        openspec_core::DriveOutcome::AwaitingCommit => {}
        openspec_core::DriveOutcome::NothingPending => {
            return Err("internal error: transaction vanished immediately after prepare".into());
        }
        openspec_core::DriveOutcome::ManualRecoveryRequired { path, detail } => {
            eprintln!(
                "Archive stopped: {path} is in an unexpected state ({detail}). \
                 No further write was performed. Run `mpd closure recover` to inspect it."
            );
            return Ok(1);
        }
    }

    // Housekeeping outside the transaction: clear the "current change"
    // pointer (a convenience cache, not a repository target) so `mpd status`
    // stops pointing at an archived change.
    if ledger::current(&root).as_deref() == Some(change.as_str()) {
        let _ = std::fs::remove_file(ledger::current_path(&root));
    }

    println!("\nArchived {change:?} to {archive_target_rel}.");
    println!(
        "Closure is AwaitingCommit — preimages were not retained, and this stage is not claimed \
         atomic beyond what the filesystem actually provided."
    );
    println!(
        "→ next: commit the archived result, then run `mpd closure abandon --yes` \
         once the commit is in (or `mpd publish --verify` once available)."
    );
    Ok(0)
}

/// `mpd use <change>` — set `.mpd/current` to an existing change (design.md D5,
/// Cond 6). Recovers a cleared pointer (the archive/abandon housekeeping removes
/// `.mpd/current`) without re-running `begin`. The argument becomes a path
/// component in `set_current`, so it is `validate_change_name`-checked AND the
/// change's ledger must already exist before we trust it.
fn cmd_use(change: String) -> CmdResult {
    let root = find_root()?;
    openspec_core::validate_change_name(&change)?;
    if !ledger::state_path(&root, &change).is_file() {
        return Err(format!(
            "no ledger for change {change:?}; run `mpd begin {change}` first"
        ));
    }
    ledger::set_current(&root, &change).map_err(|e| e.to_string())?;
    println!("Current change set to {change:?}.");
    Ok(0)
}

/// Add-only heal of `.mpd/.gitignore` so it covers exactly the transient set the
/// archive pre-flight demands ([`scaffold::TRANSIENT_GITIGNORE_ENTRIES`], the
/// single source of truth), returning the entries appended (empty ⇒ already
/// complete). Fail-closed (design.md Cond 7): the existing file is read via
/// `read_capped` (symlink-refusing + size-capped), so a symlinked/oversized
/// `.gitignore` is a hard refusal — never followed, never overwritten. Immediately
/// before writing we re-run `assert_contained` (the double-check in
/// `Config::save`/`write_new`). The append preserves every existing line, forces a
/// newline boundary so we never fuse onto a trailing partial line, and writes ONLY
/// `.mpd/.gitignore` — never the project-root `.gitignore`, never a delete/truncate.
fn fix_gitignore(root: &Path) -> Result<Vec<&'static str>, String> {
    let path = ledger::mpd_dir(root).join(".gitignore");
    // F1: contain BEFORE any read. `read_capped`/`symlink_metadata` lstat only
    // the final component, so an intermediate `.mpd/` symlink would otherwise be
    // followed and read through; refuse (fail-closed) if the path escapes root.
    openspec_core::assert_contained(root, &path)
        .map_err(|e| format!("refusing to heal .mpd/.gitignore (fail-closed): {e}"))?;
    // If the path exists in ANY form, `read_capped` decides: a symlink or an
    // oversized file becomes a hard error (fail-closed, no write). Only a truly
    // absent file reads as empty and is created fresh.
    let existing = match path.symlink_metadata() {
        Ok(_) => openspec_core::read_capped(&path)
            .map_err(|e| format!("refusing to heal .mpd/.gitignore (fail-closed): {e}"))?,
        Err(_) => String::new(),
    };
    let present: std::collections::BTreeSet<&str> = existing.lines().map(|l| l.trim()).collect();
    let missing: Vec<&'static str> = scaffold::TRANSIENT_GITIGNORE_ENTRIES
        .iter()
        .copied()
        .filter(|entry| !present.contains(entry))
        .collect();
    if missing.is_empty() {
        return Ok(missing); // idempotent: nothing to add.
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for entry in &missing {
        out.push_str(entry);
        out.push('\n');
    }
    // F2: re-assert containment IMMEDIATELY before the write (after
    // create_dir_all) — the double-check pattern in `Config::save`/`write_new`,
    // catching a symlink planted between the read and the write (TOCTOU).
    openspec_core::assert_contained(root, &path).map_err(|e| e.to_string())?;
    std::fs::write(&path, out).map_err(|e| e.to_string())?;
    Ok(missing)
}

/// `mpd doctor --fix`: the gitignore heal (design.md Cond 7). Requires a project
/// root; reports exactly what it appended. All the read-only diagnostics stay on
/// the bare-`doctor` report — `--fix` performs only the one add-only write.
fn cmd_doctor_fix(root: Option<&Path>) -> CmdResult {
    let root = root.ok_or_else(|| "no openspec/ project found (run `mpd init`)".to_string())?;
    let healed = fix_gitignore(root)?;
    if healed.is_empty() {
        println!(
            "mpd doctor --fix: .mpd/.gitignore already covers every transient path (no change)."
        );
    } else {
        println!(
            "mpd doctor --fix: appended {} missing entr{} to .mpd/.gitignore:",
            healed.len(),
            if healed.len() == 1 { "y" } else { "ies" }
        );
        for entry in &healed {
            println!("  + .mpd{entry}");
        }
    }
    Ok(0)
}

/// A read-only sanity verdict on the configured test command: flags the classic
/// no-op stubs (`true`, `:`, empty) that exit 0 without running a test, so the
/// Build/Test gate would pass with no verifiable pass count. NEVER runs the
/// command and NEVER mutates config.json (design.md Cond 7). `None` ⇒ nothing to
/// flag (a real-looking command, or an unset one the report already surfaces).
fn test_command_sanity(test_cmd: Option<&str>) -> Option<String> {
    let trimmed = test_cmd?.trim();
    if trimmed.is_empty() {
        return Some("empty — exits with no test run (no verifiable pass count)".to_string());
    }
    // The first shell word decides. `:` and `true` (bare or absolute path) are
    // the always-succeed no-ops that emit no parseable pass count.
    let first = trimmed.split_whitespace().next().unwrap_or("");
    let base = first.rsplit('/').next().unwrap_or(first);
    if first == ":" || base == "true" {
        return Some(format!(
            "`{}` is a no-op that always exits 0 without running tests (no verifiable pass count)",
            harness::terminal_safe(trimmed)
        ));
    }
    None
}

/// The current phase and how long it has sat there, from the current change's
/// `phase_started_at_epoch_secs`. Read-only; `None` when there is no current
/// change, no loadable ledger, or an unseeded timestamp.
fn phase_stall(root: Option<&Path>) -> Option<(Phase, u64)> {
    let root = root?;
    let change = ledger::current(root)?;
    let led = ledger::load(root, &change).ok()?;
    let started = led.phase_started_at_epoch_secs;
    if started == 0 {
        return None;
    }
    Some((led.phase, ledger::now_epoch_secs().saturating_sub(started)))
}

/// Render a coarse elapsed-seconds duration for the human `doctor` report.
fn humanize_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3600)
    }
}

fn cmd_doctor(json: bool, fix: bool) -> CmdResult {
    let root = find_root().ok();
    if fix {
        // `--fix` performs the one add-only gitignore write and reports it; the
        // read-only diagnostics belong to the bare report below.
        return cmd_doctor_fix(root.as_deref());
    }
    let git = root
        .as_ref()
        .map(|r| githooks::is_git_repo(r))
        .unwrap_or(false);
    let hook = root
        .as_ref()
        .map(|r| githooks::is_installed(r))
        .unwrap_or(false);
    let gitleaks = checks::tool_available("gitleaks");
    let semgrep = checks::tool_available("semgrep");
    let test_cmd = root.as_ref().map(|r| Config::load(r).test).unwrap_or(None);
    let deploy_cmd = root
        .as_ref()
        .map(|r| Config::load(r).deploy)
        .unwrap_or(None);
    let allow_entries = root.as_ref().map_or(0, |r| {
        let al = crate::allowlist::Allowlist::load(r);
        al.paths.len() + al.allow.len()
    });
    let current = root.as_ref().and_then(|r| ledger::current(r));
    let schema_ok = root
        .as_ref()
        .map(|r| r.join("openspec/schemas/mpd/schema.yaml").is_file())
        .unwrap_or(false);
    let directives_ok = root
        .as_ref()
        .map(|r| crate::directives::is_installed(r))
        .unwrap_or(false);
    let pending_closure = root
        .as_ref()
        .and_then(|r| openspec_core::inspect(r).ok().flatten());
    let hermetic_reuse = root
        .as_ref()
        .and_then(|r| Config::load(r).hermetic_reuse_policy().cloned())
        .map(|p| p.is_complete())
        .unwrap_or(false);
    let closure_cfg = root.as_ref().map(|r| Config::load(r));
    let closure_default_remote = closure_cfg
        .as_ref()
        .and_then(|c| c.closure.as_ref())
        .and_then(|c| c.default_remote.clone());
    let closure_default_ref = closure_cfg
        .as_ref()
        .and_then(|c| c.closure.as_ref())
        .and_then(|c| c.default_ref.clone());
    let closure_timeout_secs = closure_cfg.as_ref().map(|c| c.remote_timeout_secs());
    let closure_path_limit = closure_cfg.as_ref().map(|c| c.human_path_list_limit());
    // Read-only diagnostics (design.md Cond 7): neither mutates config.json.
    let test_sanity = test_command_sanity(test_cmd.as_deref());
    let stall = phase_stall(root.as_deref());

    if json {
        let v = serde_json::json!({
            "project_root": root.as_ref().map(|r| r.display().to_string()),
            "openspec_present": root.is_some(),
            "mpd_schema_installed": schema_ok,
            "directives_installed": directives_ok,
            "git_repo": git,
            "pre_commit_hook": hook,
            "secret_scanner_floor": "builtin",
            "gitleaks": gitleaks,
            "semgrep": semgrep,
            "test_command": test_cmd,
            "deploy_command": deploy_cmd,
            "allowlist_entries": allow_entries,
            "current_change": current,
            "pending_closure": pending_closure.as_ref().map(|v| serde_json::json!({"change":v.change,"stage":stage_label(v.stage),"write_eligible":v.write_eligible})),
            "hermetic_reuse_configured": hermetic_reuse,
            "test_command_sanity": test_sanity,
            "phase_stall": stall.map(|(phase, age)| serde_json::json!({
                "phase": phase.slug(),
                "age_secs": age,
            })),
            "closure": {
                "default_remote": closure_default_remote,
                "default_ref": closure_default_ref,
                "remote_timeout_secs": closure_timeout_secs,
                "human_path_list_limit": closure_path_limit,
            },
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(0);
    }

    let yn = |b: bool| if b { "yes" } else { "no" };
    println!("mpd doctor");
    match &root {
        Some(r) => println!("  project root:        {}", r.display()),
        None => println!("  project root:        (none — run `mpd init`)"),
    }
    println!("  mpd schema:          {}", yn(schema_ok));
    println!("  directives:          {}", yn(directives_ok));
    println!("  git repo:            {}", yn(git));
    println!("  pre-commit gate:     {}", yn(hook));
    println!("  secret scanner:      builtin (always-on floor)");
    println!("  gitleaks available:  {}", yn(gitleaks));
    println!("  semgrep available:   {}", yn(semgrep));
    println!(
        "  test command:        {}",
        test_cmd
            .as_deref()
            .unwrap_or("(unset — Build/Test gates will refuse)")
    );
    println!(
        "  test cmd sanity:     {}",
        match (test_cmd.as_deref(), &test_sanity) {
            (None, _) => "(no command configured)".to_string(),
            (Some(_), Some(warn)) => format!("warning: {warn}"),
            (Some(_), None) => "ok".to_string(),
        }
    );
    println!(
        "  deploy command:      {}",
        deploy_cmd
            .as_deref()
            .unwrap_or("(unset — Deploy gate records readiness only)")
    );
    println!(
        "  secret allowlist:    {allow_entries} entr{}",
        if allow_entries == 1 { "y" } else { "ies" }
    );
    println!(
        "  current change:      {}",
        current.as_deref().unwrap_or("(none)")
    );
    println!(
        "  phase stall age:     {}",
        match &stall {
            Some((phase, age)) => format!("{} for {}", phase.slug(), humanize_secs(*age)),
            None => "(no current change)".to_string(),
        }
    );
    println!(
        "  pending closure:     {}",
        pending_closure
            .as_ref()
            .map(|v| format!("{} ({})", v.change, stage_label(v.stage)))
            .unwrap_or_else(|| "(none)".to_string())
    );
    println!("  hermetic reuse:      {}", yn(hermetic_reuse));
    println!(
        "  closure remote/ref:  {}",
        match (&closure_default_remote, &closure_default_ref) {
            (Some(r), Some(f)) => format!(
                "{} / {}",
                harness::terminal_safe(r),
                harness::terminal_safe(f)
            ),
            _ => "(unset — falls back to the current branch's upstream)".to_string(),
        }
    );
    println!(
        "  remote timeout:      {}s",
        closure_timeout_secs.unwrap_or(15)
    );
    println!(
        "  path list limit:     {}",
        closure_path_limit.unwrap_or(50)
    );
    if !hook && git {
        println!("\n  Tip: re-run `mpd init` to install the pre-commit gate.");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{
        check_documentation, check_sections, extract_section, has_unfilled_placeholder,
        strict_gate_command, upstream_artifact_pointers, validate_evidence, REQUIRED_DOC_SECTIONS,
    };
    use crate::phase::{Applicability, Phase};
    use proptest::prelude::*;

    #[test]
    fn extract_section_captures_body_to_next_h2_and_is_bounded() {
        let text = "# Design\n\n## Context\nsome context\n\n\
                    ## Conditions for Builder\n1. first invariant\n### sub\nstill inside\n\n\
                    ## Risks\nnot included\n";
        let block = extract_section(text, "Conditions for Builder", 4000).unwrap();
        assert!(block.contains("1. first invariant"), "body: {block}");
        assert!(
            block.contains("still inside"),
            "a deeper ### subheading stays inside the section: {block}"
        );
        assert!(
            !block.contains("not included"),
            "the next ## heading ends the section: {block}"
        );
        // Case-insensitive prefix match, like check_sections.
        assert!(extract_section(text, "conditions", 4000).is_some());
        // Absent section → None; present-but-empty → None.
        assert!(extract_section(text, "Nonexistent", 4000).is_none());
        assert!(extract_section("## Empty\n\n## Next\nx", "Empty", 4000).is_none());
        // Length bound adds an ellipsis and never splits a char boundary.
        let long = format!("## S\n{}\n", "x".repeat(50));
        let bounded = extract_section(&long, "S", 10).unwrap();
        assert!(bounded.ends_with('…') && bounded.len() <= 10 + '…'.len_utf8());
        // Terminal control sequences are stripped (Cond 11).
        let evil = "## S\nsafe\u{1b}]8;;evil\u{7}tail\n";
        let cleaned = extract_section(evil, "S", 4000).unwrap();
        assert!(
            !cleaned.contains('\u{1b}') && !cleaned.contains('\u{7}'),
            "control chars must be stripped: {cleaned:?}"
        );
        assert!(cleaned.contains("safe") && cleaned.contains("tail"));
    }

    #[test]
    fn strict_gate_command_uses_own_artifact_or_bare_pass() {
        assert_eq!(
            strict_gate_command(Phase::SecurityCode),
            "mpd gate security-code --pass --evidence security-code.md"
        );
        // A non-judgment phase has no artifact to record.
        assert_eq!(strict_gate_command(Phase::Build), "mpd gate build --pass");
    }

    #[test]
    fn upstream_pointers_resolve_artifacts_and_honor_applicability() {
        // Security (code) reads the plan; the pointer is security-plan.md.
        let ptrs = upstream_artifact_pointers(
            Phase::SecurityCode,
            Applicability {
                ui: false,
                docs: false,
            },
        );
        assert_eq!(ptrs, vec![("Security (plan)", "security-plan.md")]);
        // Design Sign-off's upstream is DesignMock (no judgment artifact →
        // skipped) and Design Review (design-review.md). With ui=false BOTH are
        // inapplicable design phases, so nothing resolves; with ui=true only the
        // Design Review artifact shows (DesignMock has none).
        let no_ui = upstream_artifact_pointers(
            Phase::DesignSignoff,
            Applicability {
                ui: false,
                docs: false,
            },
        );
        assert!(no_ui.is_empty(), "design phases excluded when ui=false");
        let with_ui = upstream_artifact_pointers(
            Phase::DesignSignoff,
            Applicability {
                ui: true,
                docs: false,
            },
        );
        assert_eq!(with_ui, vec![("Design Review", "design-review.md")]);
    }

    #[test]
    fn check_documentation_wraps_check_sections_identically() {
        // check_documentation is now a thin wrapper over check_sections with the
        // doc sections + a 120-char floor; the two MUST agree on every input, so
        // the refactor is byte-identical to today (Cond 3).
        let long = format!(
            "## Purpose\n## Value\n## Scope\n## Functional details\n## Usage\n{}",
            "content ".repeat(40)
        );
        let samples = [
            "".to_string(),
            "## Purpose\nx".to_string(),
            "# Doc\n\n## Purpose\nThe why.\n## Value\nWorth it.".to_string(),
            "## Purpose\n## Value\n## Scope\n## Functional\n## Usage\n".to_string(),
            long,
        ];
        for s in &samples {
            assert_eq!(
                check_documentation(s),
                check_sections(s, REQUIRED_DOC_SECTIONS, 120),
                "wrapper diverged from check_sections on {s:?}"
            );
        }
        // Load-bearing: the wrapper still flags a missing section and short body.
        let issues = check_documentation("## Purpose\nshort");
        assert!(issues.iter().any(|i| i == "missing section: Value"));
        assert!(issues.iter().any(|i| i.contains("too short")));
        // And check_sections honors an arbitrary min_len (parameter is real).
        assert!(check_sections("## A\nx", &["A"], 1).is_empty());
        assert!(check_sections("## A\nx", &["A"], 500)
            .iter()
            .any(|i| i.contains("too short")));
        // The section match is a case-insensitive `##`-level prefix.
        assert!(check_sections("## purpose and scope\ncontent", &["Purpose"], 1).is_empty());
        assert!(!check_sections("# Purpose\ncontent", &["Purpose"], 1).is_empty());
    }

    #[test]
    fn placeholder_detection_ignores_inline_code_mentions() {
        // Genuine unfilled placeholders (outside inline code) are detected,
        // whether standalone or after a markdown marker.
        assert!(has_unfilled_placeholder(
            "# Title\n\n<!-- The problem this solves. -->\n"
        ));
        assert!(has_unfilled_placeholder(
            "- [ ] 1.1 <!-- Task description -->\n"
        ));
        // A doc that only *describes* the `<!--` convention inside inline code
        // (as this change's own design/proposal do) is NOT a stub — the bug the
        // dogfooding of this very change surfaced.
        assert!(!has_unfilled_placeholder(
            "The check rejects `<!--` placeholders, e.g. the `<!-- ... -->` stub, when unfilled.\n"
        ));
        // A fully-authored doc has none.
        assert!(!has_unfilled_placeholder(
            "# Real\n\nAll content here, no comments.\n"
        ));
    }

    /// Build a read-only evidence-validation fixture under the OS temp dir: a
    /// change dir carrying the phase's own artifact (`security-code.md`), a real
    /// non-artifact in-tree file (`proposal.md`), and an out-of-tree secret
    /// (`secret.md`). Idempotent (safe to call per proptest case); each caller
    /// passes a distinct `tag` so concurrently-run tests never share a directory.
    fn evidence_fixture(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("mpd-prop-ev-{}-{tag}", std::process::id()));
        let change_dir = root.join("openspec/changes/guarded");
        std::fs::create_dir_all(&change_dir).unwrap();
        std::fs::write(change_dir.join("security-code.md"), "authored findings\n").unwrap();
        std::fs::write(change_dir.join("proposal.md"), "not the artifact\n").unwrap();
        std::fs::write(root.join("secret.md"), "TOP-SECRET-CANARY\n").unwrap();
        root
    }

    #[test]
    fn validate_evidence_refuses_escape_absolute_and_basename_alias() {
        // Cond 2 escape vectors the e2e R3 test does not cover: a same-basename
        // file in a subdir must not alias; a `..` traversal to an out-of-tree
        // secret is refused with no content leak; an absolute path is rejected
        // before the join; the exact own artifact (optionally anchored) is
        // accepted verbatim.
        let root = evidence_fixture("concrete");
        let cd = root.join("openspec/changes/guarded");
        std::fs::create_dir_all(cd.join("subdir")).unwrap();
        std::fs::write(cd.join("subdir/security-code.md"), "planted alias\n").unwrap();

        let alias = validate_evidence(
            &root,
            "guarded",
            Phase::SecurityCode,
            Some("subdir/security-code.md".to_string()),
        );
        assert!(
            alias.is_err(),
            "a same-basename file in a subdir must not alias the own artifact: {alias:?}"
        );

        let escape = validate_evidence(
            &root,
            "guarded",
            Phase::SecurityCode,
            Some("../../../secret.md".to_string()),
        );
        assert!(
            escape.is_err(),
            "a traversal escape must be refused: {escape:?}"
        );
        assert!(
            !format!("{escape:?}").contains("TOP-SECRET"),
            "evidence validation must never surface out-of-tree content: {escape:?}"
        );

        let abs = validate_evidence(
            &root,
            "guarded",
            Phase::SecurityCode,
            Some(root.join("secret.md").display().to_string()),
        );
        assert!(
            abs.is_err(),
            "an absolute evidence path must be refused: {abs:?}"
        );

        let ok = validate_evidence(
            &root,
            "guarded",
            Phase::SecurityCode,
            Some("security-code.md#Findings".to_string()),
        );
        assert_eq!(
            ok.expect("own artifact accepted").expect("Some pointer"),
            "security-code.md#Findings",
            "the own artifact (anchor stripped for resolution) is recorded verbatim"
        );
    }

    proptest! {
        /// Fuzz `validate_evidence` for a judgment phase over path-shaped inputs
        /// assembled from adversarial components (`..`, `.`, the own artifact, a
        /// sibling non-artifact, an out-of-tree secret, a subdir, random names,
        /// plus an optional `#anchor`) — so the accept, alias, and traversal-
        /// escape branches are all genuinely exercised, not left to chance. Every
        /// input is EITHER rejected (Err) OR accepted as the RAW input verbatim,
        /// and an accepted pointer always resolves (post-`#`-strip, post-join) to
        /// the phase's OWN in-tree artifact and nothing else — so it can never
        /// alias `proposal.md`/`subdir/security-code.md`, never reach
        /// `../secret.md`, and never returns Ok(None) for a present pointer. The
        /// returned value being the input itself proves no file content is ever
        /// read into the result (Cond 2). It never panics.
        #[test]
        fn validate_evidence_only_ever_accepts_the_own_artifact(
            parts in prop::collection::vec(
                prop_oneof![
                    Just("security-code.md".to_string()),
                    Just("proposal.md".to_string()),
                    Just("secret.md".to_string()),
                    Just("subdir".to_string()),
                    Just("..".to_string()),
                    Just(".".to_string()),
                    "[A-Za-z0-9]{1,6}",
                ],
                0..6,
            ),
            anchor in prop::option::of("#[A-Za-z]{0,6}"),
        ) {
            let ev = format!("{}{}", parts.join("/"), anchor.unwrap_or_default());
            let root = evidence_fixture("prop");
            let change_dir = root.join("openspec/changes/guarded");
            // A planted same-basename file in a subdir must not alias the artifact.
            std::fs::create_dir_all(change_dir.join("subdir")).unwrap();
            std::fs::write(change_dir.join("subdir/security-code.md"), "planted\n").unwrap();
            let own = change_dir.join("security-code.md");
            match validate_evidence(&root, "guarded", Phase::SecurityCode, Some(ev.clone())) {
                Err(_) => {}
                Ok(None) => prop_assert!(false, "a present pointer must never yield Ok(None)"),
                Ok(Some(v)) => {
                    prop_assert_eq!(&v, &ev, "an accepted pointer is the raw input, unread");
                    let stripped = ev.split('#').next().unwrap_or("").trim();
                    prop_assert_eq!(
                        change_dir.join(stripped),
                        own.clone(),
                        "only the phase's own in-tree artifact is ever accepted"
                    );
                }
            }
        }

        /// Fuzz `check_sections`: it never panics on arbitrary text / section
        /// lists / floors and reports at most one issue per section plus the two
        /// global issues (placeholder + too-short). Metamorphic (min_len 0
        /// isolates heading logic): a heading-free body reports its section
        /// missing, and prepending that section's `##` heading clears exactly
        /// that issue — detection is driven by a matching `##` heading, nothing
        /// else.
        #[test]
        fn check_sections_never_panics_and_detects_by_heading(
            section in "[A-Za-z][A-Za-z0-9]{0,15}",
            body in ".{0,300}",
            others in prop::collection::vec("[A-Za-z ]{0,10}", 0..4),
            min_len in 0usize..300,
        ) {
            let mut sections: Vec<&str> = others.iter().map(String::as_str).collect();
            sections.push(section.as_str());
            let issues = check_sections(&body, &sections, min_len);
            prop_assert!(
                issues.len() <= sections.len() + 2,
                "at most one issue per section plus placeholder + too-short"
            );

            // A body with every '#' neutralized carries no `##` heading.
            let clean = body.replace('#', "x");
            let want = format!("missing section: {section}");
            prop_assert!(
                check_sections(&clean, &[section.as_str()], 0).contains(&want),
                "a heading-free body must report the section missing"
            );
            let with = format!("## {section}\n{clean}");
            prop_assert!(
                !check_sections(&with, &[section.as_str()], 0).contains(&want),
                "prepending the section's `##` heading clears the missing-issue"
            );
        }

        /// Fuzz `extract_section`: the document is BUILT to contain the section
        /// (independent random text almost never matches a `##` heading, which
        /// would leave the bounded render path unexercised), with a possibly
        /// hostile single-line body that may carry control/escape bytes and run
        /// far past the cap. Whatever the body and cap, the render is bounded
        /// (≤ cap + one ellipsis), terminal-safe (no control chars beyond
        /// `\n`/`\t`), and never empty when `Some` — a hostile design.md can
        /// neither flood a terminal nor smuggle an escape sequence through the
        /// `--context` slice (Cond 11). It never panics.
        #[test]
        fn extract_section_output_is_bounded_and_terminal_safe(
            body in ".{0,500}",
            section in "[A-Za-z][A-Za-z0-9]{0,10}",
            max_len in 1usize..200,
        ) {
            let text = format!("# Doc\n\n## {section}\n{body}\n\n## After\ntail\n");
            if let Some(out) = extract_section(&text, &section, max_len) {
                prop_assert!(
                    out.len() <= max_len + '…'.len_utf8(),
                    "output must not exceed the cap plus a single ellipsis: {out:?}"
                );
                prop_assert!(
                    out.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\t')),
                    "terminal control sequences must be stripped: {out:?}"
                );
                prop_assert!(!out.is_empty(), "an empty body yields None, not Some(\"\")");
            }
        }
    }
}
