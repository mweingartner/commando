//! The `mpd` command surface: thin verbs over the phase machine, gate ledger,
//! deterministic checks, and the OpenSpec-format engine.

use crate::checks::{self, tests_runner};
use crate::config::Config;
use crate::ledger::{
    self, bounded_text, ChangeKind, CheckSummary, Condition, Exploitability, FailureClass,
    GateRecord, Governance, ReconciliationKind, RiskLevel, ThreatProfile, Verdict,
};
use crate::phase::Phase;
use crate::{githooks, harness, scaffold};
use clap::{Parser, Subcommand};
use openspec_core::{date, Project};
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
    },
    /// Show the current phase, gate verdicts, and readiness.
    Status {
        /// Change to inspect (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
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
    /// Diagnose the project setup.
    Doctor {
        /// Emit machine-readable JSON.
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
        } => cmd_begin(name, ui, fix, chore, risk, threat_profile),
        Command::Status { change, json } => cmd_status(change, json),
        Command::Next {
            change,
            harness,
            json,
            full,
        } => cmd_next(change, harness, json, full),
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
        ),
        Command::Reconcile {
            continue_reason,
            narrow,
            risk,
            threat_profile,
            change,
        } => cmd_reconcile(continue_reason, narrow, risk, threat_profile, change),
        Command::Resolve { index, all, change } => cmd_resolve(index, all, change),
        Command::Check { staged, quiet } => cmd_check(staged, quiet),
        Command::Archive {
            change,
            skip_specs,
            yes,
        } => cmd_archive(change, skip_specs, yes),
        Command::Doctor { json } => cmd_doctor(json),
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
    ledger::current(root)
        .ok_or_else(|| "no change specified and no current change set; pass --change".to_string())
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

fn cmd_begin(
    name: String,
    ui: bool,
    fix: bool,
    chore: bool,
    risk: Option<String>,
    threat_profile: Option<String>,
) -> CmdResult {
    let kind = match (fix, chore) {
        (false, false) => ChangeKind::Feature,
        (true, false) => ChangeKind::Fix,
        (false, true) => ChangeKind::Chore,
        (true, true) => return Err("specify at most one of --fix, --chore".into()),
    };
    let root = find_root()?;
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
    let ledger = scaffold::begin(&root, &name, ui, kind, governance).map_err(|e| e.to_string())?;
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
    println!("Next: mpd next");
    Ok(0)
}

fn cmd_status(change: Option<String>, json: bool) -> CmdResult {
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
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
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
        for ev in &ledger.history {
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
    if open_conditions > 0 {
        println!("\n→ close open conditions: mpd resolve <n>");
    } else if ledger.phase != Phase::Done {
        println!("\n→ next: mpd next");
    } else if ready {
        println!("\n→ ready: mpd archive --yes");
    }
    Ok(0)
}

fn cmd_next(change: Option<String>, harness_kind: String, json: bool, full: bool) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    if ledger.phase == Phase::Done {
        println!(
            "All phases complete for {change:?}. Run `mpd archive` to fold specs into the record."
        );
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
        ledger.next_attempt(ledger.phase),
        !ledger.attempt_authorized(ledger.phase),
        ledger
            .attempt_authorization(ledger.phase)
            .map(|r| r.kind.label().to_string()),
        page_warning,
    );

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
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(0);
    }

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
    evidence: Option<String>,
    by: Option<String>,
    conditions: Vec<String>,
    failure_class: Option<String>,
    attacker: Option<String>,
    capability: Option<String>,
    boundary: Option<String>,
    harm: Option<String>,
    exact_fix: Option<String>,
) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let phase =
        Phase::from_slug(&phase_slug).ok_or_else(|| format!("unknown phase {phase_slug:?}"))?;

    let verdict = match (pass, conditional, fail) {
        (true, false, false) => Verdict::Pass,
        (false, true, false) => Verdict::ConditionalPass,
        (false, false, true) => Verdict::Fail,
        _ => return Err("specify exactly one of --pass, --conditional, --fail".into()),
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
    if !ledger.attempt_authorized(phase) {
        return Err(format!("attempt {} exceeds the {}-risk limit; run `mpd reconcile --continue \"reason\"` (or narrow/change governance) first", ledger.next_attempt(phase), ledger.governance.risk));
    }
    let attempt = ledger.next_attempt(phase);
    let completed = ledger::now_epoch_secs();
    let mut checks_summary: Option<CheckSummary> = None;

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
                return Ok(gate_blocked(&format!(
                    "{} gate refused: {} (command: {})",
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
            let text = openspec_core::read_capped(&path).unwrap_or_default();
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
        match openspec_core::read_capped(&project.change_dir(change).join(name)) {
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

/// Structural completeness check for a documentation file. Returns the list of
/// problems (empty ⇒ complete): missing sections, unfilled template
/// placeholders, or too-short content.
fn check_documentation(text: &str) -> Vec<String> {
    let mut issues = Vec::new();
    for section in REQUIRED_DOC_SECTIONS {
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
    if text.trim().len() < 120 {
        issues.push("documentation is too short to be meaningful".to_string());
    }
    issues
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
        let text = openspec_core::read_capped(&dir.join(name)).unwrap_or_default();
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

fn cmd_archive(change: Option<String>, skip_specs: bool, yes: bool) -> CmdResult {
    let root = find_root()?;
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

    let plan = project
        .plan_archive(&change, skip_specs)
        .map_err(|e| e.to_string())?;

    // Documentation fold-in (feature changes only): read the change's
    // documentation.md now, before commit_archive moves the change directory.
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

    project.commit_archive(&plan).map_err(|e| e.to_string())?;

    // Fold the documentation into the durable project docs directory. Reuse the
    // hardened containment walk (every component, incl. the leaf, checked for
    // symlinks) BEFORE creating or following any directory, and again after
    // mkdir to close the TOCTOU window — refusing a symlinked docs dir or a
    // symlinked target that would redirect the write outside the project.
    if let Some((target, content)) = &doc_fold {
        openspec_core::assert_contained(&root, target).map_err(|e| e.to_string())?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        openspec_core::assert_contained(&root, target).map_err(|e| e.to_string())?;
        std::fs::write(target, content).map_err(|e| e.to_string())?;
        println!("  documentation → {}", target.display());
    }

    // Record Deploy gate and persist final ledger state.
    let mut ledger = ledger;
    ledger.record(
        Phase::Deploy,
        GateRecord {
            verdict: Verdict::Pass,
            by: "main-session".to_string(),
            evidence: Some(plan.archive_target.display().to_string()),
            checks: None,
            at: date::today_utc(),
            failure_class: None,
            exploitability: None,
            attempt: ledger.next_attempt(Phase::Deploy),
            started_at_epoch_secs: ledger.phase_started_at_epoch_secs,
            completed_at_epoch_secs: ledger::now_epoch_secs(),
        },
    );
    ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
    if ledger::current(&root).as_deref() == Some(change.as_str()) {
        let _ = std::fs::remove_file(ledger::current_path(&root));
    }
    println!("\nArchived {change:?}.");
    Ok(0)
}

fn cmd_doctor(json: bool) -> CmdResult {
    let root = find_root().ok();
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
    if !hook && git {
        println!("\n  Tip: re-run `mpd init` to install the pre-commit gate.");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::has_unfilled_placeholder;

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
}
