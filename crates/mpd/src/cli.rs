//! The `mpd` command surface: thin verbs over the phase machine, gate ledger,
//! deterministic checks, and the OpenSpec-format engine.

use crate::checks::{self, tests_runner};
use crate::config::Config;
use crate::ledger::{self, CheckSummary, Condition, GateRecord, Verdict};
use crate::phase::Phase;
use crate::{githooks, harness, scaffold};
use clap::{Parser, Subcommand};
use openspec_core::{date, Project};
use std::path::PathBuf;

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
        /// Rendering: `generic` or `claude-code`.
        #[arg(long, default_value = "generic")]
        harness: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
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
    },
    /// Run deterministic checks now (secret scan + optional test run).
    Check {
        /// Scan only staged files (used by the pre-commit hook).
        #[arg(long)]
        staged: bool,
        /// Suppress success output.
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
        Command::Begin { name, ui } => cmd_begin(name, ui),
        Command::Status { change, json } => cmd_status(change, json),
        Command::Next {
            change,
            harness,
            json,
        } => cmd_next(change, harness, json),
        Command::Gate {
            phase,
            change,
            pass,
            conditional,
            fail,
            evidence,
            by,
            conditions,
        } => cmd_gate(
            phase,
            change,
            pass,
            conditional,
            fail,
            evidence,
            by,
            conditions,
        ),
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
    if report.hook_installed {
        println!("  + .git/hooks/pre-commit (gate installed)");
    } else if let Some(note) = &report.hook_note {
        println!("  ! pre-commit hook: {note}");
    } else {
        println!("  ! not a git repo — run `git init` then `mpd init` to install the commit gate");
    }
    println!("\nNext: mpd begin <change-name>");
    Ok(0)
}

fn cmd_begin(name: String, ui: bool) -> CmdResult {
    let root = find_root()?;
    let ledger = scaffold::begin(&root, &name, ui).map_err(|e| e.to_string())?;
    println!(
        "Started change {:?} (ui: {}). Current phase: {}.",
        name,
        ui,
        ledger.phase.label()
    );
    println!("Next: mpd next");
    Ok(0)
}

fn cmd_status(change: Option<String>, json: bool) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    let project = Project::new(&root);
    let tasks = project.task_status(&change).unwrap_or_default();
    let reasons = ledger.blocking_reasons();
    let ready = ledger.ready_to_archive();

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
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(0);
    }

    println!("Change: {}  (ui: {})", ledger.change, ledger.ui);
    println!("Current phase: {}\n", ledger.phase.label());
    println!("Pipeline:");
    for phase in Phase::applicable(ledger.ui) {
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
    println!("\nTasks: {}/{} complete", tasks.done, tasks.total);
    if ready {
        println!("Ready to archive: yes");
    } else {
        println!("Ready to archive: no");
        for r in &reasons {
            println!("  - {r}");
        }
    }
    Ok(0)
}

fn cmd_next(change: Option<String>, harness_kind: String, json: bool) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    if ledger.phase == Phase::Done {
        println!(
            "All phases complete for {change:?}. Run `mpd archive` to fold specs into the record."
        );
        return Ok(0);
    }
    let brief = harness::brief(&change, ledger.phase);
    if json {
        println!("{}", serde_json::to_string_pretty(&brief).unwrap());
        return Ok(0);
    }
    let rendered = match harness_kind.as_str() {
        "claude-code" => harness::render_claude_code(&brief),
        "generic" => harness::render_generic(&brief),
        other => {
            return Err(format!(
                "unknown harness {other:?} (use generic|claude-code)"
            ))
        }
    };
    print!("{rendered}");
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

    let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
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
            if !report.clean() {
                for f in &report.findings {
                    eprintln!("  secret: {}:{} [{}]", f.path, f.line, f.rule);
                }
                return Ok(gate_blocked(&format!(
                    "{} gate refused: {} secret finding(s) via {}",
                    phase.label(),
                    report.findings.len(),
                    report.scanner
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
            let mut scanners = vec![report.scanner.to_string()];
            scanners.extend(external.ran.iter().cloned());
            let summary = checks_summary.get_or_insert_with(CheckSummary::default);
            summary.secrets_clean = Some(true);
            summary.scanner = Some(scanners.join("+"));
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

fn gate_blocked(msg: &str) -> i32 {
    eprintln!("{msg}");
    1
}

fn cmd_check(staged: bool, quiet: bool) -> CmdResult {
    let root = find_root()?;
    let files = if staged {
        checks::git_staged_files(&root)
    } else {
        checks::git_tracked_files(&root)
    };
    let report = checks::scan_secrets(&files);
    let mut failed = false;

    if !report.clean() {
        failed = true;
        eprintln!(
            "Secret scan ({}) found {} finding(s):",
            report.scanner,
            report.findings.len()
        );
        for f in &report.findings {
            let loc = if f.line == 0 {
                f.path.clone()
            } else {
                format!("{}:{}", f.path, f.line)
            };
            eprintln!("  {loc} [{}]", f.rule);
        }
    }

    // External scanners (gitleaks / Semgrep) when installed.
    let external = checks::run_external_scanners(&root);
    if !external.failures.is_empty() {
        failed = true;
        for msg in &external.failures {
            eprintln!("{msg}");
        }
    }

    // Verify tests when configured.
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
    let plan = project
        .plan_archive(&change, skip_specs)
        .map_err(|e| e.to_string())?;

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
    println!("  → archive to {}", plan.archive_target.display());

    if !yes {
        println!("\nDry run. Re-run with --yes to apply.");
        return Ok(0);
    }

    project.commit_archive(&plan).map_err(|e| e.to_string())?;

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
    let current = root.as_ref().and_then(|r| ledger::current(r));
    let schema_ok = root
        .as_ref()
        .map(|r| r.join("openspec/schemas/mpd/schema.yaml").is_file())
        .unwrap_or(false);

    if json {
        let v = serde_json::json!({
            "project_root": root.as_ref().map(|r| r.display().to_string()),
            "openspec_present": root.is_some(),
            "mpd_schema_installed": schema_ok,
            "git_repo": git,
            "pre_commit_hook": hook,
            "secret_scanner_floor": "builtin",
            "gitleaks": gitleaks,
            "semgrep": semgrep,
            "test_command": test_cmd,
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
        "  current change:      {}",
        current.as_deref().unwrap_or("(none)")
    );
    if !hook && git {
        println!("\n  Tip: re-run `mpd init` to install the pre-commit gate.");
    }
    Ok(0)
}
