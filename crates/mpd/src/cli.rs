//! The `mpd` command surface: thin verbs over the phase machine, gate ledger,
//! deterministic checks, and the OpenSpec-format engine.

use crate::checks::{self, tests_runner};
use crate::config::Config;
use crate::ledger::{
    self, bounded_text, ChangeKind, CheckSummary, Condition, Exploitability, FailureClass,
    GateRecord, Governance, ReconciliationKind, RiskLevel, ThreatProfile, Verdict,
};
use crate::phase::Phase;
use crate::{closure, digest, git, githooks, harness, scaffold};
use clap::{Parser, Subcommand};
use closure::ArchiveClosure;
use openspec_core::{date, Project};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// mpd — an adversarial-gate overlay over the OpenSpec format.
#[derive(Debug, Parser)]
#[command(name = "mpd", version, about, after_help = COMMAND_GUIDE)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Grouped command guide shown under `mpd --help` — tiers the verbs by role so the
/// everyday loop leads (clap lists subcommands flat; this is the map).
const COMMAND_GUIDE: &str = "\
Command groups:
  Core loop      conduct · next · gate · status · archive · publish   (the everyday motion)
  Author/govern  brief · resolve · reconcile · persona · manifest · use
  Setup/recovery init · strict · check · validate · policy activate · doctor
                 (archive --recover/--abandon recovers an interrupted archive)

Drive a change: mpd conduct <name> → loop (mpd next → do the work → mpd gate <phase>)
→ mpd archive --yes → commit + push → mpd publish --verify.";

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize an OpenSpec+mpd project in the current directory.
    Init {
        /// The test command used to verify Build/Test gates (e.g. "cargo test").
        #[arg(long)]
        test: Option<String>,
    },
    /// Create a new change in the MANUAL tier (hidden alias — most callers should
    /// use `conduct` for the strict, self-enforcing tier). Still fully functional;
    /// `begin --strict` is equivalent to the strict start.
    #[command(hide = true)]
    Begin {
        /// Change name (lowercase kebab-case).
        name: String,
        /// Mark the change as having a UI/UX surface (enables design phases).
        #[arg(long)]
        ui: bool,
        /// A defect fix (all mandatory phases still run).
        #[arg(long)]
        fix: bool,
        /// A non-functional chore (refactor/tooling/perf); all mandatory phases run.
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
        /// Defect-escape provenance: the archived change this fix was opened to
        /// address a defect that escaped from. Requires --fix; validated before
        /// anything is created (the archive must actually exist), then stored
        /// write-once — display/measurement data only, never a gate input.
        #[arg(long = "introduced-by", requires = "fix")]
        introduced_by: Option<String>,
    },
    /// Begin a change under the strict tier: begin + strict + a seeded judgment
    /// stub + the harness call-loop contract. The way a harness drives mpd.
    Conduct {
        /// Change name (lowercase kebab-case).
        name: String,
        /// Mark the change as having a UI/UX surface (enables design phases).
        #[arg(long)]
        ui: bool,
        /// A defect fix (all mandatory phases still run).
        #[arg(long)]
        fix: bool,
        /// A non-functional chore (refactor/tooling/perf); all mandatory phases run.
        #[arg(long)]
        chore: bool,
        /// Review rigor (`low`, `medium`, or `high`).
        #[arg(long)]
        risk: Option<String>,
        /// Credible threat boundary for this change.
        #[arg(long = "threat-profile")]
        threat_profile: Option<String>,
        /// Defect-escape provenance: the archived change this fix was opened to
        /// address a defect that escaped from. Requires --fix; validated before
        /// anything is created (the archive must actually exist), then stored
        /// write-once — display/measurement data only, never a gate input.
        #[arg(long = "introduced-by", requires = "fix")]
        introduced_by: Option<String>,
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
        /// Required on a Security FAIL: the credible exploit path as five
        /// `|`-delimited fields — `"attacker|capability|boundary|harm|fix"`.
        #[arg(long)]
        exploit: Option<String>,
        /// Explicitly reuse an exact, valid executed evidence receipt.
        #[arg(long)]
        reuse: Option<String>,
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
    /// Preview or append a deterministic legacy-ledger rewind. Never creates a PASS.
    RepairState {
        /// Earlier phase to rewind to.
        #[arg(long, value_name = "PHASE")]
        to: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        yes: bool,
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
        /// Actor closing the condition. Required so a resolution has durable provenance.
        #[arg(long)]
        by: String,
        /// Contained evidence pointer or receipt identifier for the resolution.
        #[arg(long)]
        evidence: String,
        /// Change (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
    },
    /// Record or revoke an evidence-backed deferral for one stable Builder task.
    Task {
        #[command(subcommand)]
        command: TaskCommand,
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
    /// Validate an exact local Git subject under the approved structured policy.
    /// Missing or changed trust blocks before any candidate-defined check runs.
    Validate {
        /// Local commit or tag subject (defaults to HEAD; peeled to a commit).
        #[arg(long)]
        commit: Option<String>,
        /// Approved local-validation profile (defaults to the configured test profile).
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Hash one installed file. This is deliberately a leaf probe: it never
    /// runs doctor, validation, installation, or Deploy.
    Identity {
        /// Contained repository-relative installed file to inspect.
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Git-hook entry points.  Tracked wrappers only forward here; all parsing
    /// and authorization remains in Rust so shell cannot reinterpret refs.
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    /// Activate one explicitly reviewed immutable validation policy locally.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// One-time first trusted-policy adoption helpers. These commands never
    /// run configured validation profiles; they only inventory or reconcile
    /// explicitly reviewed checkpoint state.
    #[cfg(test)]
    FirstAdoption {
        #[command(subcommand)]
        command: FirstAdoptionCommand,
    },
    /// Internal sandbox entry point. It is intentionally hidden: only the
    /// reviewed supervisor constructs this separated argv before sandboxing.
    #[command(name = "__mpd-limited-exec", hide = true)]
    InternalLimitedExec {
        #[arg(long)]
        cpu_secs: u64,
        #[arg(long)]
        processes: u64,
        #[arg(long)]
        open_files: u64,
        #[arg(long)]
        file_bytes: u64,
        #[arg(last = true, required = true, num_args = 1..)]
        argv: Vec<String>,
    },
    /// Internal exact-host macOS sandbox entry. All authority, limits, and the
    /// typed checked invocation arrive in one private canonical request.
    #[cfg(target_os = "macos")]
    #[command(name = "__mpd-sandbox-exec", hide = true)]
    InternalSandboxExec,
    /// Internal, non-recursive static validation-policy check. It parses only
    /// the exact materialized subject and executes no Git, profile, or tool.
    #[command(name = "__mpd-static-policy-check", hide = true)]
    InternalStaticPolicyCheck,
    /// Fold a completed change's specs into the record and archive it. Also
    /// recovers/abandons an interrupted archive closure (`--recover`/`--abandon`).
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
        /// Recover an interrupted archive closure transaction (completion-only).
        #[arg(long)]
        recover: bool,
        /// Abandon owned closure transaction metadata after AwaitingCommit.
        #[arg(long)]
        abandon: bool,
        /// Emit machine-readable JSON (only with --recover/--abandon).
        #[arg(long)]
        json: bool,
    },
    /// Seed the active change's manifest.json (declare its path scope) without
    /// guessing project scope.
    Manifest {
        /// Change (defaults to the current change).
        #[arg(long)]
        change: Option<String>,
    },
    /// Read-only outcome measurement over every recorded gate ledger:
    /// per-change and aggregate attempts, wall-clock, reconciliations,
    /// rewinds, failure classes, weakened-tuning incidence, deferrals, and
    /// defect-escape provenance. Never mutates any ledger.
    Stats {
        /// Restrict the report to exactly one change (by name).
        #[arg(long)]
        change: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect or freshly verify closure commit parity with its configured remote ref.
    Publish {
        #[arg(long)]
        verify: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect or recover an interrupted archive closure transaction (hidden alias
    /// — prefer `archive --recover` / `archive --abandon`).
    #[command(hide = true)]
    Closure {
        #[command(subcommand)]
        command: ClosureCommand,
    },
    /// Point `.mpd/current` at an existing change — recovers a cleared pointer
    /// (e.g. after `mpd archive --abandon` or an archive that reset it).
    Use {
        /// Change name to make current (must have a seeded ledger).
        change: String,
    },
    /// Promote an already-begun change to the strict (orchestration) tier — its
    /// judgment gates then enforce their artifacts. Monotonic and idempotent.
    Strict {
        /// Change name to promote (must have a seeded ledger).
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
        /// Read-only diagnostic scope: `validator-policy` or `runtime-health`.
        /// Scoped doctor never executes validation, installation, or Deploy.
        #[arg(long)]
        scope: Option<String>,
        /// Exit non-zero when the selected scoped diagnostic reports a blocker.
        /// This is valid only with --scope; it never makes bare doctor a gate.
        #[arg(long)]
        enforce: bool,
    },
    /// Inspect or tune per-persona behavior — the interview primitives a harness
    /// drives (show current/range, warn on the un-rankable change, record).
    Persona {
        #[command(subcommand)]
        command: PersonaCommand,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Print the non-executing exact-subject policy preflight.
    #[cfg(test)]
    Status {
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Create the first trusted-policy commit/ref with an all-zero CAS. This is
    /// an explicit owner trust decision, never an ordinary validation action.
    #[cfg(test)]
    Bootstrap {
        /// Immutable checkpoint commit reviewed before the pretrust proof.
        #[arg(long)]
        commit: String,
        /// Exact SHA-256 digest of the policy reviewed by the operator.
        #[arg(long = "confirm-digest")]
        confirm_digest: String,
        /// Digest of the exclusive clone-private pretrust proof.
        #[arg(long = "pretrust-proof")]
        pretrust_proof: String,
        /// Public nonce preimage from that proof. This interface consumes it
        /// only to recompute the domain-separated digest.
        #[arg(long)]
        nonce: String,
        /// Required acknowledgement that this creates a clone-local trust root.
        #[arg(long = "i-reviewed-this-policy")]
        reviewed: bool,
    },
    /// Explicitly review and promote an immutable candidate commit against the
    /// already-established clone-local trusted floor.  This never activates
    /// candidate coordinator/hooks and never creates a validation receipt.
    #[cfg(test)]
    Promote {
        /// Full immutable commit object id containing the proposed policy.
        #[arg(long)]
        commit: String,
        /// Exact SHA-256 digest of the candidate local-validation policy that
        /// the owner reviewed before either candidate command can run.
        #[arg(long = "confirm-digest")]
        confirm_digest: String,
    },
    /// Bind and activate an immutable reviewed policy, coordinator, and hooks.
    Activate {
        #[arg(long)]
        commit: String,
        #[arg(long = "confirm-policy-digest")]
        confirm_policy_digest: String,
        #[arg(long)]
        coordinator: PathBuf,
        #[arg(long = "confirm-executable-digest")]
        confirm_executable_digest: String,
        #[arg(long)]
        hooks: PathBuf,
        #[arg(long)]
        yes: bool,
    },
}

#[cfg(test)]
#[derive(Debug, Subcommand)]
enum FirstAdoptionCommand {
    /// Read-only exact checkpoint scope preparation.
    Prepare {
        #[arg(long)]
        change: String,
        #[arg(long)]
        base: String,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long)]
        security_evidence: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify the committed checkpoint in the restricted pretrust control
    /// plane and exclusively write the nonce-bound proof.
    VerifyCheckpoint {
        #[arg(long)]
        change: String,
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        security_evidence: String,
        #[arg(long = "confirm-policy-digest")]
        confirm_policy_digest: String,
        #[arg(long = "confirm-coordinator-digest")]
        confirm_coordinator_digest: String,
        #[arg(long)]
        json: bool,
    },
    /// Preview or append one bounded checkpoint correction. This records
    /// eligibility only; it never stages, commits, rewrites, advances a ref,
    /// installs bytes, executes policy, or synthesizes a gate PASS.
    Restart {
        #[arg(long)]
        change: String,
        /// `pretrust` before the one trust CAS, or `posttrust` afterwards.
        #[arg(long)]
        stage: String,
        #[arg(long)]
        superseded_checkpoint: String,
        #[arg(long)]
        superseded_proof: Option<String>,
        #[arg(long)]
        replacement_tip: Option<String>,
        #[arg(long)]
        security_evidence: String,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        reason: String,
        /// Atomically append to the contained ledger (preview is the default).
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Append the sole posttrust reconciliation and rewind Build. Preview is
    /// the default; `--yes` is required for ledger mutation.
    Reconcile {
        #[arg(long)]
        change: String,
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        policy_object: String,
        #[arg(long)]
        pretrust_proof: String,
        #[arg(long)]
        security_evidence: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum HookCommand {
    /// Fast, read-only staged gate used by pre-commit.
    PreCommit {
        #[arg(long)]
        json: bool,
    },
    /// Read Git's exact pre-push protocol from stdin and issue only an
    /// invocation-local authorization; it never pushes, fetches, or writes refs.
    PrePush {
        remote_name: String,
        remote_location: String,
        #[arg(long)]
        json: bool,
    },
    /// Create one exact, clone-private, one-use approval for deleting a
    /// non-main branch on the next matching pre-push invocation.
    ApproveDeletion {
        remote_name: String,
        remote_location: String,
        #[arg(long)]
        remote_ref: String,
        #[arg(long)]
        old_oid: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PersonaCommand {
    /// List every tunable persona with its current tuning.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show one persona: per field the current value, range, baseline, and danger.
    Show {
        /// Persona (Architect|Designer|Security|Builder|Tester|Documenter|DocValidation).
        persona: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Set a persona field (`rigor`|`depth`|`directive-append`). Rejects an unknown
    /// persona name or enum term; warns loudly on the un-rankable `directive-append`.
    Set {
        /// Persona display name (or `DocValidation`).
        persona: String,
        /// Field: `rigor`, `depth`, or `directive-append`.
        field: String,
        /// Value (an enum term for rigor/depth; free text for directive-append).
        value: String,
    },
    /// Clear a persona's tuning back to baseline — a single `field`, or all of it.
    Reset {
        /// Persona display name (or `DocValidation`).
        persona: String,
        /// The field to clear; omit to clear the whole persona entry.
        field: Option<String>,
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

#[derive(Debug, Subcommand)]
enum TaskCommand {
    Defer {
        id: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        evidence: String,
        #[arg(long)]
        change: Option<String>,
    },
    Revoke {
        id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        change: Option<String>,
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
            introduced_by,
        } => cmd_begin(
            name,
            ui,
            fix,
            chore,
            risk,
            threat_profile,
            strict,
            introduced_by,
        ),
        Command::Conduct {
            name,
            ui,
            fix,
            chore,
            risk,
            threat_profile,
            introduced_by,
        } => cmd_conduct(name, ui, fix, chore, risk, threat_profile, introduced_by),
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
            exploit,
            reuse,
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
            exploit,
            reuse,
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
        Command::RepairState {
            to,
            reason,
            yes,
            change,
        } => cmd_repair_state(to, reason, yes, change),
        Command::Resolve { index, all, by, evidence, change } => {
            cmd_resolve(index, all, by, evidence, change)
        }
        Command::Task { command } => cmd_task(command),
        Command::Check { staged, quiet } => cmd_check(staged, quiet),
        Command::Validate { commit, profile, json } => cmd_validate(commit, profile, json),
        Command::Identity { path, json } => cmd_identity(path, json),
        Command::Hook { command } => cmd_hook(command),
        Command::Policy { command } => cmd_policy(command),
        #[cfg(test)]
        Command::FirstAdoption { command } => cmd_first_adoption(command),
        Command::InternalLimitedExec {
            cpu_secs,
            processes,
            open_files,
            file_bytes,
            argv,
        } => {
            // Clap versions differ on whether `last = true` retains the `--`
            // delimiter. The supervisor always emits one; accept either parsed
            // representation while preserving the individual argv boundaries.
            let argv = argv.strip_prefix(&["--".to_string()]).unwrap_or(&argv);
            match crate::sandbox::limited_exec(cpu_secs, processes, open_files, file_bytes, argv)
            {
                Ok(()) => Ok(0),
                Err(error) => {
                    // 125 is reserved for the supervisor wrapper. A checked
                    // program's ordinary non-zero exit is still a check failure;
                    // this code means no approved argv began because resource
                    // setup or the exact exec handoff failed.
                    eprintln!("resource-limit-setup: {error}");
                    Ok(125)
                }
            }
        }
        #[cfg(target_os = "macos")]
        Command::InternalSandboxExec => {
            match crate::sandbox_macos::hidden_entry() {
                Ok(()) => Ok(0),
                Err(error) => {
                    eprintln!("sandbox-entry-blocked: {error}");
                    Ok(125)
                }
            }
        }
        Command::InternalStaticPolicyCheck => (|| -> CmdResult {
            let root = find_root()?;
            crate::local_validation::static_policy_check(&root)?;
            println!("static validation policy: PASS");
            Ok(0)
        })(),
        // `--recover`/`--abandon` route to the closure logic HERE, ahead of
        // `cmd_archive` — whose first check refuses on a pending closure, exactly the
        // state recovery exists for (Security-plan Finding 2). `--json`/`--change`
        // are scoped to the recovery branch.
        Command::Archive {
            change,
            skip_specs,
            yes,
            recover,
            abandon,
            json,
        } => match (recover, abandon) {
            (true, true) => Err("--recover and --abandon are mutually exclusive".into()),
            (true, false) | (false, true) if skip_specs => {
                Err("--recover/--abandon are mutually exclusive with --skip-specs".into())
            }
            (true, false) | (false, true) if change.is_some() => Err(
                "--change is not valid with --recover/--abandon (they act on the single pending closure)"
                    .into(),
            ),
            (true, false) => find_root().and_then(|root| cmd_closure_recover(&root, yes, json)),
            (false, true) => find_root().and_then(|root| cmd_closure_abandon(&root, yes, json)),
            (false, false) if json => {
                Err("--json is valid only with --recover/--abandon".into())
            }
            (false, false) => cmd_archive(change, skip_specs, yes),
        },
        Command::Manifest { change } => cmd_manifest(change),
        Command::Stats { change, json } => cmd_stats(change, json),
        Command::Publish { verify, json } => cmd_publish(verify, json),
        Command::Closure { command } => cmd_closure(command),
        Command::Use { change } => cmd_use(change),
        Command::Strict { change } => cmd_strict(change),
        Command::Doctor {
            json,
            fix,
            scope,
            enforce,
        } => cmd_doctor(json, fix, scope, enforce),
        Command::Persona { command } => cmd_persona(command),
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

/// D8 / Cond 8, 18: validate a `--introduced-by <archived-change>` argument
/// BEFORE anything is created. The referenced change must be a real archive:
/// either its ledger (kept at `.mpd/state/<name>.json` even after archive)
/// has `archive_closure` set, or a legacy pre-closure dated archive directory
/// `openspec/changes/archive/<YYYY-MM-DD>-<name>` exists — exact
/// decomposition only, never substring/glob matching.
fn validate_introduced_by(root: &Path, name: &str) -> Result<String, String> {
    openspec_core::validate_change_name(name)?;
    if let Ok(ledger) = ledger::load(root, name) {
        if ledger.archive_closure.is_some() {
            return Ok(name.to_string());
        }
    }
    if legacy_dated_archive_exists(root, name) {
        return Ok(name.to_string());
    }
    Err(format!(
        "cannot resolve --introduced-by {name:?}: no archived ledger (`archive_closure`) and no \
         dated archive directory `openspec/changes/archive/<YYYY-MM-DD>-{name}` was found"
    ))
}

/// Whether `openspec/changes/archive/` contains a directory whose name
/// decomposes EXACTLY as `<YYYY-MM-DD>-<name>` — a bounded, non-recursive
/// listing, never a glob or substring search.
fn legacy_dated_archive_exists(root: &Path, name: &str) -> bool {
    let archive_dir = root.join("openspec").join("changes").join("archive");
    let Ok(entries) = std::fs::read_dir(&archive_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(dir_name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if dated_archive_matches(&dir_name, name) {
            return true;
        }
    }
    false
}

/// Exact `<YYYY-MM-DD>-<name>` decomposition: stripping the literal `-<name>`
/// suffix must leave EXACTLY a 10-character `YYYY-MM-DD` date, nothing more
/// and nothing less — never a prefix/suffix/substring match.
fn dated_archive_matches(dir_name: &str, name: &str) -> bool {
    match dir_name.strip_suffix(&format!("-{name}")) {
        Some(rest) => is_valid_date_prefix(rest),
        None => false,
    }
}

fn is_valid_date_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
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
    introduced_by: Option<String>,
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
             run `mpd archive --recover` or `mpd archive --abandon` first",
            view.change,
            stage_label(view.stage)
        ));
    }
    // D8 Cond 8: validate BEFORE anything is created — no ledger, no
    // scaffold, no `.mpd/current` change on a failure.
    let introduced_by = introduced_by
        .map(|origin| validate_introduced_by(&root, &origin))
        .transpose()?;
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
    // D8: write-once at begin, additive-defaulted on load, never mutated by
    // any later verb (Cond 19 — display/measurement data only).
    if let Some(origin) = &introduced_by {
        ledger.introduced_by = Some(origin.clone());
        println!("Introduced by: {origin} (defect-escape provenance).");
    }
    // The strict tier is a durable, per-change bit (`conduct` and `begin --strict`
    // are the only setters). Turn it on, persist it, and seed the current phase's
    // judgment stub so the very first gate has an artifact to author.
    if strict {
        ledger.set_strict();
    }
    if strict || introduced_by.is_some() {
        ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
    }
    if strict {
        if let Some(created) = scaffold::seed_judgment_template(&root, &name, ledger.phase)
            .map_err(|e| e.to_string())?
        {
            println!(
                "  + {created} (seeded {} judgment stub)",
                ledger.phase.label()
            );
        }
        println!(
            "Strict tier ON: canonical judgment artifacts are gate-enforced and cannot be waived. \
             `mpd brief <phase>` scaffolds the required artifact."
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
    introduced_by: Option<String>,
) -> CmdResult {
    let name_for_contract = name.clone();
    let code = cmd_begin(
        name,
        ui,
        fix,
        chore,
        risk,
        threat_profile,
        true,
        introduced_by,
    )?;
    print_conduct_contract(&name_for_contract);
    // Risk nudge (once per change; conduct is a once-per-change command): if the
    // conducted change resolved below high risk, remind that novel/risky surface
    // warrants `--risk high` — which floors Security/Tester to the deep model + max
    // effort so the brief directs a full-depth review. Read from the ledger (the raw
    // `--risk` arg is None on a defaulted change), best-effort so it never fails the
    // command. Deliberately does NOT recommend `mpd reconcile --risk high`: that verb
    // advances a pre-Security change to security-plan, skipping Architecture
    // (a separate latent bug, filed as a follow-up).
    if let Ok(root) = find_root() {
        if let Ok(ledger) = ledger::load(&root, &name_for_contract) {
            if ledger.governance.risk.rank() < RiskLevel::High.rank() {
                println!(
                    "\nTip: risk={}. For novel or risky surface (auth, credentials, untrusted \
                     input, crypto, or a feature with no analog already shipped), start at \
                     `--risk high` — it floors Security and Tester to the deep model + max \
                     reasoning effort, so the brief directs a full-depth review.",
                    ledger.governance.risk
                );
            }
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
enum WorkflowOutcome {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "BLOCKED")]
    Blocked,
    #[serde(rename = "CONDITIONAL")]
    Conditional,
    #[serde(rename = "STALE")]
    Stale,
    #[serde(rename = "IN PROGRESS")]
    InProgress,
    #[serde(rename = "NOT RUN")]
    NotRun,
}

impl WorkflowOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Blocked => "BLOCKED",
            Self::Conditional => "CONDITIONAL",
            Self::Stale => "STALE",
            Self::InProgress => "IN PROGRESS",
            Self::NotRun => "NOT RUN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct WorkflowFact {
    outcome: WorkflowOutcome,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
}

impl WorkflowFact {
    fn new(outcome: WorkflowOutcome, state: impl Into<String>) -> Self {
        Self {
            outcome,
            state: state.into(),
            evidence: None,
        }
    }

    fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct ContainmentStatus {
    adapter: String,
    host: Option<String>,
    spi_abi_digest: Option<String>,
    fixed_profile_digest: Option<String>,
    root_inventory_digests: Vec<String>,
    canaries: WorkflowFact,
    compiler_process_tree: WorkflowFact,
    full_local_profile: String,
    certified_claim: String,
    residual_limitations: Vec<String>,
    blocker_code: Option<String>,
    blocker_action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct WorkflowStatus {
    worktree: WorkflowFact,
    candidate: WorkflowFact,
    gates: WorkflowFact,
    local_validation: WorkflowFact,
    archive: WorkflowFact,
    commit: WorkflowFact,
    push_authorization: WorkflowFact,
    transfer: WorkflowFact,
    remote_parity: WorkflowFact,
    install: WorkflowFact,
    containment: ContainmentStatus,
    next_action: String,
}

fn sandbox_blocker(error: &str) -> (&'static str, &'static str) {
    let lower = error.to_ascii_lowercase();
    if lower.contains("host") || lower.contains("platform") || lower.contains("architecture") {
        (
            "sandbox.host-drift",
            "run the unchanged candidate/policy on the exact certified host",
        )
    } else if lower.contains("profile") || lower.contains("policy") || lower.contains("activation")
    {
        (
            "sandbox.profile-drift",
            "run the printed digest-confirmed policy activation",
        )
    } else if lower.contains("root") || lower.contains("candidate") {
        (
            "sandbox.root-drift",
            "return to Build and recapture candidate/root inventory",
        )
    } else if lower.contains("canary") {
        (
            "sandbox.canary-failed",
            "return to Security(code) with the named failure/log",
        )
    } else if lower.contains("receipt")
        || lower.contains("not run")
        || lower.contains("missing")
        || lower.contains("absent")
        || lower.contains("incomplete")
    {
        (
            "sandbox.full-profile-incomplete",
            "run `scripts/ci-local.sh` for the current candidate on the exact certified host",
        )
    } else {
        (
            "sandbox.spi-abi-drift",
            "return to Architecture for adapter revision",
        )
    }
}

fn receipt_failure_fact(error: &str) -> WorkflowFact {
    let lower = error.to_ascii_lowercase();
    if lower.contains("stale") || lower.contains("changed-dependency") {
        WorkflowFact::new(WorkflowOutcome::Stale, "STALE").with_evidence(error)
    } else if lower.contains("failed") {
        WorkflowFact::new(WorkflowOutcome::Fail, "FAILED").with_evidence(error)
    } else if lower.contains("missing") || lower.contains("no receipt") {
        WorkflowFact::new(WorkflowOutcome::NotRun, "MISSING").with_evidence(error)
    } else {
        WorkflowFact::new(WorkflowOutcome::Blocked, "BLOCKED").with_evidence(error)
    }
}

fn blocked_containment(error: &str) -> ContainmentStatus {
    let (code, action) = sandbox_blocker(error);
    ContainmentStatus {
        adapter: "NOT CERTIFIED".into(),
        host: None,
        spi_abi_digest: None,
        fixed_profile_digest: None,
        root_inventory_digests: Vec::new(),
        canaries: WorkflowFact::new(WorkflowOutcome::NotRun, "NOT RUN"),
        compiler_process_tree: WorkflowFact::new(
            WorkflowOutcome::NotRun,
            "FEASIBILITY EVIDENCE ONLY; NOT A FULL-PROFILE SUBSTITUTE",
        ),
        full_local_profile: "NOT CERTIFIED".into(),
        certified_claim: "NOT CERTIFIED".into(),
        residual_limitations: vec![
            "global path metadata and literal-root entries are not confidential".into(),
            "same-user process isolation is not claimed".into(),
        ],
        blocker_code: Some(code.into()),
        blocker_action: Some(action.into()),
    }
}

fn current_receipt_status(
    receipt: &crate::local_validation::ValidationReceiptV1,
    full_profile: bool,
) -> (WorkflowFact, ContainmentStatus) {
    current_validation_status(
        &receipt.profile,
        &receipt.id,
        &receipt.sandbox,
        &receipt.results,
        &receipt.outcome,
        full_profile,
    )
}

fn current_validation_status(
    profile: &str,
    receipt_id: &str,
    sandbox: &crate::local_validation::SandboxReceiptBindingV1,
    results: &[crate::local_validation::ValidationCheckResult],
    receipt_outcome: &str,
    full_profile: bool,
) -> (WorkflowFact, ContainmentStatus) {
    let all_passed = receipt_outcome == "passed"
        && !results.is_empty()
        && results.iter().all(|result| result.outcome == "passed");
    let canaries_current = !sandbox.run_canary_digests.is_empty()
        && sandbox.run_canary_digests.len() >= results.len()
        && sandbox
            .run_canary_digests
            .iter()
            .all(|digest| digest == &sandbox.canary_contract_digest);
    let validation_current = all_passed && canaries_current;
    let certified = validation_current && full_profile;
    (
        WorkflowFact::new(
            if validation_current {
                WorkflowOutcome::Pass
            } else {
                WorkflowOutcome::Blocked
            },
            if validation_current {
                "CURRENT"
            } else {
                "BLOCKED"
            },
        )
        .with_evidence(format!(
            "profile={} receipt={} checks={}",
            profile,
            receipt_id,
            results.len()
        )),
        ContainmentStatus {
            adapter: if canaries_current {
                "CERTIFIED".into()
            } else {
                "NOT CERTIFIED".into()
            },
            host: Some(sandbox.certified_host.clone()),
            spi_abi_digest: Some(sandbox.adapter_abi_digest.clone()),
            fixed_profile_digest: Some(sandbox.profile_digest.clone()),
            root_inventory_digests: sandbox.run_root_inventory_digests.clone(),
            canaries: WorkflowFact::new(
                if canaries_current {
                    WorkflowOutcome::Pass
                } else {
                    WorkflowOutcome::Blocked
                },
                if canaries_current {
                    "CURRENT"
                } else {
                    "BLOCKED"
                },
            ),
            compiler_process_tree: WorkflowFact::new(
                WorkflowOutcome::NotRun,
                "FEASIBILITY EVIDENCE ONLY; NOT A FULL-PROFILE SUBSTITUTE",
            ),
            full_local_profile: if certified {
                "CERTIFIED".into()
            } else {
                "NOT CERTIFIED".into()
            },
            certified_claim: if certified {
                "CERTIFIED".into()
            } else {
                "NOT CERTIFIED".into()
            },
            residual_limitations: sandbox.residual_limitations.clone(),
            blocker_code: (!certified).then_some("sandbox.full-profile-incomplete".into()),
            blocker_action: (!certified).then_some(
                "run `scripts/ci-local.sh` for the current candidate on the exact certified host"
                    .into(),
            ),
        },
    )
}

fn workflow_status(
    root: &Path,
    ledger: &ledger::Ledger,
    config: &Config,
    freshness: &closure::FreshnessProjection,
    coherence: Option<&closure::CommitCoherence>,
    parity: Option<&closure::ParityObservation>,
) -> WorkflowStatus {
    let status_entries = git::status_v2(root);
    let worktree = match status_entries {
        Err(error) => WorkflowFact::new(WorkflowOutcome::Blocked, "BLOCKED")
            .with_evidence(format!("cannot inspect worktree: {error}")),
        Ok(entries)
            if entries
                .iter()
                .any(|entry| matches!(entry, git::StatusEntry::Unmerged { .. })) =>
        {
            WorkflowFact::new(WorkflowOutcome::Blocked, "CONFLICTED")
        }
        Ok(entries) => {
            let dirty = entries
                .iter()
                .filter(|entry| !matches!(entry, git::StatusEntry::Ignored { .. }))
                .count();
            if dirty == 0 {
                WorkflowFact::new(WorkflowOutcome::Pass, "CLEAN")
            } else {
                WorkflowFact::new(WorkflowOutcome::InProgress, "DIRTY")
                    .with_evidence(format!("{dirty} changed path(s)"))
            }
        }
    };

    let candidate_record = [Phase::Test, Phase::SecurityCode, Phase::Build]
        .into_iter()
        .find_map(|phase| {
            ledger
                .gates
                .get(&phase)
                .and_then(|record| record.candidate.as_ref().map(|capture| (phase, capture)))
        });
    let candidate_is_stale = freshness
        .stale
        .iter()
        .any(|item| item.phase <= Phase::Build);
    let candidate = match candidate_record {
        None => WorkflowFact::new(WorkflowOutcome::NotRun, "NOT CAPTURED").with_evidence(format!(
            "planning subject: HEAD at {}",
            ledger.phase.label()
        )),
        Some((phase, capture)) if candidate_is_stale => {
            WorkflowFact::new(WorkflowOutcome::Stale, "STALE").with_evidence(format!(
                "{} candidate {}",
                phase.label(),
                capture.subject.id
            ))
        }
        Some((phase, capture)) => WorkflowFact::new(WorkflowOutcome::Pass, "CURRENT")
            .with_evidence(format!(
                "{} candidate {}",
                phase.label(),
                capture.subject.id
            )),
    };

    let gate_fact = if freshness.effective_phase < freshness.stored_phase {
        WorkflowFact::new(WorkflowOutcome::Stale, "STALE").with_evidence(format!(
            "rewind {} -> {}",
            freshness.stored_phase.label(),
            freshness.effective_phase.label()
        ))
    } else if let Some(record) = ledger.gates.get(&ledger.phase) {
        match record.verdict {
            Verdict::Pass => WorkflowFact::new(WorkflowOutcome::InProgress, ledger.phase.label()),
            Verdict::ConditionalPass => {
                WorkflowFact::new(WorkflowOutcome::Conditional, ledger.phase.label())
            }
            Verdict::Fail => WorkflowFact::new(WorkflowOutcome::Fail, ledger.phase.label()),
        }
    } else if ledger.phase == Phase::Done {
        WorkflowFact::new(WorkflowOutcome::Pass, "ALL CURRENT")
    } else {
        WorkflowFact::new(WorkflowOutcome::InProgress, ledger.phase.label())
    };

    let stored_validation = [Phase::Test, Phase::SecurityCode, Phase::Build]
        .into_iter()
        .find_map(|phase| {
            ledger.gates.get(&phase).and_then(|record| {
                record
                    .validation_receipt
                    .as_ref()
                    .map(|receipt| (phase, receipt))
            })
        });
    let (local_validation, containment) = if candidate_is_stale && stored_validation.is_some() {
        let error = "candidate validation receipt is stale";
        (receipt_failure_fact(error), blocked_containment(error))
    } else if let Some((phase, receipt)) = stored_validation {
        match crate::local_validation::validate_receipt_for_status(receipt) {
            Ok(()) => {
                let full_profile = phase == Phase::Test
                    && config.local_validation.as_ref().is_some_and(|local| {
                        receipt.profile == local.gates.test
                            || receipt.profile == local.gates.high_risk_test
                    });
                current_receipt_status(receipt, full_profile)
            }
            Err(error) => (
                WorkflowFact::new(WorkflowOutcome::Blocked, "BLOCKED").with_evidence(error.clone()),
                blocked_containment(&error),
            ),
        }
    } else if ledger.archive_closure.is_some() && coherence.is_some_and(|value| value.coherent) {
        match config.local_validation.as_ref() {
            None => {
                let error = "structured local_validation is absent";
                (
                    WorkflowFact::new(WorkflowOutcome::Blocked, "MISSING"),
                    blocked_containment(error),
                )
            }
            Some(local) => {
                // design.md Condition 8: share the exact same selection
                // helper the strict gate executor uses. Post-archive there
                // is no live `manifest.json` to reload (the change
                // directory has already moved into `openspec/changes/
                // archive/...`), so the closest live stand-in is the
                // closure's own frozen `allowed_paths` — the declared scope
                // merged with system-owned paths at archive time. Because
                // that merge always includes the change's own sensitive
                // `.mpd/state/<change>.json` ledger path, the predicate can
                // never hold here, so this always resolves to exactly
                // today's High/non-High split — a fail-safe, not a gap.
                let synthetic_manifest = ledger
                    .archive_closure
                    .as_ref()
                    .map(|record| closure::ChangeManifest {
                        version: closure::MANIFEST_SCHEMA,
                        paths: record.allowed_paths.clone(),
                        shared_paths: Vec::new(),
                        publish: None,
                    })
                    .unwrap_or_else(closure::ChangeManifest::seed);
                match closure::select_gate_profile(
                    local,
                    Phase::Test,
                    &synthetic_manifest,
                    &ledger.change,
                    ledger.effective_risk(),
                ) {
                    Err(error) => (receipt_failure_fact(&error), blocked_containment(&error)),
                    Ok(profile) => {
                        match crate::local_validation::doctor_runtime_receipt_health(
                            root, local, &profile,
                        ) {
                            Ok(health) => current_validation_status(
                                &health.profile,
                                &health.receipt_id,
                                &health.sandbox,
                                &health.results,
                                "passed",
                                true,
                            ),
                            Err(error) => {
                                (receipt_failure_fact(&error), blocked_containment(&error))
                            }
                        }
                    }
                }
            }
        }
    } else {
        let error = "required full local profile receipt is missing";
        (
            WorkflowFact::new(WorkflowOutcome::NotRun, "MISSING"),
            blocked_containment(error),
        )
    };

    let archive = match ledger.archive_closure.as_ref() {
        Some(record) => WorkflowFact::new(WorkflowOutcome::Pass, "ARCHIVED")
            .with_evidence(record.post_archive_digest.to_string()),
        None if ledger.phase == Phase::Done => {
            WorkflowFact::new(WorkflowOutcome::InProgress, "READY")
        }
        None => WorkflowFact::new(WorkflowOutcome::NotRun, "NOT RUN"),
    };
    let commit = match (ledger.archive_closure.as_ref(), coherence) {
        (None, _) => WorkflowFact::new(WorkflowOutcome::NotRun, "NOT RUN"),
        (Some(_), Some(value)) if value.coherent => {
            WorkflowFact::new(WorkflowOutcome::Pass, "COHERENT")
                .with_evidence(value.head.clone().unwrap_or_default())
        }
        (Some(_), Some(value)) => WorkflowFact::new(WorkflowOutcome::Blocked, "BLOCKED")
            .with_evidence(value.blockers.join("; ")),
        (Some(_), None) => WorkflowFact::new(WorkflowOutcome::NotRun, "NOT OBSERVED"),
    };

    let head = git::head_commit(root).ok().flatten();
    let authorization = crate::local_validation::load_push_authorization_audit(root);
    let matching_authorization = authorization.as_ref().ok().and_then(|authorization| {
        authorization.as_ref().and_then(|authorization| {
            let update = authorization.updates.iter().find(|update| {
                head.as_deref() == Some(update.local_oid.as_str())
                    && parity.is_none_or(|observation| {
                        authorization.remote_name == observation.remote
                            && update.remote_ref == observation.reference
                    })
            })?;
            Some((authorization, update))
        })
    });
    let parity_current = parity.is_some_and(|observation| {
        observation.state == closure::ParityState::Verified
            && head.as_deref() == Some(observation.local_oid.as_str())
            && observation.remote_oid.as_deref() == head.as_deref()
    });
    let push_authorization = match (&authorization, matching_authorization) {
        (Err(error), _) => {
            WorkflowFact::new(WorkflowOutcome::Blocked, "BLOCKED").with_evidence(error.clone())
        }
        (_, Some((authorization, _))) => WorkflowFact::new(WorkflowOutcome::Pass, "CURRENT")
            .with_evidence(authorization.authorization_id.clone()),
        (Ok(Some(authorization)), None) => WorkflowFact::new(WorkflowOutcome::Stale, "STALE")
            .with_evidence(authorization.authorization_id.clone()),
        (Ok(None), None) if parity_current => {
            WorkflowFact::new(WorkflowOutcome::Blocked, "BYPASSED")
        }
        (Ok(None), None) => WorkflowFact::new(WorkflowOutcome::NotRun, "MISSING"),
    };
    let remote_parity = match parity {
        // Security-code Condition 18: the ref-level classification and the
        // raw landing-containment fact are surfaced as evidence alongside
        // the per-change verdict in every case where an observation exists
        // — a Verified/Blocked label alone cannot distinguish "the ref is
        // also ahead/behind" from "the landing itself never reached the
        // remote".
        Some(observation) if parity_current => WorkflowFact::new(WorkflowOutcome::Pass, "VERIFIED")
            .with_evidence(format!(
                "{}; {}",
                observation.local_oid,
                describe_ref_level_parity(observation)
            )),
        Some(observation) if head.as_deref() != Some(observation.local_oid.as_str()) => {
            WorkflowFact::new(WorkflowOutcome::Stale, "STALE")
                .with_evidence(observation.local_oid.clone())
        }
        Some(observation) => WorkflowFact::new(WorkflowOutcome::Blocked, observation.state.label())
            .with_evidence(describe_ref_level_parity(observation)),
        None => WorkflowFact::new(WorkflowOutcome::NotRun, "NOT VERIFIED"),
    };
    let transfer = match (matching_authorization, parity_current) {
        (Some((_, update)), true) if update.remote_oid != update.local_oid => {
            WorkflowFact::new(WorkflowOutcome::Pass, "OBSERVED")
                .with_evidence(format!("{} -> {}", update.remote_oid, update.local_oid))
        }
        (None, true) => WorkflowFact::new(WorkflowOutcome::Blocked, "UNAUTHORIZED/BYPASSED"),
        _ => WorkflowFact::new(WorkflowOutcome::NotRun, "NOT OBSERVED"),
    };

    let install = match ledger
        .gates
        .get(&Phase::Deploy)
        .and_then(|gate| gate.deploy_result.as_ref())
    {
        None => WorkflowFact::new(WorkflowOutcome::NotRun, "NOT RUN"),
        Some(result) if result.mode == "readiness" && result.verified => {
            WorkflowFact::new(WorkflowOutcome::Pass, "readiness-only")
                .with_evidence(result.result_digest.clone())
        }
        Some(result) if result.mode == "execute" && result.verified => {
            match config
                .local_validation
                .as_ref()
                .map(|local| doctor_installed_deploy_health(root, local, ledger))
            {
                Some(Ok(())) => WorkflowFact::new(WorkflowOutcome::Pass, "installed-and-verified")
                    .with_evidence(result.result_digest.clone()),
                Some(Err(error)) => {
                    WorkflowFact::new(WorkflowOutcome::Blocked, "BLOCKED").with_evidence(error)
                }
                None => WorkflowFact::new(WorkflowOutcome::Blocked, "BLOCKED"),
            }
        }
        Some(result) => WorkflowFact::new(WorkflowOutcome::Fail, "FAILED")
            .with_evidence(result.result_digest.clone()),
    };

    let next_action = if freshness.effective_phase < freshness.stored_phase {
        "run `mpd next` to record the required freshness rewind".into()
    } else if ledger.phase != Phase::Done {
        "run `mpd next --harness codex --context`".into()
    } else if ledger.archive_closure.is_none() {
        "run `mpd archive --yes`".into()
    } else if !coherence.is_some_and(|value| value.coherent) {
        "commit the exact archived result with normal Git".into()
    } else if !matches!(push_authorization.state.as_str(), "CURRENT") {
        "run a normal non-force `git push`; the local pre-push hook must authorize it".into()
    } else if !parity_current {
        "run `mpd publish --verify` after Git transport completes".into()
    } else if !matches!(
        install.state.as_str(),
        "installed-and-verified" | "readiness-only"
    ) {
        "complete the typed final Deploy gate".into()
    } else {
        "no further workflow action is required".into()
    };

    WorkflowStatus {
        worktree,
        candidate,
        gates: gate_fact,
        local_validation,
        archive,
        commit,
        push_authorization,
        transfer,
        remote_parity,
        install,
        containment,
        next_action,
    }
}

fn print_workflow_status(status: &WorkflowStatus) {
    println!("\nWorkflow truth:");
    for (label, fact) in [
        ("Worktree", &status.worktree),
        ("Candidate", &status.candidate),
        ("Gates/freshness", &status.gates),
        ("Local validation", &status.local_validation),
        ("Archive", &status.archive),
        ("Commit", &status.commit),
        ("Push authorization", &status.push_authorization),
        ("Transfer", &status.transfer),
        ("Remote parity", &status.remote_parity),
        ("Install", &status.install),
    ] {
        println!(
            "  {:<19} {:<11} {}",
            label,
            fact.outcome.label(),
            harness::terminal_safe(&fact.state)
        );
        if let Some(evidence) = &fact.evidence {
            println!("    evidence: {}", harness::terminal_safe(evidence));
        }
    }
    println!("  Containment:");
    println!(
        "    adapter={} full-profile={} certified-claim={}",
        status.containment.adapter,
        status.containment.full_local_profile,
        status.containment.certified_claim
    );
    println!(
        "    host={} spi/abi={} fixed-profile={} root-inventories={}",
        status
            .containment
            .host
            .as_deref()
            .map(harness::terminal_safe)
            .unwrap_or_else(|| "(not observed)".into()),
        status
            .containment
            .spi_abi_digest
            .as_deref()
            .unwrap_or("(not observed)"),
        status
            .containment
            .fixed_profile_digest
            .as_deref()
            .unwrap_or("(not observed)"),
        status.containment.root_inventory_digests.len(),
    );
    println!(
        "    canaries={} compiler-tree={}",
        status.containment.canaries.outcome.label(),
        harness::terminal_safe(&status.containment.compiler_process_tree.state)
    );
    for limitation in &status.containment.residual_limitations {
        println!("    limitation: {}", harness::terminal_safe(limitation));
    }
    if let (Some(code), Some(action)) = (
        &status.containment.blocker_code,
        &status.containment.blocker_action,
    ) {
        println!("    blocker: {code}");
        println!("    action: {}", harness::terminal_safe(action));
    }
    println!(
        "  Next action: {}",
        harness::terminal_safe(&status.next_action)
    );
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

fn current_risk_assessment(
    root: &Path,
    change: &str,
    ledger: &ledger::Ledger,
    config: &Config,
) -> Result<ledger::RiskAssessment, String> {
    let manifest = closure::load_manifest(root, change).map_err(|error| error.to_string())?;
    Ok(closure::classify_effective_risk(
        &manifest,
        config,
        ledger.governance.risk,
        change,
    ))
}

/// Refresh risk and stop immediately if current PASS evidence projects an
/// earlier phase. The compare-before-atomic-save path prevents a stale command
/// from overwriting a concurrently changed ledger.
fn enforce_freshness_before_effects(
    root: &Path,
    change: &str,
    ledger: &mut ledger::Ledger,
    observed: &str,
    config: &Config,
    json: bool,
) -> Result<bool, String> {
    let assessment = current_risk_assessment(root, change, ledger, config)?;
    let projection = closure::freshness_projection(root, change, ledger, config)?;
    let assessment_changed = ledger.risk_assessment.as_ref() != Some(&assessment);
    ledger.risk_assessment = Some(assessment.clone());
    if projection.effective_phase < projection.stored_phase {
        let stale_phases = projection.stale.iter().map(|item| item.phase).collect();
        let reasons = projection
            .stale
            .iter()
            .flat_map(|item| {
                item.reasons
                    .iter()
                    .map(move |reason| format!("{}: {reason}", item.phase.slug()))
            })
            .collect();
        ledger.invalidate_for_freshness(projection.effective_phase, stale_phases, reasons)?;
        ledger::save_if_observed(root, ledger, observed).map_err(|error| error.to_string())?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "state": "rewound",
                    "stored_phase": projection.stored_phase.slug(),
                    "effective_phase": projection.effective_phase.slug(),
                    "stale": projection.stale,
                    "risk_assessment": assessment,
                    "next": "run mpd next again after reviewing the rewind",
                }))
                .unwrap()
            );
        } else {
            eprintln!(
                "Stale evidence rewound {} to {} before any downstream action. Re-run `mpd next`.",
                projection.stored_phase.label(),
                projection.effective_phase.label()
            );
        }
        return Ok(true);
    }
    if assessment_changed {
        ledger::save_if_observed(root, ledger, observed).map_err(|error| error.to_string())?;
    }
    Ok(false)
}

fn cmd_status(change: Option<String>, json: bool, brief: bool) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    let config = Config::load(&root);
    let risk = current_risk_assessment(&root, &change, &ledger, &config)?;
    let freshness = closure::freshness_projection(&root, &change, &ledger, &config)?;
    let project = Project::new(&root);
    let tasks = project.task_status(&change).unwrap_or_default();
    let task_plan = project
        .task_plan(&change)
        .map_err(|error| format!("invalid tasks.md: {error}"))?;
    let task_accounting = ledger.task_accounting(&task_plan);
    // Readiness = the ledger's gate/condition reasons PLUS unfilled core-artifact
    // stubs (which `mpd archive` also refuses), so status and archive agree.
    let mut reasons = ledger.blocking_reasons();
    reasons.extend(current_evidence_blockers(&root, &change, &ledger));
    if freshness.effective_phase < freshness.stored_phase {
        reasons.push(format!(
            "stale evidence requires rewind from {} to {}",
            freshness.stored_phase.label(),
            freshness.effective_phase.label()
        ));
    }
    if task_plan.strict && !task_accounting.accounted() {
        if !task_accounting.open.is_empty() {
            reasons.push(format!(
                "{} Builder task(s) open: {}",
                task_accounting.open.len(),
                task_accounting.open.join(", ")
            ));
        }
        for id in &task_accounting.stale {
            reasons.push(format!("task deferral for {id} is stale"));
        }
    }
    reasons.extend(artifact_stub_issues(&project, &change));
    let ready = reasons.is_empty();
    let artifact_budget = artifact_budget(&project, &change, risk.effective);
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
    let workflow = workflow_status(
        &root,
        &ledger,
        &config,
        &freshness,
        coherence.as_ref(),
        parity.as_ref(),
    );

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
            "stored_phase": freshness.stored_phase.slug(),
            "effective_phase": freshness.effective_phase.slug(),
            "freshness": freshness,
            "gates": gates,
            "tasks": { "done": task_accounting.done, "deferred": task_accounting.deferred, "open": task_accounting.open.len(), "stale": task_accounting.stale, "total": task_accounting.total, "legacy_done": tasks.done, "legacy_total": tasks.total },
            "ready_to_archive": ready,
            "introduced_by": ledger.introduced_by,
            "blocking_reasons": reasons,
            "history": serde_json::to_value(&ledger.history).unwrap_or(serde_json::Value::Null),
            "governance": ledger.governance,
            "risk_assessment": risk,
            "artifact_budget": artifact_budget,
            "current_attempt": ledger.next_attempt(ledger.phase),
            "attempt_limit": risk.effective.attempt_limit(),
            "reconciliation_required": !ledger.attempt_authorized(ledger.phase),
            "attempt_authorization": attempt_authorization,
            "evidence": evidence,
            "manifest": manifest,
            "commit_coherence": coherence.as_ref().map(|c| serde_json::json!({"coherent":c.coherent,"head":c.head,"ready_to_commit":c.ready_to_commit,"blockers":c.blockers})),
            "remote_parity": parity,
            "workflow": workflow,
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
        if let Some(origin) = &ledger.introduced_by {
            println!("Introduced by: {}", harness::terminal_safe(origin));
        }
        println!(
            "Governance: requested {}, derived {}, effective {}; threat profile {} — review attempt {}/{}",
            risk.requested,
            risk.derived,
            risk.effective,
            ledger.governance.threat_profile,
            ledger.next_attempt(ledger.phase),
            risk.effective.attempt_limit()
        );
        println!(
            "Workflow: {} — {}",
            workflow.gates.outcome.label(),
            harness::terminal_safe(&workflow.next_action)
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
    if let Some(origin) = &ledger.introduced_by {
        println!(
            "Introduced by: {} (defect-escape provenance)",
            harness::terminal_safe(origin)
        );
    }
    println!(
        "Governance: requested {}, derived {}, effective {}; threat profile {}",
        risk.requested, risk.derived, risk.effective, ledger.governance.threat_profile
    );
    println!(
        "Review attempt: {}/{}",
        ledger.next_attempt(ledger.phase),
        risk.effective.attempt_limit()
    );
    if let Some(kind) = &attempt_authorization {
        println!(
            "Excess attempt {} authorized by {} reconciliation (base limit {}).",
            ledger.next_attempt(ledger.phase),
            kind,
            risk.effective.attempt_limit()
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

    println!(
        "\nTasks: {} done, {} deferred, {} open, {} total",
        task_accounting.done,
        task_accounting.deferred,
        task_accounting.open.len(),
        task_accounting.total
    );
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
        println!("  {}", describe_ref_level_parity(p));
    } else {
        println!("\nRemote parity: NOT VERIFIED");
    }
    print_workflow_status(&workflow);
    if ready {
        println!("Ready to archive: yes");
    } else {
        println!("Ready to archive: no");
        for r in &reasons {
            println!("  - {r}");
        }
    }

    // Point the operator at the next command instead of leaving it to be guessed.
    let open_conditions = ledger.conditions.iter().filter(|c| c.is_open()).count();
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
                .unwrap_or("run `mpd archive --recover`")
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
    let (mut ledger, observed) =
        ledger::load_observed(&root, &change).map_err(|e| e.to_string())?;
    // Archived changes no longer have an active manifest/change directory.
    // Their publication closure is immutable evidence, so preserve the
    // existing read-only terminal response without attempting active-change
    // risk/freshness capture.
    if ledger.phase == Phase::Done && ledger.archive_closure.is_some() {
        let release_closure = release_closure_facts(&root, &change, &ledger);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "change": change,
                    "phase": "done",
                    "archived": true,
                    "release_closure": release_closure,
                }))
                .unwrap()
            );
            return Ok(0);
        }
        print_release_closure_facts(&release_closure);
        if release_closure["pending_closure"].is_null() {
            println!(
                "{change:?} is archived and its closure metadata is resolved. Run \
                 `mpd publish --verify` to (re)confirm remote parity."
            );
        }
        return Ok(0);
    }
    let cfg = Config::load(&root);
    if enforce_freshness_before_effects(&root, &change, &mut ledger, &observed, &cfg, json)? {
        return Ok(1);
    }
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
    let risk = ledger
        .risk_assessment
        .clone()
        .ok_or("risk assessment missing after freshness preflight")?;
    let page_warning = artifact_budget(&Project::new(&root), &change, risk.effective).warning;
    let mut effective_governance = ledger.governance.clone();
    effective_governance.risk = risk.effective;
    let mut brief = harness::brief(
        &cfg,
        &change,
        ledger.phase,
        &harness_kind,
        &effective_governance,
        ledger.strict,
        ledger.next_attempt(ledger.phase),
        !ledger.attempt_authorized(ledger.phase),
        ledger
            .attempt_authorization(ledger.phase)
            .map(|r| r.kind.label().to_string()),
        page_warning,
    );

    // Resolve the phase persona's base directive(s) ONCE (round-4 F4-2), shared
    // with the `--full` display below. `base_modified` (a divergent base directive
    // file — the second un-rankable weakening vector) is folded into the brief's
    // `weakened` flag and RECORDED into `brief_tuning` UNCONDITIONALLY and
    // PRE-BRANCH here — before the `--json`/`--context`/`--full` branches — so a
    // plain `mpd next` still records it (round-4 F4-1). A gate-time live re-read
    // would re-open the `edit directive → next → restore → gate` TOCTOU (round-3 F1).
    let phase_directives: Vec<(String, crate::directives::Directive)> = ledger
        .phase
        .tuning_personas()
        .into_iter()
        .filter_map(|n| crate::directives::for_persona(&root, n).map(|d| (n.to_string(), d)))
        .collect();
    let base_modified = phase_directives.iter().any(|(_, d)| d.modified);
    if base_modified {
        brief.weakened = true;
        let msg = "modified base directive (un-rankable — recorded)";
        brief.tuning_note = Some(match brief.tuning_note.take() {
            Some(n) => format!("{n}; {msg}"),
            None => format!("persona tuning: {msg}"),
        });
    }
    // Record the brief-time weakening determination (config tuning + base_modified)
    // for (phase, attempt), monotonic weakest-seen; only when non-baseline, so an
    // untuned+unmodified project's ledger is byte-unchanged by `next` (Cond 11).
    {
        let resolved = harness::resolve_tuning_governed(&cfg, ledger.phase, risk.effective);
        let record = ledger::PersonaTuningRecord {
            rigor: resolved.rigor,
            depth: resolved.depth,
            had_append: resolved.had_append,
            base_modified,
            weakened: resolved.had_append || base_modified,
        };
        if !record.is_baseline() {
            let attempt = ledger.next_attempt(ledger.phase);
            let phase = ledger.phase;
            ledger.record_brief_tuning(phase, attempt, record);
            ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
        }
    }
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

    // With --full, inline the phase persona's directive(s) — the SAME resolution
    // used for `base_modified` above (resolved once, round-4 F4-2). A composite
    // persona (Doc Validation) already resolved its two parts.
    let no_directives: Vec<(String, crate::directives::Directive)> = Vec::new();
    let directives: &Vec<(String, crate::directives::Directive)> = if full {
        &phase_directives
    } else {
        &no_directives
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
        v["risk_assessment"] = serde_json::to_value(&risk).unwrap_or(serde_json::Value::Null);
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
    for (persona, d) in directives {
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

/// The persona-tuning stamp for a gate on `(phase, attempt)`. It derives the
/// stamp from the brief `mpd next` recorded for this exact `(phase, attempt)` when
/// present — closing the `next`→`gate` TOCTOU (design.md Cond 11) — and falls back
/// to a LIVE determination (config tuning + directive `base_modified`) only when no
/// matching brief was recorded (a manual `gate` with no preceding `next`, or a
/// stale superseded record). Returns `None` at baseline (untuned + unmodified), so
/// a baseline gate is unstamped and byte-identical. Note: the fallback recomputes
/// from config + directives (NO gate-time-only source), and it is the ONLY
/// directive read in the stamp path — there is no `directives::for_persona` call in
/// the `GateRecord` construction itself (round-4 F4-1).
fn persona_tuning_stamp(
    root: &Path,
    cfg: &Config,
    ledger: &ledger::Ledger,
    phase: Phase,
    attempt: usize,
) -> Option<ledger::PersonaTuningRecord> {
    if let Some(rec) = ledger.brief_tuning_for(phase, attempt) {
        return (!rec.is_baseline()).then(|| rec.clone());
    }
    let resolved = harness::resolve_tuning_governed(cfg, phase, ledger.effective_risk());
    let base_modified = phase
        .tuning_personas()
        .into_iter()
        .filter_map(|n| crate::directives::for_persona(root, n))
        .any(|d| d.modified);
    let record = ledger::PersonaTuningRecord {
        rigor: resolved.rigor,
        depth: resolved.depth,
        had_append: resolved.had_append,
        base_modified,
        weakened: resolved.had_append || base_modified,
    };
    (!record.is_baseline()).then_some(record)
}

/// Parse the `--exploit` value into a structured [`Exploitability`]: exactly five
/// `|`-delimited fields (attacker|capability|boundary|harm|fix), each
/// `bounded_text`-validated (non-blank, trimmed, ≤500). A wrong field count or a
/// blank field ERRORS — a Security FAIL never records with partial/empty exploit
/// evidence (design.md D4 / Security-plan Finding 1). A literal `|` inside a field
/// is unsupported; the fields are short structured phrases, not prose.
fn parse_exploit(raw: &str) -> Result<Exploitability, String> {
    let parts: Vec<&str> = raw.split('|').collect();
    if parts.len() != 5 {
        return Err(format!(
            "--exploit must be exactly five `|`-delimited fields \
             (attacker|capability|boundary|harm|fix); got {}",
            parts.len()
        ));
    }
    Ok(Exploitability {
        attacker: bounded_text(parts[0], "attacker")?,
        capability: bounded_text(parts[1], "capability")?,
        boundary: bounded_text(parts[2], "boundary")?,
        harm: bounded_text(parts[3], "harm")?,
        fix: bounded_text(parts[4], "fix")?,
    })
}

pub(crate) struct PendingCandidateBuild {
    captured: Option<crate::candidate::CapturedCandidate>,
    build_output: Option<crate::local_validation::OwnedCandidateBuildOutput>,
}

impl PendingCandidateBuild {
    pub(crate) fn new(captured: crate::candidate::CapturedCandidate) -> Self {
        Self {
            captured: Some(captured),
            build_output: None,
        }
    }

    pub(crate) fn attach_output(
        &mut self,
        output: crate::local_validation::OwnedCandidateBuildOutput,
    ) {
        self.build_output = Some(output);
    }

    fn capture(&self) -> &crate::candidate::CandidateCapture {
        &self
            .captured
            .as_ref()
            .expect("pending candidate ownership is armed")
            .projection
            .capture
    }

    fn captured(&self) -> &crate::candidate::CapturedCandidate {
        self.captured
            .as_ref()
            .expect("pending candidate ownership is armed")
    }

    pub(crate) fn revalidate_output(&self, root: &Path) -> Result<(), String> {
        self.build_output
            .as_ref()
            .ok_or("pending candidate Build has no owned typed output")?
            .revalidate(root)
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        let mut preserve_candidate = false;
        if let Some(mut output) = self.build_output.take() {
            if let Err(error) = output.cleanup() {
                preserve_candidate = output.destination_exists();
                errors.push(error);
            }
        }
        if preserve_candidate {
            let _ = self.captured.take();
            errors.push(
                "candidate retained because output cleanup could not prove the versioned path was unbound"
                    .into(),
            );
        } else if let Some(captured) = self.captured.take() {
            if let Err(error) = captured.cleanup() {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// The durable ledger now owns the compact binding. Dropping the runtime
    /// handle without calling cleanup intentionally retains the root/sidecar
    /// for Security(code), Test, and closure.
    fn retain_after_ledger_commit(&mut self) {
        if let Some(output) = self.build_output.as_mut() {
            output.retain();
        }
        let _ = self.build_output.take();
        let _ = self.captured.take();
    }
}

pub(crate) fn resolve_candidate_save_outcome(
    root: &Path,
    pending: Option<&mut PendingCandidateBuild>,
    outcome: ledger::ExactSaveOutcome,
) -> Result<Option<String>, String> {
    match outcome {
        ledger::ExactSaveOutcome::Committed => {
            if let Some(pending) = pending {
                if let Err(error) = pending.revalidate_output(root) {
                    pending.retain_after_ledger_commit();
                    return Err(format!(
                        "Build output changed after the exact ledger commit; durable candidate state was preserved for append-only reconciliation: {error}"
                    ));
                }
                pending.retain_after_ledger_commit();
            }
            Ok(None)
        }
        ledger::ExactSaveOutcome::CommittedAfterRename { error } => {
            if let Some(pending) = pending {
                if let Err(output_error) = pending.revalidate_output(root) {
                    pending.retain_after_ledger_commit();
                    return Err(format!(
                        "ledger commit was confirmed after a post-rename error, but Build output revalidation failed; durable candidate state was preserved for append-only reconciliation: {error}; {output_error}"
                    ));
                }
                pending.retain_after_ledger_commit();
            }
            Ok(Some(format!(
                "ledger commit was confirmed by exact readback after a post-rename error: {error}"
            )))
        }
        ledger::ExactSaveOutcome::NotCommitted(error) => Err(error.to_string()),
        ledger::ExactSaveOutcome::UncertainAfterRename(error) => {
            let output_state = pending
                .as_deref()
                .and_then(|pending| pending.revalidate_output(root).err());
            if let Some(pending) = pending {
                pending.retain_after_ledger_commit();
            }
            Err(match output_state {
                Some(output) => format!(
                    "ledger commit remains uncertain and Build output revalidation failed; candidate state was preserved: {error}; {output}"
                ),
                None => format!(
                    "ledger commit remains uncertain; candidate state was preserved for reconciliation: {error}"
                ),
            })
        }
    }
}

impl Drop for PendingCandidateBuild {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("candidate-transaction-cleanup-blocked: {error}");
        }
    }
}

fn execute_strict_candidate_build(
    root: &Path,
    change: &str,
    expected_policy: &crate::config::LocalValidationConfig,
    profile: &str,
) -> Result<
    (
        PendingCandidateBuild,
        crate::local_validation::ValidationReport,
    ),
    String,
> {
    let (candidate_policy, policy_digest) = crate::local_validation::load_candidate_policy(root)?;
    if candidate_policy != *expected_policy {
        return Err("Build policy changed between strict config load and candidate capture".into());
    }
    let captured = crate::candidate::capture_candidate(root, change, &policy_digest)?;
    let mut pending = PendingCandidateBuild::new(captured);
    let outcome = (|| {
        pending.captured().rehash(root)?;
        crate::candidate::reopen_candidate(root, pending.capture())?;
        let validation = crate::local_validation::validate_candidate_profile(
            root,
            pending.captured().root(),
            pending.capture(),
            profile,
            &candidate_policy,
        )?;
        if let Some(output) = validation.build_output {
            pending.attach_output(output);
        }
        let report = validation.report;
        if report.status != "passed" {
            return Err(format!(
                "Build candidate profile {profile:?} refused: {}",
                report.blocker.as_deref().unwrap_or(&report.status)
            ));
        }
        pending.captured().rehash(root)?;
        crate::candidate::reopen_candidate(root, pending.capture())?;
        pending.revalidate_output(root)?;
        let output = report
            .receipt
            .as_ref()
            .and_then(|receipt| receipt.build_output.as_ref())
            .ok_or("Build candidate profile passed without a typed BuildOutputV1")?;
        if output.candidate_id.as_deref() != Some(pending.capture().subject.id.as_str()) {
            return Err("Build output does not bind the executed candidate ID".into());
        }
        Ok(report)
    })();
    match outcome {
        Ok(report) => Ok((pending, report)),
        Err(error) => match pending.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; candidate cleanup also failed: {cleanup}")),
        },
    }
}

fn retained_candidate_for_objective_gate(
    ledger: &ledger::Ledger,
    change: &str,
    phase: Phase,
) -> Result<crate::candidate::CandidateCapture, String> {
    if !matches!(phase, Phase::SecurityCode | Phase::Test) {
        return Err(format!(
            "{} is not a retained-candidate objective gate",
            phase.label()
        ));
    }
    let build = ledger
        .gates
        .get(&Phase::Build)
        .filter(|record| record.verdict == Verdict::Pass)
        .ok_or("candidate-bound objective gate requires a current Build PASS")?;
    let capture = build
        .candidate
        .as_ref()
        .ok_or("current Build PASS has no retained Candidate binding")?;
    if capture.subject.change != change {
        return Err("current Build Candidate names a different change".into());
    }
    let output = build
        .build_output
        .as_ref()
        .ok_or("current Build PASS has no candidate-bound Build output")?;
    if output.candidate_id.as_deref() != Some(capture.subject.id.as_str()) {
        return Err("current Build output and Candidate IDs differ".into());
    }
    if phase == Phase::Test {
        let security = ledger
            .gates
            .get(&Phase::SecurityCode)
            .filter(|record| record.verdict == Verdict::Pass)
            .ok_or("candidate-bound Test requires a current Security(code) PASS")?;
        if security.candidate.as_ref() != Some(capture) {
            return Err("Build and Security(code) Candidate bindings differ".into());
        }
    }
    Ok(capture.clone())
}

fn validate_candidate_report_binding(
    report: &crate::local_validation::ValidationReport,
    capture: &crate::candidate::CandidateCapture,
) -> Result<(), String> {
    let expected_request = format!("candidate:{}", capture.subject.id);
    let receipt = report
        .receipt
        .as_ref()
        .ok_or("candidate profile passed without an ephemeral result receipt")?;
    for (label, subject) in [("report", &report.subject), ("receipt", &receipt.subject)] {
        if subject.requested != expected_request
            || subject.pushed_kind != "candidate"
            || subject.commit != capture.subject.base_commit
            || subject.tree != capture.subject.base_tree
            || subject.pushed_oid != capture.subject.base_commit
            || !subject.tag_chain.is_empty()
        {
            return Err(format!(
                "candidate validation {label} subject differs from the retained Candidate"
            ));
        }
    }
    // Security-code Condition C3: pin the Build output's candidate_id to the
    // exact retained Candidate too, when the receipt carries a typed one.
    // The D1 eviction guard keys on `record.candidate.subject.id` and D2's
    // ledger-binding predicate keys on `build_output.candidate_id`
    // independently; neither previously cross-checked the two against each
    // other on this path, so a receipt whose subject matched the Candidate
    // but whose typed Build output named a DIFFERENT candidate would have
    // passed here undetected. Fail closed rather than trust the two fields
    // to cooperate.
    if let Some(output) = receipt.build_output.as_ref() {
        if output.candidate_id.as_deref() != Some(capture.subject.id.as_str()) {
            return Err(
                "candidate validation receipt's Build output candidate ID differs from the \
                 retained Candidate"
                    .into(),
            );
        }
    }
    Ok(())
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
    mut conditions: Vec<String>,
    failure_class: Option<String>,
    exploit: Option<String>,
    reuse: Option<String>,
) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let phase =
        Phase::from_slug(&phase_slug).ok_or_else(|| format!("unknown phase {phase_slug:?}"))?;
    let actor = bounded_text(
        &by.unwrap_or_else(|| phase.persona().name.to_string()),
        "gate actor",
    )?;

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
    // Strict judgment gates default an omitted *gate* evidence pointer to the
    // phase artifact. A conditional obligation must not silently inherit that
    // default, so preserve whether the caller supplied its evidence explicitly.
    let condition_evidence_supplied = evidence.is_some();

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
    // `--exploit` is MANDATORY on a Security FAIL — not merely validated-when-present
    // (Security-plan Finding 1): a Security FAIL must always carry a credible exploit
    // path. An exhaustive match (never `exploit.map(parse).transpose()?`, which would
    // let `None` record a FAIL with no exploitability) makes absence error identically
    // to a malformed value. `--reuse` forces Verdict::Pass, so `--exploit --reuse`
    // falls out of the third arm (refused).
    let exploitability =
        match (verdict, security, exploit) {
            (Verdict::Fail, true, Some(raw)) => Some(parse_exploit(&raw)?),
            (Verdict::Fail, true, None) => return Err(
                "a Security --fail requires --exploit \"attacker|capability|boundary|harm|fix\""
                    .into(),
            ),
            (_, _, Some(_)) => return Err("--exploit is valid only with a Security --fail".into()),
            (_, _, None) => None,
        };

    let (mut ledger, observed) =
        ledger::load_observed_exact(&root, &change).map_err(|e| e.to_string())?;
    if ledger.strict && !ledger.waivers.is_empty() {
        return Ok(gate_blocked(
            "strict gate refused: legacy artifact waivers are present; rewind and rerun the affected canonical gates",
        ));
    }
    if ledger.strict {
        if let Some(issue) = strict_actor_separation_issue(&ledger, phase, &actor) {
            return Ok(gate_blocked(&issue));
        }
    }
    // Candidate-backed objective gates are always fresh executions. Refuse a
    // reuse request before freshness/risk maintenance can write the ledger, so
    // an inapplicable receipt cannot advance or otherwise mutate strict state.
    if reuse.is_some()
        && ledger.strict
        && matches!(phase, Phase::Build | Phase::SecurityCode | Phase::Test)
    {
        return Err(format!(
            "strict {} is candidate-backed and cannot reuse a prior receipt",
            phase.label()
        ));
    }
    let config = Config::load(&root);
    if enforce_freshness_before_effects(
        &root,
        &change,
        &mut ledger,
        observed.digest(),
        &config,
        false,
    )? {
        return Ok(1);
    }
    // Freshness maintenance may itself have committed a risk-only ledger
    // update. Start the gate transaction from a new exact file observation so
    // the final compare-and-swap never relies on an image predating that write.
    let (fresh_ledger, observed) =
        ledger::load_observed_exact(&root, &change).map_err(|e| e.to_string())?;
    ledger = fresh_ledger;
    let effective_risk = ledger.effective_risk();
    if verdict == Verdict::ConditionalPass {
        if ledger.strict && conditions.is_empty() {
            return Err("--conditional requires at least one --condition".into());
        }
        conditions = conditions
            .iter()
            .map(|condition| bounded_text(condition, "condition"))
            .collect::<Result<Vec<_>, _>>()?;
    } else if !conditions.is_empty() {
        return Err("--condition is valid only with --conditional".into());
    }
    // Canonical judgment truth is checked for PASS, CONDITIONAL, and FAIL
    // before any objective command or durable mutation. A strict condition is
    // therefore bound to the same authored artifact that declared it.
    if ledger.strict && phase.judgment_artifact().is_some() {
        if let Some(message) =
            strict_artifact_issues(&root, &change, phase, effective_risk, verdict, &actor)
        {
            return Ok(gate_blocked(&message));
        }
        evidence = validate_evidence(&root, &change, phase, evidence)?;
    }
    let condition_binding = if verdict == Verdict::ConditionalPass && ledger.strict {
        if !condition_evidence_supplied {
            return Err("--conditional requires --evidence <contained-file[#anchor]>".into());
        }
        let pointer = evidence
            .as_deref()
            .expect("explicit condition evidence was checked above");
        Some(contained_evidence(&root, &change, pointer)?)
    } else {
        None
    };
    if reuse.is_none() && !ledger.attempt_authorized(phase) {
        return Err(format!("attempt {} exceeds the {}-risk limit; run `mpd reconcile --continue \"reason\"` (or narrow/change governance) first", ledger.next_attempt(phase), effective_risk));
    }
    let attempt = ledger.next_attempt(phase);
    // The persona-tuning stamp for this gate — from the brief `mpd next` recorded
    // for this exact (phase, attempt), else a live fallback (design.md Cond 11).
    // Computed once and applied at BOTH GateRecord sites (reuse + execute, Cond 6).
    let persona_stamp = persona_tuning_stamp(&root, &Config::load(&root), &ledger, phase, attempt);
    let completed = ledger::now_epoch_secs();
    let mut checks_summary: Option<CheckSummary> = None;
    let mut structured_gate_ran = false;
    let mut structured_build_output = None;
    let mut structured_validation_receipt = None;
    let mut deploy_result = None;
    let mut pending_candidate_build: Option<PendingCandidateBuild> = None;
    let mut gate_candidate: Option<crate::candidate::CandidateCapture> = None;

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
            if let Some(msg) =
                strict_artifact_issues(&root, &change, phase, effective_risk, Verdict::Pass, &actor)
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
                by: actor.clone(),
                evidence: Some(format!("reused from {receipt_hex}")),
                checks: None,
                at: date::today_utc(),
                failure_class: None,
                exploitability: None,
                attempt,
                started_at_epoch_secs: completed,
                completed_at_epoch_secs: completed,
                receipt: Some(receipt),
                persona_tuning: persona_stamp.clone(),
                candidate: None,
                build_output: None,
                deploy_result: None,
                validation_receipt: None,
            },
        )?;
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
        // Refuse an open/ambiguous strict task contract before any expensive
        // structured or legacy Test execution and before any receipt write.
        if phase == Phase::Test {
            let plan = Project::new(&root)
                .task_plan(&change)
                .map_err(|e| format!("Test gate refused: invalid tasks.md: {e}"))?;
            let accounting = ledger.task_accounting(&plan);
            if plan.strict && !accounting.accounted() {
                let preview = accounting
                    .open
                    .iter()
                    .take(12)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let suffix = if accounting.open.len() > 12 {
                    " …"
                } else {
                    ""
                };
                return Ok(gate_blocked(&format!(
                    "Test gate refused before execution: {} Builder task(s) remain open and {} deferral(s) stale: {preview}{suffix}",
                    accounting.open.len(), accounting.stale.len()
                )));
            }
        }
        // Under the strict tier, objective Build/Security(code)/Test execution
        // is delegated to the exact-subject structured validator. This happens
        // only after the judgment artifact has already been checked, so an
        // artifact/CLI mismatch cannot launch tools or publish a receipt.
        if ledger.strict && matches!(phase, Phase::Build | Phase::SecurityCode | Phase::Test) {
            if let Some(message) =
                strict_artifact_issues(&root, &change, phase, effective_risk, Verdict::Pass, &actor)
            {
                return Ok(gate_blocked(&message));
            }
            let cfg = Config::load_strict(&root)?;
            if let Some(local) = cfg.local_validation.as_ref() {
                // design.md Condition 12: prefer the single manifest/
                // assessment snapshot this command already established.
                // `effective_risk` above is already the freshly-recomputed,
                // just-saved value for THIS command (`enforce_freshness_
                // before_effects` ran, then the ledger was reloaded before
                // reading it). Reloading the manifest here is fail-safe by
                // construction rather than a rigor gap: `select_gate_profile`
                // requires BOTH the live predicate to hold AND this fixed
                // `effective_risk == Low`, so a manifest that widens between
                // reads only ever forces the full profile, never the reverse
                // (see `select_gate_profile`'s doc comment).
                let live_manifest =
                    closure::load_manifest(&root, &change).map_err(|error| error.to_string())?;
                let profile = closure::select_gate_profile(
                    local,
                    phase,
                    &live_manifest,
                    &change,
                    effective_risk,
                )?;
                let profile = profile.as_str();
                let report = if phase == Phase::Build {
                    // Fail-early manifest process-scope validation (design.md
                    // "Fail-early manifest process-scope validation"): a
                    // strict candidate retains only its DECLARED dirty
                    // paths, so an undeclared `openspec/changes/<change>/**`
                    // or durable-doc target is silently dropped from the
                    // candidate and only surfaces as a cryptic late `mpd
                    // archive` failure. Refuse here, before the candidate is
                    // even captured, with the exact entries to add.
                    let scope_gaps =
                        closure::missing_process_scope(&live_manifest, &change, cfg.docs_dir());
                    if !scope_gaps.is_empty() {
                        return Ok(gate_blocked(&format!(
                            "Build gate refused: manifest.json is missing required process-scope path(s): {}. Add them to openspec/changes/{change}/manifest.json \"paths\" and re-run the Build gate.",
                            scope_gaps.join(", ")
                        )));
                    }
                    let (pending, report) =
                        execute_strict_candidate_build(&root, &change, local, profile)?;
                    gate_candidate = Some(pending.capture().clone());
                    pending_candidate_build = Some(pending);
                    report
                } else {
                    let capture = retained_candidate_for_objective_gate(&ledger, &change, phase)?;
                    // Reopen and rehash the immutable projection immediately
                    // before and after execution. This is deliberately not a
                    // new capture of the later ambient worktree.
                    crate::candidate::reopen_candidate(&root, &capture)?;
                    let report = crate::local_validation::validate_candidate_profile(
                        &root,
                        Path::new(&capture.clone_private_root),
                        &capture,
                        profile,
                        local,
                    )?;
                    crate::candidate::reopen_candidate(&root, &capture)?;
                    gate_candidate = Some(capture);
                    report.report
                };
                if report.status != "passed" {
                    return Ok(gate_blocked(&format!(
                        "{} structured profile {profile:?} refused: {}",
                        phase.label(),
                        report.blocker.as_deref().unwrap_or(&report.status)
                    )));
                }
                let candidate = gate_candidate
                    .as_ref()
                    .ok_or("strict objective gate omitted its Candidate binding")?;
                // The ephemeral execution receipt is never a Commit/HEAD
                // substitute. Its exact subject must match the same Candidate
                // that will be written into the durable gate record.
                validate_candidate_report_binding(&report, candidate)?;
                let receipt = report
                    .receipt
                    .ok_or("structured validator passed without a receipt")?;
                let tests_passed: u64 = receipt
                    .results
                    .iter()
                    .filter_map(|result| result.count)
                    .sum();
                structured_build_output = receipt.build_output.clone();
                let command = format!(
                    "candidate {} profile {} (receipt {})",
                    candidate.subject.id, receipt.profile, receipt.id
                );
                checks_summary = Some(CheckSummary {
                    tests_passed: (tests_passed > 0).then_some(tests_passed as usize),
                    secrets_clean: matches!(phase, Phase::SecurityCode | Phase::Test)
                        .then_some(true),
                    scanner: matches!(phase, Phase::SecurityCode | Phase::Test)
                        .then(|| "builtin+gitleaks+semgrep+cargo-audit".to_string()),
                    command: Some(command),
                });
                structured_validation_receipt = Some(receipt);
                structured_gate_ran = true;
            } else {
                if ledger.strict {
                    return Ok(gate_blocked(
                        "strict objective gate requires local_validation migration; legacy test/deploy strings are manual-only",
                    ));
                }
                eprintln!(
                    "warning: structured local_validation is absent; using deprecated legacy objective gate for manual compatibility. `mpd validate` and policy-aware hooks remain blocked until migration."
                );
            }
        }
        if phase.requires_tests() && !structured_gate_ran {
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
        if phase.requires_secret_scan() && !structured_gate_ran {
            let files = match checks::git_tracked_files(&root) {
                Ok(files) => files,
                Err(e) => {
                    return Ok(gate_blocked(&format!(
                        "{} gate refused: {e}",
                        phase.label()
                    )))
                }
            };
            let report = match checks::scan_secrets(&files) {
                Ok(report) => report,
                Err(e) => {
                    return Ok(gate_blocked(&format!(
                        "{} gate refused: {e}",
                        phase.label()
                    )))
                }
            };
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
        // Deploy has a closed typed branch in the strict tier. A string command
        // is deliberately retained only for manual/legacy changes: it has no
        // named Build receipt, no no-follow revalidation, and no byte-identity proof.
        if phase == Phase::Deploy {
            let cfg = if ledger.strict {
                Config::load_strict(&root)?
            } else {
                Config::load(&root)
            };
            if let Some(local) = cfg.local_validation.as_ref() {
                if let Err(error) = local.validate() {
                    return Ok(gate_blocked(&format!(
                        "Deploy gate refused: invalid typed local_validation: {error}"
                    )));
                }
                if let Some(deploy) = local.deploy_output.as_ref() {
                    let (contract, build) = match deploy {
                        crate::config::DeployOutputConfig::Execute { .. } => {
                            let contract = local.build_output.as_ref().ok_or_else(|| {
                                "Deploy gate refused: typed execute Deploy requires build_output"
                                    .to_string()
                            })?;
                            let build_record = ledger
                                .gates
                                .get(&Phase::Build)
                                .filter(|record| record.verdict == Verdict::Pass)
                                .ok_or_else(|| {
                                    "Deploy gate refused: current Build has no PASS record"
                                        .to_string()
                                })?;
                            let build = build_record.build_output.as_ref().ok_or_else(|| {
                                "Deploy gate refused: current Build has no typed BuildOutputV1 (provisional output is ineligible)".to_string()
                            })?;
                            if ledger.strict {
                                let values = closure::capture_dependency_values(
                                    &root,
                                    &change,
                                    &ledger,
                                    &cfg,
                                    Phase::Build,
                                )?;
                                if !matches!(
                                    closure::evidence_validity(
                                        build_record.receipt.as_ref(),
                                        &values
                                    ),
                                    closure::EvidenceValidity::Valid
                                ) {
                                    return Ok(gate_blocked(
                                        "Deploy gate refused: Build source/config receipt is stale or absent",
                                    ));
                                }
                            }
                            (Some(contract), Some(build))
                        }
                        crate::config::DeployOutputConfig::Readiness { .. } => (None, None),
                    };
                    match crate::local_validation::execute_typed_deploy(
                        &root, contract, deploy, build,
                    ) {
                        Ok(result) => {
                            checks_summary
                                .get_or_insert_with(CheckSummary::default)
                                .command = Some(format!(
                                "typed Deploy {} target={} definition={}",
                                result.mode, result.target, result.definition_digest
                            ));
                            deploy_result = Some(result);
                        }
                        Err(error) => {
                            return Ok(gate_blocked(&format!("Deploy gate refused: {error}")))
                        }
                    }
                } else {
                    if ledger.strict {
                        return Ok(gate_blocked(
                            "Deploy gate refused: strict changes require tagged deploy_output; legacy string/unset config is manual-only",
                        ));
                    }
                    // A typed validation graph without a typed Deploy is still
                    // migration-incomplete in the manual tier; fall through to
                    // the legacy string only below.
                    if let Some(cmd) = cfg.deploy {
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
            } else if ledger.strict {
                return Ok(gate_blocked(
                    "Deploy gate refused: strict changes require tagged typed deploy_output; legacy string/unset config is manual-only",
                ));
            } else if let Some(cmd) = cfg.deploy {
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
        // and byte-identical to today). This runs after every objective gate.
        if ledger.strict {
            // `--evidence` must resolve to a real contained file — its OWN
            // artifact for a judgment phase — and defaults to that artifact when
            // omitted. Validation is metadata-only; it never reads content into
            // output (Cond 2).
            evidence = validate_evidence(&root, &change, phase, evidence)?;
            if let Some(msg) =
                strict_artifact_issues(&root, &change, phase, effective_risk, Verdict::Pass, &actor)
            {
                return Ok(gate_blocked(&msg));
            }
        }
    }

    let build_output = if structured_gate_ran && phase == Phase::Build {
        structured_build_output
            .ok_or_else(|| {
                "Build gate refused: structured Build receipt has no BuildOutputV1".to_string()
            })?
            .into()
    } else if verdict == Verdict::Pass && phase == Phase::Build {
        Config::load(&root)
            .local_validation
            .as_ref()
            .and_then(|v| v.build_output.as_ref())
            .map(|output| crate::local_validation::capture_build_output(&root, &output.path))
            .transpose()
            .map_err(|e| format!("Build gate refused: {e}"))?
    } else {
        None
    };
    ledger.record(
        phase,
        GateRecord {
            verdict,
            by: actor,
            evidence: evidence.clone(),
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
            persona_tuning: persona_stamp,
            candidate: gate_candidate.clone(),
            build_output,
            deploy_result,
            validation_receipt: structured_validation_receipt,
        },
    )?;
    if verdict == Verdict::ConditionalPass {
        let opener = phase.persona().name.to_string();
        let (condition_evidence, condition_evidence_digest) =
            condition_binding.clone().unwrap_or_else(|| {
                let evidence = evidence
                    .clone()
                    .unwrap_or_else(|| "legacy-manual-condition".to_string());
                let digest = digest::Digest::of_bytes(evidence.as_bytes()).to_hex();
                (evidence, digest)
            });
        for text in conditions {
            let condition_number = ledger.conditions.len().saturating_add(1);
            ledger.conditions.push(Condition {
                id: format!("{}.{}", phase.slug(), condition_number),
                phase,
                attempt,
                text,
                owner: phase.persona().name.to_string(),
                closed: false,
                opened_at_epoch_secs: completed,
                events: vec![ledger::ConditionEvent::Opened {
                    by: opener.clone(),
                    at_epoch_secs: completed,
                    evidence: condition_evidence.clone(),
                    evidence_digest: condition_evidence_digest.clone(),
                }],
            });
        }
    }
    // Final descriptor reopen is adjacent to the ledger CAS. Earlier profile
    // checks cannot authorize a path that was deleted or replaced while the
    // judgment record was assembled.
    if let Some(pending) = pending_candidate_build.as_ref() {
        pending.revalidate_output(&root)?;
    }
    if let Some(candidate) = gate_candidate.as_ref() {
        crate::candidate::reopen_candidate(&root, candidate)?;
    }
    crate::local_validation::maybe_crash_candidate_output("pre-ledger-cas");
    if let Some(warning) = resolve_candidate_save_outcome(
        &root,
        pending_candidate_build.as_mut(),
        ledger::save_exact_observed(&root, &ledger, &observed),
    )? {
        eprintln!("{warning}");
    }

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

/// Strict archive truth requires a *current* receipt for every recorded
/// applicable PASS. Gate and validation receipts remain distinct namespaces;
/// this checks only the gate receipt attached to the ledger record.
fn current_evidence_blockers(root: &Path, change: &str, ledger: &ledger::Ledger) -> Vec<String> {
    if !ledger.strict || !Project::new(root).change_dir(change).is_dir() {
        return Vec::new();
    }
    let config = Config::load(root);
    Phase::applicable(ledger.applicability())
        .into_iter()
        .filter_map(|phase| {
            let record = ledger.gates.get(&phase)?;
            if record.verdict != Verdict::Pass {
                return None;
            }
            let validity = closure::capture_dependency_values(root, change, ledger, &config, phase)
                .ok()
                .map(|values| closure::evidence_validity(record.receipt.as_ref(), &values))
                .unwrap_or(closure::EvidenceValidity::Absent);
            match validity {
                closure::EvidenceValidity::Valid => None,
                other => Some(format!("{} evidence is {}", phase.label(), other.label())),
            }
        })
        .collect()
}

/// Resolve `path[#anchor]` to a contained, nonempty regular evidence file and
/// return its pointer plus digest. Anchors are descriptive only; the digest
/// always binds the full reviewed file bytes so a later edit stales the claim.
fn contained_evidence(root: &Path, change: &str, raw: &str) -> Result<(String, String), String> {
    let raw = bounded_text(raw, "evidence")?;
    let (relative, anchor) = raw.split_once('#').unwrap_or((&raw, ""));
    if relative.is_empty() {
        return Err("evidence must name a file inside the active change directory".into());
    }
    let change_dir = Project::new(root).change_dir(change);
    let path = change_dir.join(relative);
    openspec_core::assert_contained(&change_dir, &path)
        .map_err(|_| "evidence path escapes the active change directory".to_string())?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| format!("evidence file {relative:?} is absent"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("evidence must be a regular non-symlink file".into());
    }
    let bytes = openspec_core::read_capped(&path)
        .map_err(|error| format!("cannot read evidence: {error}"))?;
    if bytes.trim().is_empty() {
        return Err("evidence file must be nonempty".into());
    }
    let pointer = if anchor.is_empty() {
        relative.to_string()
    } else {
        format!("{relative}#{anchor}")
    };
    Ok((pointer, digest::Digest::of_bytes(bytes.as_bytes()).to_hex()))
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
    expected_verdict: Verdict,
    expected_actor: &str,
) -> Option<String> {
    let (filename, sections) = phase.judgment_artifact()?;
    let path = Project::new(root).change_dir(change).join(filename);
    let text = read_contained(root, &path);
    let mut required: Vec<&str> = sections.to_vec();
    if phase == Phase::SecurityCode && risk == RiskLevel::High {
        required.push("Independent review");
        required.push("Refutation");
    }
    let mut issues = check_sections(&text, &required, JUDGMENT_MIN_LEN);
    // Canonical verdict binding is activated by the explicit stable-ID task
    // contract. Older strict changes remain structurally readable, while a
    // high-assurance plan cannot quietly downgrade its artifact semantics.
    match Project::new(root).task_plan(change) {
        Ok(plan) if plan.strict => {
            match canonical_artifact_verdict(&text) {
                Ok(actual) if actual == expected_verdict => {}
                Ok(actual) => issues.push(format!(
                    "Verdict declares {} but this gate requested {}",
                    actual.label(),
                    expected_verdict.label()
                )),
                Err(issue) => issues.push(issue),
            }
            match canonical_artifact_actor(&text) {
                Ok(actual) if actual == expected_actor => {}
                Ok(actual) => issues.push(format!(
                    "Actor declares {actual:?} but this gate records {expected_actor:?}"
                )),
                Err(issue) => issues.push(issue),
            }
        }
        Ok(_) => {}
        Err(error) => issues.push(format!("tasks.md stable-ID contract is invalid: {error}")),
    }
    if issues.is_empty() {
        return None;
    }
    for issue in &issues {
        eprintln!("  artifact: {issue}");
    }
    Some(format!(
        "{} gate refused: {filename} incomplete ({} issue(s)). \
         Author it with `mpd brief {slug}`; Commando does not permit artifact waivers.",
        phase.label(),
        issues.len(),
        slug = phase.slug(),
    ))
}

/// Read the single bounded actor identity recorded by a canonical judgment
/// artifact. This is cooperative provenance, not authentication.
fn canonical_artifact_actor(text: &str) -> Result<String, String> {
    let heading_count = text
        .lines()
        .filter(|line| line.trim() == "## Actor")
        .count();
    if heading_count != 1 {
        return Err(format!(
            "artifact must contain exactly one `## Actor` heading (found {heading_count})"
        ));
    }
    let body = extract_section(text, "Actor", CONTEXT_SECTION_MAX)
        .ok_or_else(|| "artifact Actor section is missing or oversized".to_string())?;
    let entries: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if entries.len() != 1 {
        return Err("artifact Actor section must contain exactly one nonempty line".into());
    }
    bounded_text(entries[0], "artifact actor")
}

/// Cooperative role separation: a strict gate actor cannot equal the actor on
/// the latest applicable upstream gate. MPD records and enforces the labels but
/// does not claim to authenticate a model, session, or human identity.
/// D6: the phase whose output `phase`'s gate adjudicates, if any. Every
/// judgment/review phase has exactly one review subject; DesignMock,
/// Architecture, Build, Documentation, and Deploy are authoring/synthesis/
/// execution phases with none, and keep the adjacency rule only.
fn review_subject(phase: Phase) -> Option<Phase> {
    match phase {
        Phase::DesignReview => Some(Phase::Architecture),
        Phase::SecurityPlan => Some(Phase::Architecture),
        Phase::SecurityCode => Some(Phase::Build),
        Phase::DesignSignoff => Some(Phase::Build),
        Phase::Test => Some(Phase::Build),
        Phase::DocValidation => Some(Phase::Documentation),
        _ => None,
    }
}

/// D6: actor separation is checked by two independent rules, either of which
/// can refuse a gate:
///
/// - **Adjacency** (kept exactly as before): the gate actor must differ from
///   the actor of the latest applicable upstream gate record.
/// - **Review subject** (new): a judgment phase's actor must ALSO differ from
///   the actor recorded on its current review-subject phase's gate — this is
///   what blocks the alternating-label self-review exploit (Build=A,
///   SecurityCode=B, DesignSignoff=A passes adjacency at every step, but
///   DesignSignoff's subject is Build and A==A). "Differ from ALL distinct
///   upstream actors" would be wrong by construction: the Designer
///   legitimately records DesignMock/DesignReview/DesignSignoff, Security
///   records both Security gates, and the Architect records
///   Architecture+DocValidation — the dual-persona reuse is by design.
///
/// Both comparisons read only the current `gates` map (latest record per
/// phase), which a rewind clears, so the rule naturally scopes to the
/// change's current attempt cycle. A subject phase with no current record
/// contributes no comparison.
fn strict_actor_separation_issue(
    ledger: &ledger::Ledger,
    phase: Phase,
    actor: &str,
) -> Option<String> {
    let prior = Phase::applicable(ledger.applicability())
        .into_iter()
        .take_while(|candidate| *candidate != phase)
        .filter_map(|candidate| {
            ledger
                .gates
                .get(&candidate)
                .map(|record| (candidate, record))
        })
        .last();
    if let Some((prior_phase, prior_record)) = prior {
        if actor == prior_record.by {
            return Some(format!(
                "{} gate actor {actor:?} matches the latest upstream {} actor (adjacency rule); \
                 use a cooperatively distinct reviewer label",
                phase.label(),
                prior_phase.label()
            ));
        }
    }
    if let Some(subject_phase) = review_subject(phase) {
        if let Some(subject_record) = ledger.gates.get(&subject_phase) {
            if actor == subject_record.by {
                return Some(format!(
                    "{} gate actor {actor:?} matches the {} actor it reviews (review-subject \
                     rule); use a cooperatively distinct reviewer label",
                    phase.label(),
                    subject_phase.label()
                ));
            }
        }
    }
    None
}

/// Read exactly one canonical terminal decision from a judgment artifact.
/// Rationale may follow the decision, but the first nonempty line under the
/// unique `## Verdict` heading must be one of the ledger's literal values.
/// This prevents loose prose such as `PASS — probably` from being interpreted
/// differently by an author, a reviewer, and the CLI.
fn canonical_artifact_verdict(text: &str) -> Result<Verdict, String> {
    let heading_count = text
        .lines()
        .filter(|line| line.trim() == "## Verdict")
        .count();
    if heading_count != 1 {
        return Err(format!(
            "artifact must contain exactly one `## Verdict` heading (found {heading_count})"
        ));
    }
    let body = extract_section(text, "Verdict", CONTEXT_SECTION_MAX)
        .ok_or_else(|| "artifact Verdict section is missing or oversized".to_string())?;
    let token = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "Verdict section has no canonical decision".to_string())?;
    match token {
        "PASS" => Ok(Verdict::Pass),
        "CONDITIONAL PASS" => Ok(Verdict::ConditionalPass),
        "FAIL" => Ok(Verdict::Fail),
        _ => Err("Verdict must begin with exactly PASS, CONDITIONAL PASS, or FAIL".into()),
    }
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
/// change is folded into the permanent record. Under `ledger.strict`, sweep every
/// applicable judgment phase and re-run its structural check. Historical waiver
/// records are explicit blockers: the current Commando contract denies waivers.
/// Reads go through the same symlink-refusing, size-capped path as the gate; no
/// artifact content is surfaced.
fn strict_archive_recheck(root: &Path, change: &str, ledger: &ledger::Ledger) -> Vec<String> {
    let mut refusals = Vec::new();
    if !ledger.waivers.is_empty() {
        refusals.push(
            "historical artifact waiver records are present; rewind and rerun the affected canonical gates"
                .into(),
        );
    }
    for phase in Phase::applicable(ledger.applicability()) {
        if phase.judgment_artifact().is_none() {
            continue;
        }
        let Some(record) = ledger.gates.get(&phase) else {
            refusals.push(format!("{} has no recorded gate actor", phase.label()));
            continue;
        };
        if let Some(msg) = strict_artifact_issues(
            root,
            change,
            phase,
            ledger.effective_risk(),
            Verdict::Pass,
            &record.by,
        ) {
            refusals.push(msg);
        }
    }
    refusals
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

fn cmd_repair_state(to: String, reason: String, yes: bool, change: Option<String>) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    if ledger::current(&root).as_deref() != Some(change.as_str()) {
        return Err("repair-state applies only to the active current change".into());
    }
    let rewind = Phase::from_slug(&to).ok_or_else(|| format!("unknown phase {to:?}"))?;
    let (mut ledger, observed) =
        ledger::load_observed(&root, &change).map_err(|error| error.to_string())?;
    let already_exists = ledger.repair_state_preview(rewind, &reason)?;
    if already_exists {
        println!(
            "Rewind to {} already exists; no state changed.",
            rewind.label()
        );
        return Ok(0);
    }
    if !yes {
        println!(
            "Preview only: repair would append a reconciliation and rewind {} to {} (observed ledger {}). Re-run with --yes to apply; no PASS will be synthesized.",
            ledger.phase.label(), rewind.label(), observed
        );
        return Ok(0);
    }
    ledger.repair_state_to(rewind, &reason, &observed)?;
    ledger::save_if_observed(&root, &ledger, &observed).map_err(|error| error.to_string())?;
    println!(
        "Applied append-only legacy repair; current phase is {}. No PASS or archive content was created.",
        rewind.label()
    );
    Ok(0)
}

fn cmd_resolve(
    index: Option<usize>,
    all: bool,
    by: String,
    evidence: String,
    change: Option<String>,
) -> CmdResult {
    let root = find_root()?;
    let change = resolve_change(&root, change)?;
    let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;

    match (index, all) {
        (Some(_), true) => return Err("specify a condition number or --all, not both".into()),
        (None, false) => {
            return Err("specify a condition number (see `mpd status`) or --all".into())
        }
        _ => {}
    }
    let (evidence, evidence_digest) = if ledger.strict {
        contained_evidence(&root, &change, &evidence)?
    } else {
        let evidence = bounded_text(&evidence, "condition evidence")?;
        let digest = digest::Digest::of_bytes(evidence.as_bytes()).to_hex();
        (evidence, digest)
    };

    match (index, all) {
        (Some(i), false) => {
            ledger.close_condition(i, &by, evidence.clone(), evidence_digest.clone())?;
            println!("Closed condition #{i}.");
        }
        (None, true) => {
            let n = ledger.close_all_conditions(&by, evidence.clone(), evidence_digest.clone())?;
            println!("Closed {n} open condition(s).");
        }
        // Validated above before any evidence-file read or state mutation.
        _ => unreachable!("invalid resolve arguments were rejected above"),
    }
    ledger::save(&root, &ledger).map_err(|e| e.to_string())?;

    let remaining = ledger.conditions.iter().filter(|c| c.is_open()).count();
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

fn cmd_task(command: TaskCommand) -> CmdResult {
    let root = find_root()?;
    let (id, change) = match &command {
        TaskCommand::Defer { id, change, .. } | TaskCommand::Revoke { id, change, .. } => {
            (id.as_str(), change.clone())
        }
    };
    let change = resolve_change(&root, change)?;
    let plan = Project::new(&root)
        .task_plan(&change)
        .map_err(|error| format!("task command refused: invalid tasks.md: {error}"))?;
    if !plan.strict {
        return Err("task command requires a strict stable-ID tasks.md plan".into());
    }
    let task = plan
        .entries
        .iter()
        .find(|task| task.id == id)
        .ok_or_else(|| format!("no current Builder task with ID {id:?}"))?;
    let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    match command {
        TaskCommand::Defer {
            owner,
            reason,
            evidence,
            ..
        } => {
            // The current hardening plan declares no deferrals. Keep that
            // constraint in the artifact rather than inventing a global policy.
            let tasks_text = read_contained(&root, &Project::new(&root).tasks_path(&change));
            if tasks_text
                .to_ascii_lowercase()
                .contains("this change allows no task deferral")
            {
                return Err("this change's task plan allows no task deferral".into());
            }
            let (evidence, evidence_digest) = contained_evidence(&root, &change, &evidence)?;
            ledger.defer_task(task, &owner, &reason, evidence, evidence_digest)?;
            println!(
                "Deferred task {} with evidence-bound record digest.",
                task.id
            );
        }
        TaskCommand::Revoke { reason, .. } => {
            ledger.revoke_task_deferral(task, &reason)?;
            println!("Revoked current deferral for task {}.", task.id);
        }
    }
    ledger::save(&root, &ledger).map_err(|error| error.to_string())?;
    Ok(0)
}

/// D3: the AwaitingCommit closure-commit scope is the union of the
/// transaction's classification rows and a validated closure-plan's expected
/// post-archive entry paths — this is what makes the FIRST-ever closure
/// commit (source tree never previously committed) possible, since every
/// staged source path is an expected plan entry. `plan` is `None` when no
/// plan was ever recorded for this transaction (see
/// `closure::candidate_closure_plan_recorded`) — a legacy/non-candidate
/// closure, so the rows-only scope is kept unchanged. When a plan WAS
/// recorded, `Err` (malformed, non-canonical, oversized, or bound to a
/// different transaction) is evidence of tampering or corruption, so this
/// BLOCKS rather than silently narrowing to rows-only exactly where
/// suspicion is warranted.
fn union_closure_scope(
    mut rows: Vec<String>,
    plan: Option<Result<closure::CandidateClosurePlan, String>>,
) -> Result<Vec<String>, String> {
    match plan {
        Some(Ok(plan)) => rows.extend(plan.entries.into_iter().map(|entry| entry.path)),
        Some(Err(error)) => {
            return Err(format!(
                "pre-commit blocked: pending Candidate closure plan is invalid: {error}"
            ));
        }
        None => {}
    }
    rows.sort();
    rows.dedup();
    Ok(rows)
}

/// D2 Condition 11 (security-plan): whether the staged diff itself removes
/// `path` — the archived-closure fallback's unforgeable trigger signature.
/// Status `D` (destination deleted) or `R` (renamed away, i.e.
/// `orig_path == path`) trigger; status `C` (copy) never does — the path
/// remains present as a copy source's *sibling*, and `path` itself still
/// exists post-copy only when `path` is the copy's origin, which a rename/
/// copy of a protected artifact already blocks in the ordinary path. Exact
/// equality only, never a prefix/suffix match.
fn stages_removal_of(entries: &[git::DiffEntry], path: &str) -> bool {
    entries.iter().any(|entry| match entry.status {
        'D' => entry.path == path,
        'R' => entry.orig_path.as_deref() == Some(path),
        _ => false,
    })
}

/// D5 (Conditions 8/11): if some staged `D`-destination or `R`-origin path is
/// exactly `openspec/changes/<X>/manifest.json` for a name `X` that itself
/// passes `validate_change_name`, return `X`. Used only to enrich guidance
/// text — e.g. when there is no resolvable coordinator, or when the ordinary
/// coverage check trips on a *different* change's own manifest path — never
/// to select which ledger authorizes a commit: a staged-path-derived name
/// may appear only in error text (Condition 11).
fn removed_manifest_change_name(entries: &[git::DiffEntry]) -> Option<String> {
    entries.iter().find_map(|entry| {
        let candidate = match entry.status {
            'D' => Some(entry.path.as_str()),
            'R' => entry.orig_path.as_deref(),
            _ => None,
        };
        candidate.and_then(|path| {
            let name = path
                .strip_prefix("openspec/changes/")?
                .strip_suffix("/manifest.json")?;
            if name.is_empty() || name.contains('/') {
                return None;
            }
            openspec_core::validate_change_name(name)
                .ok()
                .map(|()| name.to_string())
        })
    })
}

/// D5: the recovery-guidance sentence appended when a closure-shaped staged
/// diff (a manifest deletion) is detected for change `name` but its pending
/// transaction is not (or is no longer) the active coordinator. Never
/// suggests `mpd archive --recover` — that requires the pointer `abandon`
/// deleted — and never directs the operator to re-create the active
/// manifest (the opposite of what closed the footgun this fallback exists
/// for). `name` has already passed `validate_change_name`; `terminal_safe`
/// is applied anyway per Condition 8's blanket hygiene rule.
fn closure_recovery_hint(name: &str) -> String {
    let name = harness::terminal_safe(name);
    format!(
        " A closure-shaped staged change for {name:?} was detected without its pending \
         transaction; the closure commit belongs before `mpd archive --abandon --yes`. To \
         commit it now: run `mpd use {name}` and retry. Do not re-create \
         openspec/changes/{name}/manifest.json."
    )
}

/// Cond 12 (security-plan): bound + sanitize a ledger-record- or
/// closure-plan-derived string before it reaches hook output. Neither is
/// staged content, but the worktree ledger (and the closure plan it names)
/// is owner-writable and therefore attacker-controlled text under this arm's
/// own threat model — mirrors the `ledger_version_probe` precedent
/// (`ledger.rs:1690-1708`).
fn bounded_record_hint(value: &str) -> String {
    const MAX_RECORD_HINT_CHARS: usize = 200;
    let safe = harness::terminal_safe(value);
    if safe.chars().count() > MAX_RECORD_HINT_CHARS {
        safe.chars().take(MAX_RECORD_HINT_CHARS).collect::<String>() + "…"
    } else {
        safe
    }
}

/// D1/D2 (Conditions 2-6, 14): the archived-closure fallback's sole
/// authority. Call only once the ELSE branch's exhaustive trigger holds (no
/// pending closure; the resolved change's OWN active manifest is being
/// removed by the staged diff; its worktree ledger carries an
/// `archive_closure` record — see `stages_removal_of`). Returns the
/// authorized scope — `record.system_paths` unioned with the retained
/// Candidate closure plan's validated entries, via the SAME
/// `union_closure_scope` the AwaitingCommit branch uses — or a fail-closed
/// block reason. Reuses only the existing hardened loader
/// (`load_candidate_closure_plan`: no-follow open, 64 MiB cap, canonical
/// round-trip, transaction-id binding); never reads the archived manifest
/// (index or worktree) or any other worktree file, so nothing but this
/// record+plan pair can ever authorize (Condition 14) — an additional check
/// may only narrow/block, never widen.
fn archived_closure_fallback_scope(
    root: &Path,
    record: &ArchiveClosure,
) -> Result<Vec<String>, String> {
    if record.system_paths.is_empty() {
        // D2.5: a pre-`system_paths` legacy record degrades to empty and
        // must fail closed here, exactly as `manifest_view` does.
        return Err(
            "pre-commit blocked: archived closure record has no concrete recorded scope \
             (legacy record predates system_paths); this commit cannot be authorized from it"
                .to_string(),
        );
    }
    let plan = match &record.candidate_id {
        Some(candidate_id) => {
            let transaction_id = record.transaction_id.to_hex();
            let plan =
                closure::load_candidate_closure_plan(root, &transaction_id).map_err(|_| {
                    format!(
                        "pre-commit blocked: archived closure plan for candidate {} is missing or \
                     invalid; refusing to authorize this commit",
                        bounded_record_hint(candidate_id)
                    )
                })?;
            // D2.6/Cond 5: mirror `verify_commit_coherence`'s binding check
            // (`closure.rs:3284-3288`) field-for-field. Any mismatch blocks —
            // never a silent narrowing to `system_paths` alone.
            if &plan.candidate_id != candidate_id
                || plan.candidate_base_commit != record.base_commit
                || plan.archive_path != record.archive_path
                || plan.archive_transaction_id != transaction_id
            {
                return Err(format!(
                    "pre-commit blocked: archived closure plan binding differs from the \
                     archive record (archive path {}); refusing to authorize this commit",
                    bounded_record_hint(&record.archive_path)
                ));
            }
            Some(Ok(plan))
        }
        // D2.6: a legacy (pre-Candidate) archive expected no plan; keep the
        // concrete-footprint scope alone, matching `union_closure_scope`'s
        // `None` semantics.
        None => None,
    };
    // Reuse the identical widen-or-block scope union the AwaitingCommit
    // branch runs, with `system_paths` as the rows argument (D1).
    union_closure_scope(record.system_paths.clone(), plan)
        .map_err(|error| format!("pre-commit blocked: {error}"))
}

/// The ELSE branch's ordinary (non-closure) authority: the resolved change's
/// own active manifest + ledger, read from authoritative index postimages
/// (never the worktree) so an unstaged edit can never broaden the decision.
/// Factored out so it runs byte-identically from every call site — no
/// pending closure and no fallback trigger, or no pending closure with a
/// fallback trigger whose ledger carries no archive record (security-plan
/// Condition 10) — with no risk of the copies drifting apart.
fn ordinary_else_governance(
    root: &Path,
    change: &str,
    entries: &[git::DiffEntry],
    manifest_path: &str,
    tasks_path: &str,
    ledger_path: &str,
    judgment_paths: &[String],
) -> Result<ledger::Ledger, String> {
    let protected = |path: &str| {
        path == manifest_path
            || path == tasks_path
            || path == ledger_path
            || judgment_paths.iter().any(|candidate| candidate == path)
    };
    for entry in entries {
        if entry.status == 'D' && protected(&entry.path) {
            return Err(format!(
                "pre-commit blocked: deletion of required governance artifact {}",
                entry.path
            ));
        }
        if matches!(entry.status, 'R' | 'C') && entry.orig_path.as_deref().is_some_and(protected) {
            return Err("pre-commit blocked: rename/copy of required governance artifact".into());
        }
    }

    // The manifest and ledger are read from `:<path>` even when they are not
    // part of this staged diff, so an unstaged worktree edit cannot broaden
    // a hook decision. A missing index object is a coherence failure, not a
    // reason to fall back to the worktree.
    let manifest_bytes = git::staged_blob(root, manifest_path).map_err(|_| {
        "pre-commit blocked: active manifest is absent or unreadable in the index".to_string()
    })?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| "pre-commit blocked: active manifest is not UTF-8")?;
    let manifest: closure::ChangeManifest = serde_json::from_str(manifest_text)
        .map_err(|_| "pre-commit blocked: active manifest is malformed")?;
    if !manifest.validate().is_empty() {
        return Err("pre-commit blocked: active manifest has invalid scope".into());
    }
    let ledger_bytes = git::staged_blob(root, ledger_path).map_err(|_| {
        "pre-commit blocked: active ledger is absent or unreadable in the index".to_string()
    })?;
    let ledger: ledger::Ledger = serde_json::from_slice(&ledger_bytes)
        .map_err(|_| "pre-commit blocked: active ledger is malformed")?;
    if ledger.change != change || !ledger.integrity_blockers().is_empty() {
        return Err("pre-commit blocked: active ledger is incoherent".into());
    }

    let system = closure::active_system_scope(root, change);
    for entry in entries {
        for path in entry.orig_path.iter().chain(std::iter::once(&entry.path)) {
            let policy_path = path == ".mpd/config.json"
                || path.starts_with(".mpd/directives/")
                || path == ".githooks/pre-commit"
                || path == ".githooks/pre-push";
            if !policy_path && !manifest.covers(path, &system) {
                let mut message = format!(
                    "pre-commit blocked: staged path falls outside active manifest scope: {}",
                    harness::terminal_safe(path)
                );
                // D5: if the out-of-scope path is itself a DIFFERENT
                // change's own active-manifest path, the operator very
                // likely coordinated the wrong change for a closure commit.
                // Text only — never used to pick an authority (Condition
                // 11) — so this cannot widen what gets authorized.
                if let Some(other) = path
                    .strip_prefix("openspec/changes/")
                    .and_then(|rest| rest.strip_suffix("/manifest.json"))
                    .filter(|name| *name != change && !name.contains('/'))
                    .filter(|name| openspec_core::validate_change_name(name).is_ok())
                {
                    message.push_str(&closure_recovery_hint(other));
                }
                return Err(message);
            }
        }
    }
    Ok(ledger)
}

/// Validate the staged governance record used by the pre-commit hook.  This is
/// intentionally separate from `manifest_view`: the latter is a status UI and
/// may inspect the worktree, while a hook must make its decision solely from
/// bounded Git index postimages plus the current coordinator name.
fn staged_precommit_governance(root: &Path) -> Result<(), String> {
    // A completed archive has deliberately removed the active change directory
    // while its ignored pending-closure pointer remains the sole coordinator
    // for the one closure commit. Its transaction journal is bounded and
    // read-only; use its concrete targets rather than trying to read deleted
    // active manifest/state postimages from the index.
    let pending = openspec_core::inspect(root)
        .map_err(|_| "pre-commit blocked: pending closure metadata is malformed")?;
    let pending_scope = match pending.as_ref() {
        Some(view) if view.stage == openspec_core::TransactionState::AwaitingCommit => {
            if view.truncated {
                return Err(
                    "pre-commit blocked: pending closure scope exceeds its safe view cap".into(),
                );
            }
            let mut scope = Vec::new();
            for row in &view.classifications {
                if let Some((source, destination)) = row.path.split_once(" -> ") {
                    scope.push(source.to_string());
                    scope.push(destination.to_string());
                } else {
                    scope.push(row.path.clone());
                }
            }
            // D3: union in the validated closure-plan's expected
            // post-archive entry paths — see `union_closure_scope`. The
            // loader already enforces no-follow open, the 64 MiB cap,
            // canonical round-trip, and transaction-id binding — no weaker
            // parallel read path here.
            let transaction_id = view.transaction_id.to_hex();
            let plan = closure::candidate_closure_plan_recorded(root, &transaction_id)
                .then(|| closure::load_candidate_closure_plan(root, &transaction_id));
            Some(union_closure_scope(scope, plan)?)
        }
        Some(_) => {
            return Err("pre-commit blocked: pending closure is not ready for its commit".into())
        }
        None => None,
    };
    let change = pending
        .as_ref()
        .map(|view| view.change.clone())
        .map(Ok)
        .unwrap_or_else(|| {
            resolve_change(root, None).map_err(|_| {
                // D5: no active coordinator is the exact post-abandon state
                // this fallback exists to recover from. If the staged diff
                // is closure-shaped (removes some change X's own active
                // manifest), name X and point at the recovery command
                // instead of the bare generic message — never suggesting
                // `mpd archive --recover` (recover needs the pointer
                // `abandon` deleted) and never re-creating the manifest.
                // Best-effort only: a failure reading the staged diff here
                // just falls back to the generic message, which is what the
                // main flow's own `diff_cached_name_status` call below would
                // then also report.
                let hint = git::diff_cached_name_status(root)
                    .ok()
                    .as_deref()
                    .and_then(removed_manifest_change_name);
                match hint {
                    Some(name) => format!(
                        "pre-commit blocked: no active change coordinator.{}",
                        closure_recovery_hint(&name)
                    ),
                    None => "pre-commit blocked: no active change coordinator".to_string(),
                }
            })
        })?;
    let entries = git::diff_cached_name_status(root)
        .map_err(|error| format!("pre-commit blocked: cannot parse staged changes: {error}"))?;
    for entry in &entries {
        if !matches!(entry.status, 'A' | 'C' | 'D' | 'M' | 'R' | 'T') {
            return Err(format!(
                "pre-commit blocked: unsupported staged status {:?}",
                entry.status
            ));
        }
        digest::validate_canonical_path(&entry.path)
            .map_err(|_| "pre-commit blocked: unsafe staged destination path".to_string())?;
        if let Some(source) = &entry.orig_path {
            digest::validate_canonical_path(source)
                .map_err(|_| "pre-commit blocked: unsafe staged rename source path".to_string())?;
        }
    }

    let change_dir = format!("openspec/changes/{change}");
    let manifest_path = format!("{change_dir}/manifest.json");
    let tasks_path = format!("{change_dir}/tasks.md");
    let ledger_path = format!(".mpd/state/{change}.json");
    let judgment_paths: Vec<String> = Phase::applicable(crate::phase::Applicability {
        ui: true,
        docs: true,
    })
    .into_iter()
    .filter_map(|phase| {
        phase
            .judgment_artifact()
            .map(|(name, _)| format!("{change_dir}/{name}"))
    })
    .collect();
    let staged_ledger = if let Some(scope) = pending_scope {
        for entry in &entries {
            for path in entry.orig_path.iter().chain(std::iter::once(&entry.path)) {
                let policy_path = path == ".mpd/config.json"
                    || path.starts_with(".mpd/directives/")
                    || path == ".githooks/pre-commit"
                    || path == ".githooks/pre-push";
                if !policy_path && !closure::covers_concrete_paths(&scope, path) {
                    return Err(format!(
                        "pre-commit blocked: staged path falls outside pending closure scope: {}",
                        harness::terminal_safe(path)
                    ));
                }
            }
        }
        None
    } else if stages_removal_of(&entries, &manifest_path) {
        // D2/Condition 10: the fallback trigger's unforgeable manifest-
        // removal signature holds for the RESOLVED change — never a
        // staged-path-derived name (Condition 11). Resolve the archive
        // record from the worktree ledger: the one authority
        // `abandon_apply` never touches (`transaction.rs:1536-1561`).
        match ledger::load(root, &change) {
            Ok(ledger_doc) => match ledger_doc.archive_closure {
                Some(record) => {
                    // D2.5/D2.6, Condition 4/5/14: the record+plan pair is
                    // the sole authorizing input; any failure here blocks,
                    // never narrows, never falls through to the ordinary
                    // manifest read.
                    let scope = archived_closure_fallback_scope(root, &record)?;
                    for entry in &entries {
                        for path in entry.orig_path.iter().chain(std::iter::once(&entry.path)) {
                            let policy_path = path == ".mpd/config.json"
                                || path.starts_with(".mpd/directives/")
                                || path == ".githooks/pre-commit"
                                || path == ".githooks/pre-push";
                            if !policy_path && !closure::covers_concrete_paths(&scope, path) {
                                return Err(format!(
                                    "pre-commit blocked: staged path falls outside archived \
                                     closure scope: {}",
                                    harness::terminal_safe(path)
                                ));
                            }
                        }
                    }
                    None
                }
                // Condition 10: no archive record — the ordinary path runs
                // byte-identical and blocks via its own protected-artifact
                // check (spec scenario "Closure-shaped commit without an
                // archive record"). Never a fallback-specific message here.
                None => Some(ordinary_else_governance(
                    root,
                    &change,
                    &entries,
                    &manifest_path,
                    &tasks_path,
                    &ledger_path,
                    &judgment_paths,
                )?),
            },
            // Condition 10: a worktree ledger that cannot even be read is a
            // distinct, specific failure — never falls through to the
            // ordinary (index-based) manifest read, which could disagree
            // with what was just observed in the worktree.
            Err(_) => {
                return Err(
                    "pre-commit blocked: staged diff removes the active manifest for a change \
                     whose ledger cannot be read; refusing to authorize this commit from an \
                     unreadable archive record"
                        .to_string(),
                );
            }
        }
    } else {
        Some(ordinary_else_governance(
            root,
            &change,
            &entries,
            &manifest_path,
            &tasks_path,
            &ledger_path,
            &judgment_paths,
        )?)
    };

    for entry in &entries {
        if entry.status == 'D' {
            continue;
        }
        let path = &entry.path;
        if path == &tasks_path {
            let bytes = git::staged_blob(root, path)
                .map_err(|_| "pre-commit blocked: cannot read staged tasks.md".to_string())?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| "pre-commit blocked: staged tasks.md is not UTF-8")?;
            openspec_core::parse_task_plan_text(text)
                .map_err(|_| "pre-commit blocked: staged tasks.md violates stable task rules")?;
        }
        if judgment_paths.iter().any(|candidate| candidate == path)
            && staged_ledger.as_ref().is_some_and(|ledger| ledger.strict)
        {
            let staged_ledger = staged_ledger.as_ref().expect("checked above");
            let phase = Phase::applicable(staged_ledger.applicability())
                .into_iter()
                .find(|phase| {
                    phase
                        .judgment_artifact()
                        .is_some_and(|(name, _)| path.ends_with(name))
                })
                .ok_or_else(|| {
                    "pre-commit blocked: unknown staged judgment artifact".to_string()
                })?;
            let bytes = git::staged_blob(root, path).map_err(|_| {
                "pre-commit blocked: cannot read staged judgment artifact".to_string()
            })?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| "pre-commit blocked: staged judgment artifact is not UTF-8")?;
            let (_, sections) = phase.judgment_artifact().expect("filtered above");
            if !check_sections(text, sections, JUDGMENT_MIN_LEN).is_empty() {
                return Err("pre-commit blocked: staged judgment artifact is incomplete".into());
            }
            if openspec_core::parse_task_plan_text(
                std::str::from_utf8(
                    &git::staged_blob(root, &tasks_path).map_err(|_| {
                        "pre-commit blocked: cannot read staged tasks.md".to_string()
                    })?,
                )
                .map_err(|_| "pre-commit blocked: staged tasks.md is not UTF-8")?,
            )
            .map_err(|_| "pre-commit blocked: staged tasks.md violates stable task rules")?
            .strict
                && canonical_artifact_verdict(text).is_err()
            {
                return Err(
                    "pre-commit blocked: staged judgment artifact has no canonical verdict".into(),
                );
            }
        }
        if path == ".mpd/config.json" {
            let bytes = git::staged_blob(root, path)
                .map_err(|_| "pre-commit blocked: cannot read staged config".to_string())?;
            // Keep syntax failures distinct from a well-formed document whose
            // typed policy does not satisfy the current schema. Parsing Config
            // directly would collapse a missing newly-required policy field
            // into the generic malformed-config path and hide the actionable
            // fail-closed policy diagnosis.
            let value = serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|_| "pre-commit blocked: staged config is malformed")?;
            let has_local_validation = value
                .as_object()
                .is_some_and(|object| object.contains_key("local_validation"));
            let config = serde_json::from_value::<Config>(value).map_err(|_| {
                if has_local_validation {
                    "pre-commit blocked: staged local validation policy is invalid"
                } else {
                    "pre-commit blocked: staged config is malformed"
                }
            })?;
            if let Some(local_validation) = &config.local_validation {
                local_validation
                    .validate()
                    .map_err(|_| "pre-commit blocked: staged local validation policy is invalid")?;
            }
        }
        if path.starts_with(".mpd/directives/") {
            let relative = path.trim_start_matches(".mpd/directives/");
            if !crate::directives::bundled()
                .iter()
                .any(|(known, _)| *known == relative)
            {
                return Err("pre-commit blocked: unknown staged directive path".into());
            }
            let bytes = git::staged_blob(root, path)
                .map_err(|_| "pre-commit blocked: cannot read staged directive".to_string())?;
            if std::str::from_utf8(&bytes).map_or(true, |text| text.trim().is_empty()) {
                return Err("pre-commit blocked: staged directive is empty or non-UTF-8".into());
            }
        }
        if path.starts_with(".githooks/") {
            if path != ".githooks/pre-commit" && path != ".githooks/pre-push" {
                return Err("pre-commit blocked: unknown staged hook policy path".into());
            }
            let bytes = git::staged_blob(root, path)
                .map_err(|_| "pre-commit blocked: cannot read staged hook policy".to_string())?;
            if std::str::from_utf8(&bytes).map_or(true, |text| !text.starts_with("#!/bin/sh")) {
                return Err("pre-commit blocked: staged hook policy is malformed".into());
            }
        }
    }
    Ok(())
}

fn cmd_check(staged: bool, quiet: bool) -> CmdResult {
    let root = find_root()?;
    let report = if staged {
        checks::scan_staged_postimages(&root)?
    } else {
        checks::scan_secrets(&checks::git_tracked_files(&root)?)?
    };
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

fn cmd_validate(commit: Option<String>, profile: Option<String>, json: bool) -> CmdResult {
    let root = find_root()?;
    let cfg = Config::load(&root);
    let local = cfg.local_validation.ok_or_else(|| {
        "structured local_validation is absent; legacy `test` is compatibility-only and cannot authorize local validation".to_string()
    })?;
    let report = crate::local_validation::validate_profile(
        &root,
        commit.as_deref(),
        profile.as_deref(),
        &local,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!(
            "Local validation {}: {} ({})",
            report.status, report.subject.commit, report.subject.tree
        );
        println!("Profile: {}", report.profile);
        if let Some(receipt) = &report.receipt {
            println!("Receipt: {}", receipt.id);
        }
        if let Some(blocker) = &report.blocker {
            eprintln!("Validation blocked: {blocker}");
        }
    }
    Ok(if report.status == "passed" { 0 } else { 1 })
}

fn cmd_identity(path: Option<String>, json: bool) -> CmdResult {
    let root = find_root()?;
    let identity = crate::local_validation::identity_report(&root, path.as_deref())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&identity).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "{} {} {} {}",
            identity.artifact.path,
            identity.artifact.size,
            identity.artifact.mode,
            identity.artifact.sha256
        );
    }
    Ok(0)
}

fn cmd_hook(command: HookCommand) -> CmdResult {
    match command {
        HookCommand::PreCommit { json } => {
            // Reuse the same fast staged postimage scanner as the compatibility
            // hook. It is read-only and deliberately does not run a profile or
            // any configured command; governance is read from exact index blobs.
            let root = find_root()?;
            staged_precommit_governance(&root)?;
            let code = cmd_check(true, true)?;
            if json {
                println!(
                    "{{\"schema\":1,\"hook\":\"pre-commit\",\"status\":\"{}\"}}",
                    if code == 0 { "passed" } else { "blocked" }
                );
            }
            Ok(code)
        }
        HookCommand::PrePush {
            remote_name,
            remote_location,
            json,
        } => {
            let root = find_root()?;
            let mut input = Vec::new();
            std::io::stdin()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut input)
                .map_err(|e| format!("malformed-hook-input: cannot read pre-push stdin: {e}"))?;
            if input.len() > 1024 * 1024 {
                return Err("malformed-hook-input: pre-push stdin exceeds its cap".into());
            }
            // Reject malformed wire data before configuration/trust lookup so a
            // hook failure always identifies malformed Git input precisely.
            let _ = crate::local_validation::parse_pre_push_records(&input)?;
            let cfg = Config::load(&root);
            let local = cfg.local_validation.ok_or_else(|| {
                "pre-push blocked: structured local_validation is absent; activate an explicitly reviewed policy first".to_string()
            })?;
            let authorization = crate::local_validation::authorize_pre_push(
                &root,
                &remote_name,
                &remote_location,
                &input,
                &local,
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&authorization).map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "pre-push authorization: {} objects / {} bytes / {} deletions ({})",
                    authorization.object_count,
                    authorization.object_bytes,
                    authorization.deletion_count,
                    authorization.object_set_digest
                );
            }
            Ok(0)
        }
        HookCommand::ApproveDeletion {
            remote_name,
            remote_location,
            remote_ref,
            old_oid,
            yes,
            json,
        } => {
            if !yes {
                return Err(
                    "deletion approval is a one-use local authorization mutation; rerun with --yes"
                        .into(),
                );
            }
            let root = find_root()?;
            let cfg = Config::load(&root);
            let local = cfg.local_validation.ok_or_else(|| {
                "deletion approval blocked: structured local_validation is absent".to_string()
            })?;
            let approval = crate::local_validation::create_deletion_approval(
                &root,
                &remote_name,
                &remote_location,
                &remote_ref,
                &old_oid,
                &local,
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&approval).map_err(|error| error.to_string())?
                );
            } else {
                println!(
                    "Deletion approval READY id={} ref={} old={}; it is consumed by one exact matching pre-push invocation.",
                    approval.id, approval.remote_ref, approval.old_oid
                );
            }
            Ok(0)
        }
    }
}

fn cmd_policy(command: PolicyCommand) -> CmdResult {
    match command {
        #[cfg(test)]
        PolicyCommand::Status { commit, json } => {
            let root = find_root()?;
            let cfg = Config::load(&root);
            let local = cfg.local_validation.ok_or_else(|| "structured local_validation is absent; legacy `test` cannot become a trusted policy".to_string())?;
            let report = crate::local_validation::preflight(&root, commit.as_deref(), &local)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!(
                    "Local validation subject: {} ({})",
                    report.subject.commit, report.subject.tree
                );
                if let Some(blocker) = report.blocker {
                    eprintln!("Validation blocked: {blocker}");
                }
            }
            Ok(0)
        }
        #[cfg(test)]
        PolicyCommand::Bootstrap {
            commit,
            confirm_digest,
            pretrust_proof,
            nonce,
            reviewed,
        } => {
            require_pretrust_mode("bootstrap")?;
            if !reviewed {
                return Err(
                    "policy bootstrap requires --i-reviewed-this-policy; it creates a clone-local trust root"
                        .into(),
                );
            }
            let root = find_root()?;
            let cfg = Config::load(&root);
            let local = cfg.local_validation.ok_or_else(|| {
                "structured local_validation is absent; legacy `test` cannot become a trusted policy"
                    .to_string()
            })?;
            let (oid, already_completed) =
                crate::local_validation::bootstrap_first_adoption_policy(
                    &root,
                    &local,
                    crate::local_validation::BootstrapRequest {
                        checkpoint_oid: &commit,
                        reviewed_policy_digest: &confirm_digest,
                        pretrust_proof_digest: &pretrust_proof,
                        nonce: &nonce,
                    },
                )?;
            if already_completed {
                println!("Trusted local validation policy already completed at {oid}; exact proof/policy/nonce inputs were reparsed without a second CAS.");
            } else {
                println!("Trusted local validation policy initialized at {oid}. This is owner authorization, not an independent attestation.");
            }
            Ok(0)
        }
        #[cfg(test)]
        PolicyCommand::Promote {
            commit,
            confirm_digest,
        } => {
            let root = find_root()?;
            let report =
                crate::local_validation::promote_trusted_policy(&root, &commit, &confirm_digest)?;
            println!(
                "Trusted policy promoted at {} from {} for immutable commit {}.",
                report.promoted_policy_oid, report.trusted_before_oid, report.subject_commit
            );
            println!("Semantic review:");
            for change in &report.semantic_diff {
                println!("- {change}");
            }
            println!(
                "Reviewed candidate digests: policy={}, tool-lock={}, sandbox={}, hooks={}",
                report.candidate_policy_digest,
                report.candidate_tool_lock_digest,
                report.candidate_sandbox_digest,
                report.candidate_hook_digest
            );
            println!("Promotion created no validation receipt or gate PASS; separately activate the expected policy/coordinator if needed.");
            Ok(0)
        }
        PolicyCommand::Activate {
            commit,
            confirm_policy_digest,
            coordinator,
            confirm_executable_digest,
            hooks,
            yes,
        } => {
            if !yes {
                return Err("policy activation is a local trust mutation; rerun with --yes after reviewing every printed digest".into());
            }
            let root = find_root()?;
            let activation = crate::local_validation::activate_reviewed_policy(
                &root,
                &commit,
                &confirm_policy_digest,
                &coordinator,
                &confirm_executable_digest,
                &hooks,
            )?;
            println!(
                "ACTIVE policy={} commit={} coordinator={} hooks={}",
                activation.trusted_policy_oid,
                commit,
                confirm_executable_digest,
                hooks.display()
            );
            println!("Activation created no validation receipt, gate PASS, push authorization, transfer, or remote-parity fact.");
            Ok(0)
        }
    }
}

#[cfg(test)]
fn cmd_first_adoption(command: FirstAdoptionCommand) -> CmdResult {
    match command {
        FirstAdoptionCommand::Prepare {
            change,
            base,
            branch,
            upstream,
            security_evidence,
            json,
        } => {
            require_pretrust_mode("verify")?;
            let root = find_root()?;
            // Evidence is intentionally only a contained input marker here; no
            // profile/check is executed by preparation.
            let evidence = Project::new(&root)
                .change_dir(&change)
                .join(&security_evidence);
            let _ = openspec_core::read_contained_capped(&root, &evidence, 1024 * 1024)
                .map_err(|e| format!("invalid first-adoption security evidence: {e}"))?;
            let scope = crate::local_validation::prepare_checkpoint_scope(
                &root,
                &change,
                &base,
                &branch,
                upstream.as_deref(),
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&scope).map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "Prepared checkpoint scope {} entries, digest {}",
                    scope.entries.len(),
                    scope.aggregate_digest
                );
                for entry in &scope.entries {
                    println!(
                        "  {}",
                        match entry {
                            crate::local_validation::CheckpointEntryV1::Present {
                                path, ..
                            } => path,
                            crate::local_validation::CheckpointEntryV1::Deleted {
                                path, ..
                            } => path,
                        }
                    );
                }
            }
            Ok(0)
        }
        FirstAdoptionCommand::VerifyCheckpoint {
            change,
            checkpoint,
            security_evidence,
            confirm_policy_digest,
            confirm_coordinator_digest,
            json,
        } => {
            require_pretrust_mode("verify")?;
            let root = find_root()?;
            let cfg = Config::load(&root);
            let local = cfg.local_validation.ok_or_else(|| "structured local_validation is absent; first adoption cannot construct a trusted policy".to_string())?;
            let (proof, digest, nonce) = crate::local_validation::verify_first_adoption_checkpoint(
                &root,
                &change,
                &checkpoint,
                &security_evidence,
                &local,
                &confirm_policy_digest,
                &confirm_coordinator_digest,
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "proof": proof,
                        "pretrust_proof_digest": digest,
                        "bootstrap_nonce_preimage": nonce,
                    })
                );
            } else {
                println!(
                    "Verified checkpoint proof {digest}; public nonce: {}",
                    nonce
                );
            }
            Ok(0)
        }
        FirstAdoptionCommand::Restart {
            change,
            stage,
            superseded_checkpoint,
            superseded_proof,
            replacement_tip,
            security_evidence,
            actor,
            reason,
            yes,
            json,
        } => {
            let root = find_root()?;
            let ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
            let stage = match stage.as_str() {
                "pretrust" => ledger::FirstAdoptionRestartStage::Pretrust,
                "posttrust" => ledger::FirstAdoptionRestartStage::Posttrust,
                _ => return Err("restart stage must be exactly pretrust or posttrust".into()),
            };
            if !git::valid_oid_hex(&superseded_checkpoint) {
                return Err("superseded checkpoint must be a full lowercase object id".into());
            }
            if !git::sanitized_commit_exists(&root, &superseded_checkpoint)
                .map_err(|e| e.to_string())?
            {
                return Err("superseded checkpoint is not an existing direct commit".into());
            }
            if let Some(replacement) = replacement_tip.as_deref() {
                if !git::valid_oid_hex(replacement) {
                    return Err("replacement tip must be a full lowercase object id".into());
                }
                if !git::sanitized_commit_exists(&root, replacement).map_err(|e| e.to_string())? {
                    return Err("replacement tip is not an existing direct commit".into());
                }
                match git::sanitized_is_ancestor(&root, &superseded_checkpoint, replacement)
                    .map_err(|e| e.to_string())?
                {
                    Some(true) if replacement != superseded_checkpoint => {}
                    Some(true) => {
                        return Err("replacement tip must differ from superseded checkpoint".into());
                    }
                    Some(false) => {
                        return Err(
                            "replacement tip must descend from the superseded checkpoint".into(),
                        );
                    }
                    None => return Err("checkpoint ancestry is unavailable locally".into()),
                }
            }
            let trusted =
                git::sanitized_direct_ref_oid(&root, "refs/mpd/trusted-validation-policy")
                    .map_err(|e| e.to_string())?;
            if let Some(oid) = trusted.as_deref() {
                if !git::sanitized_commit_exists(&root, oid).map_err(|e| e.to_string())? {
                    return Err("trusted-policy ref does not name an existing direct commit".into());
                }
            }
            match (stage, trusted.as_ref()) {
                (ledger::FirstAdoptionRestartStage::Pretrust, Some(_)) => {
                    return Err("pretrust restart refused after trusted-policy CAS".into());
                }
                (ledger::FirstAdoptionRestartStage::Posttrust, None) => {
                    return Err(
                        "posttrust restart requires the initialized trusted-policy ref".into(),
                    );
                }
                _ => {}
            }
            if matches!(stage, ledger::FirstAdoptionRestartStage::Posttrust) {
                let reconciliation = ledger
                    .first_adoption_reconciliations
                    .first()
                    .ok_or("posttrust restart requires first-adoption reconciliation")?;
                if trusted.as_deref() != Some(reconciliation.policy_object_oid.as_str()) {
                    return Err(
                        "posttrust restart trusted ref differs from reconciliation policy object"
                            .into(),
                    );
                }
            }
            if let Some(proof) = superseded_proof.as_deref() {
                crate::digest::Digest::from_hex(proof)?;
                crate::local_validation::verify_restart_superseded_proof(
                    &root,
                    &change,
                    &superseded_checkpoint,
                    proof,
                )?;
            }
            let evidence_relative = std::path::Path::new(&security_evidence);
            if security_evidence.is_empty()
                || evidence_relative.is_absolute()
                || evidence_relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err("first-adoption restart evidence path is unsafe".into());
            }
            let evidence_path = Project::new(&root)
                .change_dir(&change)
                .join(evidence_relative);
            let evidence = openspec_core::read_contained_capped(&root, &evidence_path, 1024 * 1024)
                .map_err(|e| format!("invalid first-adoption restart evidence: {e}"))?;
            if canonical_artifact_verdict(&evidence)? != Verdict::Pass {
                return Err("first-adoption restart requires reviewed PASS evidence".into());
            }
            let event = ledger::FirstAdoptionRestartV1 {
                schema: 1,
                stage,
                superseded_checkpoint_oid: superseded_checkpoint,
                superseded_proof_digest: superseded_proof,
                replacement_tip_oid: replacement_tip,
                actor,
                reason,
                evidence_digest: crate::digest::Digest::of_bytes(evidence.as_bytes()).to_hex(),
                at_epoch_secs: ledger::now_epoch_secs(),
            };
            let mut candidate = ledger.clone();
            let appended = candidate.append_first_adoption_restart(event.clone())?;
            let first = candidate
                .first_adoption_restarts
                .first()
                .ok_or("restart eligibility state is unexpectedly empty")?;
            let eligibility = candidate.first_adoption_eligibility(
                &first.superseded_checkpoint_oid,
                first.superseded_proof_digest.as_deref(),
                &first.evidence_digest,
            )?;
            if !yes {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": if appended { "preview" } else { "already-recorded" },
                            "event": event,
                            "eligibility": eligibility,
                            "mutated": false,
                        })
                    );
                } else if appended {
                    println!(
                        "Preview: append first-adoption restart; latest eligible checkpoint {}. Rerun with --yes.",
                        eligibility.latest_eligible_checkpoint_oid
                    );
                } else {
                    println!("First-adoption restart is already recorded; no mutation needed.");
                }
                return Ok(0);
            }
            if appended {
                ledger::save(&root, &candidate).map_err(|e| e.to_string())?;
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": if appended { "restarted" } else { "already-recorded" },
                        "eligibility": eligibility,
                        "mutated": appended,
                    })
                );
            } else if appended {
                println!(
                    "First-adoption restart appended; latest eligible checkpoint {}. No gate PASS or Git ref was created.",
                    eligibility.latest_eligible_checkpoint_oid
                );
            } else {
                println!("First-adoption restart is already recorded; no second event appended.");
            }
            Ok(0)
        }
        FirstAdoptionCommand::Reconcile {
            change,
            checkpoint,
            policy_object,
            pretrust_proof,
            security_evidence,
            reason,
            yes,
            json,
        } => {
            let root = find_root()?;
            let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
            for (label, value) in [
                ("checkpoint", &checkpoint),
                ("policy-object", &policy_object),
            ] {
                if !(value.len() == 40 || value.len() == 64)
                    || !value.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(format!("invalid {label} oid"));
                }
            }
            crate::digest::Digest::from_hex(&pretrust_proof)?;
            let evidence_path = Project::new(&root)
                .change_dir(&change)
                .join(&security_evidence);
            let _ = openspec_core::read_contained_capped(&root, &evidence_path, 1024 * 1024)
                .map_err(|e| format!("invalid first-adoption security evidence: {e}"))?;
            let proof = crate::local_validation::verify_first_adoption_reconciliation(
                &root,
                &change,
                &checkpoint,
                &policy_object,
                &pretrust_proof,
                &security_evidence,
            )?;
            let trusted_policy_digest =
                crate::local_validation::trusted_policy_object_digest(&root, &policy_object)?;
            let event = ledger::FirstAdoptionReconciliationV1 {
                schema: 1,
                checkpoint_oid: checkpoint,
                policy_object_oid: policy_object,
                pretrust_proof_digest: pretrust_proof,
                security_evidence,
                reason: ledger::bounded_text(&reason, "reason")?,
                at_epoch_secs: ledger::now_epoch_secs(),
                checkpoint_scope_digest: proof.checkpoint_scope.aggregate_digest.clone(),
                security_evidence_digest: proof.security_evidence_digest.clone(),
                bootstrap_nonce_digest: proof.nonce_digest.clone(),
                trusted_policy_digest,
            };
            if let Some(existing) = ledger.first_adoption_reconciliations.first() {
                let same = existing.checkpoint_oid == event.checkpoint_oid
                    && existing.policy_object_oid == event.policy_object_oid
                    && existing.pretrust_proof_digest == event.pretrust_proof_digest
                    && existing.security_evidence == event.security_evidence
                    && existing.reason == event.reason
                    && existing.checkpoint_scope_digest == event.checkpoint_scope_digest
                    && existing.security_evidence_digest == event.security_evidence_digest
                    && existing.bootstrap_nonce_digest == event.bootstrap_nonce_digest
                    && existing.trusted_policy_digest == event.trusted_policy_digest;
                if !same {
                    return Err("conflicting first-adoption reconciliation already exists".into());
                }
                if json {
                    println!("{{\"status\":\"already-reconciled\"}}");
                } else {
                    println!("First-adoption already reconciled; no second event appended.");
                }
                return Ok(0);
            }
            if !yes {
                if json {
                    println!("{{\"status\":\"preview\",\"action\":\"rewind-build\"}}");
                } else {
                    println!("Preview: append one first-adoption reconciliation and rewind to Build; rerun with --yes.");
                }
                return Ok(0);
            }
            ledger.reconcile_first_adoption(event)?;
            ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
            if json {
                println!("{{\"status\":\"reconciled\",\"phase\":\"build\"}}");
            } else {
                println!("First-adoption reconciled; provisional Build history retained and current phase rewound to Build.");
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
fn require_pretrust_mode(expected: &str) -> Result<(), String> {
    match std::env::var("MPD_PRETRUST_MODE") {
        Ok(observed) if observed == expected => Ok(()),
        _ => Err(format!(
            "pretrust control-plane command refused outside the reviewed {expected} sandbox; use scripts/run-pretrust.sh"
        )),
    }
}

fn cmd_manifest(change: Option<String>) -> CmdResult {
    let root = find_root()?;
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
    let docs_dir = Config::load(&root).docs_dir().to_string();
    println!(
        "Seeded {}. Declare paths before Architecture PASS — every strict change needs at \
         least \"openspec/changes/{change}/**\" and \"{docs_dir}/{change}.md\" declared, or the \
         Build gate will refuse.",
        path.display()
    );
    Ok(0)
}

/// D7: read-only outcome measurement. Deliberately does NOT call
/// `resolve_change` — an omitted `--change` means "every ledger under
/// `.mpd/state/`", never a fallback to the current-change pointer, and
/// `.mpd/current` is never consulted (Cond 5).
fn cmd_stats(change: Option<String>, json: bool) -> CmdResult {
    let root = find_root()?;
    if let Some(name) = &change {
        openspec_core::validate_change_name(name)?;
    }
    let report = crate::stats::collect(&root, change.as_deref());
    if json {
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| e.to_string())?
        );
    } else {
        print!("{}", crate::stats::render_human(&report));
    }
    Ok(0)
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

/// Security-code Condition 18 / C1: the per-change landing-containment
/// verdict (`observation.state`) and the ref-level classification
/// (`observation.ref_state`) are deliberately separate facts — a Diverged or
/// Rewritten `state` can mean either "the landing itself never reached the
/// remote" or "the landing is fine but the ref diverged elsewhere", and an
/// operator cannot tell those apart from `state` alone. This renders both,
/// plus the raw landing-containment boolean, as one human-readable line so
/// every text surface presents them identically; `--json` output already
/// carries both fields directly on `ParityObservation`.
fn describe_ref_level_parity(observation: &closure::ParityObservation) -> String {
    let ref_state = observation
        .ref_state
        .map(|state| state.label().to_ascii_uppercase())
        .unwrap_or_else(|| "UNKNOWN (no stable observation)".into());
    let contained = match observation.landing_contained {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown (remote object not locally present, no fetch performed)",
    };
    format!("ref-level state: {ref_state}; landing commit contained in remote: {contained}")
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
        let next = if coherence.coherent {
            "mpd publish --verify"
        } else if coherence.ready_to_commit {
            "commit the exact archived result"
        } else {
            "resolve the blockers below before publishing"
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "change": change,
                "remote": target.remote,
                "ref": target.reference,
                "commit_coherence": {"coherent": coherence.coherent, "head": coherence.head, "ready_to_commit": coherence.ready_to_commit, "blockers": coherence.blockers},
                "last_observation": cached,
                "next": next
            })).unwrap());
        } else {
            println!(
                "Publish readiness: {}",
                if coherence.coherent {
                    "READY"
                } else if coherence.ready_to_commit {
                    "AWAITING COMMIT"
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
            println!("\n→ next: {next}");
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
                if let Some(landed) = observation.landed_oid.as_deref() {
                    println!("  this change's landing commit: {landed}");
                }
                println!("  {}", describe_ref_level_parity(&observation));
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

/// Read one exact regular repository postimage for Candidate closure
/// construction.  The descriptor is opened no-follow and its identity/length
/// is rechecked after the bounded read so a path replacement cannot be
/// silently attributed to the reviewed overlay.
fn closure_postimage_from_file(
    root: &Path,
    relative: &str,
) -> Result<closure::ClosureFilePostimage, String> {
    digest::validate_canonical_path(relative).map_err(|error| error.to_string())?;
    let path = root.join(relative);
    openspec_core::assert_contained(root, &path).map_err(|error| error.to_string())?;
    let before = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect closure postimage {relative:?}: {error}"))?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > 16 * 1024 * 1024 {
        return Err(format!(
            "closure postimage {relative:?} is not a bounded regular file"
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| format!("cannot open closure postimage {relative:?}: {error}"))?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read closure postimage {relative:?}: {error}"))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(format!("closure postimage {relative:?} exceeds its cap"));
    }
    let after = file
        .metadata()
        .map_err(|error| format!("cannot recheck closure postimage {relative:?}: {error}"))?;
    #[cfg(unix)]
    let unchanged = {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mode() == after.mode()
    };
    #[cfg(not(unix))]
    let unchanged = before.len() == after.len();
    if !unchanged {
        return Err(format!(
            "closure postimage {relative:?} changed during its bounded read"
        ));
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        if after.permissions().mode() & 0o111 != 0 {
            0o100755
        } else {
            0o100644
        }
    };
    #[cfg(not(unix))]
    let mode = 0o100644;
    Ok(closure::ClosureFilePostimage {
        path: relative.to_string(),
        mode,
        bytes,
    })
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
/// `mpd archive --recover` and `mpd archive --abandon` both use for their
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
                // D7: reiterate the intended order. Abandon is post-commit
                // housekeeping — if the closure commit has not been made
                // yet, the archived change can still be committed via
                // `mpd use <change>` followed by `git commit` (the
                // pre-commit gate authorizes it from the archive record).
                println!(
                    "If the closure commit has not been made yet: it still can be — run \
                     `mpd use <change>` then `git commit` (do not re-create the active \
                     manifest)."
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

/// Resolve the closure-plan `Result` captured out of the archive transaction
/// callback (D2). This is a pure fail-closed checkpoint — never a panic —
/// deliberately factored out so the "an invalid Candidate closure input
/// surfaces as `Err`, not `.expect()`-triggered abort" contract is directly
/// unit-testable without driving the whole archive transaction.
fn require_closure_plan(
    captured: Option<Result<closure::CandidateClosurePlan, String>>,
) -> Result<Option<closure::CandidateClosurePlan>, String> {
    match captured {
        Some(Ok(plan)) => Ok(Some(plan)),
        Some(Err(error)) => Err(format!("cannot archive: {error}")),
        None => Ok(None),
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
        eprintln!("Run `mpd archive --recover` or `mpd archive --abandon` first.");
        return Ok(1);
    }

    let change = resolve_change(&root, change)?;
    let (mut ledger, observed) =
        ledger::load_observed(&root, &change).map_err(|e| e.to_string())?;
    let config = Config::load(&root);
    if enforce_freshness_before_effects(&root, &change, &mut ledger, &observed, &config, false)? {
        return Ok(1);
    }

    // Irreversibility guard: never archive over an unmet gate or open condition.
    let mut reasons = ledger.blocking_reasons();
    let task_plan = Project::new(&root)
        .task_plan(&change)
        .map_err(|error| format!("Cannot archive {change:?} — invalid tasks.md: {error}"))?;
    let task_accounting = ledger.task_accounting(&task_plan);
    if task_plan.strict && !task_accounting.accounted() {
        if !task_accounting.open.is_empty() {
            reasons.push(format!(
                "{} Builder task(s) remain open: {}",
                task_accounting.open.len(),
                task_accounting.open.join(", ")
            ));
        }
        for id in &task_accounting.stale {
            reasons.push(format!("task deferral for {id} is stale"));
        }
    }
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
    // Current Commando policy denies artifact waivers. Inert when
    // `strict=false`, so the manual tier is unchanged.
    if ledger.strict {
        let refusals = strict_archive_recheck(&root, &change, &ledger);
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

    let evidence_blockers = current_evidence_blockers(&root, &change, &ledger);
    if !evidence_blockers.is_empty() {
        eprintln!("Cannot archive {change:?} — gate evidence is no longer current:");
        for blocker in &evidence_blockers {
            eprintln!("  - {blocker}");
        }
        return Ok(1);
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

    // Modern strict gates retain a Build Candidate.  When present, archive
    // must carry it through full Candidate-to-Commit equivalence.  Ledgers
    // created by the older manual tier have no Candidate record and retain
    // the legacy scoped-coherence path; absence is never upgraded into a
    // modern claim.
    let candidate_context = if let Some(build_capture) = ledger
        .gates
        .get(&Phase::Build)
        .and_then(|record| record.candidate.as_ref())
    {
        for phase in [Phase::SecurityCode, Phase::Test] {
            let capture = ledger
                .gates
                .get(&phase)
                .and_then(|record| record.candidate.as_ref())
                .ok_or_else(|| {
                    format!(
                        "cannot archive: {} has no retained Candidate binding",
                        phase.label()
                    )
                })?;
            if capture.subject.id != build_capture.subject.id {
                return Err(format!(
                    "cannot archive: {} Candidate differs from Build",
                    phase.label()
                ));
            }
        }
        let candidate = crate::candidate::reopen_candidate(&root, build_capture)?;
        let candidate_root = PathBuf::from(&candidate.capture.clone_private_root);
        let mut phase_postimages = Vec::new();
        for phase in [
            Phase::SecurityCode,
            Phase::DesignSignoff,
            Phase::Test,
            Phase::Documentation,
            Phase::DocValidation,
        ] {
            if !phase.is_active(ledger.applicability()) {
                continue;
            }
            let record = ledger.gates.get(&phase).ok_or_else(|| {
                format!("cannot archive: {} gate record is missing", phase.label())
            })?;
            let receipt_id = record
                .receipt
                .as_ref()
                .ok_or_else(|| format!("cannot archive: {} receipt is missing", phase.label()))?
                .id
                .to_hex();
            let filename = match phase {
                Phase::SecurityCode => "security-code.md",
                Phase::DesignSignoff => "design-signoff.md",
                Phase::Test => "test.md",
                Phase::Documentation => "documentation.md",
                Phase::DocValidation => "doc-validation.md",
                _ => unreachable!(),
            };
            let relative = format!("openspec/changes/{change}/{filename}");
            phase_postimages.push(closure::PhaseArtifactPostimage {
                phase,
                receipt_id,
                file: closure_postimage_from_file(&root, &relative)?,
            });
        }
        Some((candidate, candidate_root, phase_postimages))
    } else {
        None
    };

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
    // D2: the closure plan is captured as a `Result`, never `.expect()`-ed
    // inside the transaction callback. A validation failure surfaces as a
    // normal fail-closed error, checked and returned immediately after
    // `build_plan` returns and BEFORE any durable write it could feed
    // (`closure::save_candidate_closure_plan`, then `openspec_core::prepare`).
    let closure_plan_out: std::cell::RefCell<
        Option<Result<closure::CandidateClosurePlan, String>>,
    > = std::cell::RefCell::new(None);
    let documentation_postimages = candidate_context
        .as_ref()
        .map(|_| {
            let doc_validation_receipt_id = ledger
                .gates
                .get(&Phase::DocValidation)
                .and_then(|record| record.receipt.as_ref())
                .ok_or("cannot archive: Doc Validation receipt is missing")?
                .id
                .to_hex();
            Ok::<closure::ReviewedDocumentationPostimages, String>(
                closure::ReviewedDocumentationPostimages {
                    doc_validation_receipt_id,
                    files: doc_fold
                        .as_ref()
                        .map(|(target, content)| {
                            Ok(closure::ClosureFilePostimage::regular(
                                relative_to_root(&root, target)?,
                                content.as_bytes().to_vec(),
                            ))
                        })
                        .into_iter()
                        .collect::<Result<Vec<_>, String>>()?,
                },
            )
        })
        .transpose()?;
    let spec_postimages = plan
        .updates
        .iter()
        .map(|update| {
            Ok(closure::ClosureFilePostimage::regular(
                relative_to_root(&root, &update.target_path)?,
                update.content.as_bytes().to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
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
            let archive_closure = ArchiveClosure {
                base_commit: base_commit.clone(),
                archive_path: archive_target_rel.clone(),
                transaction_id: digest::Digest::from_hex(&transaction_id.to_hex())
                    .expect("openspec_core Digest hex always parses as an mpd Digest"),
                candidate_id: candidate_context
                    .as_ref()
                    .map(|(candidate, _, _)| candidate.capture.subject.id.clone()),
                allowed_paths: closure_scope.clone(),
                system_paths: scope_snapshot.clone(),
                post_archive_digest: final_scoped_digest,
                archived_at,
            };
            lg.archive_closure = Some(archive_closure.clone());
            let mut bytes = serde_json::to_string_pretty(&lg)
                .expect("ledger always serializes")
                .into_bytes();
            bytes.push(b'\n');
            *ledger_bytes_out.borrow_mut() = Some(bytes.clone());
            if let Some((candidate, candidate_root, phase_postimages)) = &candidate_context {
                // Never `.expect()` on input-derived state (design.md D2,
                // Cond 3): a missing documentation postimage is an internal
                // contract violation reported through the same captured-Result
                // channel as every other closure-plan validation failure,
                // rather than a panic.
                let closure_result: Result<closure::CandidateClosurePlan, String> =
                    match documentation_postimages.as_ref() {
                        Some(documentation) => closure::build_candidate_closure_plan(
                            candidate_root,
                            candidate,
                            &archive_closure,
                            phase_postimages,
                            documentation,
                            &closure::DeterministicArchivePostimages {
                                spec_writes: spec_postimages.clone(),
                                ledger: closure::ClosureFilePostimage::regular(
                                    ledger_path_rel.clone(),
                                    bytes.clone(),
                                ),
                            },
                        ),
                        None => Err(
                            "internal error: modern Candidate closure is missing documentation \
                             evidence"
                                .to_string(),
                        ),
                    };
                *closure_plan_out.borrow_mut() = Some(closure_result);
            }
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

    // D2/Cond 13: check the captured closure-plan Result BEFORE either durable
    // write it could feed — the clone-private plan file
    // (`closure::save_candidate_closure_plan`) and the archive transaction
    // itself (`openspec_core::prepare`). At this point nothing has been
    // journaled or staged, so an `Err` here leaves the tree untouched with no
    // cleanup required (fail-closed, never a panic).
    let closure_plan = require_closure_plan(closure_plan_out.into_inner())?;

    if let Some(closure_plan) = closure_plan {
        closure::save_candidate_closure_plan(&root, &closure_plan)?;
    }

    openspec_core::prepare(&root, &plan_txn, &contents).map_err(|e| e.to_string())?;
    match openspec_core::drive(&root).map_err(|e| e.to_string())? {
        openspec_core::DriveOutcome::AwaitingCommit => {}
        openspec_core::DriveOutcome::NothingPending => {
            return Err("internal error: transaction vanished immediately after prepare".into());
        }
        openspec_core::DriveOutcome::ManualRecoveryRequired { path, detail } => {
            eprintln!(
                "Archive stopped: {path} is in an unexpected state ({detail}). \
                 No further write was performed. Run `mpd archive --recover` to inspect it."
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
        "→ next: commit the archived result, then run `mpd archive --abandon --yes` \
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

/// `mpd strict <change>`: promote an already-begun change to the strict tier
/// (design.md#conditions-for-builder). Mirrors `cmd_use`'s name-validation +
/// ledger-existence check; mutates strictness ONLY through the monotonic
/// `set_strict()` (never `strict=false`); idempotent when already strict; touches
/// only the change's own ledger. The change name is charset-validated by
/// `validate_change_name`, so it carries no control characters into output.
fn cmd_strict(change: String) -> CmdResult {
    let root = find_root()?;
    openspec_core::validate_change_name(&change)?;
    if !ledger::state_path(&root, &change).is_file() {
        return Err(format!(
            "no ledger for change {change:?}; run `mpd begin {change}` first"
        ));
    }
    let mut ledger = ledger::load(&root, &change).map_err(|e| e.to_string())?;
    if ledger.strict {
        println!("Change {change:?} is already strict — no change.");
        return Ok(0);
    }
    ledger.set_strict();
    ledger::save(&root, &ledger).map_err(|e| e.to_string())?;
    println!("Promoted {change:?} to the strict tier: judgment gates now enforce their artifacts.");
    Ok(0)
}

/// The tunable personas (persona display names + the normalized `DocValidation`
/// key). `main-session`/`-` are not tunable. A `persona set` for a name outside
/// this set is rejected, so a fat-fingered name cannot write inert config rot that
/// silently no-ops a strengthening the operator believes they applied (round-4 F4-3).
const TUNABLE_PERSONAS: &[&str] = &[
    "Architect",
    "Designer",
    "Security",
    "Builder",
    "Tester",
    "Documenter",
    "DocValidation",
];

/// Canonicalize a persona name (case-insensitive) to its `TUNABLE_PERSONAS` form,
/// or `None` if it is not a tunable persona.
fn normalize_persona(name: &str) -> Option<&'static str> {
    TUNABLE_PERSONAS
        .iter()
        .copied()
        .find(|p| p.eq_ignore_ascii_case(name))
}

/// The per-field current/range/baseline/dangerous view for one persona — the same
/// structure `persona show --json` exposes so a harness interview renders the same
/// warnings mpd enforces.
fn persona_show_json(key: &str, t: &crate::config::PersonaTuning) -> serde_json::Value {
    serde_json::json!({
        "persona": key,
        "fields": {
            "rigor": {
                "current": t.rigor.map(|r| r.label()),
                "baseline": "standard",
                "range": ["standard", "deep", "paranoid"],
                "dangerous": false,
            },
            "depth": {
                "current": t.depth.map(|d| d.label()),
                "baseline": "examples",
                "range": ["examples", "property", "fuzz"],
                "dangerous": false,
                "note": "Tester only",
            },
            "directive-append": {
                "current": t.directive_append.as_deref(),
                "baseline": serde_json::Value::Null,
                "range": "free text — appended after the base directive; un-rankable",
                "dangerous": true,
            },
        }
    })
}

fn print_persona_text(key: &str, t: &crate::config::PersonaTuning) {
    let show = |v: Option<&str>| v.map(|s| s.to_string()).unwrap_or_else(|| "—".to_string());
    println!("Persona: {key}");
    println!(
        "  rigor            current {:<10} range standard|deep|paranoid (baseline standard)",
        show(t.rigor.map(|r| r.label()))
    );
    println!(
        "  depth            current {:<10} range examples|property|fuzz (baseline examples, Tester only)",
        show(t.depth.map(|d| d.label()))
    );
    println!(
        "  directive-append current {:<10} ⚠ un-rankable — recorded/flagged on every gate receipt",
        if t.directive_append.is_some() {
            "<set>"
        } else {
            "—"
        }
    );
}

fn cmd_persona(command: PersonaCommand) -> CmdResult {
    let root = find_root()?;
    match command {
        PersonaCommand::List { json } => {
            let cfg = Config::load(&root);
            let default = crate::config::PersonaTuning::default();
            if json {
                let arr: Vec<_> = TUNABLE_PERSONAS
                    .iter()
                    .map(|key| persona_show_json(key, cfg.persona_tuning(key).unwrap_or(&default)))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
            } else {
                for key in TUNABLE_PERSONAS {
                    print_persona_text(key, cfg.persona_tuning(key).unwrap_or(&default));
                }
            }
            Ok(0)
        }
        PersonaCommand::Show { persona, json } => {
            let key = normalize_persona(&persona).ok_or_else(|| {
                format!(
                    "unknown persona {persona:?}; one of: {}",
                    TUNABLE_PERSONAS.join(", ")
                )
            })?;
            let cfg = Config::load(&root);
            let default = crate::config::PersonaTuning::default();
            let t = cfg.persona_tuning(key).unwrap_or(&default);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&persona_show_json(key, t)).unwrap()
                );
            } else {
                print_persona_text(key, t);
            }
            Ok(0)
        }
        PersonaCommand::Set {
            persona,
            field,
            value,
        } => {
            let key = normalize_persona(&persona).ok_or_else(|| {
                format!(
                    "unknown persona {persona:?}; one of: {}",
                    TUNABLE_PERSONAS.join(", ")
                )
            })?;
            let mut cfg = Config::load(&root);
            let entry = cfg.personas.entry(key.to_string()).or_default();
            match field.as_str() {
                "rigor" => {
                    let r: crate::ledger::Rigor = value.parse().map_err(|_| {
                        format!("unknown rigor {value:?}; range: standard | deep | paranoid")
                    })?;
                    let prior = entry.rigor.map(|r| r.label()).unwrap_or("—");
                    entry.rigor = Some(r);
                    println!("{key}.rigor: {prior} → {}", r.label());
                }
                "depth" => {
                    let d: crate::ledger::Depth = value.parse().map_err(|_| {
                        format!("unknown depth {value:?}; range: examples | property | fuzz")
                    })?;
                    let prior = entry.depth.map(|d| d.label()).unwrap_or("—");
                    entry.depth = Some(d);
                    println!("{key}.depth: {prior} → {} (Tester only)", d.label());
                }
                "directive-append" | "directive_append" => {
                    let safe = harness::terminal_safe(&value);
                    entry.directive_append = Some(safe);
                    println!(
                        "  ⚠ {key}.directive-append set — this is the ONE un-rankable knob. It is \
                         appended (never replaces the base directive), recorded on every gate \
                         receipt, and flagged `weakened`. mpd cannot prove it rigor-preserving."
                    );
                }
                other => {
                    return Err(format!(
                        "unknown field {other:?}; one of: rigor, depth, directive-append"
                    ))
                }
            }
            cfg.save(&root).map_err(|e| e.to_string())?;
            Ok(0)
        }
        PersonaCommand::Reset { persona, field } => {
            let key = normalize_persona(&persona).ok_or_else(|| {
                format!(
                    "unknown persona {persona:?}; one of: {}",
                    TUNABLE_PERSONAS.join(", ")
                )
            })?;
            let mut cfg = Config::load(&root);
            match field.as_deref() {
                None => {
                    cfg.personas.remove(key);
                    println!("{key}: all tuning cleared (baseline).");
                }
                Some("rigor") => {
                    if let Some(e) = cfg.personas.get_mut(key) {
                        e.rigor = None;
                    }
                    println!("{key}.rigor cleared (baseline standard).");
                }
                Some("depth") => {
                    if let Some(e) = cfg.personas.get_mut(key) {
                        e.depth = None;
                    }
                    println!("{key}.depth cleared (baseline examples).");
                }
                Some("directive-append") | Some("directive_append") => {
                    if let Some(e) = cfg.personas.get_mut(key) {
                        e.directive_append = None;
                    }
                    println!("{key}.directive-append cleared.");
                }
                Some(other) => {
                    return Err(format!(
                        "unknown field {other:?}; one of: rigor, depth, directive-append"
                    ))
                }
            }
            // Drop an entry that is now fully baseline so config stays minimal.
            if let Some(e) = cfg.personas.get(key) {
                if *e == crate::config::PersonaTuning::default() {
                    cfg.personas.remove(key);
                }
            }
            cfg.save(&root).map_err(|e| e.to_string())?;
            Ok(0)
        }
    }
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

const VALIDATOR_POLICY_CHECKS: &[&str] = &[
    "typed-config-effective-graph",
    "trusted-direct-ref-object-cas",
    "clone-private-hooks-coordinator",
    "directive-parity",
    "locked-tools-rust-components-offline-cache",
    "sandbox-contract-capability",
    "advisory-revision-tree-freshness",
    "path-safety-private-state-log-health",
    "note-codec-direct-ref-readability",
];

const VALIDATOR_POLICY_EXCLUSIONS: &[&str] = &[
    "current-subject-receipt",
    "deploy-install-record",
    "installed-path-identity",
    "installed-identity-probe",
    "configured-validation-execution",
    "remote-parity",
];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DoctorSeverity {
    Info,
    Blocker,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorFinding {
    code: String,
    severity: DoctorSeverity,
    component: String,
    state: String,
    message: String,
    fix: String,
}

#[derive(Debug, Serialize)]
struct ScopedDoctorReport {
    /// Stable, versioned machine format. New meanings require a schema bump.
    schema: u32,
    scope: String,
    included_checks: Vec<String>,
    excluded_checks: Vec<String>,
    resolved_subject: Option<String>,
    findings: Vec<DoctorFinding>,
    effects: DoctorEffectCounts,
    status: String,
}

/// Explicit negative-effect evidence for each scoped doctor invocation. These
/// counters are produced by the command DAG itself: scoped doctor has no edge
/// to validation, install, probe, or remote observation functions.
#[derive(Debug, Default, Serialize)]
struct DoctorEffectCounts {
    configured_validation: u32,
    install: u32,
    identity_probe: u32,
    remote: u32,
}

fn doctor_finding(
    code: &str,
    component: &str,
    fix: &str,
    check: impl FnOnce() -> Result<(), String>,
) -> DoctorFinding {
    match check() {
        Ok(()) => DoctorFinding {
            code: code.into(),
            severity: DoctorSeverity::Info,
            component: component.into(),
            state: "healthy".into(),
            message: format!("{component} is healthy"),
            fix: String::new(),
        },
        Err(message) => DoctorFinding {
            code: code.into(),
            severity: DoctorSeverity::Blocker,
            component: component.into(),
            state: "blocked".into(),
            message,
            fix: fix.into(),
        },
    }
}

fn doctor_directive_parity(root: &Path) -> Result<(), String> {
    let base = root.join(".mpd/directives");
    for (relative, bundled) in crate::directives::bundled() {
        let path = base.join(relative);
        openspec_core::assert_contained(root, &path)
            .map_err(|e| format!("unsafe directive {relative}: {e}"))?;
        let actual = openspec_core::read_contained_capped(root, &path, 1024 * 1024)
            .map_err(|e| format!("directive {relative} is missing or unreadable: {e}"))?;
        if actual != bundled {
            return Err(format!(
                "directive {relative} differs from bundled doctrine"
            ));
        }
    }
    Ok(())
}

fn static_doctor_findings(
    root: &Path,
) -> (
    Vec<DoctorFinding>,
    Option<crate::config::LocalValidationConfig>,
    Option<crate::local_validation::Subject>,
) {
    let mut findings = Vec::new();
    let loaded = Config::load_strict(root).and_then(|config| {
        let local = config
            .local_validation
            .ok_or("structured local_validation is absent")?;
        local.validate()?;
        Ok(local)
    });
    let local = loaded.as_ref().ok().cloned();
    findings.push(match loaded {
        Ok(_) => doctor_finding(
            "typed-config-effective-graph",
            "local-validation",
            "repair .mpd/config.json with the supported structured local_validation schema",
            || crate::local_validation::static_policy_check(root),
        ),
        Err(message) => DoctorFinding {
            code: "typed-config-effective-graph".into(),
            severity: DoctorSeverity::Blocker,
            component: "local-validation".into(),
            state: "blocked".into(),
            message,
            fix: "repair .mpd/config.json with the supported structured local_validation schema"
                .into(),
        },
    });

    let mut subject = None;
    if let Some(local) = &local {
        let preflight = crate::local_validation::preflight(root, Some("HEAD"), local);
        match preflight {
            Ok(preflight) => {
                subject = Some(preflight.subject.clone());
                findings.push(match preflight.blocker {
                    Some(message) => DoctorFinding {
                        code: "trusted-direct-ref-object-cas".into(),
                        severity: DoctorSeverity::Blocker,
                        component: "trusted-policy".into(),
                        state: "blocked".into(),
                        message,
                        fix: "activate the reviewed direct immutable policy object".into(),
                    },
                    None => DoctorFinding {
                        code: "trusted-direct-ref-object-cas".into(),
                        severity: DoctorSeverity::Info,
                        component: "trusted-policy".into(),
                        state: "healthy".into(),
                        message: "trusted direct policy object matches the exact HEAD policy"
                            .into(),
                        fix: String::new(),
                    },
                });
            }
            Err(message) => findings.push(DoctorFinding {
                code: "trusted-direct-ref-object-cas".into(),
                severity: DoctorSeverity::Blocker,
                component: "trusted-policy".into(),
                state: "blocked".into(),
                message,
                fix: "repair the exact HEAD policy inputs and direct trusted-policy ref".into(),
            }),
        }
        // This preflight is intentionally evaluated once. The three findings
        // are separate operator-facing components of one acyclic static input
        // observation, not three repeated filesystem/tool/cache traversals.
        let static_inputs = crate::local_validation::doctor_static_validation_inputs(root, local);
        for (code, component, fix) in [
            (
                "locked-tools-rust-components-offline-cache",
                "toolchain",
                "run the reviewed bootstrap to restore locked tools, Rust components, and the offline Cargo cache",
            ),
            (
                "sandbox-contract-capability",
                "sandbox",
                "restore the mandatory reviewed network-denial sandbox adapter and profile",
            ),
            (
                "advisory-revision-tree-freshness",
                "advisory-db",
                "refresh the clone-private advisory database from its reviewed lock",
            ),
        ] {
            findings.push(doctor_finding(code, component, fix, || static_inputs.clone()));
        }
    } else {
        for (code, component) in [
            ("trusted-direct-ref-object-cas", "trusted-policy"),
            ("locked-tools-rust-components-offline-cache", "toolchain"),
            ("sandbox-contract-capability", "sandbox"),
            ("advisory-revision-tree-freshness", "advisory-db"),
        ] {
            findings.push(DoctorFinding {
                code: code.into(),
                severity: DoctorSeverity::Blocker,
                component: component.into(),
                state: "blocked".into(),
                message:
                    "cannot inspect this policy input until structured local_validation is valid"
                        .into(),
                fix: "repair .mpd/config.json first".into(),
            });
        }
    }
    findings.push(doctor_finding(
        "clone-private-hooks-coordinator",
        "activation",
        "activate the reviewed clone-private coordinator and hook launchers",
        || crate::local_validation::doctor_activation_health(root),
    ));
    findings.push(doctor_finding(
        "directive-parity",
        "directives",
        "review and synchronize project directives with the bundled doctrine",
        || doctor_directive_parity(root),
    ));
    findings.push(doctor_finding(
        "path-safety-private-state-log-health",
        "private-state",
        "remove or repair unsafe clone-private state through the reviewed recovery workflow",
        || crate::local_validation::doctor_private_state_health(root),
    ));
    if let Some(subject) = &subject {
        findings.push(doctor_finding(
            "note-codec-direct-ref-readability",
            "receipt-store",
            "repair the direct validation-notes ref or its bounded receipt codec",
            || crate::local_validation::doctor_note_store_health(root, subject),
        ));
    } else {
        findings.push(DoctorFinding {
            code: "note-codec-direct-ref-readability".into(),
            severity: DoctorSeverity::Blocker,
            component: "receipt-store".into(),
            state: "blocked".into(),
            message: "cannot resolve a safe exact HEAD subject for note codec inspection".into(),
            fix: "repair local Git object health and the structured validation policy".into(),
        });
    }
    (findings, local, subject)
}

fn resolve_runtime_head(root: &Path) -> Result<String, String> {
    let head = git::head_commit(root)
        .map_err(|e| e.to_string())?
        .ok_or("runtime-health requires a committed HEAD")?;
    let dirty = git::status_v2(root)
        .map_err(|e| e.to_string())?
        .into_iter()
        .any(|entry| !matches!(entry, git::StatusEntry::Ignored { .. }));
    if dirty {
        return Err(format!(
            "runtime-health requires a clean exact HEAD; resolved {head} but repository state is dirty"
        ));
    }
    Ok(head)
}

/// Resolve runtime ownership after archive clears `.mpd/current`. Pending
/// closure metadata is authoritative while present; after it is removed, the
/// newest archived ledger whose base is in HEAD ancestry is selected under a
/// bounded, non-following state-directory scan.
fn resolve_runtime_ledger(root: &Path, head: &str) -> Result<ledger::Ledger, String> {
    if let Some(change) = ledger::current(root) {
        return ledger::load(root, &change).map_err(|e| e.to_string());
    }
    match openspec_core::inspect(root) {
        Ok(Some(pending)) => {
            return ledger::load(root, &pending.change).map_err(|e| e.to_string());
        }
        Ok(None) => {}
        Err(error) => return Err(format!("pending closure metadata is unreadable: {error}")),
    }
    let state = ledger::mpd_dir(root).join("state");
    openspec_core::assert_contained(root, &state).map_err(|e| e.to_string())?;
    let entries = std::fs::read_dir(&state)
        .map_err(|e| format!("ledger state directory is unavailable: {e}"))?;
    let mut candidates = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= 256 {
            return Err("ledger state directory exceeds the 256-entry runtime cap".into());
        }
        let entry = entry.map_err(|e| e.to_string())?;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let entry_path = entry.path();
        let Some(name) = entry_path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        if openspec_core::validate_change_name(name).is_err() {
            continue;
        }
        let candidate = ledger::load(root, name).map_err(|e| e.to_string())?;
        let Some(closure) = candidate.archive_closure.as_ref() else {
            continue;
        };
        if git::is_ancestor(root, &closure.base_commit, head).map_err(|e| e.to_string())?
            == Some(true)
        {
            candidates.push((closure.archived_at, candidate));
        }
    }
    candidates.sort_by_key(|(archived_at, _)| *archived_at);
    let Some((latest_at, latest)) = candidates.pop() else {
        return Err("no active, pending, or archived runtime ledger is available".into());
    };
    if candidates
        .last()
        .is_some_and(|(archived_at, _)| *archived_at == latest_at)
    {
        return Err("multiple archived ledgers are equally eligible for runtime-health".into());
    }
    Ok(latest)
}

/// Reopen and hash the declared installed artifact without executing it. The
/// observation must match the recorded Build identity and the exact Deploy
/// definition/result digest; readiness-only Deploy instead re-hashes its
/// contained evidence file.
fn doctor_installed_deploy_health(
    root: &Path,
    local: &crate::config::LocalValidationConfig,
    ledger: &ledger::Ledger,
) -> Result<(), String> {
    let deploy = local
        .deploy_output
        .as_ref()
        .ok_or("typed Deploy configuration is absent")?;
    let record = ledger
        .gates
        .get(&Phase::Deploy)
        .and_then(|gate| gate.deploy_result.as_ref())
        .ok_or("typed Deploy record is absent")?;
    if record.schema != 1 || !record.verified {
        return Err("typed Deploy record is unsupported or unverified".into());
    }
    let definition = serde_json::to_vec(deploy).map_err(|e| e.to_string())?;
    if digest::Digest::of_bytes(&definition).to_hex() != record.definition_digest {
        return Err("Deploy record differs from the configured Deploy definition".into());
    }
    match deploy {
        crate::config::DeployOutputConfig::Execute {
            artifact,
            installed_path,
            target,
            ..
        } => {
            if record.mode != "execute"
                || record.target != *target
                || !record.install_executed
                || record.probe_executed
            {
                return Err("execute Deploy record has inconsistent effect state".into());
            }
            let contract = local
                .build_output
                .as_ref()
                .ok_or("typed Build output configuration is absent")?;
            let build = ledger
                .gates
                .get(&Phase::Build)
                .and_then(|gate| gate.build_output.as_ref())
                .ok_or("typed Build output record is absent")?;
            if build.schema != 1
                || build.size > build.max_bytes
                || build.mode != build.required_mode
                || build.name != *artifact
                || build.name != contract.name
                || build.path != contract.path
                || build.max_bytes != contract.max_bytes
                || build.required_mode != contract.required_mode
            {
                return Err("Build record differs from the configured artifact contract".into());
            }
            let installed = crate::local_validation::identity(root, installed_path)?;
            if installed.size != build.size
                || installed.mode != build.mode
                || installed.sha256 != build.sha256
            {
                return Err(
                    "installed path identity differs from the recorded Build output".into(),
                );
            }
            let expected = serde_json::to_vec(&serde_json::json!({
                "build_sha256": build.sha256,
                "installed_sha256": installed.sha256,
                "installed_size": installed.size,
                "installed_mode": installed.mode,
            }))
            .map_err(|e| e.to_string())?;
            if digest::Digest::of_bytes(&expected).to_hex() != record.result_digest {
                return Err("installed path identity differs from the Deploy result digest".into());
            }
        }
        crate::config::DeployOutputConfig::Readiness { evidence, target } => {
            if record.mode != "readiness"
                || record.target != *target
                || record.install_executed
                || record.probe_executed
            {
                return Err("readiness Deploy record has inconsistent effect state".into());
            }
            let bytes =
                openspec_core::read_contained_capped(root, &root.join(evidence), 1024 * 1024)
                    .map_err(|e| format!("readiness evidence is unavailable: {e}"))?;
            if digest::Digest::of_bytes(bytes.as_bytes()).to_hex() != record.result_digest {
                return Err("readiness evidence differs from the Deploy result digest".into());
            }
        }
    }
    Ok(())
}

fn runtime_doctor_findings(
    root: &Path,
    local: Option<&crate::config::LocalValidationConfig>,
) -> (Vec<DoctorFinding>, Option<String>, bool) {
    runtime_doctor_findings_with_receipt(root, local, |root, local, profile| {
        crate::local_validation::doctor_runtime_receipt_health(root, local, profile)
    })
}

fn runtime_doctor_findings_with_receipt(
    root: &Path,
    local: Option<&crate::config::LocalValidationConfig>,
    receipt_observer: impl FnOnce(
        &Path,
        &crate::config::LocalValidationConfig,
        &str,
    ) -> Result<crate::local_validation::DoctorReceiptHealth, String>,
) -> (Vec<DoctorFinding>, Option<String>, bool) {
    let mut findings = Vec::new();
    let head = resolve_runtime_head(root);
    let subject = head.as_ref().ok().cloned();
    findings.push(match &head {
        Ok(head) => DoctorFinding {
            code: "clean-resolved-head".into(),
            severity: DoctorSeverity::Info,
            component: "subject".into(),
            state: "clean".into(),
            message: format!("runtime-health resolved one clean exact HEAD {head}"),
            fix: String::new(),
        },
        Err(message) => DoctorFinding {
            code: "clean-resolved-head".into(),
            severity: DoctorSeverity::Blocker,
            component: "subject".into(),
            state: "blocked".into(),
            message: message.clone(),
            fix: "commit or remove local changes, then issue a receipt for exact HEAD".into(),
        },
    });

    let runtime_ledger = head.as_deref().map_or_else(
        |_| Err("clean HEAD is unavailable".into()),
        |head| resolve_runtime_ledger(root, head),
    );
    let receipt = match local {
        Some(local) => {
            let profile = match runtime_ledger.as_ref() {
                Ok(ledger) if ledger.effective_risk() == RiskLevel::High => {
                    &local.gates.high_risk_test
                }
                _ => &local.gates.test,
            };
            receipt_observer(root, local, profile)
        }
        None => Err("structured local_validation is absent".into()),
    };
    let receipt_subject = receipt
        .as_ref()
        .ok()
        .map(|value| value.subject.commit.clone());
    findings.push(match receipt {
        Ok(health) if Some(health.subject.commit.as_str()) == subject.as_deref() => DoctorFinding {
            code: "exact-head-required-receipt".into(),
            severity: DoctorSeverity::Info,
            component: "validation-receipt".into(),
            state: "current".into(),
            message: format!(
                "required profile {} has current receipt {} for {}",
                health.profile, health.receipt_id, health.subject.commit
            ),
            fix: String::new(),
        },
        Ok(health) => DoctorFinding {
            code: "exact-head-required-receipt".into(),
            severity: DoctorSeverity::Blocker,
            component: "validation-receipt".into(),
            state: "stale".into(),
            message: format!(
                "required receipt binds {} instead of resolved HEAD {}",
                health.subject.commit,
                subject.as_deref().unwrap_or("(unresolved)")
            ),
            fix: "run exact-HEAD local validation after policy health is restored".into(),
        },
        Err(message) => DoctorFinding {
            code: "exact-head-required-receipt".into(),
            severity: DoctorSeverity::Blocker,
            component: "validation-receipt".into(),
            state: "blocked".into(),
            message,
            fix: "run exact-HEAD local validation after policy health is restored".into(),
        },
    });

    let mut coherent = false;
    match runtime_ledger {
        Ok(runtime_ledger) => {
            findings.push(DoctorFinding {
                code: "active-pending-ledger".into(),
                severity: DoctorSeverity::Info,
                component: "ledger".into(),
                state: "readable".into(),
                message: format!("ledger for change {} is readable", runtime_ledger.change),
                fix: String::new(),
            });
            let deploy_record = runtime_ledger
                .gates
                .get(&Phase::Deploy)
                .and_then(|gate| gate.deploy_result.as_ref());
            findings.push(match deploy_record {
                Some(result) if result.verified => DoctorFinding {
                    code: "deploy-install-record".into(),
                    severity: DoctorSeverity::Info,
                    component: "deploy".into(),
                    state: "observed".into(),
                    message: format!("verified {} Deploy record is present", result.mode),
                    fix: String::new(),
                },
                _ => DoctorFinding {
                    code: "deploy-install-record".into(),
                    severity: DoctorSeverity::Blocker,
                    component: "deploy".into(),
                    state: "blocked".into(),
                    message: "no verified Deploy/install record is available".into(),
                    fix: "complete the typed Deploy gate; doctor will not install or probe".into(),
                },
            });
            findings.push(match local {
                Some(local) => match doctor_installed_deploy_health(root, local, &runtime_ledger) {
                    Ok(()) => DoctorFinding {
                        code: "installed-path-identity".into(),
                        severity: DoctorSeverity::Info,
                        component: "installed-artifact".into(),
                        state: "current".into(),
                        message: "configured installed path matches Build and Deploy identity"
                            .into(),
                        fix: String::new(),
                    },
                    Err(message) => DoctorFinding {
                        code: "installed-path-identity".into(),
                        severity: DoctorSeverity::Blocker,
                        component: "installed-artifact".into(),
                        state: "blocked".into(),
                        message,
                        fix: "rerun typed Deploy; doctor will not install or execute identity"
                            .into(),
                    },
                },
                None => DoctorFinding {
                    code: "installed-path-identity".into(),
                    severity: DoctorSeverity::Blocker,
                    component: "installed-artifact".into(),
                    state: "blocked".into(),
                    message: "structured local_validation is absent".into(),
                    fix: "repair typed Deploy configuration".into(),
                },
            });
            findings.push(match runtime_ledger.archive_closure.as_ref() {
                Some(archive) => match closure::verify_commit_coherence(root, archive) {
                    Ok(observation)
                        if observation.coherent
                            && receipt_subject.as_deref() == subject.as_deref()
                            && observation.head.as_deref().is_some_and(|landing| {
                                Some(landing) == subject.as_deref()
                                    || subject.as_deref().is_some_and(|head| {
                                        crate::git::is_ancestor(root, landing, head)
                                            == Ok(Some(true))
                                    })
                            }) =>
                    {
                        coherent = true;
                        DoctorFinding {
                            code: "archived-closure-head-coherence".into(),
                            severity: DoctorSeverity::Info,
                            component: "closure".into(),
                            state: "coherent".into(),
                            message: format!(
                                "archived closure's landing commit {} coheres with exact HEAD {}",
                                observation.head.as_deref().unwrap_or_default(),
                                subject.as_deref().unwrap_or_default()
                            ),
                            fix: String::new(),
                        }
                    }
                    Ok(observation) => DoctorFinding {
                        code: "archived-closure-head-coherence".into(),
                        severity: DoctorSeverity::Blocker,
                        component: "closure".into(),
                        state: "blocked".into(),
                        message: format!(
                            "closure/HEAD/receipt incoherent: {}",
                            observation.blockers.join(", ")
                        ),
                        fix: "restore the closure commit and issue a receipt for exact HEAD".into(),
                    },
                    Err(message) => DoctorFinding {
                        code: "archived-closure-head-coherence".into(),
                        severity: DoctorSeverity::Blocker,
                        component: "closure".into(),
                        state: "blocked".into(),
                        message,
                        fix: "repair the archive closure before validation or push".into(),
                    },
                },
                None => DoctorFinding {
                    code: "archived-closure-head-coherence".into(),
                    severity: DoctorSeverity::Blocker,
                    component: "closure".into(),
                    state: "blocked".into(),
                    message: "no archived closure record is available".into(),
                    fix: "complete archive and create its coherent closure commit".into(),
                },
            });
        }
        Err(message) => {
            for (code, component) in [
                ("active-pending-ledger", "ledger"),
                ("deploy-install-record", "deploy"),
                ("installed-path-identity", "installed-artifact"),
                ("archived-closure-head-coherence", "closure"),
            ] {
                findings.push(DoctorFinding {
                    code: code.into(),
                    severity: DoctorSeverity::Blocker,
                    component: component.into(),
                    state: "blocked".into(),
                    message: format!("runtime state is unreadable: {message}"),
                    fix: "repair the active, pending, or archived ledger state".into(),
                });
            }
        }
    }
    (findings, subject, coherent)
}

fn doctor_expected_pending_remote(coherent: bool, findings: &[DoctorFinding]) -> bool {
    coherent
        && !findings
            .iter()
            .any(|finding| matches!(finding.severity, DoctorSeverity::Blocker))
}

fn cmd_scoped_doctor(scope: &str, json: bool, enforce: bool) -> CmdResult {
    if !matches!(scope, "validator-policy" | "runtime-health") {
        return Err("--scope must be validator-policy or runtime-health".into());
    }
    let root = find_root()?;
    let (mut findings, local, static_subject) = static_doctor_findings(&root);
    let mut included_checks = VALIDATOR_POLICY_CHECKS
        .iter()
        .map(|check| (*check).to_string())
        .collect::<Vec<_>>();
    let mut excluded_checks = VALIDATOR_POLICY_EXCLUSIONS
        .iter()
        .map(|check| (*check).to_string())
        .collect::<Vec<_>>();
    let mut resolved_subject = static_subject.map(|subject| subject.commit);
    let mut expected_pending_remote = false;
    if scope == "runtime-health" {
        included_checks.extend(
            [
                "clean-resolved-head",
                "exact-head-required-receipt",
                "activation-observation",
                "active-pending-ledger",
                "deploy-install-record",
                "installed-path-identity",
                "archived-closure-head-coherence",
                "expected-pending-remote-state",
            ]
            .into_iter()
            .map(str::to_string),
        );
        excluded_checks.retain(|check| {
            check != "current-subject-receipt"
                && check != "deploy-install-record"
                && check != "installed-path-identity"
        });
        let (runtime, subject, coherent) = runtime_doctor_findings(&root, local.as_ref());
        resolved_subject = subject.or(resolved_subject);
        findings.extend(runtime);
        expected_pending_remote = doctor_expected_pending_remote(coherent, &findings);
        if expected_pending_remote {
            findings.push(DoctorFinding {
                code: "remote-parity".into(),
                severity: DoctorSeverity::Info,
                component: "remote-parity".into(),
                state: "expected_pending_remote".into(),
                message: "local closure is coherent; fresh remote parity remains an explicit later observation".into(),
                fix: String::new(),
            });
        }
    }
    let blocked = findings
        .iter()
        .any(|finding| matches!(finding.severity, DoctorSeverity::Blocker));
    let report = ScopedDoctorReport {
        schema: 1,
        scope: scope.into(),
        included_checks,
        excluded_checks,
        resolved_subject,
        findings,
        effects: DoctorEffectCounts::default(),
        status: if blocked {
            "blocked".into()
        } else if expected_pending_remote {
            "expected_pending_remote".into()
        } else {
            "pass".into()
        },
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("mpd doctor --scope {scope} (read-only)");
        println!(
            "  resolved subject: {}",
            report.resolved_subject.as_deref().unwrap_or("(unresolved)")
        );
        println!("  included checks: {}", report.included_checks.join(", "));
        println!("  excluded checks: {}", report.excluded_checks.join(", "));
        println!(
            "  effects: validation={} install={} identity-probe={} remote={}",
            report.effects.configured_validation,
            report.effects.install,
            report.effects.identity_probe,
            report.effects.remote
        );
        for finding in report
            .findings
            .iter()
            .filter(|finding| matches!(finding.severity, DoctorSeverity::Blocker))
        {
            println!("  BLOCKED [{}] {}", finding.code, finding.message);
        }
    }
    if enforce && blocked {
        eprintln!("doctor --scope {scope} blocked; inspect typed findings for repairs");
        return Ok(3);
    }
    Ok(0)
}

fn cmd_doctor(json: bool, fix: bool, scope: Option<String>, enforce: bool) -> CmdResult {
    if let Some(scope) = scope {
        if fix {
            return Err("--scope cannot be combined with --fix".into());
        }
        return cmd_scoped_doctor(&scope, json, enforce);
    }
    if enforce {
        return Err("--enforce requires --scope validator-policy|runtime-health".into());
    }
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
    let configured = root.as_ref().map(|r| Config::load(r));
    let test_cmd = configured.as_ref().and_then(|c| c.test.clone());
    let deploy_cmd = configured.as_ref().and_then(|c| c.deploy.clone());
    let local_validation = configured
        .as_ref()
        .and_then(|c| c.local_validation.as_ref());
    let local_validation_status = local_validation.map(|v| v.validate());
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
    let closure_cfg = configured;
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
            "local_validation": match local_validation_status.as_ref() {
                None => serde_json::json!({"configured":false,"migration_blocker":"structured local_validation is absent; legacy test is compatibility-only"}),
                Some(Ok(())) => serde_json::json!({"configured":true,"valid":true}),
                Some(Err(error)) => serde_json::json!({"configured":true,"valid":false,"error":error}),
            },
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
        archived_closure_fallback_scope, bounded_record_hint, canonical_artifact_actor,
        canonical_artifact_verdict, check_documentation, check_sections, closure_recovery_hint,
        current_validation_status, dated_archive_matches, doctor_expected_pending_remote,
        doctor_installed_deploy_health, extract_section, has_unfilled_placeholder,
        is_valid_date_prefix, parse_exploit, receipt_failure_fact, removed_manifest_change_name,
        require_closure_plan, resolve_runtime_head, resolve_runtime_ledger,
        retained_candidate_for_objective_gate, runtime_doctor_findings_with_receipt,
        sandbox_blocker, stages_removal_of, strict_actor_separation_issue, strict_gate_command,
        union_closure_scope, upstream_artifact_pointers, validate_candidate_report_binding,
        validate_evidence, validate_introduced_by, WorkflowOutcome, REQUIRED_DOC_SECTIONS,
    };
    use crate::ledger::{self, ChangeKind, CheckSummary, GateRecord, Verdict};
    use crate::phase::{Applicability, Phase};
    use proptest::prelude::*;
    use std::process::Command;

    // D2 / Cond 3, 13: the two reproduced archive panics
    // (`.expect("archive inputs were validated before the transaction
    // callback")` and `.expect("modern Candidate closure has documentation
    // evidence")`) both flowed into `closure_plan_out`, then were unwrapped
    // through this exact checkpoint. Testing it directly proves the fix
    // structurally: an `Err` captured here can never reach a panic, it can
    // only reach this ordinary `Result` return — checked before either
    // durable write (`save_candidate_closure_plan`, `openspec_core::prepare`).
    #[test]
    fn require_closure_plan_never_panics_on_a_captured_validation_error() {
        assert_eq!(require_closure_plan(None), Ok(None));

        let plan = crate::closure::CandidateClosurePlan {
            schema: crate::closure::CANDIDATE_CLOSURE_SCHEMA,
            candidate_id: "c".repeat(64),
            candidate_base_commit: "b".repeat(40),
            archive_path: "openspec/changes/archive/2026-01-01-x".into(),
            archive_transaction_id: "t".repeat(64),
            overlay_digest: "o".repeat(64),
            expected_tree_digest: "e".repeat(64),
            entries: Vec::new(),
        };
        assert_eq!(require_closure_plan(Some(Ok(plan.clone()))), Ok(Some(plan)));

        // The durable-doc-outside-manifest and retained-manifest-read-failure
        // reproductions both arrive here as a plain `Err(String)` — this must
        // surface as a normal `Result::Err`, never a panic/abort, and the
        // underlying diagnostic must survive into the returned message.
        let err = require_closure_plan(Some(Err(
            "reviewed documentation postimage \"docs/x.md\" is not a regular declared \
             durable-doc path"
                .to_string(),
        )))
        .unwrap_err();
        assert!(
            err.contains("durable-doc path"),
            "the failing input's diagnostic must survive: {err}"
        );

        let err = require_closure_plan(Some(Err(
            "candidate closure cannot read its retained manifest: permission denied".to_string(),
        )))
        .unwrap_err();
        assert!(
            err.contains("retained manifest"),
            "the failing input's diagnostic must survive: {err}"
        );
    }

    fn closure_entry(path: &str) -> crate::closure::ClosureTreeEntry {
        crate::closure::ClosureTreeEntry {
            path: path.to_string(),
            mode: 0o100644,
            byte_len: 4,
            sha256: "a".repeat(64),
        }
    }

    fn closure_plan_with(
        entries: Vec<crate::closure::ClosureTreeEntry>,
    ) -> crate::closure::CandidateClosurePlan {
        crate::closure::CandidateClosurePlan {
            schema: crate::closure::CANDIDATE_CLOSURE_SCHEMA,
            candidate_id: "c".repeat(64),
            candidate_base_commit: "b".repeat(40),
            archive_path: "openspec/changes/archive/2026-01-01-x".into(),
            archive_transaction_id: "t".repeat(64),
            overlay_digest: "o".repeat(64),
            expected_tree_digest: "e".repeat(64),
            entries,
        }
    }

    #[test]
    fn union_closure_scope_widens_rows_with_plan_entries_sorted_and_deduped() {
        // D3 / Cond 4: a valid plan unions its entry paths into the rows-only
        // scope. A first-ever closure commit (no prior classification rows)
        // must pass with exactly the plan's entries as scope.
        let plan = closure_plan_with(vec![
            closure_entry("crates/mpd/src/a.rs"),
            closure_entry("README.md"),
        ]);
        let scope = union_closure_scope(vec!["README.md".to_string()], Some(Ok(plan))).unwrap();
        assert_eq!(
            scope,
            vec!["README.md".to_string(), "crates/mpd/src/a.rs".to_string()]
        );

        // First-ever closure commit: empty rows, scope = exactly the plan entries.
        let plan = closure_plan_with(vec![closure_entry("openspec/specs/x/spec.md")]);
        let scope = union_closure_scope(Vec::new(), Some(Ok(plan))).unwrap();
        assert_eq!(scope, vec!["openspec/specs/x/spec.md".to_string()]);
    }

    #[test]
    fn union_closure_scope_keeps_rows_only_when_no_plan_was_ever_recorded() {
        // D3 / Cond 4: no plan recorded (legacy/non-candidate closure, or a
        // repo that has never saved a Candidate closure plan at all) must
        // leave the rows-only scope completely unchanged.
        let rows = vec!["a.txt".to_string(), "b.txt".to_string()];
        let scope = union_closure_scope(rows.clone(), None).unwrap();
        assert_eq!(scope, rows);
    }

    #[test]
    fn union_closure_scope_blocks_on_any_recorded_but_invalid_plan() {
        // D3 / Cond 4: a present-but-invalid plan (corrupt, non-canonical,
        // oversized, or wrong-transaction) must BLOCK, never silently fall
        // back to rows-only.
        for reason in [
            "Candidate closure plan is unsafe or oversized",
            "Candidate closure plan is malformed",
            "Candidate closure plan transaction binding differs",
            "Candidate closure plan is not canonical",
        ] {
            let error =
                union_closure_scope(vec!["a.txt".to_string()], Some(Err(reason.to_string())))
                    .unwrap_err();
            assert!(error.contains("invalid"), "{error}");
            assert!(error.contains(reason), "{error}");
        }
    }

    fn diff_entry(status: char, path: &str, orig_path: Option<&str>) -> crate::git::DiffEntry {
        crate::git::DiffEntry {
            status,
            score: None,
            path: path.to_string(),
            orig_path: orig_path.map(str::to_string),
        }
    }

    #[test]
    fn stages_removal_of_matches_delete_and_rename_origin_never_copy() {
        // D2 Condition 11: exact equality only. `D` (destination) or `R`
        // (origin) trigger; `C` (copy) never does — the path remains
        // present as the copy's own destination, so a copy of the manifest
        // never counts as "removed".
        let target = "openspec/changes/thing/manifest.json";
        assert!(stages_removal_of(&[diff_entry('D', target, None)], target));
        assert!(stages_removal_of(
            &[diff_entry(
                'R',
                "openspec/changes/archive/2026-01-01-thing/manifest.json",
                Some(target)
            )],
            target
        ));
        assert!(!stages_removal_of(
            &[diff_entry(
                'C',
                "openspec/changes/other/manifest.json",
                Some(target)
            )],
            target
        ));
        assert!(!stages_removal_of(&[diff_entry('M', target, None)], target));
        // A near-match must never trigger — byte-exact equality only, never
        // a prefix/suffix match.
        assert!(!stages_removal_of(
            &[diff_entry(
                'D',
                "openspec/changes/thing-evil/manifest.json",
                None
            )],
            target
        ));
        assert!(!stages_removal_of(&[], target));
    }

    #[test]
    fn removed_manifest_change_name_extracts_only_a_validated_single_component_name() {
        // D5/Condition 8, 11: used only to enrich guidance text, so it must
        // reject anything `validate_change_name` would — path traversal,
        // multi-component paths, and invalid characters all return `None`
        // rather than a name that could ever double as an authority.
        assert_eq!(
            removed_manifest_change_name(&[diff_entry(
                'D',
                "openspec/changes/some-thing/manifest.json",
                None
            )]),
            Some("some-thing".to_string())
        );
        assert_eq!(
            removed_manifest_change_name(&[diff_entry(
                'R',
                "openspec/changes/archive/2026-01-01-some-thing/manifest.json",
                Some("openspec/changes/some-thing/manifest.json")
            )]),
            Some("some-thing".to_string())
        );
        // A copy never counts — the manifest is still present at its path.
        assert_eq!(
            removed_manifest_change_name(&[diff_entry(
                'C',
                "openspec/changes/copy-of-thing/manifest.json",
                Some("openspec/changes/some-thing/manifest.json")
            )]),
            None
        );
        assert_eq!(
            removed_manifest_change_name(&[diff_entry(
                'D',
                "openspec/changes/../../etc/manifest.json",
                None
            )]),
            None
        );
        assert_eq!(
            removed_manifest_change_name(&[diff_entry(
                'D',
                "openspec/changes/a/b/manifest.json",
                None
            )]),
            None
        );
        assert_eq!(
            removed_manifest_change_name(&[diff_entry(
                'D',
                "openspec/changes/Evil_Name/manifest.json",
                None
            )]),
            None
        );
        assert_eq!(removed_manifest_change_name(&[]), None);
    }

    #[test]
    fn closure_recovery_hint_names_the_change_suggests_use_never_recover_or_recreate() {
        let hint = closure_recovery_hint("some-thing");
        assert!(hint.contains("mpd use some-thing"), "{hint}");
        assert!(hint.contains("archive --abandon --yes"), "{hint}");
        // D5/Condition 3.2: never suggest `archive --recover` for this state
        // — recover requires the pointer abandon already deleted.
        assert!(!hint.contains("archive --recover"), "{hint}");
        assert!(hint.contains("Do not re-create"), "{hint}");
    }

    #[test]
    fn bounded_record_hint_strips_control_bytes_and_truncates_long_input() {
        // Cond 12 (security-plan): the worktree ledger/plan are attacker-
        // controlled text under this arm's own threat model — control
        // characters (terminal escape/spoofing) must never survive, and
        // length is bounded exactly like the `ledger_version_probe`
        // precedent (`ledger.rs:1690-1708`).
        let hostile = format!("safe-prefix\u{7}\u{1b}[31mtail{}", "x".repeat(300));
        let safe = bounded_record_hint(&hostile);
        assert!(!safe.contains('\u{7}'), "{safe}");
        assert!(!safe.contains('\u{1b}'), "{safe}");
        assert!(safe.contains("safe-prefix"), "{safe}");
        assert!(safe.ends_with('…'), "{safe}");
        assert!(safe.chars().count() <= 201, "{safe}");

        let short = bounded_record_hint("short-value");
        assert_eq!(short, "short-value");
    }

    fn closure_test_root(label: &str) -> std::path::PathBuf {
        let root = doctor_test_dir(label);
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        root
    }

    fn test_candidate_plan(
        candidate_id: &str,
        candidate_base_commit: &str,
        archive_path: &str,
        archive_transaction_id: &str,
        entries: Vec<crate::closure::ClosureTreeEntry>,
    ) -> crate::closure::CandidateClosurePlan {
        // `expected_tree_digest` must be the REAL digest of `entries` —
        // `validate_candidate_closure_plan` (run by both `save_` and
        // `load_candidate_closure_plan`) rejects a stale one, so a
        // hand-picked placeholder would never round-trip through disk.
        let expected_tree_digest = crate::closure::closure_tree_digest(&entries).unwrap();
        crate::closure::CandidateClosurePlan {
            schema: crate::closure::CANDIDATE_CLOSURE_SCHEMA,
            candidate_id: candidate_id.to_string(),
            candidate_base_commit: candidate_base_commit.to_string(),
            archive_path: archive_path.to_string(),
            archive_transaction_id: archive_transaction_id.to_string(),
            overlay_digest: "0".repeat(64),
            expected_tree_digest,
            entries,
        }
    }

    fn test_archive_record(
        candidate_id: Option<&str>,
        base_commit: &str,
        archive_path: &str,
        transaction_id_hex: &str,
        system_paths: Vec<String>,
    ) -> crate::closure::ArchiveClosure {
        crate::closure::ArchiveClosure {
            base_commit: base_commit.to_string(),
            archive_path: archive_path.to_string(),
            transaction_id: crate::digest::Digest::from_hex(transaction_id_hex).unwrap(),
            candidate_id: candidate_id.map(str::to_string),
            allowed_paths: system_paths.clone(),
            system_paths,
            post_archive_digest: crate::digest::Digest::of_bytes(b"test-postimage"),
            archived_at: 10,
        }
    }

    #[test]
    fn archived_closure_fallback_scope_blocks_on_empty_system_paths() {
        // D2.5: a pre-`system_paths` legacy record degrades to empty and
        // must fail closed here — mirrors `manifest_view`. This check runs
        // before any filesystem access, so an unused placeholder root path
        // is fine.
        let record = test_archive_record(
            None,
            &"b".repeat(40),
            "openspec/changes/archive/x",
            &"1".repeat(64),
            vec![],
        );
        let error = archived_closure_fallback_scope(std::path::Path::new("/nonexistent"), &record)
            .unwrap_err();
        assert!(error.contains("no concrete recorded scope"), "{error}");
    }

    #[test]
    fn archived_closure_fallback_scope_authorizes_legacy_record_from_system_paths_alone() {
        // D2.6 / Condition 9(d): `candidate_id: None` (a legacy, pre-
        // Candidate archive) keeps the concrete-footprint scope alone — no
        // plan is ever consulted, so no filesystem access happens here
        // either.
        let record = test_archive_record(
            None,
            &"b".repeat(40),
            "openspec/changes/archive/x",
            &"1".repeat(64),
            vec!["b.txt".to_string(), "a.txt".to_string()],
        );
        let scope =
            archived_closure_fallback_scope(std::path::Path::new("/nonexistent"), &record).unwrap();
        assert_eq!(scope, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn archived_closure_fallback_scope_blocks_when_candidate_bound_plan_is_missing() {
        let root = closure_test_root("fallback-missing-plan");
        let record = test_archive_record(
            Some(&"c".repeat(64)),
            &"b".repeat(40),
            "openspec/changes/archive/x",
            &"1".repeat(64),
            vec!["a.txt".to_string()],
        );
        let error = archived_closure_fallback_scope(&root, &record).unwrap_err();
        assert!(error.contains("missing or invalid"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn archived_closure_fallback_scope_blocks_when_plan_binding_differs_from_record() {
        // Security-plan Condition 5/14 and the Q1/Q4 bypass framing: a
        // resolved change whose OWN manifest deletion is staged and whose
        // ledger DOES carry a candidate-bound archive record must still be
        // blocked outright — never narrowed to `system_paths` alone — the
        // moment its retained plan disagrees with the record on any bound
        // field.
        let root = closure_test_root("fallback-rebound-plan");
        let candidate_id = "c".repeat(64);
        let archive_path = "openspec/changes/archive/2026-01-01-thing";
        let txid = "1".repeat(64);
        let plan = test_candidate_plan(&candidate_id, &"b".repeat(40), archive_path, &txid, vec![]);
        crate::closure::save_candidate_closure_plan(&root, &plan).unwrap();

        // The record disagrees with the saved plan on `base_commit` — a
        // rebound/tampered shape.
        let record = test_archive_record(
            Some(&candidate_id),
            &"d".repeat(40),
            archive_path,
            &txid,
            vec!["system-only.txt".to_string()],
        );
        let error = archived_closure_fallback_scope(&root, &record).unwrap_err();
        assert!(error.contains("binding differs"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn archived_closure_fallback_scope_authorizes_union_of_system_paths_and_plan_entries() {
        let root = closure_test_root("fallback-authorized");
        let candidate_id = "c".repeat(64);
        let base_commit = "b".repeat(40);
        let archive_path = "openspec/changes/archive/2026-01-01-thing";
        let txid = "1".repeat(64);
        let plan = test_candidate_plan(
            &candidate_id,
            &base_commit,
            archive_path,
            &txid,
            vec![crate::closure::ClosureTreeEntry {
                path: "plan-only.txt".into(),
                mode: 0o100644,
                byte_len: 1,
                sha256: "a".repeat(64),
            }],
        );
        crate::closure::save_candidate_closure_plan(&root, &plan).unwrap();

        let record = test_archive_record(
            Some(&candidate_id),
            &base_commit,
            archive_path,
            &txid,
            vec!["system-only.txt".to_string()],
        );
        let scope = archived_closure_fallback_scope(&root, &record).unwrap();
        assert_eq!(
            scope,
            vec!["plan-only.txt".to_string(), "system-only.txt".to_string()]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn doctor_test_dir(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-doctor-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn doctor_gate_record() -> GateRecord {
        GateRecord {
            verdict: Verdict::Pass,
            by: "fixture".into(),
            evidence: None,
            checks: Some(CheckSummary::default()),
            at: "2026-01-01".into(),
            failure_class: None,
            exploitability: None,
            attempt: 1,
            started_at_epoch_secs: 1,
            completed_at_epoch_secs: 2,
            receipt: None,
            persona_tuning: None,
            candidate: None,
            build_output: None,
            deploy_result: None,
            validation_receipt: None,
        }
    }

    fn candidate_capture(id: char) -> crate::candidate::CandidateCapture {
        crate::candidate::CandidateCapture {
            subject: crate::candidate::CandidateSubject {
                version: 1,
                change: "candidate-chain".into(),
                base_commit: "a".repeat(40),
                base_tree: "b".repeat(40),
                manifest_digest: "c".repeat(64),
                entries_digest: "d".repeat(64),
                policy_digest: "e".repeat(64),
                source_digest: "f".repeat(64),
                id: id.to_string().repeat(64),
            },
            clone_private_root: "/private/candidate".into(),
            storage: crate::candidate::CandidateStorageBinding {
                record_path: "/private/candidate.json".into(),
                record_sha256: "1".repeat(64),
                root_device: 1,
                root_inode: 2,
                record_device: 1,
                record_inode: 3,
            },
            counts: crate::candidate::CandidateCounts::default(),
            excluded_dirty_digest: "2".repeat(64),
            excluded_dirty_sample: Vec::new(),
            declared_status_digest: "3".repeat(64),
            captured_at_epoch_secs: 1,
        }
    }

    fn candidate_output(id: &str) -> crate::ledger::BuildOutputV1 {
        crate::ledger::BuildOutputV1 {
            schema: 1,
            name: "mpd".into(),
            path: ".mpd/build-output/mpd".into(),
            max_bytes: 1024,
            required_mode: 0o755,
            size: 1,
            mode: 0o755,
            device: 1,
            inode: 2,
            sha256: "4".repeat(64),
            candidate_id: Some(id.into()),
        }
    }

    #[test]
    fn strict_objective_gates_require_one_candidate_id() {
        let capture = candidate_capture('5');
        let mut ledger =
            ledger::Ledger::new("candidate-chain", "mpd", false, ledger::ChangeKind::Fix);
        ledger.strict = true;
        ledger
            .record(Phase::Architecture, doctor_gate_record())
            .unwrap();
        ledger
            .record(Phase::SecurityPlan, doctor_gate_record())
            .unwrap();
        let mut build = doctor_gate_record();
        build.candidate = Some(capture.clone());
        build.build_output = Some(candidate_output(&capture.subject.id));
        ledger.record(Phase::Build, build).unwrap();

        let security_capture =
            retained_candidate_for_objective_gate(&ledger, "candidate-chain", Phase::SecurityCode)
                .unwrap();
        assert_eq!(security_capture.subject.id, capture.subject.id);
        let mut security = doctor_gate_record();
        security.candidate = Some(security_capture);
        ledger.record(Phase::SecurityCode, security).unwrap();

        let test_capture =
            retained_candidate_for_objective_gate(&ledger, "candidate-chain", Phase::Test).unwrap();
        assert_eq!(test_capture.subject.id, capture.subject.id);
        let mut test = doctor_gate_record();
        test.candidate = Some(test_capture);
        ledger.record(Phase::Test, test).unwrap();

        let ids = [Phase::Build, Phase::SecurityCode, Phase::Test].map(|phase| {
            ledger.gates[&phase]
                .candidate
                .as_ref()
                .unwrap()
                .subject
                .id
                .clone()
        });
        assert!(ids.iter().all(|id| id == &capture.subject.id));

        let mut mismatched = ledger.clone();
        mismatched
            .gates
            .get_mut(&Phase::SecurityCode)
            .unwrap()
            .candidate = Some(candidate_capture('6'));
        assert!(
            retained_candidate_for_objective_gate(&mismatched, "candidate-chain", Phase::Test)
                .unwrap_err()
                .contains("bindings differ")
        );
    }

    /// Security-code Condition C3: `validate_candidate_report_binding` must
    /// pin a typed Build output's `candidate_id` to the retained Candidate,
    /// not just the report/receipt subject — a receipt whose subject matches
    /// but whose `build_output.candidate_id` names a different candidate
    /// must fail closed rather than pass on subject agreement alone.
    #[test]
    fn validate_candidate_report_binding_pins_build_output_candidate_id_too() {
        let capture = candidate_capture('7');
        let subject = crate::local_validation::Subject {
            requested: format!("candidate:{}", capture.subject.id),
            pushed_oid: capture.subject.base_commit.clone(),
            pushed_kind: "candidate".into(),
            tag_chain: Vec::new(),
            commit: capture.subject.base_commit.clone(),
            tree: capture.subject.base_tree.clone(),
        };
        let receipt = crate::local_validation::ValidationReceiptV1 {
            schema: 1,
            id: "1".repeat(64),
            subject: subject.clone(),
            profile: "build".into(),
            config_digest: "2".repeat(64),
            checks_digest: "3".repeat(64),
            trusted_policy_oid: "4".repeat(40),
            trusted_before_policy_digest: "5".repeat(64),
            candidate_policy_digest: "6".repeat(64),
            effective_policy_digest: "7".repeat(64),
            sandbox: crate::local_validation::SandboxReceiptBindingV1 {
                contract_version: 1,
                adapter_digest: "8".repeat(64),
                profile_digest: "9".repeat(64),
                environment_keys: Vec::new(),
                certified_host: "fixture-host".into(),
                adapter_abi_digest: "a".repeat(64),
                canary_contract_digest: "b".repeat(64),
                residual_limitations: Vec::new(),
                run_request_digests: Vec::new(),
                run_authority_digests: Vec::new(),
                run_root_inventory_digests: Vec::new(),
                run_canary_digests: Vec::new(),
            },
            validation_contract_version: 1,
            validator_version: "fixture".into(),
            validator_digest: "c".repeat(64),
            platform: crate::local_validation::PlatformReceiptBindingV1 {
                operating_system: "linux".into(),
                architecture: "x86_64".into(),
                cargo_target: "x86_64-unknown-linux-gnu".into(),
            },
            toolchain: crate::local_validation::ToolchainReceiptBindingV1 {
                rust_release: "1.80.0".into(),
                host: None,
                components: Vec::new(),
            },
            cargo_lock_digest: "d".repeat(64),
            advisory: crate::local_validation::AdvisoryReceiptBindingV1 {
                revision: "e".repeat(40),
                tree: "f".repeat(40),
                lock_digest: "1".repeat(64),
                max_age_days: 30,
            },
            tool_policy_digest: "2".repeat(64),
            tool_digests: std::collections::BTreeMap::new(),
            results: Vec::new(),
            started_epoch_secs: 1,
            completed_epoch_secs: 2,
            outcome: "passed".into(),
            build_output: Some(candidate_output(&capture.subject.id)),
        };
        let report = crate::local_validation::ValidationReport {
            schema: 1,
            subject: subject.clone(),
            profile: "build".into(),
            status: "passed".into(),
            receipt: Some(receipt.clone()),
            blocker: None,
            counts: crate::local_validation::ValidationCountsV1 {
                total: 1,
                passed: 1,
                failed: 0,
                blocked: 0,
                not_run: 0,
            },
            actions: Vec::new(),
        };

        // A matching build_output.candidate_id passes.
        validate_candidate_report_binding(&report, &capture).unwrap();

        // A build_output naming a DIFFERENT candidate must fail closed, even
        // though the report/receipt subjects still match the retained
        // Candidate exactly — the two fields must agree, not merely
        // cooperate.
        let mut mismatched_report = report.clone();
        mismatched_report.receipt.as_mut().unwrap().build_output =
            Some(candidate_output(&"9".repeat(64)));
        let error = validate_candidate_report_binding(&mismatched_report, &capture).unwrap_err();
        assert!(
            error.contains("Build output candidate ID differs"),
            "{error}"
        );

        // No typed build_output at all (e.g. a Security/Test profile
        // receipt) is unaffected — the check is conditional on one being
        // present.
        let mut no_output_report = report.clone();
        no_output_report.receipt.as_mut().unwrap().build_output = None;
        validate_candidate_report_binding(&no_output_report, &capture).unwrap();
    }

    #[test]
    fn runtime_ledger_resolves_archived_state_after_current_clears_and_requires_clean_head() {
        let root = doctor_test_dir("archived-ledger");
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join("base"), b"base\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "base"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "-c",
                "user.name=Doctor Test",
                "-c",
                "user.email=doctor@invalid",
                "commit",
                "-qm",
                "base",
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let base = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&root)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let mut archived =
            ledger::Ledger::new("archived-change", "mpd", false, ledger::ChangeKind::Fix);
        archived.archive_closure = Some(crate::closure::ArchiveClosure {
            base_commit: base,
            archive_path: "openspec/changes/archive/archived-change".into(),
            transaction_id: crate::digest::Digest::of_bytes(b"doctor-transaction"),
            candidate_id: None,
            allowed_paths: vec![".mpd/state/archived-change.json".into()],
            system_paths: vec![".mpd/state/archived-change.json".into()],
            post_archive_digest: crate::digest::Digest::of_bytes(b"doctor-postimage"),
            archived_at: 10,
        });
        ledger::save(&root, &archived).unwrap();
        assert!(Command::new("git")
            .args(["add", ".mpd/state/archived-change.json"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args([
                "-c",
                "user.name=Doctor Test",
                "-c",
                "user.email=doctor@invalid",
                "commit",
                "-qm",
                "archived ledger",
            ])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(!ledger::current_path(&root).exists());
        let head = resolve_runtime_head(&root).unwrap();
        assert_eq!(
            resolve_runtime_ledger(&root, &head).unwrap().change,
            "archived-change"
        );
        std::fs::write(root.join("dirty"), b"dirty\n").unwrap();
        assert!(resolve_runtime_head(&root).unwrap_err().contains("dirty"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn doctor_reopens_installed_path_and_blocks_mismatch_or_absence_without_probe() {
        use std::os::unix::fs::PermissionsExt;

        let root = doctor_test_dir("installed-identity");
        let config: crate::config::Config =
            serde_json::from_str(include_str!("../../../.mpd/config.json")).unwrap();
        let local = config.local_validation.unwrap();
        let build_contract = local.build_output.as_ref().unwrap();
        let deploy = local.deploy_output.as_ref().unwrap();
        let (installed_path, target) = match deploy {
            crate::config::DeployOutputConfig::Execute {
                installed_path,
                target,
                ..
            } => (installed_path, target),
            _ => panic!("repository fixture uses execute Deploy"),
        };
        for relative in [&build_contract.path, installed_path] {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"same reviewed installed bytes\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let build = crate::local_validation::capture_configured_build_output(&root, build_contract)
            .unwrap();
        let installed = crate::local_validation::identity(&root, installed_path).unwrap();
        let definition = serde_json::to_vec(deploy).unwrap();
        let result = serde_json::to_vec(&serde_json::json!({
            "build_sha256": build.sha256,
            "installed_sha256": installed.sha256,
            "installed_size": installed.size,
            "installed_mode": installed.mode,
        }))
        .unwrap();
        let mut ledger =
            ledger::Ledger::new("installed-doctor", "mpd", false, ledger::ChangeKind::Fix);
        let mut build_gate = doctor_gate_record();
        build_gate.build_output = Some(build);
        ledger.gates.insert(Phase::Build, build_gate);
        let mut deploy_gate = doctor_gate_record();
        deploy_gate.deploy_result = Some(ledger::DeployResultV1 {
            schema: 1,
            mode: "execute".into(),
            target: target.clone(),
            definition_digest: crate::digest::Digest::of_bytes(&definition).to_hex(),
            result_digest: crate::digest::Digest::of_bytes(&result).to_hex(),
            install_executed: true,
            probe_executed: false,
            verified: true,
        });
        ledger.gates.insert(Phase::Deploy, deploy_gate);

        doctor_installed_deploy_health(&root, &local, &ledger).unwrap();
        std::fs::write(
            root.join(installed_path),
            b"same length but altered bytes\n",
        )
        .unwrap();
        assert!(doctor_installed_deploy_health(&root, &local, &ledger)
            .unwrap_err()
            .contains("installed path identity"));
        std::fs::remove_file(root.join(installed_path)).unwrap();
        assert!(doctor_installed_deploy_health(&root, &local, &ledger).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn runtime_health_composes_closure_head_receipt_and_deploy_before_pending_remote() {
        use std::os::unix::fs::PermissionsExt;

        let root = doctor_test_dir("coherent-runtime");
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(
            root.join(".gitignore"),
            ".mpd/state/\n.mpd/build-output/\n.mpd/local/\n",
        )
        .unwrap();
        assert!(Command::new("git")
            .args(["add", ".gitignore"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let commit = |message: &str| {
            assert!(Command::new("git")
                .args([
                    "-c",
                    "user.name=Doctor Test",
                    "-c",
                    "user.email=doctor@invalid",
                    "commit",
                    "-qm",
                    message,
                ])
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        };
        commit("runtime base");
        let oid = || {
            String::from_utf8(
                Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .current_dir(&root)
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap()
            .trim()
            .to_string()
        };
        let base = oid();
        std::fs::write(root.join("artifact.txt"), b"archived postimage\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "artifact.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        commit("closure commit");
        let head = oid();
        let allowed = vec!["artifact.txt".to_string()];
        let postimage = crate::closure::scoped_digest_for_patterns(&root, &allowed).unwrap();

        let config: crate::config::Config =
            serde_json::from_str(include_str!("../../../.mpd/config.json")).unwrap();
        let local = config.local_validation.unwrap();
        let build_contract = local.build_output.as_ref().unwrap();
        let deploy = local.deploy_output.as_ref().unwrap();
        let (installed_path, target) = match deploy {
            crate::config::DeployOutputConfig::Execute {
                installed_path,
                target,
                ..
            } => (installed_path, target),
            _ => panic!("repository fixture uses execute Deploy"),
        };
        for relative in [&build_contract.path, installed_path] {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"coherent runtime binary\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let build = crate::local_validation::capture_configured_build_output(&root, build_contract)
            .unwrap();
        let installed = crate::local_validation::identity(&root, installed_path).unwrap();
        let definition = serde_json::to_vec(deploy).unwrap();
        let result = serde_json::to_vec(&serde_json::json!({
            "build_sha256": build.sha256,
            "installed_sha256": installed.sha256,
            "installed_size": installed.size,
            "installed_mode": installed.mode,
        }))
        .unwrap();
        let mut runtime_ledger =
            ledger::Ledger::new("runtime-closure", "mpd", false, ledger::ChangeKind::Fix);
        runtime_ledger.governance.risk = ledger::RiskLevel::High;
        runtime_ledger.archive_closure = Some(crate::closure::ArchiveClosure {
            base_commit: base,
            archive_path: "openspec/changes/archive/runtime-closure".into(),
            transaction_id: crate::digest::Digest::of_bytes(b"runtime-transaction"),
            candidate_id: None,
            allowed_paths: allowed.clone(),
            system_paths: allowed,
            post_archive_digest: postimage,
            archived_at: 20,
        });
        let mut build_gate = doctor_gate_record();
        build_gate.build_output = Some(build);
        runtime_ledger.gates.insert(Phase::Build, build_gate);
        let mut deploy_gate = doctor_gate_record();
        deploy_gate.deploy_result = Some(ledger::DeployResultV1 {
            schema: 1,
            mode: "execute".into(),
            target: target.clone(),
            definition_digest: crate::digest::Digest::of_bytes(&definition).to_hex(),
            result_digest: crate::digest::Digest::of_bytes(&result).to_hex(),
            install_executed: true,
            probe_executed: false,
            verified: true,
        });
        runtime_ledger.gates.insert(Phase::Deploy, deploy_gate);
        ledger::save(&root, &runtime_ledger).unwrap();
        let tree = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD^{tree}"])
                .current_dir(&root)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let health = |commit: String| crate::local_validation::DoctorReceiptHealth {
            subject: crate::local_validation::Subject {
                requested: "HEAD".into(),
                pushed_oid: commit.clone(),
                pushed_kind: "commit".into(),
                tag_chain: Vec::new(),
                commit,
                tree: tree.clone(),
            },
            receipt_id: "f".repeat(64),
            profile: local.gates.high_risk_test.clone(),
            sandbox: crate::local_validation::SandboxReceiptBindingV1 {
                contract_version: 1,
                adapter_digest: "a".repeat(64),
                profile_digest: "b".repeat(64),
                environment_keys: Vec::new(),
                certified_host: "fixture-host".into(),
                adapter_abi_digest: "c".repeat(64),
                canary_contract_digest: "d".repeat(64),
                residual_limitations: Vec::new(),
                run_request_digests: Vec::new(),
                run_authority_digests: Vec::new(),
                run_root_inventory_digests: Vec::new(),
                run_canary_digests: Vec::new(),
            },
            results: Vec::new(),
        };

        let (findings, subject, coherent) =
            runtime_doctor_findings_with_receipt(&root, Some(&local), |_, _, profile| {
                assert_eq!(profile, local.gates.high_risk_test);
                Ok(health(head.clone()))
            });
        assert_eq!(subject.as_deref(), Some(head.as_str()));
        assert!(coherent);
        assert!(doctor_expected_pending_remote(coherent, &findings));
        assert!(findings
            .iter()
            .all(|finding| !matches!(finding.severity, super::DoctorSeverity::Blocker)));

        let (stale, _, coherent) =
            runtime_doctor_findings_with_receipt(&root, Some(&local), |_, _, _| {
                Ok(health("a".repeat(40)))
            });
        assert!(!doctor_expected_pending_remote(coherent, &stale));
        assert!(stale
            .iter()
            .any(|finding| finding.code == "exact-head-required-receipt"
                && matches!(finding.severity, super::DoctorSeverity::Blocker)));

        let (missing, _, coherent) =
            runtime_doctor_findings_with_receipt(&root, Some(&local), |_, _, _| {
                Err("required exact-HEAD receipt is Missing".into())
            });
        assert!(!doctor_expected_pending_remote(coherent, &missing));

        std::fs::write(root.join("outside.txt"), b"out of closure scope\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "outside.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        commit("out-of-scope closure mismatch");
        let moved_head = oid();
        let (mismatch, _, coherent) =
            runtime_doctor_findings_with_receipt(&root, Some(&local), |_, _, _| {
                Ok(health(moved_head))
            });
        assert!(!coherent);
        assert!(!doctor_expected_pending_remote(coherent, &mismatch));
        assert!(mismatch.iter().any(|finding| {
            finding.code == "archived-closure-head-coherence"
                && matches!(finding.severity, super::DoctorSeverity::Blocker)
        }));
        let _ = std::fs::remove_dir_all(root);
    }

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
    fn canonical_artifact_verdict_requires_one_exact_token() {
        assert_eq!(
            canonical_artifact_verdict("## Verdict\n\nPASS\n\nRationale follows.\n").unwrap(),
            Verdict::Pass
        );
        assert_eq!(
            canonical_artifact_verdict("## Verdict\nCONDITIONAL PASS\n").unwrap(),
            Verdict::ConditionalPass
        );
        assert!(canonical_artifact_verdict("## Verdict\nPASS — prose\n").is_err());
        assert!(canonical_artifact_verdict("## Verdict\n\nPASS\n\n## Verdict\n\nPASS\n").is_err());
        assert!(canonical_artifact_verdict("## Verdict\n\npass\n").is_err());
    }

    #[test]
    fn canonical_actor_is_exact_and_same_actor_is_blocked_cooperatively() {
        assert_eq!(
            canonical_artifact_actor("## Actor\n\nSecurity reviewer 2\n\n## Verdict\nPASS\n")
                .unwrap(),
            "Security reviewer 2"
        );
        assert!(canonical_artifact_actor("## Actor\nA\nB\n").is_err());
        assert!(canonical_artifact_actor("## Actor\nA\n## Actor\nA\n").is_err());

        let mut ledger = ledger::Ledger::new("actors", "mpd", true, ChangeKind::Feature);
        ledger.strict = true;
        let mut prior = doctor_gate_record();
        prior.by = "same-session".into();
        ledger.gates.insert(Phase::DesignMock, prior);
        assert!(
            strict_actor_separation_issue(&ledger, Phase::Architecture, "same-session")
                .unwrap()
                .contains("matches")
        );
        assert!(
            strict_actor_separation_issue(&ledger, Phase::Architecture, "architect-session")
                .is_none()
        );
    }

    fn actor_record(by: &str) -> GateRecord {
        let mut record = doctor_gate_record();
        record.by = by.into();
        record
    }

    /// D6 / Cond 7: every documented persona-reuse pattern must pass BOTH
    /// rules with distinct-per-persona labels — Designer at
    /// DesignMock/DesignReview/DesignSignoff, Security at both Security
    /// gates, and Architect at Architecture+DocValidation.
    #[test]
    fn actor_separation_preserves_every_documented_persona_reuse_pattern() {
        let mut ledger = ledger::Ledger::new("reuse", "mpd", true, ChangeKind::Feature);
        ledger.strict = true;
        ledger
            .gates
            .insert(Phase::DesignMock, actor_record("Designer"));
        assert!(strict_actor_separation_issue(&ledger, Phase::Architecture, "Architect").is_none());
        ledger
            .gates
            .insert(Phase::Architecture, actor_record("Architect"));
        assert!(strict_actor_separation_issue(&ledger, Phase::DesignReview, "Designer").is_none());
        ledger
            .gates
            .insert(Phase::DesignReview, actor_record("Designer"));
        assert!(strict_actor_separation_issue(&ledger, Phase::SecurityPlan, "Security").is_none());
        ledger
            .gates
            .insert(Phase::SecurityPlan, actor_record("Security"));
        assert!(strict_actor_separation_issue(&ledger, Phase::Build, "Builder").is_none());
        ledger.gates.insert(Phase::Build, actor_record("Builder"));
        assert!(strict_actor_separation_issue(&ledger, Phase::SecurityCode, "Security").is_none());
        ledger
            .gates
            .insert(Phase::SecurityCode, actor_record("Security"));
        assert!(strict_actor_separation_issue(&ledger, Phase::DesignSignoff, "Designer").is_none());
        ledger
            .gates
            .insert(Phase::DesignSignoff, actor_record("Designer"));
        assert!(strict_actor_separation_issue(&ledger, Phase::Test, "Tester").is_none());
        ledger.gates.insert(Phase::Test, actor_record("Tester"));
        assert!(
            strict_actor_separation_issue(&ledger, Phase::Documentation, "Documenter").is_none()
        );
        ledger
            .gates
            .insert(Phase::Documentation, actor_record("Documenter"));
        // Architect returns for Doc Validation — the second documented
        // reuse — and must still pass (subject is Documentation=Documenter,
        // adjacency prior is also Documentation=Documenter; Architect
        // matches neither).
        assert!(
            strict_actor_separation_issue(&ledger, Phase::DocValidation, "Architect").is_none()
        );
    }

    /// D6 / Cond 7: the reproduced alternating-label self-review exploit
    /// (Build=A, SecurityCode=B, DesignSignoff=A) passes adjacency at every
    /// step (A differs from the immediately prior actor each time) yet lets
    /// A sign off on A's own Build. The review-subject rule must block it,
    /// naming both the rule and both actors.
    #[test]
    fn actor_separation_blocks_the_alternating_label_self_review_exploit() {
        let mut ledger = ledger::Ledger::new("exploit", "mpd", true, ChangeKind::Feature);
        ledger.strict = true;
        ledger.gates.insert(Phase::Build, actor_record("A"));
        assert!(strict_actor_separation_issue(&ledger, Phase::SecurityCode, "B").is_none());
        ledger.gates.insert(Phase::SecurityCode, actor_record("B"));
        // Adjacency alone would accept this: A differs from the immediately
        // prior SecurityCode actor B.
        let issue = strict_actor_separation_issue(&ledger, Phase::DesignSignoff, "A")
            .expect("the review-subject rule must fire");
        assert!(issue.contains("review-subject"), "{issue}");
        assert!(issue.contains("Build"), "{issue}");
        assert!(issue.contains('A'), "{issue}");
    }

    /// D6: the adjacency rule still fires exactly as before when two
    /// directly consecutive phases share the same actor.
    #[test]
    fn actor_separation_adjacency_rule_still_fires() {
        let mut ledger = ledger::Ledger::new("adjacency", "mpd", false, ChangeKind::Chore);
        ledger.strict = true;
        ledger
            .gates
            .insert(Phase::Architecture, actor_record("Same"));
        let issue = strict_actor_separation_issue(&ledger, Phase::SecurityPlan, "Same")
            .expect("adjacency rule must fire");
        assert!(issue.contains("adjacency"), "{issue}");
    }

    // D8: `--introduced-by` provenance.

    fn introduced_by_fixture(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-introduced-by-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join(".mpd/state")).unwrap();
        std::fs::create_dir_all(root.join("openspec/changes/archive")).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        root
    }

    #[test]
    fn dated_archive_decomposition_is_exact_never_substring_or_prefix() {
        // Cond 18: the date prefix must be exactly 10 valid `YYYY-MM-DD`
        // characters and the remainder must equal `name` exactly.
        assert!(dated_archive_matches("2026-07-19-widget", "widget"));
        // Wrong length / malformed date prefix.
        assert!(!dated_archive_matches("26-07-19-widget", "widget"));
        assert!(!dated_archive_matches("2026-7-19-widget", "widget"));
        // Extra text before the date (prefix confusion).
        assert!(!dated_archive_matches("old-2026-07-19-widget", "widget"));
        // A different change name entirely must not match via substring.
        assert!(!dated_archive_matches("2026-07-19-widget", "widget-2"));
        assert!(!dated_archive_matches("2026-07-19-widget-2", "widget"));
        assert!(is_valid_date_prefix("2026-07-19"));
        assert!(!is_valid_date_prefix("2026-07-1"));
        assert!(!is_valid_date_prefix("2026/07/19"));
    }

    #[test]
    fn validate_introduced_by_rejects_an_invalid_name_and_creates_nothing() {
        let root = introduced_by_fixture("invalid-name");
        let error = validate_introduced_by(&root, "Not Valid!").unwrap_err();
        assert!(!error.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_introduced_by_rejects_a_change_with_no_archive_evidence() {
        let root = introduced_by_fixture("no-archive");
        let error = validate_introduced_by(&root, "never-archived").unwrap_err();
        assert!(error.contains("never-archived"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_introduced_by_accepts_a_ledger_with_archive_closure() {
        let root = introduced_by_fixture("closure-ledger");
        let mut ledger = ledger::Ledger::new("modern-thing", "mpd", false, ChangeKind::Feature);
        ledger.archive_closure = Some(crate::closure::ArchiveClosure {
            base_commit: "a".repeat(40),
            archive_path: "openspec/changes/archive/2026-07-19-modern-thing".into(),
            transaction_id: crate::digest::Digest::of_bytes(b"txn"),
            candidate_id: None,
            allowed_paths: vec!["**".to_string()],
            system_paths: vec![],
            post_archive_digest: crate::digest::Digest::of_bytes(b"post"),
            archived_at: 1,
        });
        ledger::save(&root, &ledger).unwrap();
        assert_eq!(
            validate_introduced_by(&root, "modern-thing").unwrap(),
            "modern-thing"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validate_introduced_by_accepts_a_legacy_dated_archive_directory() {
        let root = introduced_by_fixture("legacy-dir");
        std::fs::create_dir_all(root.join("openspec/changes/archive/2026-07-19-legacy-thing"))
            .unwrap();
        assert_eq!(
            validate_introduced_by(&root, "legacy-thing").unwrap(),
            "legacy-thing"
        );
        // A near-miss directory (prefix confusion) must not satisfy a
        // different name.
        assert!(validate_introduced_by(&root, "thing").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn workflow_outcomes_receipt_states_and_sandbox_actions_are_canonical() {
        let outcomes = [
            WorkflowOutcome::Pass,
            WorkflowOutcome::Fail,
            WorkflowOutcome::Blocked,
            WorkflowOutcome::Conditional,
            WorkflowOutcome::Stale,
            WorkflowOutcome::InProgress,
            WorkflowOutcome::NotRun,
        ];
        assert_eq!(
            serde_json::to_value(outcomes).unwrap(),
            serde_json::json!([
                "PASS",
                "FAIL",
                "BLOCKED",
                "CONDITIONAL",
                "STALE",
                "IN PROGRESS",
                "NOT RUN"
            ])
        );
        assert_eq!(receipt_failure_fact("no receipt exists").state, "MISSING");
        assert_eq!(receipt_failure_fact("receipt failed").state, "FAILED");
        assert_eq!(receipt_failure_fact("receipt is stale").state, "STALE");
        assert_eq!(receipt_failure_fact("malformed input").state, "BLOCKED");

        let cases = [
            ("host changed", "sandbox.host-drift"),
            ("sandbox ABI symbol changed", "sandbox.spi-abi-drift"),
            ("profile digest changed", "sandbox.profile-drift"),
            ("root inventory changed", "sandbox.root-drift"),
            ("canary denied unexpectedly", "sandbox.canary-failed"),
            (
                "required receipt missing",
                "sandbox.full-profile-incomplete",
            ),
        ];
        for (error, expected_code) in cases {
            let (code, action) = sandbox_blocker(error);
            assert_eq!(code, expected_code);
            assert!(!action.is_empty());
            assert!(
                !action.contains(" or "),
                "blocker action must offer one path"
            );
        }
        assert_eq!(
            sandbox_blocker("unclassified fault").0,
            "sandbox.spi-abi-drift"
        );

        let canary = "a".repeat(64);
        let sandbox = crate::local_validation::SandboxReceiptBindingV1 {
            contract_version: 1,
            adapter_digest: "b".repeat(64),
            profile_digest: "c".repeat(64),
            environment_keys: vec!["PATH".into()],
            certified_host: "macOS fixture".into(),
            adapter_abi_digest: "d".repeat(64),
            canary_contract_digest: canary.clone(),
            residual_limitations: vec!["fixture limitation".into()],
            run_request_digests: vec!["e".repeat(64)],
            run_authority_digests: vec!["f".repeat(64)],
            run_root_inventory_digests: vec!["1".repeat(64)],
            run_canary_digests: vec![canary],
        };
        let results = vec![crate::local_validation::ValidationCheckResult {
            name: "check".into(),
            kind: "SelfCheck".into(),
            outcome: "passed".into(),
            exit: Some(0),
            count: Some(1),
            duration_millis: 1,
            log_digest: "2".repeat(64),
        }];
        let (validation, containment) =
            current_validation_status("build", "receipt", &sandbox, &results, "passed", false);
        assert_eq!(validation.outcome, WorkflowOutcome::Pass);
        assert_eq!(containment.adapter, "CERTIFIED");
        assert_eq!(containment.full_local_profile, "NOT CERTIFIED");
        assert_eq!(
            containment.blocker_code.as_deref(),
            Some("sandbox.full-profile-incomplete")
        );

        let (validation, containment) =
            current_validation_status("test", "receipt", &sandbox, &results, "passed", true);
        assert_eq!(validation.outcome, WorkflowOutcome::Pass);
        assert_eq!(containment.full_local_profile, "CERTIFIED");
        assert_eq!(containment.certified_claim, "CERTIFIED");
        assert!(containment.blocker_code.is_none());
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
        // Design Sign-off's upstream includes both canonical design artifacts.
        // With ui=false both are inapplicable; with ui=true both resolve.
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
        assert_eq!(
            with_ui,
            vec![
                ("Design Mock", "design-mock.md"),
                ("Design Review", "design-review.md")
            ]
        );
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
        /// `parse_exploit` never panics on arbitrary input, and a value with a
        /// field count ≠ 5 ALWAYS errors — the mandatory-5-field guard (D4) that
        /// keeps a Security FAIL from recording with partial exploit evidence.
        #[test]
        fn parse_exploit_rejects_any_wrong_field_count(s in ".*") {
            if s.split('|').count() != 5 {
                prop_assert!(parse_exploit(&s).is_err());
            }
        }

        /// Five non-blank fields always parse and round-trip verbatim through the
        /// structured `Exploitability` (bounded_text no-ops on a non-blank ≤500 value).
        #[test]
        fn parse_exploit_accepts_five_nonblank_fields(
            f in prop::collection::vec("[a-z]{1,30}", 5..=5),
        ) {
            let ex = parse_exploit(&f.join("|")).unwrap();
            prop_assert_eq!(&ex.attacker, &f[0]);
            prop_assert_eq!(&ex.capability, &f[1]);
            prop_assert_eq!(&ex.boundary, &f[2]);
            prop_assert_eq!(&ex.harm, &f[3]);
            prop_assert_eq!(&ex.fix, &f[4]);
        }
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
