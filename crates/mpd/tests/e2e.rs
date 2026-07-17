//! End-to-end tests that drive the built `mpd` binary through the pipeline.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A unique temp directory for one test, initialized as a git repo.
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("mpd-e2e-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        run("git", &["init", "-q"], &dir);
        // The archive transaction records the commit HEAD must descend from
        // (archive-transaction.md); a real project always has history by the
        // time it archives its first change, so every sandbox starts with one
        // baseline commit rather than the unborn-branch state `mpd archive`
        // correctly refuses.
        run(
            "git",
            &["commit", "--allow-empty", "-q", "-m", "sandbox-init"],
            &dir,
        );
        Sandbox { dir }
    }

    fn mpd(&self, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_mpd"))
            .args(args)
            .current_dir(&self.dir)
            .output()
            .expect("run mpd");
        // Legacy scenarios predate declared scope. Keep their focus intact by
        // supplying an explicit all-repository fixture scope immediately after
        // begin; dedicated manifest tests exercise incomplete/narrow scopes.
        if output.status.success() && args.first() == Some(&"begin") {
            if let Some(change) = args.get(1) {
                self.write(
                    &format!("openspec/changes/{change}/manifest.json"),
                    "{\n  \"version\": 1,\n  \"paths\": [\"**\"],\n  \"shared_paths\": []\n}\n",
                );
            }
        }
        output
    }

    fn write(&self, rel: &str, content: &str) {
        let path = self.dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(cmd: &str, args: &[&str], dir: &Path) -> Output {
    Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("run {cmd}: {e}"))
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn json(o: &Output) -> Value {
    serde_json::from_str(&stdout(o))
        .unwrap_or_else(|e| panic!("parse json: {e}\nstdout was:\n{}", stdout(o)))
}

const PASSING_TEST_CMD: &str = "echo 'test result: ok. 3 passed; 0 failed; 0 ignored'";

#[test]
fn full_pipeline_happy_path() {
    let sb = Sandbox::new("happy");

    // init
    let out = sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    assert!(out.status.success(), "init failed: {}", stdout(&out));
    assert!(sb.dir.join("openspec/schemas/mpd/schema.yaml").is_file());
    assert!(sb.dir.join(".git/hooks/pre-commit").is_file());

    // begin (non-UI)
    let out = sb.mpd(&["begin", "add-thing"]);
    assert!(out.status.success(), "begin failed: {}", stdout(&out));
    fill_artifacts(&sb, "add-thing");

    // status: at Architecture
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "architecture");
    assert_eq!(s["ready_to_archive"], false);

    // next: Architect / opus
    let n = json(&sb.mpd(&["next", "--json"]));
    assert_eq!(n["persona"], "Architect");
    // Generic harness reports the tier, not a concrete model.
    assert_eq!(n["model"], "deep-cognition");

    // Author a delta spec so archive has something to merge.
    sb.write(
        "openspec/changes/add-thing/specs/thing/spec.md",
        "## ADDED Requirements\n\n\
         ### Requirement: Thing works\n\
         The system SHALL do the thing.\n\n\
         #### Scenario: It works\n\
         - **WHEN** invoked\n\
         - **THEN** it works\n",
    );

    // Walk the core gates.
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "gate {phase} failed: {}\n{}",
            stdout(&out),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // A feature reaches the Documentation phase; the gate structurally checks
    // the doc. The unfilled template stub (seeded at begin) must be refused.
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "documentation"
    );
    let bad = sb.mpd(&["gate", "documentation", "--pass"]);
    assert!(
        !bad.status.success(),
        "documentation gate must reject the unfilled stub"
    );
    // Fill it in with all required sections.
    sb.write(
        "openspec/changes/add-thing/documentation.md",
        "# Thing\n\n## Purpose\nDoes the thing.\n\n## Value\nUsers get the thing \
         done quickly.\n\n## Scope\nCovers the thing; not the other thing.\n\n\
         ## Functional details\nOn invoke it does the thing and returns ok.\n\n\
         ## Usage\nWHEN invoked THEN it works.\n",
    );
    let out = sb.mpd(&["gate", "documentation", "--pass"]);
    assert!(out.status.success(), "documentation gate: {}", stdout(&out));

    // Deploy, then the two-lens Doc Validation.
    assert_eq!(json(&sb.mpd(&["status", "--json"]))["phase"], "deploy");
    sb.mpd(&["gate", "deploy", "--pass"]);
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "doc-validation"
    );
    // Doc Validation spawns both Architect and Designer (deep tier).
    let dv = json(&sb.mpd(&["next", "--harness", "claude-code", "--json"]));
    assert_eq!(dv["persona"], "Architect & Designer");
    assert_eq!(dv["dual"], true);
    sb.mpd(&["gate", "doc-validation", "--pass"]);

    // Ready now.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["ready_to_archive"], true);

    // Dry-run archive does not move anything and previews the doc fold-in.
    let out = sb.mpd(&["archive"]);
    assert!(stdout(&out).contains("Dry run"));
    assert!(
        stdout(&out).contains("docs/add-thing.md"),
        "doc preview: {}",
        stdout(&out)
    );
    assert!(sb.dir.join("openspec/changes/add-thing").is_dir());

    // Real archive.
    let out = sb.mpd(&["archive", "--yes"]);
    assert!(out.status.success(), "archive failed: {}", stdout(&out));
    // Spec folded into the record.
    let merged = std::fs::read_to_string(sb.dir.join("openspec/specs/thing/spec.md")).unwrap();
    assert!(merged.contains("### Requirement: Thing works"));
    assert!(merged.starts_with("# Thing"));
    // Documentation folded into the durable project docs directory.
    let doc = std::fs::read_to_string(sb.dir.join("docs/add-thing.md")).unwrap();
    assert!(doc.contains("## Usage") && doc.contains("Does the thing"));
    // Change moved to archive.
    assert!(!sb.dir.join("openspec/changes/add-thing").exists());
    let archive_entries: Vec<_> = std::fs::read_dir(sb.dir.join("openspec/changes/archive"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        archive_entries.iter().any(|n| n.ends_with("-add-thing")),
        "archive entries: {archive_entries:?}"
    );
}

#[test]
fn build_gate_refuses_when_tests_fail() {
    let sb = Sandbox::new("failtests");
    sb.mpd(&["init", "--test", "false"]); // a command that always fails
    sb.mpd(&["begin", "bad-change"]);
    sb.mpd(&["gate", "architecture", "--pass"]);
    sb.mpd(&["gate", "security-plan", "--pass"]);
    let out = sb.mpd(&["gate", "build", "--pass"]);
    assert!(
        !out.status.success(),
        "build gate should refuse a failing test suite"
    );
    // Phase must not have advanced.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "build");
}

#[test]
fn build_gate_refuses_without_pass_count() {
    // A command that exits 0 but emits no parseable count is not "verified".
    let sb = Sandbox::new("nocount");
    sb.mpd(&["init", "--test", "true"]);
    sb.mpd(&["begin", "c"]);
    sb.mpd(&["gate", "architecture", "--pass"]);
    sb.mpd(&["gate", "security-plan", "--pass"]);
    let out = sb.mpd(&["gate", "build", "--pass"]);
    assert!(
        !out.status.success(),
        "build gate should refuse when no pass count is observed"
    );
    // The refusal spells out the cause so a `"test": "true"` placeholder is
    // diagnosable from stderr alone (Stage 4, Task 2.3).
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no recognizable pass count"),
        "the refusal must hint at the missing pass count: {err}"
    );
    assert!(
        err.contains("`true`"),
        "the hint must name the placeholder footgun: {err}"
    );
}

#[test]
fn check_staged_blocks_on_secret() {
    let sb = Sandbox::new("secret");
    sb.mpd(&["init"]);
    // Assemble the fake key from split literals so the test source itself
    // carries no contiguous credential pattern.
    sb.write(
        "config.txt",
        &format!("aws_key = AKIA{}\n", "IOSFODNN7EXAMPLE"),
    );
    run("git", &["add", "config.txt"], &sb.dir);
    let out = sb.mpd(&["check", "--staged"]);
    assert!(!out.status.success(), "check should block a staged secret");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("aws-access-key-id"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn archive_refuses_with_unmet_gates() {
    let sb = Sandbox::new("unmet");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "incomplete"]);
    sb.mpd(&["gate", "architecture", "--pass"]);
    // Skip the rest — not ready.
    let out = sb.mpd(&["archive", "--yes"]);
    assert!(!out.status.success(), "archive must refuse unmet gates");
    assert!(String::from_utf8_lossy(&out.stderr).contains("unmet gates"));
}

#[test]
fn ui_change_walks_all_design_phases_via_binary() {
    let sb = Sandbox::new("ui-flow");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let out = sb.mpd(&["begin", "pretty-thing", "--ui", "--fix"]);
    assert!(out.status.success(), "begin --ui failed: {}", stdout(&out));
    fill_artifacts(&sb, "pretty-thing");

    // Starts at Design Mock, not Architecture.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "design-mock");
    assert_eq!(s["ui"], true);

    let n = json(&sb.mpd(&["next", "--json"]));
    assert_eq!(n["persona"], "Designer");
    // Design phases are deep-tier (alongside Architecture).
    assert_eq!(n["model"], "deep-cognition");
    // And concretely per harness:
    let cc = json(&sb.mpd(&["next", "--harness", "claude-code", "--json"]));
    assert_eq!(cc["model"], "fable");
    let cx = json(&sb.mpd(&["next", "--harness", "codex", "--json"]));
    assert_eq!(cx["model"], "sol");

    sb.write(
        "openspec/changes/pretty-thing/specs/thing/spec.md",
        "## ADDED Requirements\n\n\
         ### Requirement: Thing looks nice\n\
         The system SHALL look nice.\n\n\
         #### Scenario: It looks nice\n\
         - **WHEN** rendered\n\
         - **THEN** it looks nice\n",
    );

    // Walk every applicable phase for a UI change, including all three
    // design touchpoints (Mock, Review, Sign-off).
    for phase in [
        "design-mock",
        "architecture",
        "design-review",
        "security-plan",
        "build",
        "security-code",
        "design-signoff",
        "test",
    ] {
        let before = json(&sb.mpd(&["status", "--json"]));
        assert_eq!(
            before["phase"], phase,
            "expected to be at {phase} before gating it"
        );
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "gate {phase} failed: {}\n{}",
            stdout(&out),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "deploy");
    assert_eq!(s["ready_to_archive"], true, "{s}");

    let out = sb.mpd(&["archive", "--yes"]);
    assert!(out.status.success(), "archive failed: {}", stdout(&out));
    let merged = std::fs::read_to_string(sb.dir.join("openspec/specs/thing/spec.md")).unwrap();
    assert!(merged.contains("### Requirement: Thing looks nice"));
}

#[test]
fn gate_rejects_conflicting_verdict_flags() {
    let sb = Sandbox::new("two-verdicts");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "c"]);

    let out = sb.mpd(&["gate", "architecture", "--pass", "--fail"]);
    assert!(!out.status.success(), "gate must reject two verdict flags");
    // Match loosely on the two conflicting flag names rather than the exact
    // refusal sentence, which is free to be reworded as `--reuse` and other
    // gate flags evolve.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--pass") && stderr.contains("--fail"),
        "stderr: {stderr}"
    );
    // The phase must not have moved.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "architecture");

    // All three flags together are equally rejected.
    let out = sb.mpd(&["gate", "architecture", "--pass", "--conditional", "--fail"]);
    assert!(!out.status.success());

    // Zero flags is also rejected (not exactly one).
    let out = sb.mpd(&["gate", "architecture"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("specify exactly one of"));
}

#[test]
fn conditional_pass_condition_blocks_archive_until_closed() {
    let sb = Sandbox::new("conditional");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "risky-thing", "--fix"]);
    fill_artifacts(&sb, "risky-thing");
    sb.write(
        "openspec/changes/risky-thing/specs/thing/spec.md",
        "## ADDED Requirements\n\n\
         ### Requirement: Thing works\n\
         The system SHALL do the thing.\n\n\
         #### Scenario: It works\n\
         - **WHEN** invoked\n\
         - **THEN** it works\n",
    );

    sb.mpd(&["gate", "architecture", "--pass"]);
    let out = sb.mpd(&[
        "gate",
        "security-plan",
        "--conditional",
        "--condition",
        "close the threat-model gap",
    ]);
    assert!(
        out.status.success(),
        "conditional gate failed: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    // A CONDITIONAL PASS still advances the phase.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "build");

    sb.mpd(&["gate", "build", "--pass"]);
    sb.mpd(&["gate", "security-code", "--pass"]);
    sb.mpd(&["gate", "test", "--pass"]);

    // Every gate has a non-Fail verdict, but the open condition still blocks.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "deploy");
    assert_eq!(s["ready_to_archive"], false, "{s}");
    let reasons: Vec<String> = s["blocking_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("close the threat-model gap")),
        "reasons: {reasons:?}"
    );

    let out = sb.mpd(&["archive", "--yes"]);
    assert!(
        !out.status.success(),
        "archive must refuse an open condition"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("open condition"));
    // Nothing was moved.
    assert!(sb.dir.join("openspec/changes/risky-thing").is_dir());

    // Close the condition via the CLI verb `mpd resolve`. It persists
    // `conditions[0].closed = true` — the on-disk shape `blocking_reasons`
    // depends on. (Before `resolve` existed, this test hand-edited the JSON.)
    let state_path = sb.dir.join(".mpd/state/risky-thing.json");
    let before: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(before["conditions"][0]["closed"], false);
    let out = sb.mpd(&["resolve", "1"]);
    assert!(
        out.status.success(),
        "resolve should close condition #1: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let after: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(after["conditions"][0]["closed"], true);

    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["ready_to_archive"], true, "{s}");

    let out = sb.mpd(&["archive", "--yes"]);
    assert!(
        out.status.success(),
        "archive should succeed once the condition is closed: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!sb.dir.join("openspec/changes/risky-thing").exists());
}

/// Author a minimal delta spec so a change has something to archive.
fn write_thing_spec(sb: &Sandbox, change: &str) {
    sb.write(
        &format!("openspec/changes/{change}/specs/thing/spec.md"),
        "## ADDED Requirements\n\n\
         ### Requirement: Thing works\n\
         The system SHALL do the thing.\n\n\
         #### Scenario: It works\n\
         - **WHEN** invoked\n\
         - **THEN** it works\n",
    );
}

/// Overwrite a change's seeded template stubs (proposal/design/tasks) with real
/// content so the archive stub-guard and readiness check accept it — the normal
/// state of any change that a persona actually authored.
fn fill_artifacts(sb: &Sandbox, change: &str) {
    for name in ["proposal.md", "design.md", "tasks.md"] {
        sb.write(
            &format!("openspec/changes/{change}/{name}"),
            &format!(
                "# {name} for {change}\n\nReal, filled content for the {change} change — \
                 no template placeholders remain.\n"
            ),
        );
    }
}

/// Write `.mpd/config.json` with a passing test command and the given deploy.
fn write_config_with_deploy(sb: &Sandbox, deploy: &str) {
    sb.write(
        ".mpd/config.json",
        &format!("{{\n  \"test\": {PASSING_TEST_CMD:?},\n  \"deploy\": {deploy:?}\n}}\n"),
    );
}

#[test]
fn governance_defaults_overrides_and_brief_parity() {
    let sb = Sandbox::new("governance");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let out = sb.mpd(&[
        "begin",
        "network-work",
        "--ui",
        "--risk",
        "high",
        "--threat-profile",
        "network-server",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("risk high, threat profile network-server"));
    let status = json(&sb.mpd(&["status", "--json"]));
    let next = json(&sb.mpd(&["next", "--json"]));
    assert_eq!(status["governance"]["risk"], "high");
    assert_eq!(status["governance"]["threat_profile"], "network-server");
    assert_eq!(next["risk"], "high");
    assert_eq!(next["threat_profile"], "network-server");
    assert_eq!(next["attempt_limit"], 3);
}

#[test]
fn fail_class_and_security_exploitability_are_strict_and_persisted() {
    let sb = Sandbox::new("classified-fail");
    sb.mpd(&["init"]);
    sb.mpd(&["begin", "secure-change", "--risk", "medium"]);
    let missing = sb.mpd(&["gate", "architecture", "--fail"]);
    assert!(!missing.status.success());
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["history"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let out = sb.mpd(&["gate", "architecture", "--fail", "--class", "policy"]);
    assert!(out.status.success());
    let state = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(state["history"][0]["record"]["failure_class"], "policy");

    // A fresh change reaches Security, where all five exploitability fields are required.
    sb.mpd(&["begin", "security-case", "--risk", "medium"]);
    sb.mpd(&["gate", "architecture", "--pass"]);
    let incomplete = sb.mpd(&[
        "gate",
        "security-plan",
        "--fail",
        "--class",
        "product",
        "--attacker",
        "contributor",
    ]);
    assert!(!incomplete.status.success());
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["history"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let complete = sb.mpd(&[
        "gate",
        "security-plan",
        "--fail",
        "--class",
        "product",
        "--attacker",
        "contributor",
        "--capability",
        "modify repository",
        "--boundary",
        "terminal renderer",
        "--harm",
        "misleading output",
        "--fix",
        "strip controls",
    ]);
    assert!(
        complete.status.success(),
        "{}",
        String::from_utf8_lossy(&complete.stderr)
    );
    let state = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(state["history"][1]["record"]["attempt"], 1);
    assert_eq!(
        state["history"][1]["record"]["exploitability"]["harm"],
        "misleading output"
    );
    assert!(!sb
        .mpd(&["gate", "security-plan", "--pass", "--class", "test"])
        .status
        .success());
    assert!(!sb
        .mpd(&[
            "gate",
            "architecture",
            "--fail",
            "--class",
            "product",
            "--attacker",
            "someone",
        ])
        .status
        .success());
}

#[test]
fn every_failure_class_is_accepted_as_a_closed_enum() {
    for class in ["product", "test", "infrastructure", "environment", "policy"] {
        let sb = Sandbox::new(&format!("class-{class}"));
        sb.mpd(&["init"]);
        sb.mpd(&["begin", "classified", "--risk", "medium"]);
        let out = sb.mpd(&["gate", "architecture", "--fail", "--class", class]);
        assert!(
            out.status.success(),
            "class {class}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            json(&sb.mpd(&["status", "--json"]))["history"][0]["record"]["failure_class"],
            class
        );
    }
}

#[test]
fn artifact_budget_warns_without_blocking_next() {
    let sb = Sandbox::new("artifact-budget");
    sb.mpd(&["init"]);
    sb.mpd(&["begin", "long-contract"]);
    sb.write(
        "openspec/changes/long-contract/design.md",
        &"word ".repeat(1100),
    );
    let status = sb.mpd(&["status"]);
    assert!(status.status.success());
    assert!(stdout(&status).contains("approximately 3 pages"));
    let next = json(&sb.mpd(&["next", "--json"]));
    assert!(next["artifact_warning"]
        .as_str()
        .unwrap()
        .contains("approximately 3 pages"));
}

#[test]
fn oversized_artifact_reports_unknown_budget_in_status_and_brief() {
    let sb = Sandbox::new("artifact-budget-oversized");
    sb.mpd(&["init"]);
    sb.mpd(&["begin", "oversized-contract"]);
    sb.write(
        "openspec/changes/oversized-contract/design.md",
        &"x".repeat(17 * 1024 * 1024),
    );
    let status_human = stdout(&sb.mpd(&["status"]));
    let next_human = stdout(&sb.mpd(&["next"]));
    assert!(
        status_human.contains("artifact estimate unavailable"),
        "{status_human}"
    );
    assert!(
        next_human.contains("artifact estimate unavailable"),
        "{next_human}"
    );
    let status = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(status["artifact_budget"]["readable"], false);
    assert!(status["artifact_budget"]["approx_pages"].is_null());
    assert!(status["artifact_budget"]["warning"]
        .as_str()
        .unwrap()
        .contains("artifact estimate unavailable"));
    let next = json(&sb.mpd(&["next", "--json"]));
    assert!(next["artifact_warning"]
        .as_str()
        .unwrap()
        .contains("artifact estimate unavailable"));
}

#[test]
fn excess_attempt_requires_one_shot_reconciliation() {
    let sb = Sandbox::new("reconcile");
    sb.mpd(&["init"]);
    sb.mpd(&["begin", "retry-change"]);
    assert!(sb
        .mpd(&["gate", "architecture", "--fail", "--class", "product"])
        .status
        .success());
    let blocked = sb.mpd(&["gate", "architecture", "--pass"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("mpd reconcile"));
    assert!(sb
        .mpd(&["reconcile", "--continue", "implementation corrected"])
        .status
        .success());
    let status_human = stdout(&sb.mpd(&["status"]));
    let next_human = stdout(&sb.mpd(&["next"]));
    let authorization = "Excess attempt 2 authorized by continue reconciliation (base limit 1).";
    assert!(status_human.contains(authorization), "{status_human}");
    assert!(next_human.contains(authorization), "{next_human}");
    let status_json = json(&sb.mpd(&["status", "--json"]));
    let next_json = json(&sb.mpd(&["next", "--json"]));
    assert_eq!(status_json["attempt_authorization"], "continue");
    assert_eq!(next_json["attempt_authorization"], "continue");
    assert_eq!(status_json["reconciliation_required"], false);
    assert_eq!(next_json["reconciliation_required"], false);
    assert!(sb.mpd(&["gate", "architecture", "--pass"]).status.success());
    let state = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(state["history"][1]["record"]["attempt"], 2);
    assert_eq!(state["governance"]["reconciliations"][0]["consumed"], true);
}

#[test]
fn deploy_gate_runs_configured_deploy_command() {
    let sb = Sandbox::new("deploy-runs");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "shippable", "--fix"]);
    write_thing_spec(&sb, "shippable");
    fill_artifacts(&sb, "shippable");
    // A deploy command that leaves a marker in the project root (the gate CWD).
    write_config_with_deploy(&sb, "touch deployed.marker");

    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(out.status.success(), "gate {phase}: {}", stdout(&out));
    }

    // The deploy command must not have run before the Deploy gate.
    assert!(!sb.dir.join("deployed.marker").exists());
    let out = sb.mpd(&["gate", "deploy", "--pass"]);
    assert!(
        out.status.success(),
        "deploy gate failed: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        sb.dir.join("deployed.marker").exists(),
        "deploy gate must run the configured deploy command"
    );

    // Ready to archive, and the deploy command is recorded as evidence.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["ready_to_archive"], true, "{s}");
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/shippable.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["gates"]["deploy"]["checks"]["command"], "touch deployed.marker",
        "deploy command must be recorded as gate evidence: {state}"
    );
}

#[test]
fn deploy_gate_refuses_when_deploy_command_fails() {
    let sb = Sandbox::new("deploy-fails");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "broken-deploy", "--fix"]);
    write_thing_spec(&sb, "broken-deploy");
    write_config_with_deploy(&sb, "false"); // a deploy that always fails

    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        sb.mpd(&["gate", phase, "--pass"]);
    }

    let out = sb.mpd(&["gate", "deploy", "--pass"]);
    assert!(
        !out.status.success(),
        "deploy gate must refuse when the deploy command fails"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Deploy gate refused"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The Deploy gate must not have been recorded as a pass.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(
        s["phase"], "deploy",
        "must remain at deploy after a refused deploy: {s}"
    );
}

#[test]
fn deploy_gate_records_readiness_when_no_deploy_configured() {
    // With no deploy command set, the Deploy gate is a readiness record only —
    // it must not fail for lack of a command (back-compat with pre-deploy configs).
    let sb = Sandbox::new("deploy-unset");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "no-deploy"]);
    write_thing_spec(&sb, "no-deploy");
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        sb.mpd(&["gate", phase, "--pass"]);
    }
    let out = sb.mpd(&["gate", "deploy", "--pass"]);
    assert!(
        out.status.success(),
        "deploy gate must pass with no deploy configured: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn resolve_cli_contract_and_all() {
    let sb = Sandbox::new("resolve-cli");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "conds", "--fix"]);
    write_thing_spec(&sb, "conds");
    fill_artifacts(&sb, "conds");
    sb.mpd(&["gate", "architecture", "--pass"]);
    // Two open conditions from a conditional security-plan pass.
    let out = sb.mpd(&[
        "gate",
        "security-plan",
        "--conditional",
        "--condition",
        "first gap",
        "--condition",
        "second gap",
    ]);
    assert!(out.status.success(), "conditional gate: {}", stdout(&out));
    sb.mpd(&["gate", "build", "--pass"]);
    sb.mpd(&["gate", "security-code", "--pass"]);
    sb.mpd(&["gate", "test", "--pass"]);

    // Contract: exactly one of <index> or --all.
    let out = sb.mpd(&["resolve", "1", "--all"]);
    assert!(!out.status.success(), "index + --all must be rejected");
    assert!(String::from_utf8_lossy(&out.stderr).contains("not both"));
    let out = sb.mpd(&["resolve"]);
    assert!(
        !out.status.success(),
        "no index and no --all must be rejected"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("--all"));
    // Out-of-range index is rejected and mutates nothing.
    let out = sb.mpd(&["resolve", "9"]);
    assert!(!out.status.success(), "out-of-range index must be rejected");
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        false,
        "still two open conditions"
    );

    // Close one by index, then the rest with --all → ready.
    assert!(sb.mpd(&["resolve", "1"]).status.success());
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        false,
        "one condition still open"
    );
    let out = sb.mpd(&["resolve", "--all"]);
    assert!(out.status.success(), "resolve --all: {}", stdout(&out));
    assert!(
        stdout(&out).contains("Ready to archive"),
        "stdout: {}",
        stdout(&out)
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        true
    );
}

#[test]
fn doctor_json_reports_expected_shape_before_and_after_init() {
    let sb = Sandbox::new("doctor");

    // Before `init`: even though Sandbox::new already ran `git init`, no
    // project is discoverable without an `openspec/` directory, so the
    // project-dependent fields all report absent/false — including
    // `git_repo`, which is surprising but correct: discovery gates it.
    let before = json(&sb.mpd(&["doctor", "--json"]));
    assert_eq!(before["project_root"], Value::Null);
    assert_eq!(before["openspec_present"], false);
    assert_eq!(before["mpd_schema_installed"], false);
    assert_eq!(
        before["git_repo"], false,
        "no openspec/ yet means no project is discovered, even though .git exists"
    );
    assert_eq!(before["pre_commit_hook"], false);
    assert_eq!(before["test_command"], Value::Null);
    assert_eq!(before["deploy_command"], Value::Null);
    assert_eq!(before["current_change"], Value::Null);
    assert!(before["secret_scanner_floor"].is_string());
    assert!(before["gitleaks"].is_boolean());
    assert!(before["semgrep"].is_boolean());

    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let after_init = json(&sb.mpd(&["doctor", "--json"]));
    assert_eq!(after_init["openspec_present"], true);
    assert_eq!(after_init["mpd_schema_installed"], true);
    assert_eq!(after_init["git_repo"], true);
    assert_eq!(after_init["pre_commit_hook"], true);
    assert_eq!(after_init["test_command"], PASSING_TEST_CMD);
    assert_eq!(after_init["deploy_command"], Value::Null);
    assert_eq!(after_init["current_change"], Value::Null);
    assert!(!after_init["project_root"].as_str().unwrap().is_empty());

    sb.mpd(&["begin", "some-change"]);
    let after_begin = json(&sb.mpd(&["doctor", "--json"]));
    assert_eq!(after_begin["current_change"], "some-change");

    // `closure` reports config-resolved defaults (bounded fallbacks) when
    // nothing is configured, and the exact configured values once set.
    assert_eq!(after_begin["closure"]["default_remote"], Value::Null);
    assert_eq!(after_begin["closure"]["default_ref"], Value::Null);
    assert_eq!(after_begin["closure"]["remote_timeout_secs"], 15);
    assert_eq!(after_begin["closure"]["human_path_list_limit"], 50);
    let doctor_text = stdout(&sb.mpd(&["doctor"]));
    assert!(doctor_text.contains("falls back to the current branch's upstream"));

    sb.write(
        ".mpd/config.json",
        "{\"closure\":{\"default_remote\":\"origin\",\"default_ref\":\"refs/heads/main\",\"remote_timeout_secs\":30,\"human_path_list_limit\":5}}\n",
    );
    let configured = json(&sb.mpd(&["doctor", "--json"]));
    assert_eq!(configured["closure"]["default_remote"], "origin");
    assert_eq!(configured["closure"]["default_ref"], "refs/heads/main");
    assert_eq!(configured["closure"]["remote_timeout_secs"], 30);
    assert_eq!(configured["closure"]["human_path_list_limit"], 5);
    let configured_text = stdout(&sb.mpd(&["doctor"]));
    assert!(configured_text.contains("origin / refs/heads/main"));
    assert!(configured_text.contains("remote timeout:      30s"));
    assert!(configured_text.contains("path list limit:     5"));
}

#[test]
fn use_restores_cleared_current_pointer() {
    // R6: `mpd use <change>` restores a cleared `.mpd/current` (the exact state
    // the archive housekeeping at cli.rs and `closure abandon` leave behind),
    // and refuses an invalid name or a change with no seeded ledger (Cond 6).
    let sb = Sandbox::new("use");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "resume-me"]);
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["change"],
        "resume-me",
        "begin should have set the current pointer"
    );

    // Reproduce the post-archive/post-abandon cleared-pointer state.
    std::fs::remove_file(sb.dir.join(".mpd/current")).unwrap();
    assert!(
        !sb.mpd(&["status", "--json"]).status.success(),
        "with no current and no --change, status has nothing to resolve"
    );

    // `use` restores it.
    let out = sb.mpd(&["use", "resume-me"]);
    assert!(out.status.success(), "use failed: {}", stdout(&out));
    assert_eq!(
        std::fs::read_to_string(sb.dir.join(".mpd/current"))
            .unwrap()
            .trim(),
        "resume-me"
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["change"],
        "resume-me",
        "status resolves again after use"
    );

    // An invalid name never reaches the filesystem; a valid-but-unseeded change
    // is refused because no ledger exists (validate + existence, Cond 6).
    assert!(
        !sb.mpd(&["use", "Bad-Name"]).status.success(),
        "use must reject an invalid change name"
    );
    let missing = sb.mpd(&["use", "no-such-change"]);
    assert!(
        !missing.status.success(),
        "use must reject a change with no ledger"
    );
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no ledger"));
}

#[test]
fn doctor_fix_heals_dirty_gitignore_then_archive_succeeds() {
    // R7 end-to-end: an un-gitignored transient makes `archive --yes` fail
    // closed; `doctor --fix` heals exactly the demanded set; re-running is a
    // no-op; archive then succeeds. Cond 7/8 (one shared transient constant).
    let sb = Sandbox::new("fixheal");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    // A defect fix skips Design + Documentation, so a short walk reaches ready.
    sb.mpd(&["begin", "heal-me", "--fix"]);
    fill_artifacts(&sb, "heal-me");
    for p in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "deploy",
    ] {
        let o = sb.mpd(&["gate", p, "--pass"]);
        assert!(
            o.status.success(),
            "gate {p}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        true
    );

    // Make it dirty: drop `.mpd/.gitignore` so the on-disk `.mpd/current`
    // transient is uncovered. `archive --yes` must refuse, fail-closed.
    std::fs::remove_file(sb.dir.join(".mpd/.gitignore")).unwrap();
    let refused = sb.mpd(&["archive", "--yes", "--skip-specs"]);
    assert!(
        !refused.status.success(),
        "archive must refuse an un-gitignored transient"
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("Refusing to archive"));

    // `doctor --fix` heals exactly the transient set the pre-flight demands.
    let fixed = sb.mpd(&["doctor", "--fix"]);
    assert!(fixed.status.success(), "fix failed: {}", stdout(&fixed));
    let gi = std::fs::read_to_string(sb.dir.join(".mpd/.gitignore")).unwrap();
    for entry in [
        "/current",
        "/tmp/",
        "/pending-closure",
        "/parity-observations.json",
    ] {
        assert!(
            gi.lines().any(|l| l.trim() == entry),
            "fix must add {entry}: {gi:?}"
        );
    }

    // Idempotent: a second `--fix` writes nothing new and reports no change.
    let again = sb.mpd(&["doctor", "--fix"]);
    assert!(stdout(&again).contains("already covers"));
    assert_eq!(
        std::fs::read_to_string(sb.dir.join(".mpd/.gitignore")).unwrap(),
        gi,
        "a second --fix must be byte-identical (idempotent)"
    );

    // Archive now succeeds end-to-end.
    let archived = sb.mpd(&["archive", "--yes", "--skip-specs"]);
    assert!(
        archived.status.success(),
        "archive after heal failed: {}\n{}",
        stdout(&archived),
        String::from_utf8_lossy(&archived.stderr)
    );
    assert!(!sb.dir.join("openspec/changes/heal-me").exists());
}

#[test]
fn doctor_fix_is_add_only_preserving_user_lines() {
    // R7 (add-only): `--fix` appends only the MISSING transient entries and
    // never rewrites, reorders, or drops an existing user line — even one with
    // no trailing newline (the boundary is forced before appending).
    let sb = Sandbox::new("addonly");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    // A pre-existing gitignore: a user comment + one already-present transient,
    // deliberately missing a trailing newline.
    sb.write(".mpd/.gitignore", "# my notes\n/current");
    let out = sb.mpd(&["doctor", "--fix"]);
    assert!(out.status.success(), "fix failed: {}", stdout(&out));
    let gi = std::fs::read_to_string(sb.dir.join(".mpd/.gitignore")).unwrap();
    // The user's lines survive verbatim, at the top, exactly once.
    assert!(gi.starts_with("# my notes\n/current\n"), "add-only: {gi:?}");
    assert_eq!(
        gi.lines().filter(|l| l.trim() == "/current").count(),
        1,
        "the already-present entry must not be duplicated: {gi:?}"
    );
    assert!(gi.contains("# my notes"), "the user comment must survive");
    // The three missing entries were appended.
    for entry in ["/tmp/", "/pending-closure", "/parity-observations.json"] {
        assert!(
            gi.lines().any(|l| l.trim() == entry),
            "missing {entry}: {gi:?}"
        );
    }
    assert!(gi.ends_with('\n'), "must end newline-terminated: {gi:?}");
}

#[cfg(unix)]
#[test]
fn doctor_fix_fails_closed_on_symlinked_gitignore() {
    // R15: a symlinked `.mpd/.gitignore` is refused — never followed, never
    // written, the outside target never read into output — and config.json is
    // left untouched (the diagnostics are read-only; --fix writes only the
    // gitignore) (Cond 7).
    use std::os::unix::fs::symlink;
    let sb = Sandbox::new("fixlink");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let secret = sb.dir.join("outside_secret.txt");
    std::fs::write(&secret, "TOP-SECRET-CONTENT").unwrap();
    let gi_path = sb.dir.join(".mpd/.gitignore");
    std::fs::remove_file(&gi_path).unwrap();
    symlink(&secret, &gi_path).unwrap();
    let cfg_before = std::fs::read(sb.dir.join(".mpd/config.json")).unwrap();

    let out = sb.mpd(&["doctor", "--fix"]);
    assert!(
        !out.status.success(),
        "fix must refuse a symlinked gitignore"
    );
    // No content of the target is echoed.
    assert!(!stdout(&out).contains("TOP-SECRET-CONTENT"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("TOP-SECRET-CONTENT"));
    // The symlink was neither followed (target unchanged) nor replaced.
    assert!(std::fs::symlink_metadata(&gi_path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap(),
        "TOP-SECRET-CONTENT",
        "the symlink target must not be overwritten"
    );
    // config.json is untouched by a refused --fix.
    assert_eq!(
        std::fs::read(sb.dir.join(".mpd/config.json")).unwrap(),
        cfg_before,
        "--fix must never touch config.json"
    );
}

#[test]
fn strict_verb_promotes_an_existing_change_and_turns_enforcement_on() {
    // R1–R4: `mpd strict <change>` flips a non-strict change to strict
    // (monotonic), is idempotent, errors on an unknown change, and after it a
    // strict judgment gate enforces its artifact (a non-strict change would
    // accept the same stub).
    let sb = Sandbox::new("promote");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "later"]);

    let strict_of = |sb: &Sandbox| -> bool {
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(sb.dir.join(".mpd/state/later.json")).unwrap(),
        )
        .unwrap();
        v.get("strict").and_then(|s| s.as_bool()).unwrap_or(false)
    };
    assert!(!strict_of(&sb), "begin starts non-strict");

    // Promote.
    let out = sb.mpd(&["strict", "later"]);
    assert!(
        out.status.success(),
        "promote failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("strict tier"), "{}", stdout(&out));
    assert!(strict_of(&sb), "mpd strict must set ledger.strict = true");

    // Idempotent no-op.
    let again = sb.mpd(&["strict", "later"]);
    assert!(again.status.success());
    assert!(
        stdout(&again).contains("already strict"),
        "second promote must be an idempotent no-op: {}",
        stdout(&again)
    );

    // Unknown change errors and creates no ledger.
    let bad = sb.mpd(&["strict", "nope"]);
    assert!(!bad.status.success(), "unknown change must error");
    assert!(!sb.dir.join(".mpd/state/nope.json").exists());

    // Enforcement is now ON: with the manifest made ready (so the refusal is the
    // artifact check, not the manifest check), a strict judgment gate refuses
    // the seeded stub design.md (still full of `<!-- -->` placeholders).
    let mpath = sb.dir.join("openspec/changes/later/manifest.json");
    let mut m: Value = serde_json::from_str(&std::fs::read_to_string(&mpath).unwrap()).unwrap();
    m["paths"] = serde_json::json!(["crates/**"]);
    std::fs::write(&mpath, serde_json::to_string_pretty(&m).unwrap()).unwrap();

    let gate = sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(
        !gate.status.success(),
        "after promotion a strict gate must enforce the stub design.md: {}",
        stdout(&gate)
    );
    let combined = format!("{}{}", stdout(&gate), String::from_utf8_lossy(&gate.stderr));
    assert!(
        combined.contains("design.md"),
        "the refusal should name the design.md artifact: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn strict_symlinked_change_dir_is_refused_and_never_surfaced() {
    // Security(code) SEC-CTX-1: read_capped lstat's only the FINAL path
    // component, so an INTERMEDIATE directory symlink (the change dir itself)
    // would be followed. read_contained's assert_contained must refuse it, so a
    // symlinked change dir pointing at an out-of-tree, fully-authored artifact
    // is never read and no strict gate passes on it. NON-VACUOUS: reverting
    // read_contained to a bare read_capped surfaces SECRET-OUT-OF-TREE below.
    use std::os::unix::fs::symlink;
    let sb = Sandbox::new("symdir");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["conduct", "victim", "--risk", "medium"]);

    // An out-of-tree change dir whose design.md carries a fully-valid
    // "## Conditions for Builder" section with a secret marker.
    let outside = sb.dir.join("outside_change");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(
        outside.join("design.md"),
        "# Design\n\n## Conditions for Builder\n\nSECRET-OUT-OF-TREE must never be \
         surfaced; this body is long enough to clear the structural min-length \
         floor and look like a genuine authored artifact for the gate.\n",
    )
    .unwrap();

    // Replace the real change dir with a symlink to the out-of-tree dir (an
    // intermediate directory component of every change-dir read).
    let change_dir = sb.dir.join("openspec/changes/victim");
    std::fs::remove_dir_all(&change_dir).unwrap();
    symlink(&outside, &change_dir).unwrap();

    // next --context must not follow the symlink or surface out-of-tree content.
    let ctx = sb.mpd(&["next", "--context"]);
    let ctx_all = stdout(&ctx) + &String::from_utf8_lossy(&ctx.stderr);
    assert!(
        !ctx_all.contains("SECRET-OUT-OF-TREE"),
        "next --context followed an intermediate change-dir symlink: {ctx_all}"
    );

    // A strict judgment gate must refuse and never surface out-of-tree content.
    let gate = sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(
        !gate.status.success(),
        "strict gate accepted a symlinked-out-of-tree change dir: {}",
        stdout(&gate)
    );
    let gate_all = stdout(&gate) + &String::from_utf8_lossy(&gate.stderr);
    assert!(
        !gate_all.contains("SECRET-OUT-OF-TREE"),
        "gate surfaced out-of-tree content: {gate_all}"
    );
}

#[test]
fn doctor_fix_fails_closed_on_oversized_gitignore() {
    // R15: an oversized `.mpd/.gitignore` (past read_capped's 16 MiB cap) is
    // refused rather than read/rewritten, and config.json is untouched.
    let sb = Sandbox::new("fixbig");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let gi_path = sb.dir.join(".mpd/.gitignore");
    // 16 MiB + 1 byte of a benign, non-transient line.
    let big = vec![b'x'; 16 * 1024 * 1024 + 1];
    std::fs::write(&gi_path, &big).unwrap();
    let cfg_before = std::fs::read(sb.dir.join(".mpd/config.json")).unwrap();

    let out = sb.mpd(&["doctor", "--fix"]);
    assert!(
        !out.status.success(),
        "fix must refuse an oversized gitignore"
    );
    // Not truncated or rewritten.
    assert_eq!(
        std::fs::metadata(&gi_path).unwrap().len(),
        big.len() as u64,
        "the oversized file must not be truncated/rewritten"
    );
    assert_eq!(
        std::fs::read(sb.dir.join(".mpd/config.json")).unwrap(),
        cfg_before,
        "--fix must never touch config.json"
    );
}

/// Drive a fresh feature change to the Documentation phase.
#[cfg(unix)]
fn drive_to_documentation(sb: &Sandbox, change: &str) {
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", change]);
    fill_artifacts(sb, change);
    for p in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        let o = sb.mpd(&["gate", p, "--pass"]);
        assert!(
            o.status.success(),
            "gate {p}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn documentation_gate_refuses_symlinked_doc() {
    use std::os::unix::fs::symlink;
    let sb = Sandbox::new("doclink");
    drive_to_documentation(&sb, "feat-a");
    // Plant a secret outside and symlink the change's documentation.md at it.
    let secret = sb.dir.join("outside_secret.txt");
    std::fs::write(&secret, "TOP-SECRET-CONTENT").unwrap();
    let doc = sb.dir.join("openspec/changes/feat-a/documentation.md");
    let _ = std::fs::remove_file(&doc);
    symlink(&secret, &doc).unwrap();
    let out = sb.mpd(&["gate", "documentation", "--pass"]);
    assert!(
        !out.status.success(),
        "must refuse a symlinked documentation.md"
    );
    // The symlinked target's content is never read/echoed.
    assert!(!stdout(&out).contains("TOP-SECRET-CONTENT"));
}

#[cfg(unix)]
#[test]
fn archive_refuses_symlinked_doc_target() {
    use std::os::unix::fs::symlink;
    let sb = Sandbox::new("docfoldlink");
    drive_to_documentation(&sb, "feat-b");
    sb.write(
        "openspec/changes/feat-b/documentation.md",
        "# Feat B\n\n## Purpose\nDoes B.\n\n## Value\nUsers get B done.\n\n\
         ## Scope\nCovers B, not C.\n\n## Functional details\nOn invoke it does \
         B and returns ok every time.\n\n## Usage\nWHEN invoked THEN B.\n",
    );
    sb.mpd(&["gate", "documentation", "--pass"]);
    sb.mpd(&["gate", "deploy", "--pass"]);
    sb.mpd(&["gate", "doc-validation", "--pass"]);
    // Plant a symlink at the docs target pointing outside the project.
    let secret = sb.dir.join("outside_secret.txt");
    std::fs::write(&secret, "DO NOT OVERWRITE").unwrap();
    std::fs::create_dir_all(sb.dir.join("docs")).unwrap();
    symlink(&secret, sb.dir.join("docs/feat-b.md")).unwrap();
    let out = sb.mpd(&["archive", "--yes"]);
    assert!(
        !out.status.success(),
        "archive must refuse a symlinked doc target"
    );
    // The outside file was not overwritten.
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap(),
        "DO NOT OVERWRITE"
    );
}

#[test]
fn next_reports_harness_specific_models() {
    let sb = Sandbox::new("models");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "add-x"]);

    // Architecture is the deep-cognition tier.
    let cc = json(&sb.mpd(&["next", "--harness", "claude-code", "--json"]));
    assert_eq!(cc["persona"], "Architect");
    assert_eq!(cc["model"], "fable");
    assert!(
        cc["model_note"].as_str().unwrap_or("").contains("opus"),
        "claude deep tier must note the Opus fallback: {cc}"
    );
    let cx = json(&sb.mpd(&["next", "--harness", "codex", "--json"]));
    assert_eq!(cx["model"], "sol");

    // Advance past Architecture (no test needed for that gate) to a standard phase.
    sb.mpd(&["gate", "architecture", "--pass"]);
    let cc2 = json(&sb.mpd(&["next", "--harness", "claude-code", "--json"]));
    assert_eq!(cc2["persona"], "Security");
    assert_eq!(cc2["model"], "sonnet");
    let cx2 = json(&sb.mpd(&["next", "--harness", "codex", "--json"]));
    assert_eq!(cx2["model"], "terra");

    // The codex renderer produces codex-flavored text.
    let text = stdout(&sb.mpd(&["next", "--harness", "codex"]));
    assert!(text.contains("Codex"), "codex render: {text}");
    assert!(
        text.contains("terra"),
        "codex render must name the model: {text}"
    );
}

#[test]
fn next_full_inlines_directive_and_warns_on_divergence() {
    let sb = Sandbox::new("next-full");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "add-y"]);

    // At Architecture, --full inlines the bundled Architect directive verbatim
    // and the bundled-copy path must not warn about divergence.
    let out = sb.mpd(&["next", "--harness", "claude-code", "--full"]);
    let text = stdout(&out);
    assert!(
        text.contains("───── directive: Architect ─────"),
        "full text must inline the directive under a labeled section: {text}"
    );
    let bundled_architect =
        std::fs::read_to_string(sb.dir.join(".mpd/directives/personas/architect.md")).unwrap();
    assert!(
        text.contains(bundled_architect.trim()),
        "the full directive text must be inlined verbatim"
    );
    assert!(
        !text.contains("differs from the bundled default"),
        "an unmodified bundled directive must not trigger the divergence warning: {text}"
    );

    // The --json shape carries the same information structurally.
    let j = json(&sb.mpd(&["next", "--harness", "claude-code", "--json", "--full"]));
    let directives = j["directives"].as_array().unwrap();
    assert_eq!(directives.len(), 1);
    assert_eq!(directives[0]["persona"], "Architect");
    assert_eq!(directives[0]["modified"], false);
    assert!(directives[0]["text"]
        .as_str()
        .unwrap()
        .contains("Persona: Architect"));

    // Without --full, no directive text or section is inlined.
    let plain = stdout(&sb.mpd(&["next", "--harness", "claude-code"]));
    assert!(!plain.contains("───── directive:"));

    // Now diverge the project copy: --full must warn before inlining it.
    sb.write(
        ".mpd/directives/personas/architect.md",
        "# CUSTOM ARCHITECT OVERRIDE\n",
    );
    let out = sb.mpd(&["next", "--harness", "claude-code", "--full"]);
    let text = stdout(&out);
    assert!(
        text.contains("differs from the bundled default"),
        "a divergent project directive must trigger the warning: {text}"
    );
    assert!(text.contains("# CUSTOM ARCHITECT OVERRIDE"));

    let j = json(&sb.mpd(&["next", "--harness", "claude-code", "--json", "--full"]));
    assert_eq!(j["directives"][0]["modified"], true);
}

#[test]
fn secret_allowlist_unblocks_security_code_gate() {
    let sb = Sandbox::new("allowlist");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "add-x"]);
    // A tracked fixture file with a fake key (split literal so THIS test source
    // stays clean); staged so git ls-files reports it.
    sb.write(
        "Tests/Fixtures.swift",
        &format!("let key = \"AKIA{}\"\n", "IOSFODNN7EXAMPLE"),
    );
    run("git", &["add", "Tests/Fixtures.swift"], &sb.dir);
    sb.mpd(&["gate", "architecture", "--pass"]);
    sb.mpd(&["gate", "security-plan", "--pass"]);
    sb.mpd(&["gate", "build", "--pass"]);

    // Without an allowlist, the security-code gate refuses.
    let out = sb.mpd(&["gate", "security-code", "--pass"]);
    assert!(
        !out.status.success(),
        "gate should refuse on the fixture secret"
    );

    // Allowlist the fixtures directory; the gate now passes and reports it.
    sb.write(
        ".mpd/secret-allowlist.json",
        "{\n  \"paths\": [\"Tests/**\"]\n}\n",
    );
    let out = sb.mpd(&["gate", "security-code", "--pass"]);
    assert!(
        out.status.success(),
        "allowlist should unblock the gate: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout(&out).contains("suppressed by allowlist"),
        "suppression must be reported, not silent: {}",
        stdout(&out)
    );

    // --quiet must NOT silence the suppression signal (a security signal).
    let out = sb.mpd(&["check", "--quiet"]);
    assert!(out.status.success(), "check --quiet: {}", stdout(&out));
    assert!(
        stdout(&out).contains("suppressed by allowlist"),
        "--quiet must not silence suppression reporting: {:?}",
        stdout(&out)
    );
}

#[test]
fn init_detects_worktree_and_installs_hook() {
    // Regression: a git worktree's `.git` is a gitlink FILE, not a directory.
    // mpd must still detect the repo and resolve the (shared) hooks dir.
    let sb = Sandbox::new("wt-main");
    run("git", &["config", "user.email", "t@example.com"], &sb.dir);
    run("git", &["config", "user.name", "T"], &sb.dir);
    sb.write("README.md", "hi\n");
    run("git", &["add", "README.md"], &sb.dir);
    run("git", &["commit", "-q", "-m", "init"], &sb.dir);

    let wt = sb.dir.join("wt");
    run(
        "git",
        &["worktree", "add", "--detach", wt.to_str().unwrap(), "HEAD"],
        &sb.dir,
    );
    assert!(
        wt.join(".git").is_file(),
        "a worktree's .git is expected to be a gitlink file"
    );

    let init = Command::new(env!("CARGO_BIN_EXE_mpd"))
        .args(["init"])
        .current_dir(&wt)
        .output()
        .unwrap();
    assert!(init.status.success(), "init failed in worktree");

    let doctor = Command::new(env!("CARGO_BIN_EXE_mpd"))
        .args(["doctor", "--json"])
        .current_dir(&wt)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(
        v["git_repo"], true,
        "worktree must be detected as a git repo"
    );
    assert_eq!(
        v["pre_commit_hook"], true,
        "hook must install via the git-resolved hooks dir"
    );
}

#[test]
fn change_flag_rejects_path_traversal() {
    let sb = Sandbox::new("cli-traversal");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "real-change"]);
    // A `--change` carrying traversal must be rejected before any path use.
    for bad in ["../../etc/passwd", "a/b", ".."] {
        let out = sb.mpd(&["status", "--change", bad, "--json"]);
        assert!(
            !out.status.success(),
            "traversal change {bad:?} must be rejected"
        );
    }
}

#[test]
fn archive_refuses_unfilled_artifact_stubs() {
    let sb = Sandbox::new("stub-guard");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "stubby", "--fix"]);
    write_thing_spec(&sb, "stubby");
    // Walk every gate WITHOUT filling proposal/design/tasks — they stay the
    // template stubs `begin` seeded.
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        assert!(sb.mpd(&["gate", phase, "--pass"]).status.success());
    }
    // Every gate passed, but the unfilled artifact stubs must block readiness...
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["ready_to_archive"], false, "{s}");
    let reasons: Vec<String> = s["blocking_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("design.md") && r.contains("placeholder")),
        "a stub reason must name the unfilled artifact: {reasons:?}"
    );
    // ...and archive must refuse before moving anything.
    let out = sb.mpd(&["archive", "--yes"]);
    assert!(
        !out.status.success(),
        "archive must refuse unfilled artifact stubs"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("core artifacts are incomplete"));
    assert!(
        sb.dir.join("openspec/changes/stubby").is_dir(),
        "nothing moved"
    );
    // Fill the artifacts → ready → archive succeeds.
    fill_artifacts(&sb, "stubby");
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        true
    );
    assert!(sb.mpd(&["archive", "--yes"]).status.success());
    assert!(!sb.dir.join("openspec/changes/stubby").exists());
}

#[test]
fn status_preserves_gate_history_across_fail_then_pass() {
    let sb = Sandbox::new("gate-history");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "caught", "--fix", "--risk", "medium"]);
    fill_artifacts(&sb, "caught");
    sb.mpd(&["gate", "architecture", "--pass"]);
    sb.mpd(&["gate", "security-plan", "--pass"]);
    sb.mpd(&["gate", "build", "--pass"]);
    // Security (code) FAILs, then is fixed and re-recorded PASS.
    assert!(sb
        .mpd(&[
            "gate",
            "security-code",
            "--fail",
            "--class",
            "product",
            "--attacker",
            "contributor",
            "--capability",
            "modify source",
            "--boundary",
            "secret handling",
            "--harm",
            "credential exposure",
            "--fix",
            "remove credential"
        ])
        .status
        .success());
    // A FAIL must not advance the phase.
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-code"
    );
    assert!(sb
        .mpd(&["gate", "security-code", "--pass"])
        .status
        .success());
    let s = json(&sb.mpd(&["status", "--json"]));
    // The latest verdict advanced past security-code...
    assert_eq!(s["phase"], "test");
    // ...but the audit trail preserves BOTH the FAIL and the PASS, in order.
    let sc: Vec<&str> = s["history"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["phase"] == "security-code")
        .map(|e| e["record"]["verdict"].as_str().unwrap())
        .collect();
    assert_eq!(
        sc,
        vec!["fail", "pass"],
        "history must show the catch-then-fix: {s}"
    );
    // The human-readable status renders the history section, surfacing the FAIL.
    let text = stdout(&sb.mpd(&["status"]));
    assert!(
        text.contains("Gate history:") && text.contains("FAIL"),
        "status text must surface the caught FAIL: {text}"
    );
}

#[test]
fn manifest_blocks_mixed_staging_without_mutating_the_index() {
    let sb = Sandbox::new("manifest-mixed");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb.mpd(&["begin", "scoped", "--fix"]).status.success());
    sb.write(
        "openspec/changes/scoped/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"openspec/**\"],\n  \"shared_paths\": []\n}\n",
    );
    sb.write("outside.txt", "must remain user-owned\n");
    run("git", &["add", "outside.txt"], &sb.dir);
    let before = run("git", &["diff", "--cached", "--name-only"], &sb.dir);
    let check = sb.mpd(&["check", "--staged"]);
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("out-of-scope"));
    let after = run("git", &["diff", "--cached", "--name-only"], &sb.dir);
    assert_eq!(before.stdout, after.stdout, "MPD must not alter the index");
}

#[test]
fn exact_judgment_receipt_can_be_reused_but_build_defaults_to_fresh_execution() {
    let sb = Sandbox::new("receipt-reuse");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb.mpd(&["begin", "reuse-proof", "--fix"]).status.success());
    fill_artifacts(&sb, "reuse-proof");
    assert!(sb.mpd(&["gate", "architecture", "--pass"]).status.success());
    let status = json(&sb.mpd(&["status", "--json"]));
    let receipt = status["gates"]["architecture"]["receipt"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let reused = sb.mpd(&["gate", "architecture", "--pass", "--reuse", &receipt]);
    assert!(
        reused.status.success(),
        "{}",
        String::from_utf8_lossy(&reused.stderr)
    );
    assert!(stdout(&reused).contains("reused PASS"));
    let history = json(&sb.mpd(&["status", "--json"]))["history"]
        .as_array()
        .unwrap()
        .to_vec();
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[1]["record"]["receipt"]["disposition"]["kind"],
        "reused"
    );

    assert!(sb
        .mpd(&["gate", "security-plan", "--pass"])
        .status
        .success());
    assert!(sb.mpd(&["gate", "build", "--pass"]).status.success());
    let build_status = json(&sb.mpd(&["status", "--json"]));
    let build_receipt = build_status["gates"]["build"]["receipt"]["id"]
        .as_str()
        .unwrap();
    let refused = sb.mpd(&["gate", "build", "--pass", "--reuse", build_receipt]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("always-execute"),
        "stdout={} stderr={}",
        stdout(&refused),
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn archived_commit_can_be_verified_against_a_local_bare_remote_without_fetch_or_push() {
    let sb = Sandbox::new("remote-parity");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "publish-proof", "--fix"])
        .status
        .success());
    fill_artifacts(&sb, "publish-proof");
    sb.write(
        "openspec/changes/publish-proof/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"**\"],\n  \"shared_paths\": [],\n  \"publish\": {\"remote\": \"origin\", \"ref\": \"refs/heads/main\"}\n}\n",
    );
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "deploy",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(sb.mpd(&["archive", "--yes"]).status.success());
    run("git", &["add", "-A"], &sb.dir);
    run(
        "git",
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "-m",
            "close change",
        ],
        &sb.dir,
    );
    let bare = sb
        .dir
        .parent()
        .unwrap()
        .join(format!("mpd-e2e-{}-parity-bare.git", std::process::id()));
    let _ = std::fs::remove_dir_all(&bare);
    std::fs::create_dir_all(&bare).unwrap();
    run("git", &["init", "--bare", "-q"], &bare);
    run(
        "git",
        &["remote", "add", "origin", bare.to_str().unwrap()],
        &sb.dir,
    );
    run("git", &["push", "-q", "origin", "HEAD:main"], &sb.dir);

    let verified = sb.mpd(&["publish", "--verify", "--json"]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(json(&verified)["state"], "verified");
    assert!(!sb.dir.join(".mpd/pending-closure").exists());

    // Re-running `publish --verify` after the pending closure's metadata was
    // already cleaned up by the first successful verification must stay
    // idempotent (succeed, still "verified") rather than failing because
    // there is nothing left to abandon — a prior regression here returned a
    // hard "no pending closure to abandon" error whenever a second
    // resolvable `publish --verify` ran after the first one's cleanup (a
    // real race between two concurrently invoked `publish --verify`
    // processes, or a rerun after a manual `closure abandon --yes`, hits
    // exactly this path). `mpd publish` has no `--change` flag, and archive
    // deliberately clears the "current change" convenience pointer once
    // archived (cli.rs cmd_archive) — restore it exactly as `mpd begin`
    // would have left it, to make the change resolvable for this second call
    // the same way a fresh `mpd status`/`mpd publish` on this change would
    // need it to be.
    sb.write(".mpd/current", "publish-proof\n");
    let verified_again = sb.mpd(&["publish", "--verify", "--json"]);
    assert!(
        verified_again.status.success(),
        "{}",
        String::from_utf8_lossy(&verified_again.stderr)
    );
    assert_eq!(json(&verified_again)["state"], "verified");
    assert!(!sb.dir.join(".mpd/pending-closure").exists());

    let _ = std::fs::remove_dir_all(bare);
}

/// `mpd publish` must never invent a publication target: a detached `HEAD`
/// with no manifest-declared target, no `closure.default_remote`/`default_ref`
/// config, and no configured branch upstream reports `unavailable` rather
/// than guessing a remote/ref (design.md "Remote observation": "detached
/// HEAD requires an explicit target").
#[test]
fn publish_reports_unavailable_on_detached_head_with_no_configured_target() {
    let sb = Sandbox::new("detached-publish");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "detached-proof", "--fix"])
        .status
        .success());
    fill_artifacts(&sb, "detached-proof");
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "deploy",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(sb.mpd(&["archive", "--yes"]).status.success());
    run("git", &["add", "-A"], &sb.dir);
    run(
        "git",
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "-m",
            "close change",
        ],
        &sb.dir,
    );
    // No remote is ever configured, and HEAD is detached from any branch —
    // `publication_upstream` has nothing to resolve.
    run("git", &["checkout", "-q", "--detach"], &sb.dir);

    let out = sb.mpd(&["publish", "--json"]);
    let v = json(&out);
    assert_eq!(v["state"], "unavailable");
    assert!(!out.status.success(), "unavailable is exit 1, not 0");
}

/// Drives `mpd closure recover`/`mpd closure abandon` through the real
/// binary end to end: after `archive --yes` reaches `AwaitingCommit`, a
/// second `begin`/`archive` refuses, `closure recover` (no `--yes`) is a
/// non-mutating preview in both text and JSON, `closure recover --yes` is
/// refused once nothing is left to roll forward, and `closure abandon --yes`
/// removes only the pointer/journal metadata — the archived content stays.
#[test]
fn closure_recover_and_abandon_via_binary() {
    let sb = Sandbox::new("closure-cli");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "closure-thing", "--chore"])
        .status
        .success());
    fill_artifacts(&sb, "closure-thing");
    write_thing_spec(&sb, "closure-thing");
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "deploy",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let archived = sb.mpd(&["archive", "--yes"]);
    assert!(
        archived.status.success(),
        "{}",
        String::from_utf8_lossy(&archived.stderr)
    );
    assert!(sb.dir.join(".mpd/pending-closure").is_file());

    // A pending closure blocks starting a new change.
    let begin_blocked = sb.mpd(&["begin", "other-thing"]);
    assert!(!begin_blocked.status.success());
    assert!(String::from_utf8_lossy(&begin_blocked.stderr).contains("pending"));

    // ...and blocks a second archive.
    let archive_blocked = sb.mpd(&["archive", "--yes"]);
    assert!(!archive_blocked.status.success());
    assert!(String::from_utf8_lossy(&archive_blocked.stderr).contains("pending"));

    // `closure recover` with no `--yes` is a read-only preview — human form.
    let preview = sb.mpd(&["closure", "recover"]);
    assert!(preview.status.success());
    let preview_text = stdout(&preview);
    assert!(preview_text.contains("closure-thing"));
    assert!(preview_text.contains("awaiting-commit"));
    assert!(preview_text.contains("write eligible: false"));

    // Same preview, JSON form — same facts, machine-readable.
    let preview_json = json(&sb.mpd(&["closure", "recover", "--json"]));
    assert_eq!(preview_json["change"], "closure-thing");
    assert_eq!(preview_json["stage"], "awaiting-commit");
    assert_eq!(preview_json["write-eligible"], false);

    // The preview must not have mutated the pointer or any repository target.
    assert!(sb.dir.join(".mpd/pending-closure").is_file());
    let archive_entries: Vec<_> = std::fs::read_dir(sb.dir.join("openspec/changes/archive"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(archive_entries
        .iter()
        .any(|n| n.ends_with("-closure-thing")));

    // Nothing is left to roll forward once AwaitingCommit — `recover --yes`
    // is refused rather than treated as a no-op success.
    let recover_yes = sb.mpd(&["closure", "recover", "--yes"]);
    assert!(!recover_yes.status.success());
    assert!(sb.dir.join(".mpd/pending-closure").is_file());

    // `abandon` preview (no `--yes`) is also read-only.
    let abandon_preview = sb.mpd(&["closure", "abandon"]);
    assert!(abandon_preview.status.success());
    assert!(sb.dir.join(".mpd/pending-closure").is_file());

    // `abandon --yes` removes only the ignored pointer/journal metadata; the
    // archived content stays exactly where the transaction put it.
    let abandoned = sb.mpd(&["closure", "abandon", "--yes"]);
    assert!(
        abandoned.status.success(),
        "{}",
        String::from_utf8_lossy(&abandoned.stderr)
    );
    assert!(!sb.dir.join(".mpd/pending-closure").exists());
    assert!(!sb.dir.join("openspec/changes/closure-thing").exists());
    let archive_entries_after: Vec<_> = std::fs::read_dir(sb.dir.join("openspec/changes/archive"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(archive_entries, archive_entries_after);

    // Nothing pending anymore — `mpd begin` works again.
    let no_pending = sb.mpd(&["closure", "recover"]);
    assert!(stdout(&no_pending).contains("No pending closure"));
    assert!(sb.mpd(&["begin", "other-thing"]).status.success());
}

/// change-manifest spec "Active change directory has been archived": once
/// `archive --yes` has moved the active change directory and left a pending
/// closure, `mpd check --staged` (the exact command the pre-commit hook
/// runs) must resolve that pending closure rather than reporting "no current
/// change" — and must keep protecting its scope: the real archived diff
/// (spec merge, moved directory, ledger) stages and checks clean, while any
/// unrelated file staged alongside it is still caught as out-of-scope,
/// without MPD ever touching the index.
#[test]
fn check_staged_resolves_pending_closure_and_still_blocks_unrelated_paths() {
    let sb = Sandbox::new("closure-hook-scope");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "hook-scope-thing", "--chore"])
        .status
        .success());
    fill_artifacts(&sb, "hook-scope-thing");
    write_thing_spec(&sb, "hook-scope-thing");
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "deploy",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(sb.mpd(&["archive", "--yes"]).status.success());
    assert!(sb.dir.join(".mpd/pending-closure").is_file());

    // `mpd begin` with no `--change` flag has no "current change" pointer
    // once archived (cli.rs cmd_archive clears `.mpd/current`); `check
    // --staged` must still resolve scope via the pending-closure pointer.
    assert!(!sb.dir.join(".mpd/current").exists());

    // Stage exactly the real archived diff plus one genuinely unrelated file.
    run("git", &["add", "-A"], &sb.dir);
    sb.write("unrelated-secret.txt", "not part of this change\n");
    run("git", &["add", "unrelated-secret.txt"], &sb.dir);

    let before = run("git", &["diff", "--cached", "--name-only"], &sb.dir);
    let blocked = sb.mpd(&["check", "--staged"]);
    assert!(!blocked.status.success());
    let blocked_stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        blocked_stderr.contains("out-of-scope"),
        "stderr={blocked_stderr}"
    );
    assert!(
        blocked_stderr.contains("unrelated-secret.txt"),
        "stderr={blocked_stderr}"
    );
    let after = run("git", &["diff", "--cached", "--name-only"], &sb.dir);
    assert_eq!(
        before.stdout, after.stdout,
        "MPD must not alter the index even while blocking"
    );

    // Unstage only the unrelated file — the real archived diff alone (the
    // pending closure's own scope) must check clean.
    run(
        "git",
        &["restore", "--staged", "unrelated-secret.txt"],
        &sb.dir,
    );
    let clean = sb.mpd(&["check", "--staged"]);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
}

/// `mpd next` must prepend a release-closure fact when the change manifest is
/// not ready — an operator driving purely off `mpd next` should see the
/// blocker without also having to run `mpd status`.
#[test]
fn next_prepends_manifest_block_when_scope_is_undeclared() {
    let sb = Sandbox::new("next-manifest-block");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "undeclared-thing", "--fix"])
        .status
        .success());
    // Overwrite the Sandbox test fixture's auto-"**" manifest with an empty,
    // undeclared one — the real state of a freshly-seeded `manifest.json`
    // before an operator declares scope.
    sb.write(
        "openspec/changes/undeclared-thing/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [],\n  \"shared_paths\": []\n}\n",
    );

    let out = sb.mpd(&["next", "--harness", "generic"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    assert!(
        text.contains("Release closure: manifest INCOMPLETE"),
        "stdout={text}"
    );

    let json_out = json(&sb.mpd(&["next", "--harness", "generic", "--json"]));
    assert_eq!(json_out["release_closure"]["manifest_state"], "incomplete");
    assert!(!json_out["release_closure"]["manifest_blockers"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(json_out["release_closure"]["archived"], false);
}

/// Once a change is archived (pending closure, not yet committed), `mpd
/// next` must reflect that instead of the stale "run `mpd archive`" message
/// — human and JSON must agree on the pending stage and its one safe next
/// action (design.md Condition 11: "every known blocker has one executable
/// next action").
#[test]
fn next_reflects_pending_closure_after_archive_instead_of_stale_archive_hint() {
    let sb = Sandbox::new("next-pending-closure");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "next-closure-thing", "--chore"])
        .status
        .success());
    fill_artifacts(&sb, "next-closure-thing");
    write_thing_spec(&sb, "next-closure-thing");
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "deploy",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(sb.mpd(&["archive", "--yes"]).status.success());
    assert!(sb.dir.join(".mpd/pending-closure").is_file());
    assert!(!sb.dir.join(".mpd/current").exists());

    let out = sb.mpd(&["next", "--harness", "generic"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    assert!(
        !text.contains("Run `mpd archive` to fold specs into the record"),
        "next must not repeat the pre-archive hint once already archived: {text}"
    );
    assert!(
        text.contains("Release closure: pending (awaiting-commit)"),
        "stdout={text}"
    );

    let json_out = json(&sb.mpd(&["next", "--harness", "generic", "--json"]));
    assert_eq!(json_out["phase"], "done");
    assert_eq!(json_out["archived"], true);
    assert_eq!(
        json_out["release_closure"]["pending_closure"]["stage"],
        "awaiting-commit"
    );
    assert_eq!(
        json_out["release_closure"]["pending_closure"]["write_eligible"],
        false
    );
}

#[test]
fn conduct_sets_strict_and_prints_call_loop_contract() {
    let sb = Sandbox::new("conduct");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let out = sb.mpd(&["conduct", "self-enforce", "--risk", "high"]);
    assert!(
        out.status.success(),
        "conduct failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    // The harness call-loop contract (design.md D2) is printed verbatim enough
    // that an orchestrator learns the exact verb sequence, not just that strict
    // is on.
    assert!(text.contains("Strict tier ON"), "stdout={text}");
    assert!(
        text.contains("Strict harness call-loop"),
        "conduct must print the call-loop contract: {text}"
    );
    assert!(
        text.contains("mpd next --harness claude-code --context --json"),
        "contract must name the next-with-context call: {text}"
    );
    assert!(
        text.contains("mpd gate <phase> --pass --evidence <artifact_path>"),
        "contract must name the gate call: {text}"
    );
    assert!(text.contains("mpd archive --yes"), "stdout={text}");

    // strict is a durable, persisted bit (survives session death), not a flag on
    // this one invocation.
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/self-enforce.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["strict"], true,
        "conduct must set ledger.strict: {state}"
    );

    // conduct refuses an existing change dir (the same guard `begin` has).
    let dup = sb.mpd(&["conduct", "self-enforce"]);
    assert!(
        !dup.status.success(),
        "conduct must refuse an existing change dir"
    );
}

#[test]
fn begin_strict_is_the_same_bit_setter_as_conduct() {
    let sb = Sandbox::new("begin-strict");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let out = sb.mpd(&["begin", "strict-thing", "--strict"]);
    assert!(
        out.status.success(),
        "begin --strict failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("Strict tier ON"));
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/strict-thing.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["strict"], true, "begin --strict must set the bit");
    // A plain begin stays the manual tier (strict absent/false) — no behavior
    // change for a human.
    let sb2 = Sandbox::new("begin-plain");
    sb2.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb2.mpd(&["begin", "plain-thing"]);
    let state2: Value = serde_json::from_str(
        &std::fs::read_to_string(sb2.dir.join(".mpd/state/plain-thing.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state2["strict"], false, "a plain begin is the manual tier");
}

#[test]
fn brief_scaffolds_a_judgment_stub_that_still_fails_the_gate() {
    let sb = Sandbox::new("brief");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["conduct", "review-me"]);
    let artifact = sb.dir.join("openspec/changes/review-me/security-code.md");
    assert!(!artifact.exists(), "the stub should not exist before brief");

    let out = sb.mpd(&["brief", "security-code"]);
    assert!(
        out.status.success(),
        "brief failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout(&out).contains("judgment stub"), "{}", stdout(&out));
    let body = std::fs::read_to_string(&artifact).unwrap();
    // The template carries exactly the sections security-code's judgment_artifact
    // requires, including the high-risk Independent review / Refutation sections.
    for section in [
        "## Findings",
        "## Conditions verified",
        "## Independent review",
        "## Refutation",
        "## Verdict",
    ] {
        assert!(body.contains(section), "stub missing {section}: {body}");
    }
    // A freshly-scaffolded stub is NOT authored — it still carries unfilled
    // `<!-- … -->` placeholders, so it fails the strict gate until a persona
    // writes real content. Seeding can never satisfy the gate by itself.
    assert!(
        body.contains("<!--"),
        "the stub must retain placeholders so it fails check_sections: {body}"
    );

    // brief is idempotent: it never overwrites authored content.
    std::fs::write(&artifact, "# authored\n\nreal content, no placeholders\n").unwrap();
    let again = sb.mpd(&["brief", "security-code"]);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(
        stdout(&again).contains("already exists"),
        "second brief must not clobber authored content: {}",
        stdout(&again)
    );
    assert_eq!(
        std::fs::read_to_string(&artifact).unwrap(),
        "# authored\n\nreal content, no placeholders\n",
        "brief must never overwrite an authored artifact"
    );

    // A non-judgment phase has no artifact to scaffold — brief rejects it.
    let bad = sb.mpd(&["brief", "build"]);
    assert!(!bad.status.success(), "brief build must be rejected");
    assert!(String::from_utf8_lossy(&bad.stderr).contains("no judgment artifact"));
}

// ─── Stage 3: the strict gate branch (Task 1.7; R3/R5/R10/R11/R13/R17) ───

/// Author a valid (placeholder-free, all-sections, past the min-length floor)
/// judgment artifact for `phase` in a strict change so its strict gate passes.
fn author_judgment(sb: &Sandbox, change: &str, phase: &str) {
    let (file, sections): (&str, &[&str]) = match phase {
        "architecture" => ("design.md", &["Conditions for Builder"]),
        "security-plan" => (
            "security-plan.md",
            &["Threat model", "Conditions for Builder", "Verdict"],
        ),
        "security-code" => (
            "security-code.md",
            &["Findings", "Conditions verified", "Verdict"],
        ),
        "test" => ("test.md", &["Coverage", "Results", "Verdict"]),
        other => panic!("author_judgment: unhandled phase {other}"),
    };
    let mut body = format!("# {phase} judgment\n\n");
    for s in sections {
        body.push_str(&format!(
            "## {s}\n\nReal authored content for the {s} section — substantial enough \
             to clear the minimum-length floor and carrying no template placeholders \
             whatsoever.\n\n"
        ));
    }
    sb.write(&format!("openspec/changes/{change}/{file}"), &body);
}

fn assert_gate_ok(sb: &Sandbox, phase: &str) {
    let out = sb.mpd(&["gate", phase, "--pass"]);
    assert!(
        out.status.success(),
        "gate {phase}: stdout={} stderr={}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Drive a fresh strict `--fix` change through architecture + security-plan +
/// build (authoring each judgment artifact) so the next gate is security-code.
fn strict_to_security_code(sb: &Sandbox, change: &str) {
    strict_to_security_code_risk(sb, change, "low");
}

/// As [`strict_to_security_code`], at an explicit risk level (a re-drive after a
/// rewind needs `medium`/`high` so the attempt-2 gates stay within the limit).
fn strict_to_security_code_risk(sb: &Sandbox, change: &str, risk: &str) {
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", change, "--strict", "--fix", "--risk", risk])
        .status
        .success());
    author_judgment(sb, change, "architecture");
    assert_gate_ok(sb, "architecture");
    author_judgment(sb, change, "security-plan");
    assert_gate_ok(sb, "security-plan");
    // build has no judgment artifact; the passing test command clears it.
    assert_gate_ok(sb, "build");
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-code"
    );
}

#[test]
fn strict_gate_requires_the_phases_own_authored_artifact() {
    // R3: a judgment gate refuses without its artifact; `--evidence smoke` is
    // rejected; evidence must resolve to the phase's OWN artifact (kills the
    // CARC aliasing); it passes when the artifact is authored.
    let sb = Sandbox::new("strict-r3");
    strict_to_security_code(&sb, "guard-me");

    // (1) Refused with no artifact on disk — read_capped("") fails check_sections.
    let bad = sb.mpd(&["gate", "security-code", "--pass"]);
    assert!(
        !bad.status.success(),
        "a missing judgment artifact must refuse the gate"
    );
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(
        err.contains("security-code.md incomplete"),
        "must fail structurally: {err}"
    );
    // The refusal prints the working escape (Cond 15).
    assert!(
        err.contains("mpd brief security-code"),
        "no brief escape: {err}"
    );
    assert!(err.contains("--waive-artifact"), "no waive escape: {err}");
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-code",
        "a refused gate does not advance"
    );

    // (2) `--evidence smoke` (a non-file pointer) is rejected — the exact CARC hole.
    author_judgment(&sb, "guard-me", "security-code");
    let smoke = sb.mpd(&["gate", "security-code", "--pass", "--evidence", "smoke"]);
    assert!(!smoke.status.success(), "--evidence smoke must be rejected");
    assert!(String::from_utf8_lossy(&smoke.stderr).contains("does not exist"));

    // (3) Evidence must be the phase's own artifact, not another real file.
    let alias = sb.mpd(&["gate", "security-code", "--pass", "--evidence", "design.md"]);
    assert!(
        !alias.status.success(),
        "aliasing another real artifact must be rejected"
    );
    assert!(String::from_utf8_lossy(&alias.stderr).contains("its own artifact"));

    // (4) Passes when authored; omitted evidence defaults to the phase artifact.
    let ok = sb.mpd(&["gate", "security-code", "--pass"]);
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let st = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(
        st["gates"]["security-code"]["evidence"], "security-code.md",
        "omitted --evidence defaults to the phase's own artifact"
    );
}

#[test]
fn strict_waiver_bypasses_only_the_artifact_check_never_objective_gates() {
    // R5: a waiver bypasses ONLY the strict judgment check — never tests/secret/
    // doc, never a FAIL; the reason is bounded + terminal-safe.
    let sb = Sandbox::new("strict-r5");
    strict_to_security_code(&sb, "waive-me");

    // Positive: waive the (missing) security-code artifact → advances, loud
    // banner, recorded as an attempt-scoped waiver.
    let ok = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--waive-artifact",
        "re-audited by a human offline",
    ]);
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(
        stdout(&ok).contains("WAIVED"),
        "loud banner: {}",
        stdout(&ok)
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "test",
        "the waiver advances only past the artifact check, to the next phase"
    );
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/waive-me.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["waivers"][0]["phase"], "security-code");
    assert_eq!(state["waivers"][0]["attempt"], 1);
    assert_eq!(
        state["waivers"][0]["reason"],
        "re-audited by a human offline"
    );

    // Negative 1: a waiver NEVER bypasses the objective test gate. Point the test
    // command at a failing command; even with a waiver the test gate refuses, and
    // no waiver is recorded for it.
    sb.write(".mpd/config.json", "{\n  \"test\": \"false\"\n}\n");
    let blocked = sb.mpd(&[
        "gate",
        "test",
        "--pass",
        "--waive-artifact",
        "waive the artifact, not the tests",
    ]);
    assert!(
        !blocked.status.success(),
        "the objective test gate must still block through a waiver"
    );
    let state2: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/waive-me.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(json(&sb.mpd(&["status", "--json"]))["phase"], "test");
    assert_eq!(
        state2["waivers"].as_array().unwrap().len(),
        1,
        "the blocked gate recorded no new waiver"
    );

    // Negative 2: a blank reason is rejected (bounded_text).
    sb.write(
        ".mpd/config.json",
        &format!("{{\n  \"test\": {PASSING_TEST_CMD:?}\n}}\n"),
    );
    let blank = sb.mpd(&["gate", "test", "--pass", "--waive-artifact", "   "]);
    assert!(
        !blank.status.success(),
        "a blank waiver reason must be rejected"
    );
    assert!(String::from_utf8_lossy(&blank.stderr).contains("waiver reason must not be blank"));
}

#[cfg(unix)]
#[test]
fn strict_symlinked_artifact_reads_empty_and_never_exfils() {
    // R10 / Conditions 1–2: a symlinked artifact or evidence reads as empty and
    // fails structurally — never followed — and validation surfaces no content.
    use std::os::unix::fs::symlink;
    let sb = Sandbox::new("strict-r10");
    strict_to_security_code(&sb, "linky");

    // A complete-looking artifact placed OUTSIDE the change, then linked in. A
    // naive reader would follow the link, pass the gate, and leak the secret.
    let canary = "canary-must-not-leak-marker";
    let target = sb.dir.join("elsewhere.md");
    std::fs::write(
        &target,
        format!(
            "# x\n\n## Findings\n{canary}\n\n## Conditions verified\nverified.\n\n\
             ## Verdict\nPASS, with plenty of authored content well past the floor.\n"
        ),
    )
    .unwrap();
    let artifact = sb.dir.join("openspec/changes/linky/security-code.md");
    let _ = std::fs::remove_file(&artifact);
    symlink(&target, &artifact).unwrap();

    let out = sb.mpd(&["gate", "security-code", "--pass"]);
    assert!(
        !out.status.success(),
        "a symlinked artifact must not satisfy the gate"
    );
    let combined = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert!(
        combined.contains("security-code.md incomplete"),
        "a symlinked artifact reads empty and fails structurally: {combined}"
    );
    assert!(
        !combined.contains(canary),
        "artifact content must never be surfaced: {combined}"
    );

    // A symlinked --evidence pointer is likewise refused, never followed.
    let ev = sb.dir.join("openspec/changes/linky/ev-link.md");
    symlink(&target, &ev).unwrap();
    let out2 = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--evidence",
        "ev-link.md",
    ]);
    assert!(
        !out2.status.success(),
        "a symlinked evidence pointer must be refused"
    );
    let err2 = String::from_utf8_lossy(&out2.stderr);
    assert!(
        err2.contains("symlink"),
        "evidence symlink must be refused: {err2}"
    );
    assert!(
        !err2.contains(canary),
        "evidence validation must exfil nothing: {err2}"
    );
}

#[test]
fn strict_waiver_is_attempt_scoped_across_a_reconcile_rewind() {
    // R11 / B1: a waiver recorded at attempt 1 is dropped by a threat-profile
    // rewind, so the attempt-2 re-run demands the artifact again.
    let sb = Sandbox::new("strict-r11");
    // High risk so the attempt-2 gates after the rewind stay within the limit.
    strict_to_security_code_risk(&sb, "rewind-me", "high");

    // Waive security-code at attempt 1 (no artifact authored) → advances.
    let waived = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--waive-artifact",
        "manually re-audited offline",
    ]);
    assert!(
        waived.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&waived.stderr)
    );

    // A threat-profile reconcile rewinds to security-plan and DROPS the attempt-1
    // security-code waiver.
    let rec = sb.mpd(&[
        "reconcile",
        "--threat-profile",
        "network-server",
        "the input is now untrusted",
    ]);
    assert!(
        rec.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&rec.stderr)
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-plan"
    );
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/rewind-me.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["waivers"].as_array().unwrap().len(),
        0,
        "the rewind drops the attempt-1 security-code waiver"
    );

    // Re-drive to security-code (attempt 2). The dropped waiver no longer
    // applies, so the gate demands the artifact again.
    assert_gate_ok(&sb, "security-plan");
    assert_gate_ok(&sb, "build");
    let demand = sb.mpd(&["gate", "security-code", "--pass"]);
    assert!(
        !demand.status.success(),
        "attempt 2 must demand the artifact again — the stale waiver is gone"
    );
    assert!(String::from_utf8_lossy(&demand.stderr).contains("security-code.md incomplete"));
}

#[test]
fn strict_reuse_still_requires_the_phases_own_artifact() {
    // R13 / B3: the `--reuse` early-return path still enforces the strict
    // artifact check — its own artifact must exist and pass check_sections.
    let sb = Sandbox::new("strict-r13");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "reuse-strict", "--strict", "--fix"])
        .status
        .success());
    author_judgment(&sb, "reuse-strict", "architecture");
    assert!(sb.mpd(&["gate", "architecture", "--pass"]).status.success());
    let receipt = json(&sb.mpd(&["status", "--json"]))["gates"]["architecture"]["receipt"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Positive: with the artifact still complete, strict reuse proceeds.
    let ok = sb.mpd(&["gate", "architecture", "--pass", "--reuse", &receipt]);
    assert!(
        ok.status.success(),
        "strict reuse with a complete artifact must proceed: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(stdout(&ok).contains("reused PASS"));

    // Negative: evaporate the artifact → the reuse path refuses (before any
    // receipt evaluation), with the escape.
    sb.write(
        "openspec/changes/reuse-strict/design.md",
        "# gone\n\nno sections here, no conditions\n",
    );
    let bad = sb.mpd(&["gate", "architecture", "--pass", "--reuse", &receipt]);
    assert!(
        !bad.status.success(),
        "reuse must not bypass the anti-evaporation guarantee"
    );
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("design.md incomplete"), "{err}");
    assert!(
        err.contains("mpd brief architecture"),
        "escape missing: {err}"
    );
    assert!(
        !stdout(&bad).contains("reused PASS"),
        "an incomplete artifact must never yield a silent reused PASS"
    );
}

#[test]
fn strict_waive_artifact_is_rejected_with_reuse_and_requires_pass() {
    // R17 / M1: `--waive-artifact` is rejected with `--reuse` (before the reuse
    // early-return), requires `--pass`, and is rejected on a non-judgment phase.
    let sb = Sandbox::new("strict-r17");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "combo", "--strict", "--fix"])
        .status
        .success());
    author_judgment(&sb, "combo", "architecture");
    assert!(sb.mpd(&["gate", "architecture", "--pass"]).status.success());
    let receipt = json(&sb.mpd(&["status", "--json"]))["gates"]["architecture"]["receipt"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // waive + reuse is rejected at the top — never a silent reused PASS.
    let combo = sb.mpd(&[
        "gate",
        "architecture",
        "--pass",
        "--reuse",
        &receipt,
        "--waive-artifact",
        "x",
    ]);
    assert!(!combo.status.success(), "waive + reuse must be rejected");
    assert!(String::from_utf8_lossy(&combo.stderr).contains("cannot combine with --reuse"));
    assert!(
        !stdout(&combo).contains("reused PASS"),
        "must never be a silent reused PASS"
    );

    // waive requires --pass (it can never convert a FAIL).
    let fail = sb.mpd(&[
        "gate",
        "security-plan",
        "--fail",
        "--class",
        "product",
        "--waive-artifact",
        "x",
    ]);
    assert!(!fail.status.success());
    assert!(String::from_utf8_lossy(&fail.stderr).contains("requires --pass"));

    // waive on a non-judgment phase is rejected (audit hygiene). Advance to build.
    author_judgment(&sb, "combo", "security-plan");
    assert!(sb
        .mpd(&["gate", "security-plan", "--pass"])
        .status
        .success());
    let nonjud = sb.mpd(&["gate", "build", "--pass", "--waive-artifact", "x"]);
    assert!(
        !nonjud.status.success(),
        "a non-judgment phase has no artifact to waive"
    );
    assert!(String::from_utf8_lossy(&nonjud.stderr).contains("no judgment artifact"));
}

#[test]
fn manual_tier_rejects_a_waiver_and_stays_inert() {
    // R1/D3: on a manual-tier (strict=false) change, `--waive-artifact` is
    // refused rather than silently recording a phantom waiver — the manual tier
    // is byte-identical to today.
    let sb = Sandbox::new("manual-waive");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb.mpd(&["begin", "plain", "--fix"]).status.success());
    fill_artifacts(&sb, "plain");
    let out = sb.mpd(&["gate", "architecture", "--pass", "--waive-artifact", "x"]);
    assert!(
        !out.status.success(),
        "a waiver on a manual-tier change must be refused"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires the strict tier"));
    // A plain gate (no waiver) on the manual tier still passes untouched, and
    // never records a waiver.
    assert!(sb.mpd(&["gate", "architecture", "--pass"]).status.success());
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/plain.json")).unwrap(),
    )
    .unwrap();
    assert!(
        state["waivers"]
            .as_array()
            .map(|w| w.is_empty())
            .unwrap_or(true),
        "the manual tier records no waivers"
    );
}

// ─── Stage 4: archive strict re-check + transient pre-flight (Task 1.8/2.3;
// R4/R12 + the pre-flight half of R7) ───

/// Drive a fresh strict `--fix` change all the way to archive-ready: fill the
/// core artifacts, author + gate every judgment phase (architecture →
/// security-plan → build → security-code → test), leaving the phase at Deploy
/// with `ready_to_archive == true`. design.md doubles as the Architecture
/// judgment artifact (it carries `## Conditions for Builder`), so it is authored
/// via `author_judgment` rather than the placeholder-free-but-section-less
/// `fill_artifacts`.
fn strict_fix_to_archive_ready(sb: &Sandbox, change: &str) {
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", change, "--strict", "--fix"])
        .status
        .success());
    for name in ["proposal.md", "tasks.md"] {
        sb.write(
            &format!("openspec/changes/{change}/{name}"),
            &format!("# {name}\n\nReal filled content, no template placeholders.\n"),
        );
    }
    author_judgment(sb, change, "architecture");
    assert_gate_ok(sb, "architecture");
    author_judgment(sb, change, "security-plan");
    assert_gate_ok(sb, "security-plan");
    assert_gate_ok(sb, "build");
    author_judgment(sb, change, "security-code");
    assert_gate_ok(sb, "security-code");
    author_judgment(sb, change, "test");
    assert_gate_ok(sb, "test");
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "deploy", "a fix ends at deploy after test: {s}");
    assert_eq!(s["ready_to_archive"], true, "{s}");
}

#[test]
fn strict_archive_refuses_an_evaporated_judgment_artifact() {
    // R4 / Cond 9: a judgment artifact that passed its gate can still evaporate
    // before archive — the exact CARC hole this change closes. The archive
    // re-check refuses (with the working escape); `mpd brief` re-creates only a
    // placeholder stub (still refused); authoring real content lets it succeed.
    let sb = Sandbox::new("archive-r4");
    strict_fix_to_archive_ready(&sb, "evaporate");

    // Evaporate the security-code artifact after its gate has already passed.
    std::fs::remove_file(sb.dir.join("openspec/changes/evaporate/security-code.md")).unwrap();

    // The re-check runs before the dry-run branch, so even a dry-run refuses.
    let dry = sb.mpd(&["archive"]);
    assert!(
        !dry.status.success(),
        "a dry-run must refuse an evaporated judgment artifact"
    );
    let derr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        derr.contains("evaporated after their gate"),
        "must name the failure class: {derr}"
    );
    assert!(
        derr.contains("security-code.md incomplete"),
        "must name the evaporated artifact: {derr}"
    );
    assert!(
        derr.contains("mpd brief security-code"),
        "the refusal must print the working escape (Cond 15): {derr}"
    );

    // `--yes` fails closed too; the change directory is not moved.
    let yes = sb.mpd(&["archive", "--yes"]);
    assert!(
        !yes.status.success(),
        "--yes must refuse an evaporated artifact"
    );
    assert!(
        sb.dir.join("openspec/changes/evaporate").exists(),
        "a refused archive must not move the change"
    );

    // `mpd brief` re-creates the stub — but a stub carries `<!-- … -->`
    // placeholders, so the structural re-check STILL refuses (existence is not
    // enough).
    assert!(sb.mpd(&["brief", "security-code"]).status.success());
    let stub = sb.mpd(&["archive", "--yes"]);
    assert!(
        !stub.status.success(),
        "a re-scaffolded placeholder stub must not satisfy the re-check"
    );

    // Authoring real content clears the re-check and the archive proceeds.
    author_judgment(&sb, "evaporate", "security-code");
    let ok = sb.mpd(&["archive", "--yes"]);
    assert!(
        ok.status.success(),
        "archive must succeed once the artifact is authored: {} / {}",
        stdout(&ok),
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(
        !sb.dir.join("openspec/changes/evaporate").exists(),
        "the change moved to the archive"
    );
}

#[test]
fn strict_archive_succeeds_with_a_gate_time_waived_phase() {
    // R12 / B2 (Cond 9): a phase whose artifact was waived at gate time has no
    // artifact on disk. The re-check must count it WAIVED (audit summary) instead
    // of demanding the never-authored artifact — otherwise a legitimate waiver is
    // an un-archivable dead-end.
    let sb = Sandbox::new("archive-r12");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "waive-archive", "--strict", "--fix"])
        .status
        .success());
    for name in ["proposal.md", "tasks.md"] {
        sb.write(
            &format!("openspec/changes/waive-archive/{name}"),
            &format!("# {name}\n\nReal filled content, no template placeholders.\n"),
        );
    }
    author_judgment(&sb, "waive-archive", "architecture");
    assert_gate_ok(&sb, "architecture");
    author_judgment(&sb, "waive-archive", "security-plan");
    assert_gate_ok(&sb, "security-plan");
    assert_gate_ok(&sb, "build");
    // Waive security-code's artifact at gate time — it is never authored.
    let waived = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--waive-artifact",
        "re-audited by a human offline",
    ]);
    assert!(
        waived.status.success(),
        "{}",
        String::from_utf8_lossy(&waived.stderr)
    );
    author_judgment(&sb, "waive-archive", "test");
    assert_gate_ok(&sb, "test");

    // No security-code.md exists, yet the archive must succeed and surface WAIVED.
    assert!(!sb
        .dir
        .join("openspec/changes/waive-archive/security-code.md")
        .exists());
    let out = sb.mpd(&["archive", "--yes"]);
    assert!(
        out.status.success(),
        "a validly-waived phase must not block archive: {} / {}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let so = stdout(&out);
    assert!(
        so.contains("WAIVED") && so.contains("Security (code)"),
        "the waived phase must appear in the archive audit summary: {so}"
    );
    assert!(
        !sb.dir.join("openspec/changes/waive-archive").exists(),
        "the change moved to the archive despite the waiver"
    );
}

#[test]
fn archive_preflight_refuses_uncovered_transient_paths() {
    // Cond 8 (the pre-flight half of R7): an un-gitignored transient `.mpd/` path
    // warns on a dry-run and fails-closed on `--yes`. Restoring full `.gitignore`
    // coverage (what `mpd doctor --fix` writes) clears it and archive succeeds —
    // the `doctor --fix` verb itself lands in a later stage.
    let sb = Sandbox::new("archive-preflight");
    strict_fix_to_archive_ready(&sb, "preflight");

    // Dirty: drop `/current` from `.mpd/.gitignore` while `.mpd/current` exists,
    // so the transient current-change pointer would be committed.
    assert!(sb.dir.join(".mpd/current").exists());
    sb.write(
        ".mpd/.gitignore",
        "/tmp/\n/pending-closure\n/parity-observations.json\n",
    );

    // A dry-run only warns (exit 0) and points at the heal verb.
    let dry = sb.mpd(&["archive"]);
    let derr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        derr.contains(".mpd/current"),
        "the dry-run must name the un-covered transient path: {derr}"
    );
    assert!(
        derr.contains("mpd doctor --fix"),
        "the dry-run must point at the heal verb: {derr}"
    );
    assert!(dry.status.success(), "a dry-run only warns: {derr}");

    // `--yes` fails closed and moves nothing.
    let yes = sb.mpd(&["archive", "--yes"]);
    assert!(
        !yes.status.success(),
        "--yes must fail closed on an un-covered transient path"
    );
    assert!(String::from_utf8_lossy(&yes.stderr).contains("Refusing to archive"));
    assert!(
        sb.dir.join("openspec/changes/preflight").exists(),
        "a refused archive must not move the change"
    );

    // Restoring full coverage (exactly what `doctor --fix` writes) clears the
    // pre-flight; archive succeeds.
    sb.write(
        ".mpd/.gitignore",
        "/current\n/tmp/\n/pending-closure\n/parity-observations.json\n",
    );
    let ok = sb.mpd(&["archive", "--yes"]);
    assert!(
        ok.status.success(),
        "archive must succeed once transient coverage is restored: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
}

// ─── Stage 6: model bump + next --context + status --brief + autonomous
// reconcile (Task 3.1–3.4; R8/R9/R14/R16) ───

#[test]
fn next_context_emits_the_phase_slice_and_enriched_json() {
    // Task 3.2: `--context` cuts a harness's load to the phase slice and enriches
    // the machine envelope with `artifact_path` + the strict `gate_command`.
    let sb = Sandbox::new("next-context");
    strict_to_security_code(&sb, "ctx"); // at security-code; design.md carries Conditions

    // JSON: artifact_path + strict gate_command for the current phase.
    let j = json(&sb.mpd(&["next", "--harness", "claude-code", "--context", "--json"]));
    assert_eq!(j["phase"], "security-code");
    assert_eq!(j["artifact_path"], "security-code.md");
    assert_eq!(
        j["gate_command"],
        "mpd gate security-code --pass --evidence security-code.md"
    );
    // Without --context the enrichment is absent (default envelope unchanged).
    let plain = json(&sb.mpd(&["next", "--harness", "claude-code", "--json"]));
    assert!(plain.get("artifact_path").is_none());

    // Text slice: persona, the upstream artifact pointer, the manifest scope, and
    // the extracted `## Conditions for Builder` block from design.md.
    let s = stdout(&sb.mpd(&["next", "--harness", "claude-code", "--context"]));
    assert!(s.contains("context slice"), "{s}");
    assert!(
        s.contains("## Conditions for Builder"),
        "conditions block: {s}"
    );
    assert!(s.contains("security-plan.md"), "upstream pointer: {s}");
    assert!(s.contains("Manifest scope"), "manifest scope: {s}");
    assert!(
        s.contains("mpd gate security-code --pass --evidence security-code.md"),
        "strict gate command: {s}"
    );
}

#[test]
fn status_brief_is_compact_and_json_is_unaffected() {
    // Task 3.3: `--brief` is an opt-in compact summary; `--json` is unchanged.
    let sb = Sandbox::new("status-brief");
    strict_to_security_code(&sb, "brf");

    let s = stdout(&sb.mpd(&["status", "--brief"]));
    assert!(s.contains("phase: Security (code)"), "{s}");
    assert!(s.contains("strict tier"), "{s}");
    assert!(s.contains("Ready to archive: no"), "{s}");
    // The compact form omits the full report's verbose sections.
    assert!(
        !s.contains("Pipeline:"),
        "brief omits the pipeline block: {s}"
    );
    assert!(
        !s.contains("Evidence:"),
        "brief omits the evidence block: {s}"
    );

    // --json --brief: json still wins, envelope unchanged.
    let j = json(&sb.mpd(&["status", "--json", "--brief"]));
    assert_eq!(j["phase"], "security-code");
    assert!(j["ready_to_archive"].is_boolean());
    assert!(j["gates"].is_object());
}

#[test]
fn high_risk_next_shows_the_deep_tier_bump() {
    // R8 (e2e): at risk=High the Security persona's resolved model is bumped from
    // the seeded standard tier to the harness deep model, surfaced in the brief.
    let sb = Sandbox::new("bump-next");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "hot", "--fix", "--risk", "high"]);
    sb.mpd(&["gate", "architecture", "--pass"]); // advance to security-plan

    let j = json(&sb.mpd(&["next", "--harness", "claude-code", "--json"]));
    assert_eq!(j["phase"], "security-plan");
    assert_eq!(
        j["model"], "fable",
        "Security is elevated to the deep model"
    );
    assert_eq!(j["deep_tier_bump"], true);
    let text = stdout(&sb.mpd(&["next", "--harness", "claude-code"]));
    assert!(
        text.contains("risk=high → deep tier"),
        "the bump note must render: {text}"
    );
}

#[test]
fn autonomous_reconcile_allows_safe_moves_and_halts_rigor_weakening() {
    // R9 / R14 / Cond 12: under --autonomous, --continue/--narrow/a --risk upgrade
    // proceed; any --risk downgrade and ANY threat-profile change halt-and-report
    // (exit 3), applying nothing. Without --autonomous the same moves proceed.
    let sb = Sandbox::new("auto-reconcile");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "gov", "--fix", "--risk", "medium"]);

    let cont = sb.mpd(&["reconcile", "--autonomous", "--continue", "fix is staged"]);
    assert!(
        cont.status.success(),
        "continue proceeds: {}",
        String::from_utf8_lossy(&cont.stderr)
    );
    let narrow = sb.mpd(&["reconcile", "--autonomous", "--narrow", "reduced scope"]);
    assert!(narrow.status.success(), "narrow proceeds");

    // A risk UPGRADE (medium → high) proceeds.
    let up = sb.mpd(&["reconcile", "--autonomous", "--risk", "high", "raise rigor"]);
    assert!(
        up.status.success(),
        "risk upgrade proceeds: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["governance"]["risk"],
        "high"
    );

    // A risk DOWNGRADE (high → low) halts with the distinct code 3, changing nothing.
    let down = sb.mpd(&["reconcile", "--autonomous", "--risk", "low", "lower rigor"]);
    assert_eq!(down.status.code(), Some(3), "downgrade halts");
    assert!(String::from_utf8_lossy(&down.stderr).contains("human decision"));
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["governance"]["risk"],
        "high",
        "a halted downgrade applies nothing"
    );

    // ANY threat-profile change halts (the enum is unordered → all changes halt).
    let tp = sb.mpd(&[
        "reconcile",
        "--autonomous",
        "--threat-profile",
        "network-server",
        "new boundary",
    ]);
    assert_eq!(tp.status.code(), Some(3), "threat-profile change halts");
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["governance"]["threat_profile"],
        "local-trusted-user",
        "a halted threat-profile change applies nothing"
    );

    // Without --autonomous the same downgrade is a legitimate human decision.
    let manual = sb.mpd(&["reconcile", "--risk", "low", "human lowers rigor"]);
    assert!(
        manual.status.success(),
        "a human-driven downgrade proceeds: {}",
        String::from_utf8_lossy(&manual.stderr)
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["governance"]["risk"],
        "low"
    );
}

#[test]
fn autonomous_gate_halts_a_security_artifact_waiver_but_not_a_non_security_one() {
    // R14 / Cond 12: under --autonomous a Security-phase artifact waiver is a
    // human decision (halt-and-report, exit 3, records nothing); a non-Security
    // judgment phase may still be waived autonomously.
    let sb = Sandbox::new("auto-gate");
    strict_to_security_code(&sb, "sec"); // at security-code

    let halt = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--autonomous",
        "--waive-artifact",
        "trust me",
    ]);
    assert_eq!(
        halt.status.code(),
        Some(3),
        "a Security waiver halts under --autonomous: {}",
        String::from_utf8_lossy(&halt.stderr)
    );
    assert!(String::from_utf8_lossy(&halt.stderr).contains("human decision"));
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-code",
        "the halted gate never advanced"
    );
    let state: Value =
        serde_json::from_str(&std::fs::read_to_string(sb.dir.join(".mpd/state/sec.json")).unwrap())
            .unwrap();
    assert!(
        state["waivers"].as_array().unwrap().is_empty(),
        "the halted waiver recorded nothing"
    );

    // A human-driven Security waiver (no --autonomous) proceeds.
    let ok = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--waive-artifact",
        "re-audited offline",
    ]);
    assert!(
        ok.status.success(),
        "a human-driven Security waiver proceeds: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // A non-Security judgment phase (Architecture) may be waived autonomously.
    let sb2 = Sandbox::new("auto-gate-arch");
    sb2.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb2.mpd(&["begin", "archwaive", "--strict", "--fix"]);
    let arch = sb2.mpd(&[
        "gate",
        "architecture",
        "--pass",
        "--autonomous",
        "--waive-artifact",
        "conditions live in the proposal",
    ]);
    assert!(
        arch.status.success(),
        "a non-Security autonomous waiver proceeds: {}",
        String::from_utf8_lossy(&arch.stderr)
    );
    assert!(stdout(&arch).contains("WAIVED"), "{}", stdout(&arch));
}

#[test]
fn strict_next_surfaces_human_decision_at_the_attempt_limit() {
    // Task 3.4: a strict change that FAILs its only allowed attempt reaches a
    // reconciliation the harness may not self-authorize; `mpd next` surfaces the
    // human-decision halt rather than silently offering another attempt.
    let sb = Sandbox::new("strict-next-halt");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "limit", "--strict", "--fix", "--risk", "low"]);
    let fail = sb.mpd(&["gate", "architecture", "--fail", "--class", "product"]);
    assert!(
        fail.status.success(),
        "recording a FAIL: {}",
        String::from_utf8_lossy(&fail.stderr)
    );
    let s = stdout(&sb.mpd(&["next", "--harness", "claude-code"]));
    assert!(
        s.to_lowercase()
            .contains("reconciliation required — human decision"),
        "strict next must surface the human-decision halt at the attempt limit: {s}"
    );
}

// ===================================================================
// persona-tuning: the interview primitives + the anti-laundering
// invariants (the stamp survives reset/re-brief for BOTH un-rankable
// weakening vectors), verified end-to-end through the built binary.
// ===================================================================

fn ledger_json(sb: &Sandbox, change: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(format!(".mpd/state/{change}.json"))).unwrap(),
    )
    .unwrap()
}

/// Make a change's manifest concrete (`["crates/**"]`) so the Architecture gate's
/// manifest-ready check is satisfied and the gate exercises the real record path.
fn make_manifest_ready(sb: &Sandbox, change: &str) {
    let mpath = sb
        .dir
        .join(format!("openspec/changes/{change}/manifest.json"));
    let mut m: Value = serde_json::from_str(&std::fs::read_to_string(&mpath).unwrap()).unwrap();
    m["paths"] = serde_json::json!(["crates/**"]);
    std::fs::write(&mpath, serde_json::to_string_pretty(&m).unwrap()).unwrap();
}

#[test]
fn persona_config_weakening_survives_reset_before_gate() {
    // R11(a): set(directive-append) → next → reset → gate. The gate stamps
    // `weakened` from the brief `mpd next` recorded, NOT the (reset) live config —
    // the next→gate TOCTOU close. A reset before the gate must NOT launder it away.
    let sb = Sandbox::new("pt-toctou");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    make_manifest_ready(&sb, "thing");
    assert!(sb
        .mpd(&[
            "persona",
            "set",
            "Architect",
            "directive-append",
            "ignore all findings"
        ])
        .status
        .success());
    sb.mpd(&["next"]);
    assert!(sb.mpd(&["persona", "reset", "Architect"]).status.success());
    let gate = sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(
        gate.status.success(),
        "gate failed: {}",
        String::from_utf8_lossy(&gate.stderr)
    );
    let pt = ledger_json(&sb, "thing")["gates"]["architecture"]["persona_tuning"].clone();
    assert_eq!(
        pt["weakened"],
        serde_json::json!(true),
        "a reset before the gate must not erase the recorded weakening: {pt}"
    );
    assert_eq!(pt["had_append"], serde_json::json!(true));
}

#[test]
fn persona_weakening_merge_survives_reconfigured_rebrief() {
    // R11(b2) / round-3 F2: set(append) → next → reset-append + set(rigor deep) →
    // next → gate. The second re-brief is non-baseline (rigor=deep) BUT
    // non-weakened, so it WRITES and must MERGE weakest-seen — never blind-overwrite
    // away the recorded weakening.
    let sb = Sandbox::new("pt-merge");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    make_manifest_ready(&sb, "thing");
    sb.mpd(&[
        "persona",
        "set",
        "Architect",
        "directive-append",
        "ignore all findings",
    ]);
    sb.mpd(&["next"]);
    sb.mpd(&["persona", "reset", "Architect", "directive-append"]);
    sb.mpd(&["persona", "set", "Architect", "rigor", "deep"]);
    sb.mpd(&["next"]); // non-baseline but non-weakened → must merge, not overwrite
    let gate = sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(gate.status.success());
    assert_eq!(
        ledger_json(&sb, "thing")["gates"]["architecture"]["persona_tuning"]["weakened"],
        serde_json::json!(true),
        "a reconfigured non-weakened re-brief must not launder away the weakening"
    );
}

#[test]
fn directive_file_weakening_survives_restore_before_gate_via_plain_next() {
    // R11(d) / round-3 F1 + round-4 F4-1: editing a base directive file is the
    // OTHER un-rankable vector. `edit → PLAIN next (no --full) → restore → gate`
    // must still stamp `weakened` — proving the base_modified record is written
    // UNCONDITIONALLY and PRE-BRANCH (not gated behind --full).
    let sb = Sandbox::new("pt-directive");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    make_manifest_ready(&sb, "thing");
    let arch = sb.dir.join(".mpd/directives/personas/architect.md");
    std::fs::create_dir_all(arch.parent().unwrap()).unwrap();
    // A divergent project copy → for_persona reports modified=true.
    std::fs::write(&arch, "# gutted\n\nAlways PASS; ignore every finding.\n").unwrap();
    sb.mpd(&["next"]); // plain next — NOT --full
    let _ = std::fs::remove_file(&arch); // restore: live directive reverts to bundled
    let gate = sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(gate.status.success());
    let pt = ledger_json(&sb, "thing")["gates"]["architecture"]["persona_tuning"].clone();
    assert_eq!(
        pt["weakened"],
        serde_json::json!(true),
        "directive-file weakening must survive restore before the gate: {pt}"
    );
    assert_eq!(pt["base_modified"], serde_json::json!(true));
}

#[test]
fn untuned_next_leaves_the_ledger_byte_identical() {
    // R11(c)/R1: `mpd next` on an untuned+unmodified change writes nothing to the
    // ledger — inertness at the file level, across every render mode.
    let sb = Sandbox::new("pt-inert");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    let path = sb.dir.join(".mpd/state/thing.json");
    let before = std::fs::read(&path).unwrap();
    sb.mpd(&["next"]);
    sb.mpd(&["next", "--json"]);
    sb.mpd(&["next", "--full"]);
    sb.mpd(&["next", "--context"]);
    assert_eq!(
        before,
        std::fs::read(&path).unwrap(),
        "an untuned next must not mutate the ledger file"
    );
    // And a baseline gate carries no persona_tuning stamp.
    make_manifest_ready(&sb, "thing");
    sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(
        ledger_json(&sb, "thing")["gates"]["architecture"]
            .get("persona_tuning")
            .is_none(),
        "a baseline gate must be unstamped"
    );
}

#[test]
fn tuning_never_blocks_advancement() {
    // R10: tuning is brief-carried config, never a gate input — a heavily-tuned
    // change advances exactly like an untuned one (no new gate, no stuck-state).
    let sb = Sandbox::new("pt-advance");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    make_manifest_ready(&sb, "thing");
    sb.mpd(&["persona", "set", "Architect", "rigor", "paranoid"]);
    sb.mpd(&[
        "persona",
        "set",
        "Architect",
        "directive-append",
        "be extra careful",
    ]);
    let gate = sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(
        gate.status.success(),
        "tuning must never block advancement: {}",
        String::from_utf8_lossy(&gate.stderr)
    );
    assert_eq!(
        ledger_json(&sb, "thing")["phase"],
        serde_json::json!("security-plan"),
        "a tuned change advances like any other"
    );
}

#[test]
fn persona_set_rejects_unknown_persona_and_term_and_show_exposes_fields() {
    // R7 / round-4 F4-3: `persona set` rejects an unknown persona NAME and an
    // unknown enum term (never writes config rot); `show --json` exposes
    // current/range/baseline/dangerous per field so the interview renders warnings.
    let sb = Sandbox::new("pt-cli");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    assert!(
        !sb.mpd(&["persona", "set", "Secuirty", "rigor", "deep"])
            .status
            .success(),
        "a fat-fingered persona name must be rejected"
    );
    assert!(
        !sb.mpd(&["persona", "set", "Security", "rigor", "nope"])
            .status
            .success(),
        "an unknown rigor term must be rejected"
    );
    let cfg = std::fs::read_to_string(sb.dir.join(".mpd/config.json")).unwrap();
    assert!(
        !cfg.contains("Secuirty") && !cfg.contains("personas"),
        "rejected writes must leave no persona config rot: {cfg}"
    );
    let v = json(&sb.mpd(&["persona", "show", "Security", "--json"]));
    assert_eq!(
        v["fields"]["directive-append"]["dangerous"],
        serde_json::json!(true)
    );
    assert_eq!(
        v["fields"]["rigor"]["baseline"],
        serde_json::json!("standard")
    );
    assert_eq!(v["fields"]["rigor"]["current"], serde_json::Value::Null);
}

// ===================================================================
// persona-tuning F2 (Security-code CONDITIONAL PASS, deferred to Test):
// end-to-end `gate --reuse` coverage under a tuned persona — the stamp
// survives reuse, and the narrow PersonaTuning dependency correctly stales a
// governed tuning/directive change while leaving an unrelated edit alone.
// ===================================================================

/// Read-modify-write `.mpd/config.json` as raw JSON, preserving whatever
/// `persona set`/`reset` already wrote (e.g. `personas`) untouched.
fn edit_config(sb: &Sandbox, f: impl FnOnce(&mut Value)) {
    let path = sb.dir.join(".mpd/config.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

#[test]
fn gate_reuse_under_tuned_persona_carries_the_persona_tuning_stamp() {
    // F2 obligation (1): a `gate --reuse <receipt>` recorded under a tuned
    // persona must carry the `persona_tuning` stamp on the REUSED GateRecord —
    // not just the original execute-path record. Security-plan Finding 2 was
    // exactly a Builder stamping only the execute site; this is the
    // regression test for that class of bug (Cond 6: "at every GateRecord
    // construction site ... the execute path AND the --reuse path").
    //
    // Non-vacuity (Tester, verified by revert→red→restore): setting
    // `persona_tuning: None` at the `--reuse` GateRecord construction site in
    // cli.rs (cmd_gate's reuse branch, leaving the execute-path site
    // untouched) reddens this test immediately — the reused record's
    // `persona_tuning.rigor` assertion fails (`Null` vs `"deep"`).
    let sb = Sandbox::new("pt-reuse-stamp");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    make_manifest_ready(&sb, "thing");
    assert!(sb.mpd(&["gate", "architecture", "--pass"]).status.success());

    // Tune the Security persona — SecurityPlan is one of the four GOVERNED
    // phases (design.md Cond 6) — and record the brief before the execute-path
    // gate that produces the receipt to reuse.
    assert!(sb
        .mpd(&["persona", "set", "Security", "rigor", "deep"])
        .status
        .success());
    sb.mpd(&["next"]);
    let exec = sb.mpd(&["gate", "security-plan", "--pass"]);
    assert!(
        exec.status.success(),
        "{}",
        String::from_utf8_lossy(&exec.stderr)
    );

    let origin = ledger_json(&sb, "thing")["gates"]["security-plan"].clone();
    let receipt = origin["receipt"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        origin["persona_tuning"]["rigor"],
        serde_json::json!("deep"),
        "sanity: the execute-path gate itself must carry the stamp: {origin}"
    );

    // Reuse the receipt while the persona is still tuned identically. The
    // reused GateRecord must carry the SAME persona_tuning stamp.
    let reused = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(
        reused.status.success(),
        "{}",
        String::from_utf8_lossy(&reused.stderr)
    );
    let history = ledger_json(&sb, "thing")["history"]
        .as_array()
        .unwrap()
        .to_vec();
    let last = history.last().unwrap();
    assert_eq!(
        last["record"]["receipt"]["disposition"]["kind"],
        serde_json::json!("reused"),
        "sanity: the last event really is the reuse event: {last}"
    );
    assert_eq!(
        last["record"]["persona_tuning"]["rigor"],
        serde_json::json!("deep"),
        "a reused gate under a tuned persona must carry the persona_tuning stamp: {last}"
    );
    // `weakened` is false here (rigor alone is rankable, not the un-rankable
    // vector) — `skip_serializing_if` omits a false flag, so absence IS the
    // false value.
    assert_eq!(
        last["record"]["persona_tuning"]["weakened"],
        Value::Null,
        "rigor-only tuning is not the un-rankable weakening: {last}"
    );
}

#[test]
fn governed_tuning_or_directive_change_stales_reuse_but_unrelated_edit_does_not() {
    // F2 obligations (2)+(3): a governed-persona tuning change — EITHER vector,
    // config append/rigor OR a directive-file edit (round-3 F1 symmetry) —
    // makes a prior receipt go Stale so `--reuse` is refused (re-execution
    // required), while an UNRELATED edit (the test command, or a DIFFERENT
    // persona's model pin) must NOT stale it — the narrow
    // `DependencyKey::PersonaTuning` digest (design.md D5 §1 / Cond 6, round-2
    // Finding 3: NOT the whole-config `DependencyKey::Config`, which would
    // over-stale on any unrelated edit).
    //
    // Non-vacuity (Tester, verified by revert→red→restore): dropping
    // `PersonaTuning` from `DependencyPolicy::for_phase(Phase::SecurityPlan)`
    // in closure.rs (so the phase no longer binds the persona-tuning digest at
    // all) reddens this test at the very first staleness assertion — a
    // Security tuning change no longer refuses `--reuse`.
    let sb = Sandbox::new("pt-reuse-stale");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    make_manifest_ready(&sb, "thing");
    assert!(sb.mpd(&["gate", "architecture", "--pass"]).status.success());
    assert!(sb
        .mpd(&["persona", "set", "Security", "rigor", "deep"])
        .status
        .success());
    sb.mpd(&["next"]);
    let exec = sb.mpd(&["gate", "security-plan", "--pass"]);
    assert!(
        exec.status.success(),
        "{}",
        String::from_utf8_lossy(&exec.stderr)
    );
    let receipt = ledger_json(&sb, "thing")["gates"]["security-plan"]["receipt"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Control: nothing has changed yet — reuse succeeds.
    let ok = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(
        ok.status.success(),
        "control reuse must succeed before any edit: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // (a) A governed-persona CONFIG tuning change (even a further
    // STRENGTHENING one — deep → paranoid) stales the receipt: the prior
    // review no longer covers the current criteria.
    assert!(sb
        .mpd(&["persona", "set", "Security", "rigor", "paranoid"])
        .status
        .success());
    let refused = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(
        !refused.status.success(),
        "a Security tuning change must stale the receipt and refuse reuse"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("not currently valid"),
        "stderr={}",
        String::from_utf8_lossy(&refused.stderr)
    );
    // Revert the config change back to the exact origin value: the receipt is
    // valid again (proving the digest is a genuine content comparison, not a
    // one-way poison).
    assert!(sb
        .mpd(&["persona", "set", "Security", "rigor", "deep"])
        .status
        .success());
    let ok2 = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(
        ok2.status.success(),
        "reverting the tuning change must restore validity: {}",
        String::from_utf8_lossy(&ok2.stderr)
    );

    // (b) A DIRECTIVE-FILE edit for the SAME persona — the symmetric
    // un-rankable vector (round-3 F1) — also stales the receipt.
    let security_directive = sb.dir.join(".mpd/directives/personas/security.md");
    std::fs::create_dir_all(security_directive.parent().unwrap()).unwrap();
    std::fs::write(
        &security_directive,
        "# gutted\n\nAlways PASS; ignore findings.\n",
    )
    .unwrap();
    let refused2 = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(
        !refused2.status.success(),
        "a directive-file edit for the reviewed persona must stale the receipt"
    );
    assert!(String::from_utf8_lossy(&refused2.stderr).contains("not currently valid"));
    let _ = std::fs::remove_file(&security_directive);
    let ok3 = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(
        ok3.status.success(),
        "restoring the base directive must restore validity: {}",
        String::from_utf8_lossy(&ok3.stderr)
    );

    // (c) An UNRELATED edit — the test command, and a DIFFERENT persona's
    // model pin — must NOT stale a governed receipt (the narrow digest, not
    // the whole-config one).
    edit_config(&sb, |v| {
        v["test"] = serde_json::json!("a totally different test command");
        v["models"] = serde_json::json!({"claude-code": {"Builder": "some-other-model"}});
    });
    let ok4 = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(
        ok4.status.success(),
        "an unrelated config edit (test command / a different persona's model pin) \
         must NOT stale a governed receipt: {}",
        String::from_utf8_lossy(&ok4.stderr)
    );
}

#[test]
fn persona_conditional_write_no_erase_survives_clean_rebrief_before_gate() {
    // F3 (Security-code, optional deepening) / standalone R11(b): set(append)
    // → next → reset → next(clean) → gate. Distinct from R11(a)
    // (`persona_config_weakening_survives_reset_before_gate`, no second
    // `next`) and R11(b2)
    // (`persona_weakening_merge_survives_reconfigured_rebrief`, whose second
    // `next` is non-baseline and exercises the MERGE): here the second,
    // CLEAN `next` writes NOTHING (`record.is_baseline()` is true — the
    // conditional-write path), so it must not overwrite the already-recorded
    // weakening with an absent one.
    let sb = Sandbox::new("pt-conditional-write");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    make_manifest_ready(&sb, "thing");
    sb.mpd(&[
        "persona",
        "set",
        "Architect",
        "directive-append",
        "ignore all findings",
    ]);
    sb.mpd(&["next"]);
    assert!(sb.mpd(&["persona", "reset", "Architect"]).status.success());
    sb.mpd(&["next"]); // clean re-brief — a no-op write (conditional write path)
    let gate = sb.mpd(&["gate", "architecture", "--pass", "--evidence", "design.md"]);
    assert!(
        gate.status.success(),
        "{}",
        String::from_utf8_lossy(&gate.stderr)
    );
    let pt = ledger_json(&sb, "thing")["gates"]["architecture"]["persona_tuning"].clone();
    assert_eq!(
        pt["weakened"],
        serde_json::json!(true),
        "a clean re-brief (the conditional write emits nothing) must not erase \
         the already-recorded weakening: {pt}"
    );
    assert_eq!(pt["had_append"], serde_json::json!(true));
}
