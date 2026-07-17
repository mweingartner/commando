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
