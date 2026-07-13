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
        Sandbox { dir }
    }

    fn mpd(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mpd"))
            .args(args)
            .current_dir(&self.dir)
            .output()
            .expect("run mpd")
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
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("specify exactly one of"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
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

/// Write `.mpd/config.json` with a passing test command and the given deploy.
fn write_config_with_deploy(sb: &Sandbox, deploy: &str) {
    sb.write(
        ".mpd/config.json",
        &format!("{{\n  \"test\": {PASSING_TEST_CMD:?},\n  \"deploy\": {deploy:?}\n}}\n"),
    );
}

#[test]
fn deploy_gate_runs_configured_deploy_command() {
    let sb = Sandbox::new("deploy-runs");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "shippable", "--fix"]);
    write_thing_spec(&sb, "shippable");
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
}

/// Drive a fresh feature change to the Documentation phase.
#[cfg(unix)]
fn drive_to_documentation(sb: &Sandbox, change: &str) {
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", change]);
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
