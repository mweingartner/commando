//! End-to-end tests that drive the built `mpd` binary through the pipeline.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
struct SandboxRootBinding {
    path: String,
    device: u64,
    inode: u64,
    directory: bool,
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
struct SandboxControlLimits {
    cpu_secs: u64,
    processes: u64,
    open_files: u64,
    file_bytes: u64,
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
struct SandboxControlRequest {
    schema: u32,
    nonce: String,
    profile_digest: String,
    authority_digest: String,
    read_roots: Vec<SandboxRootBinding>,
    read_write_root: SandboxRootBinding,
    allowed_read_probe: SandboxRootBinding,
    limits: SandboxControlLimits,
    argv: Vec<String>,
}

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
        // Archive-success scenarios written before Deploy became mandatory still
        // model a completed pipeline.  Make the fixture satisfy that explicit
        // terminal gate immediately before archive; tests that exercise Deploy
        // itself invoke it directly and remain independent.
        if args.first() == Some(&"archive") {
            let status = Command::new(env!("CARGO_BIN_EXE_mpd"))
                .args(["status", "--json"])
                .current_dir(&self.dir)
                .output()
                .expect("inspect mpd status before archive");
            if status.status.success()
                && serde_json::from_slice::<Value>(&status.stdout)
                    .ok()
                    .and_then(|v| v["phase"].as_str().map(str::to_owned))
                    .as_deref()
                    == Some("deploy")
            {
                let _ = Command::new(env!("CARGO_BIN_EXE_mpd"))
                    .args(["gate", "deploy", "--pass"])
                    .current_dir(&self.dir)
                    .output()
                    .expect("satisfy mandatory deploy fixture gate");
            }
        }
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

    fn mpd_input(&self, args: &[&str], input: &[u8]) -> Output {
        use std::io::Write;
        let mut child = Command::new(env!("CARGO_BIN_EXE_mpd"))
            .args(args)
            .current_dir(&self.dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("run mpd with hook stdin");
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
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

/// A real `git commit` that goes through the ACTUAL installed `.githooks/
/// pre-commit` script — which shells out to plain `mpd` on `$PATH`
/// (`githooks.rs`: "shells out only to the typed `mpd hook pre-commit`
/// coordinator"), not the freshly built test binary. An ambient globally
/// installed `mpd` on the developer's own `$PATH` can be stale (predating a
/// subcommand this binary just added), which would make the hook itself
/// error with "unrecognized subcommand" — a test-environment artifact, not
/// a real hook failure. Prepending `CARGO_BIN_EXE_mpd`'s own directory makes
/// the installed hook resolve to the exact binary this test suite just
/// built, the same way a real clone's `$PATH` would after `cargo install`.
fn git_commit_through_installed_hook(dir: &Path, message: &str) -> Output {
    let mpd_dir = Path::new(env!("CARGO_BIN_EXE_mpd"))
        .parent()
        .expect("CARGO_BIN_EXE_mpd has a parent directory")
        .to_path_buf();
    let mut path = std::ffi::OsString::from(mpd_dir);
    if let Some(existing) = std::env::var_os("PATH") {
        path.push(":");
        path.push(existing);
    }
    Command::new("git")
        .args(["commit", "-q", "-m", message])
        .current_dir(dir)
        .env("PATH", path)
        .output()
        .unwrap_or_else(|e| panic!("run git commit: {e}"))
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn json(o: &Output) -> Value {
    serde_json::from_str(&stdout(o))
        .unwrap_or_else(|e| panic!("parse json: {e}\nstdout was:\n{}", stdout(o)))
}

const PASSING_TEST_CMD: &str = "echo 'test result: ok. 3 passed; 0 failed; 0 ignored'";

/// True only when actually inside the validation sandbox: the marker alone is
/// not trusted (an ambient variable must not silently skip coverage in
/// uncontained runs); the denied-read canary corroborates it.
#[cfg(target_os = "macos")]
fn nested_in_validation_sandbox() -> bool {
    std::env::var_os("MPD_SANDBOXED").is_some() && std::fs::read("/private/etc/hosts").is_err()
}

#[cfg(target_os = "macos")]
#[test]
fn exact_host_sandbox_entry_completes_canaries_and_ready_go() {
    if nested_in_validation_sandbox() {
        eprintln!("skipped: cannot nest the validation sandbox");
        return;
    }
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::process::Stdio;

    fn binding(path: &Path) -> SandboxRootBinding {
        let path = std::fs::canonicalize(path).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        SandboxRootBinding {
            path: path.to_str().unwrap().to_string(),
            device: metadata.dev(),
            inode: metadata.ino(),
            directory: metadata.is_dir(),
        }
    }

    let sandbox = Sandbox::new("macos-sandbox-handshake");
    let runtime =
        std::env::temp_dir().join(format!("mpd-e2e-sandbox-runtime-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&runtime);
    std::fs::create_dir(&runtime).unwrap();
    let profile = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../security/sandbox/validation.sb"),
    )
    .unwrap();
    let mut read_roots = [
        binding(&sandbox.dir),
        binding(Path::new("/System")),
        binding(Path::new("/dev")),
        binding(Path::new("/usr")),
    ]
    .into_iter()
    .collect::<Vec<_>>();
    read_roots.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let request = SandboxControlRequest {
        schema: 1,
        nonce: "42".repeat(32),
        profile_digest: format!("{:x}", Sha256::digest(&profile)),
        authority_digest: "ab".repeat(32),
        read_roots,
        read_write_root: binding(&runtime),
        allowed_read_probe: binding(Path::new("/usr/bin/true")),
        limits: SandboxControlLimits {
            cpu_secs: 30,
            processes: 32,
            open_files: 64,
            file_bytes: 1_048_576,
        },
        argv: vec!["/usr/bin/true".into()],
    };
    let request_line = serde_json::to_vec(&request).unwrap();
    let mut ready_preimage = Vec::new();
    ready_preimage.extend_from_slice(b"mpd:macos-sandbox-ready:v1\0");
    ready_preimage.extend_from_slice(&request_line);
    ready_preimage.extend_from_slice(&profile);
    ready_preimage.extend_from_slice(b"26A5378n");
    ready_preimage.extend_from_slice(b"aarch64");
    let ready_digest = format!("{:x}", Sha256::digest(&ready_preimage));

    let mut child = Command::new(env!("CARGO_BIN_EXE_mpd"))
        .arg("__mpd-sandbox-exec")
        .current_dir(&sandbox.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(&request_line).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    output.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim_end(), format!("MPD_READY {ready_digest}"));
    writeln!(input, "MPD_GO {ready_digest}").unwrap();
    input.flush().unwrap();
    drop(input);
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "sandbox helper failed: {stderr}");
    std::fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn scoped_doctor_is_versioned_read_only_and_enforce_uses_exit_three() {
    let sb = Sandbox::new("scoped-doctor-read-only");
    let init = sb.mpd(&["init"]);
    assert!(init.status.success(), "init: {}", stdout(&init));
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".mpd/config.json");
    let mut config = std::fs::read_to_string(config_path).unwrap();
    config = config.replacen(
        "\"test\": \"cargo test --workspace\",",
        "\"test\": \"cargo test --workspace\",\n  \"deploy\": \"touch scoped-doctor-executed\",",
        1,
    );
    sb.write(".mpd/config.json", &config);

    for scope in ["validator-policy", "runtime-health"] {
        let out = sb.mpd(&["doctor", "--scope", scope, "--json"]);
        assert!(out.status.success(), "{scope}: {}", stdout(&out));
        let report = json(&out);
        assert_eq!(report["schema"], 1);
        assert_eq!(report["scope"], scope);
        assert_eq!(report["effects"]["configured_validation"], 0);
        assert_eq!(report["effects"]["install"], 0);
        assert_eq!(report["effects"]["identity_probe"], 0);
        assert_eq!(report["effects"]["remote"], 0);
        assert!(report["included_checks"].is_array());
        assert!(report["excluded_checks"].is_array());
        assert!(report["findings"].is_array());
        assert!(report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| {
                finding["code"].is_string()
                    && finding["severity"].is_string()
                    && finding["component"].is_string()
                    && finding["state"].is_string()
                    && finding["message"].is_string()
                    && finding["fix"].is_string()
            }));
    }
    let validation = sb.mpd(&["validate", "--commit", "HEAD", "--profile", "test"]);
    assert!(!validation.status.success());
    let head = stdout(&run("git", &["rev-parse", "HEAD"], &sb.dir))
        .trim()
        .to_string();
    let pre_push = sb.mpd_input(
        &["hook", "pre-push", "origin", "example.invalid"],
        format!(
            "refs/heads/main {head} refs/heads/main {}\n",
            "0".repeat(head.len())
        )
        .as_bytes(),
    );
    assert!(!pre_push.status.success());
    assert!(
        !sb.dir.join("scoped-doctor-executed").exists(),
        "doctor, validation, and pre-push must never execute configured Deploy commands"
    );
    assert!(
        !sb.dir.join(".git/mpd/first-adoption").exists(),
        "doctor must not create clone-private activation state while reporting"
    );

    let enforced = sb.mpd(&["doctor", "--scope", "validator-policy", "--enforce"]);
    assert_eq!(enforced.status.code(), Some(3), "{}", stdout(&enforced));
    let bare = sb.mpd(&["doctor", "--enforce"]);
    assert_eq!(bare.status.code(), Some(2), "{}", stdout(&bare));
}

#[test]
fn validation_never_executes_unactivated_candidate_policy() {
    use std::os::unix::fs::PermissionsExt;

    let sb = Sandbox::new("sandbox-capability-blocker");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    let marker = sb.dir.join("candidate-command-started");
    sb.write(
        "marker-check.sh",
        &format!(
            "#!/bin/sh\nprintf candidate-started > '{}'\n",
            marker.display()
        ),
    );
    std::fs::set_permissions(
        sb.dir.join("marker-check.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    sb.write(
        ".mpd/config.json",
        r#"{
  "local_validation": {
    "schema": 1,
    "required-toolchain": {
      "rust-release": "1.91.0",
      "host": "aarch64-apple-darwin",
      "components": ["marker"]
    },
    "tools": {
      "marker": {
        "program": "marker-check.sh",
        "version-args": ["--version"],
        "requirement": "required",
        "install-hint": "Fixture-only marker that must remain inert."
      }
    },
    "checks": {
      "format": { "kind": "format", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "lint": { "kind": "lint", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "test": { "kind": "test", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "release": { "kind": "release-build", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "self-check": { "kind": "self-check", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "dependency": { "kind": "dependency-audit", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "secret": { "kind": "secret-scan", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "sast": { "kind": "sast", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" },
      "nonfunctional": { "kind": "nonfunctional", "program": "marker", "args": [], "timeout-secs": 30, "result-policy": "exit-zero" }
    },
    "profiles": {
      "build": { "checks": ["format", "lint", "test", "release"] },
      "security": { "checks": ["self-check", "dependency", "secret", "sast"] },
      "test": { "checks": ["format", "lint", "test", "release", "self-check", "dependency", "secret", "sast"] },
      "high-risk": { "checks": ["format", "lint", "test", "release", "self-check", "dependency", "secret", "sast", "nonfunctional"] }
    },
    "gates": {
      "build": "build",
      "security-code": "security",
      "test": "test",
      "pre-push": "test",
      "high-risk-test": "high-risk"
    },
    "hooks": { "path": ".githooks", "require-bundled": true },
    "receipts": { "log-count-cap": 16, "log-byte-cap": 4096 },
    "offline": {
      "cargo-lock": "Cargo.lock",
      "cargo-target": "aarch64-apple-darwin",
      "advisory-db-path": "mpd/advisory-db",
      "advisory-revision": "b5fc89b8be99e96f79194d8a6f11e9b4143b99f0",
      "advisory-tree": "c943a47fee3f2b9767f664fd26c2cb6f0447b23d",
      "advisory-max-age-days": 30
    },
    "sandbox": {
      "contract-version": 1,
      "network-adapter": "platform-mandatory",
      "environment-allowlist": [
        "CARGO_HOME", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR", "CARGO_TERM_COLOR",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM",
        "GIT_OPTIONAL_LOCKS", "GIT_PAGER", "GIT_TERMINAL_PROMPT", "HOME", "LANG",
        "LC_ALL", "PAGER", "PATH", "RUSTC", "SEMGREP_SEND_METRICS", "TERM",
        "TMPDIR", "TZ"
      ]
    },
    "limits": {
      "checks-per-profile": 16,
      "aggregate-secs": 300,
      "output-bytes": 4096,
      "log-bytes": 4096,
      "worktree-bytes": 1048576,
      "child-processes": 32,
      "child-open-files": 64,
      "child-file-bytes": 1048576
    }
  }
}
"#,
    );
    let profile = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../security/sandbox/validation.sb"),
    )
    .unwrap();
    sb.write("security/sandbox/validation.sb", &profile);
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &[
            "commit",
            "--no-verify",
            "-q",
            "-m",
            "sandbox blocker fixture",
        ],
        &sb.dir,
    );

    let snapshot = || {
        let mut state = [
            vec!["rev-parse", "HEAD"],
            vec!["count-objects", "-v"],
            vec!["diff", "--binary"],
            vec!["diff", "--cached", "--binary"],
            vec!["status", "--porcelain=v2", "--untracked-files=all"],
            vec!["for-each-ref", "--format=%(refname)%00%(objectname)"],
            vec!["config", "--local", "--null", "--list"],
        ]
        .into_iter()
        .map(|args| run("git", &args, &sb.dir).stdout)
        .collect::<Vec<_>>();
        let raw_hooks = stdout(&run("git", &["rev-parse", "--git-path", "hooks"], &sb.dir));
        let hooks = Path::new(raw_hooks.trim());
        let hooks = if hooks.is_absolute() {
            hooks.to_path_buf()
        } else {
            sb.dir.join(hooks)
        };
        let mut entries = std::fs::read_dir(hooks)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        let mut hook_bytes = Vec::new();
        for entry in entries {
            let metadata = entry.metadata().unwrap();
            hook_bytes.extend_from_slice(entry.file_name().as_encoded_bytes());
            hook_bytes.push(0);
            hook_bytes.extend_from_slice(&metadata.permissions().mode().to_le_bytes());
            hook_bytes.extend_from_slice(&std::fs::read(entry.path()).unwrap());
            hook_bytes.push(0);
        }
        state.push(hook_bytes);
        state
    };
    let before = snapshot();
    let output = sb.mpd(&["validate", "--commit", "HEAD", "--profile", "test"]);
    assert!(
        !output.status.success(),
        "missing policy activation must fail closed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("trusted-policy-missing"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !marker.exists(),
        "the candidate-defined argv must never begin"
    );
    assert_eq!(
        snapshot(),
        before,
        "the failed capability probe is read-only"
    );

    let begun = sb.mpd(&["begin", "sandbox-build", "--strict", "--fix"]);
    assert!(
        begun.status.success(),
        "{}",
        String::from_utf8_lossy(&begun.stderr)
    );
    author_judgment(&sb, "sandbox-build", "architecture");
    assert_gate_ok(&sb, "architecture");
    author_judgment(&sb, "sandbox-build", "security-plan");
    assert_gate_ok(&sb, "security-plan");
    let before_reuse = snapshot();
    let ledger_before_reuse = std::fs::read(sb.dir.join(".mpd/state/sandbox-build.json")).unwrap();
    for (phase, label) in [
        ("build", "Build"),
        ("security-code", "Security (code)"),
        ("test", "Test"),
    ] {
        let refused_reuse = sb.mpd(&["gate", phase, "--pass", "--reuse", &"a".repeat(64)]);
        assert!(!refused_reuse.status.success());
        assert!(
            String::from_utf8_lossy(&refused_reuse.stderr).contains(&format!(
                "strict {label} is candidate-backed and cannot reuse"
            )),
            "phase={phase} stderr={}",
            String::from_utf8_lossy(&refused_reuse.stderr)
        );
        assert_eq!(
            snapshot(),
            before_reuse,
            "{phase} reuse refusal must not mutate Git"
        );
        assert_eq!(
            std::fs::read(sb.dir.join(".mpd/state/sandbox-build.json")).unwrap(),
            ledger_before_reuse,
            "{phase} reuse refusal must not advance or rewrite the strict ledger"
        );
    }
    assert!(
        !marker.exists(),
        "reuse refusal cannot start candidate argv"
    );
    assert!(
        !sb.dir.join(".mpd/build-output").exists(),
        "reuse refusal cannot publish a candidate binding"
    );
    let before_build = snapshot();
    let blocked = sb.mpd(&["gate", "build", "--pass"]);
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("trusted-policy-missing"),
        "stderr={}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(
        !marker.exists(),
        "the Build candidate argv must never begin"
    );
    assert_eq!(snapshot(), before_build, "failed Build must not mutate Git");
    let state: Value = serde_json::from_slice(
        &std::fs::read(sb.dir.join(".mpd/state/sandbox-build.json")).unwrap(),
    )
    .unwrap();
    assert!(
        state["gates"].get("build").is_none(),
        "blocked candidate Build cannot record PASS: {state}"
    );
    assert_eq!(state["phase"], "build");
    let common = stdout(&run(
        "git",
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        &sb.dir,
    ));
    for relative in ["mpd/candidates", "mpd/candidate-records"] {
        let directory = Path::new(common.trim()).join(relative);
        assert!(directory.is_dir());
        assert!(
            directory.read_dir().unwrap().next().is_none(),
            "blocked Build must clean exact candidate storage: {}",
            directory.display()
        );
    }
    assert!(
        !sb.dir.join(".mpd/build-output").exists(),
        "blocked Build cannot leave a candidate-bound output"
    );
}

#[test]
fn pre_push_cli_uses_real_git_field_order_and_rejects_malformed_input() {
    let sb = Sandbox::new("hook-wire");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["tag", "lightweight", "HEAD"], &sb.dir);
    run(
        "git",
        &["tag", "-a", "annotated", "-m", "annotated", "HEAD"],
        &sb.dir,
    );
    let lightweight_oid = stdout(&run("git", &["rev-parse", "lightweight"], &sb.dir))
        .trim()
        .to_string();
    let annotated_oid = stdout(&run("git", &["rev-parse", "annotated"], &sb.dir))
        .trim()
        .to_string();
    let zero = "0".repeat(40);
    let oid = "a".repeat(40);
    let snapshot = || {
        [
            run("git", &["rev-parse", "HEAD"], &sb.dir).stdout,
            run("git", &["diff", "--binary"], &sb.dir).stdout,
            run("git", &["diff", "--cached", "--binary"], &sb.dir).stdout,
            run(
                "git",
                &["for-each-ref", "--format=%(refname)%00%(objectname)"],
                &sb.dir,
            )
            .stdout,
            run("git", &["config", "--local", "--null", "--list"], &sb.dir).stdout,
        ]
    };
    let before = snapshot();
    // The authentic protocol is local-ref/local-oid/remote-ref/remote-oid.
    // Valid syntax reaches the policy blocker; missing LF and extra fields are
    // rejected as protocol errors first rather than being reinterpreted.
    let valid = sb.mpd_input(
        &["hook", "pre-push", "origin", "example.invalid"],
        format!("refs/heads/main {oid} refs/heads/main {zero}\n").as_bytes(),
    );
    assert!(!valid.status.success());
    assert!(
        String::from_utf8_lossy(&valid.stderr).contains("structured local_validation is absent")
    );
    let missing_lf = sb.mpd_input(
        &["hook", "pre-push", "origin", "example.invalid"],
        format!("refs/heads/main {oid} refs/heads/main {zero}").as_bytes(),
    );
    assert!(!missing_lf.status.success());
    assert!(
        String::from_utf8_lossy(&missing_lf.stderr).contains("malformed"),
        "{}",
        String::from_utf8_lossy(&missing_lf.stderr)
    );
    let extra = sb.mpd_input(
        &["hook", "pre-push", "origin", "example.invalid"],
        format!("refs/heads/main {oid} refs/heads/main {zero} extra\n").as_bytes(),
    );
    assert!(!extra.status.success());
    assert!(String::from_utf8_lossy(&extra.stderr).contains("exactly four fields"));

    let delete = sb.mpd_input(
        &["hook", "pre-push", "origin", "example.invalid"],
        format!("(delete) {zero} refs/heads/old {oid}\n").as_bytes(),
    );
    assert!(
        !delete.status.success(),
        "deletion-only input must still require active local policy: {}",
        String::from_utf8_lossy(&delete.stderr)
    );
    assert!(
        String::from_utf8_lossy(&delete.stderr).contains("structured local_validation is absent")
    );
    for valid in [
        format!("HEAD~1 {oid} refs/heads/expression {zero}\n"),
        format!(
            "refs/heads/one {oid} refs/heads/one {zero}\n(delete) {zero} refs/heads/old {oid}\n"
        ),
        format!(
            "refs/tags/lightweight {lightweight_oid} refs/tags/lightweight {zero}\nrefs/tags/annotated {annotated_oid} refs/tags/annotated {zero}\n"
        ),
    ] {
        let output = sb.mpd_input(
            &["hook", "pre-push", "origin", "example.invalid"],
            valid.as_bytes(),
        );
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("structured local_validation is absent"));
    }
    for malformed in [
        format!("refs/heads/main\t{oid} refs/heads/main {zero}\n"),
        format!("refs/heads/main {oid}\r refs/heads/main {zero}\n"),
        format!("refs/heads/main {oid}\u{1b} refs/heads/main {zero}\n"),
        format!(
            "refs/heads/main {} refs/heads/main {zero}\n",
            "a".repeat(39)
        ),
        format!("(delete) {oid} refs/heads/main {oid}\n"),
        format!("refs/heads/main {zero} refs/heads/main {oid}\n"),
        format!("refs/heads/main  {oid} refs/heads/main {zero}\n"),
        "\n".to_string(),
    ] {
        let output = sb.mpd_input(
            &["hook", "pre-push", "origin", "example.invalid"],
            malformed.as_bytes(),
        );
        assert!(
            !output.status.success(),
            "accepted malformed input {malformed:?}"
        );
    }
    assert_eq!(
        snapshot(),
        before,
        "pre-push parsing and policy blockers must not mutate Git or source state"
    );
}

#[test]
fn pre_push_isolated_global_hook_and_filter_config_cannot_execute_or_mutate() {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let sb = Sandbox::new("hook-global-config-canary");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    let hook_marker = sb.dir.join("global-hook-executed");
    let filter_marker = sb.dir.join("global-filter-executed");
    let hook_dir = sb.dir.join("ambient-hooks");
    let filter = sb.dir.join("ambient-filter");
    let home = sb.dir.join("isolated-home");
    std::fs::create_dir_all(&hook_dir).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        hook_dir.join("post-checkout"),
        format!("#!/bin/sh\nprintf ran > '{}'\n", hook_marker.display()),
    )
    .unwrap();
    std::fs::write(
        &filter,
        format!(
            "#!/bin/sh\nprintf ran > '{}'\ncat\n",
            filter_marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        std::fs::set_permissions(
            hook_dir.join("post-checkout"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&filter, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let global = sb.dir.join("hostile-global.gitconfig");
    std::fs::write(
        &global,
        format!(
            "[core]\n\thooksPath = {}\n[filter \"canary\"]\n\tsmudge = {}\n\trequired = true\n",
            hook_dir.display(),
            filter.display()
        ),
    )
    .unwrap();
    let before = [
        run("git", &["rev-parse", "HEAD"], &sb.dir).stdout,
        run("git", &["diff", "--binary"], &sb.dir).stdout,
        run("git", &["diff", "--cached", "--binary"], &sb.dir).stdout,
        run(
            "git",
            &["for-each-ref", "--format=%(refname)%00%(objectname)"],
            &sb.dir,
        )
        .stdout,
        run("git", &["config", "--local", "--null", "--list"], &sb.dir).stdout,
    ];
    let oid = stdout(&run("git", &["rev-parse", "HEAD"], &sb.dir))
        .trim()
        .to_string();
    let zero = "0".repeat(oid.len());
    let parent_canary = "mpd-parent-env-secret-canary-should-never-render";
    let mut child = Command::new(env!("CARGO_BIN_EXE_mpd"))
        .args(["hook", "pre-push", "origin", "example.invalid"])
        .current_dir(&sb.dir)
        .env("HOME", &home)
        .env("GIT_CONFIG_GLOBAL", &global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("MPD_PARENT_SECRET_CANARY", parent_canary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("refs/heads/main {oid} refs/heads/main {zero}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("structured local_validation is absent")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(parent_canary));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(parent_canary));
    assert!(!hook_marker.exists());
    assert!(!filter_marker.exists());
    assert_eq!(
        [
            run("git", &["rev-parse", "HEAD"], &sb.dir).stdout,
            run("git", &["diff", "--binary"], &sb.dir).stdout,
            run("git", &["diff", "--cached", "--binary"], &sb.dir).stdout,
            run(
                "git",
                &["for-each-ref", "--format=%(refname)%00%(objectname)"],
                &sb.dir,
            )
            .stdout,
            run("git", &["config", "--local", "--null", "--list"], &sb.dir).stdout,
        ],
        before,
        "ambient global Git configuration must not cause mutation"
    );
}

fn staged_snapshot(sb: &Sandbox) -> (Vec<u8>, Vec<u8>) {
    (
        run("git", &["diff", "--cached", "--binary"], &sb.dir).stdout,
        run("git", &["status", "--porcelain=v2"], &sb.dir).stdout,
    )
}

fn assert_hook_read_only(sb: &Sandbox, before: &(Vec<u8>, Vec<u8>)) {
    assert_eq!(
        staged_snapshot(sb),
        *before,
        "hook must not mutate index or worktree state"
    );
}

fn begin_and_stage_hook_governance(sb: &Sandbox, change: &str) {
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb.mpd(&["begin", change]).status.success());
    // Stage the active change's exact governance postimages. The hook must not
    // use the equivalent worktree files as a fallback authority.
    run(
        "git",
        &[
            "add",
            "openspec/changes",
            ".mpd/config.json",
            ".mpd/state",
            ".mpd/directives",
        ],
        &sb.dir,
    );
}

#[test]
fn pre_commit_fails_closed_on_missing_coordinator_without_mutation() {
    let sb = Sandbox::new("hook-missing-coordinator");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    let before = staged_snapshot(&sb);
    let out = sb.mpd(&["hook", "pre-commit"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no active change coordinator"));
    assert_hook_read_only(&sb, &before);
}

#[test]
fn pre_commit_uses_staged_governance_and_rejects_malformed_config_without_mutation() {
    let sb = Sandbox::new("hook-index-policy");
    begin_and_stage_hook_governance(&sb, "hook-index-policy");
    // An invalid unstaged task plan is deliberately irrelevant: the staged
    // postimage is the hook authority.
    sb.write(
        "openspec/changes/hook-index-policy/tasks.md",
        "Every box is required and has a stable ID\n- [ ] malformed\n",
    );
    let before = staged_snapshot(&sb);
    let pass = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        pass.status.success(),
        "{}",
        String::from_utf8_lossy(&pass.stderr)
    );
    assert_hook_read_only(&sb, &before);

    sb.write(".mpd/config.json", "{ definitely not JSON\n");
    run("git", &["add", ".mpd/config.json"], &sb.dir);
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("staged config is malformed"));
    assert_hook_read_only(&sb, &before);

    sb.write(
        ".mpd/config.json",
        r#"{
  "local_validation": {
    "schema": 2,
    "gates": {
      "build": "profile",
      "security-code": "profile",
      "test": "profile",
      "pre-push": "profile",
      "high-risk-test": "profile"
    },
    "receipts": { "log-count-cap": 1, "log-byte-cap": 1 }
  }
}
"#,
    );
    run("git", &["add", ".mpd/config.json"], &sb.dir);
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr)
        .contains("staged local validation policy is invalid"));
    assert_hook_read_only(&sb, &before);
}

#[test]
fn pre_commit_blocks_governance_rename_without_mutation() {
    let sb = Sandbox::new("hook-governance-rename");
    begin_and_stage_hook_governance(&sb, "hook-governance-rename");
    run(
        "git",
        // This fixture invokes the coordinator directly below. Its baseline
        // commit must not depend on an ambient installed `mpd` binary.
        &[
            "commit",
            "--no-verify",
            "-q",
            "-m",
            "hook governance baseline",
        ],
        &sb.dir,
    );
    run(
        "git",
        &[
            "mv",
            "openspec/changes/hook-governance-rename/tasks.md",
            "openspec/changes/hook-governance-rename/tasks-renamed.md",
        ],
        &sb.dir,
    );
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr)
        .contains("rename/copy of required governance artifact"));
    assert_hook_read_only(&sb, &before);
}

#[test]
fn pre_commit_blocks_governance_deletion_without_mutation() {
    let sb = Sandbox::new("hook-governance-delete");
    begin_and_stage_hook_governance(&sb, "hook-governance-delete");
    run(
        "git",
        &[
            "commit",
            "--no-verify",
            "-q",
            "-m",
            "hook governance baseline",
        ],
        &sb.dir,
    );
    run(
        "git",
        &["rm", "openspec/changes/hook-governance-delete/tasks.md"],
        &sb.dir,
    );
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr)
        .contains("deletion of required governance artifact"));
    assert_hook_read_only(&sb, &before);
}

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
    sb.write(
        "openspec/changes/add-thing/documentation.md",
        "# Documentation\n\n## Purpose\n<!-- … -->\n",
    );

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

    // Two-lens Doc Validation, then final Deploy.
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "doc-validation"
    );
    // Doc Validation spawns both Architect and Designer (deep tier).
    let dv = json(&sb.mpd(&["next", "--harness", "claude-code", "--json"]));
    assert_eq!(dv["persona"], "Architect & Designer");
    assert_eq!(dv["dual"], true);
    sb.mpd(&["gate", "doc-validation", "--pass"]);
    assert_eq!(json(&sb.mpd(&["status", "--json"]))["phase"], "deploy");
    sb.mpd(&["gate", "deploy", "--pass"]);

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

/// SECURITY(plan) Condition 2 (scan-secrets-fail-closed): the wrapper-level
/// unit tests prove `scan_secrets` returns `Err` on a tracked symlink; only a
/// black-box run proves the CALLER blocks instead of swallowing it. A temp
/// repo with a tracked symlink (target existing — else `git_files`' `exists()`
/// filter drops it and this proves nothing) must make non-staged `mpd check`
/// exit non-zero with the fail-closed diagnostic and never print the
/// clean-scan line. The failing scan resolves before external scanners or the
/// test runner, so this stays hermetic.
#[cfg(unix)]
#[test]
fn check_fails_closed_on_tracked_symlink() {
    let sb = Sandbox::new("symlink-fail-closed");
    sb.mpd(&["init"]);
    sb.write("safe.txt", "safe bytes\n");
    run("git", &["add", "safe.txt"], &sb.dir);
    std::os::unix::fs::symlink("safe.txt", sb.dir.join("link.txt")).unwrap();
    run("git", &["add", "link.txt"], &sb.dir);

    // Vacuity guards: git actually tracks the symlink, it is still a symlink
    // on disk, and its target exists (so enumeration retains it).
    let ls = run("git", &["ls-files"], &sb.dir);
    assert!(
        stdout(&ls).lines().any(|l| l == "link.txt"),
        "the symlink must be git-tracked or the scan never sees it: {}",
        stdout(&ls)
    );
    assert!(
        std::fs::symlink_metadata(sb.dir.join("link.txt"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "link.txt must still be a symlink on disk"
    );
    assert!(
        sb.dir.join("safe.txt").is_file(),
        "the symlink target must exist to survive the exists() filter"
    );

    let out = sb.mpd(&["check"]);
    // Exit 2 pins the operational-error path (design D3); findings would be 1,
    // and a clean pass 0 — either of those here means the caller swallowed
    // the scan error.
    assert_eq!(
        out.status.code(),
        Some(2),
        "non-staged check must propagate the scan error as exit 2: stdout={} stderr={}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("built-in secret scan failed closed"),
        "stderr must carry the fail-closed diagnostic: {err}"
    );
    assert!(
        err.contains("non-regular") && err.contains("link.txt"),
        "the diagnostic must name the cause and the offending path: {err}"
    );
    assert!(
        !err.contains("safe bytes"),
        "the diagnostic must never leak file contents: {err}"
    );
    assert!(
        !stdout(&out).contains("Checks passed"),
        "a blocked check must not print the clean-scan line: {}",
        stdout(&out)
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

    gate_mandatory_documentation(&sb, "pretty-thing");
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "deploy");
    assert_eq!(s["ready_to_archive"], false, "{s}");
    assert!(sb.mpd(&["gate", "deploy", "--pass"]).status.success());
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        true
    );

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
fn strict_conditional_and_fail_bind_canonical_verdict_and_condition_evidence() {
    let sb = Sandbox::new("strict-conditional-evidence");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&[
            "begin",
            "strict-conditions",
            "--strict",
            "--fix",
            "--risk",
            "high",
        ])
        .status
        .success());
    sb.write(
        "openspec/changes/strict-conditions/proposal.md",
        "# Proposal\n\nAuthored proposal content.\n",
    );
    // This explicit contract activates canonical Verdict parsing without
    // leaving an open Builder task in the fixture.
    sb.write(
        "openspec/changes/strict-conditions/tasks.md",
        "Every box is required and has a stable ID.\n- [x] 1.1 completed fixture setup\n",
    );

    author_architecture_verdict(&sb, "strict-conditions", "PASS");
    let mismatch = sb.mpd(&[
        "gate",
        "architecture",
        "--conditional",
        "--by",
        "Architect",
        "--condition",
        "close the bounded model gap",
        "--evidence",
        "design.md",
    ]);
    assert!(!mismatch.status.success(), "mismatched verdict must block");
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("Verdict declares PASS"));
    let state = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(state["phase"], "architecture");
    assert!(state["history"].as_array().unwrap().is_empty());

    author_architecture_verdict(&sb, "strict-conditions", "CONDITIONAL PASS");
    let missing_condition = sb.mpd(&["gate", "architecture", "--conditional", "--by", "Architect"]);
    assert!(!missing_condition.status.success());
    assert!(String::from_utf8_lossy(&missing_condition.stderr).contains("at least one --condition"));
    let missing_evidence = sb.mpd(&[
        "gate",
        "architecture",
        "--conditional",
        "--by",
        "Architect",
        "--condition",
        "close the bounded model gap",
    ]);
    assert!(!missing_evidence.status.success());
    assert!(String::from_utf8_lossy(&missing_evidence.stderr).contains("requires --evidence"));
    let escaped_evidence = sb.mpd(&[
        "gate",
        "architecture",
        "--conditional",
        "--by",
        "Architect",
        "--condition",
        "close the bounded model gap",
        "--evidence",
        "../outside.md",
    ]);
    assert!(!escaped_evidence.status.success());
    assert!(String::from_utf8_lossy(&escaped_evidence.stderr).contains("evidence"));

    let evidence_path = sb.dir.join("openspec/changes/strict-conditions/design.md");
    let expected_digest = format!(
        "{:x}",
        Sha256::digest(std::fs::read(&evidence_path).unwrap())
    );
    let conditional = sb.mpd(&[
        "gate",
        "architecture",
        "--conditional",
        "--by",
        "Architect",
        "--condition",
        "close the bounded model gap",
        "--evidence",
        "design.md#verdict",
    ]);
    assert!(
        conditional.status.success(),
        "{}",
        String::from_utf8_lossy(&conditional.stderr)
    );
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/strict-conditions.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["gates"]["architecture"]["verdict"],
        "conditional-pass"
    );
    assert_eq!(
        state["conditions"][0]["events"][0]["evidence"],
        "design.md#verdict"
    );
    assert_eq!(
        state["conditions"][0]["events"][0]["evidence_digest"],
        expected_digest
    );

    let fail_mismatch = sb.mpd(&[
        "gate",
        "architecture",
        "--fail",
        "--by",
        "Architect",
        "--class",
        "product",
    ]);
    assert!(
        !fail_mismatch.status.success(),
        "FAIL must match artifact Verdict"
    );
    assert!(String::from_utf8_lossy(&fail_mismatch.stderr)
        .contains("Verdict declares CONDITIONAL PASS"));
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["history"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    author_architecture_verdict(&sb, "strict-conditions", "FAIL");
    let fail = sb.mpd(&[
        "gate",
        "architecture",
        "--fail",
        "--by",
        "Architect",
        "--class",
        "product",
    ]);
    assert!(
        fail.status.success(),
        "{}",
        String::from_utf8_lossy(&fail.stderr)
    );
    let state = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(state["history"].as_array().unwrap().len(), 2);
    assert_eq!(state["history"][1]["record"]["verdict"], "fail");
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
    // CONDITIONAL remains on Security-plan; downstream gates are forbidden until
    // the obligation has evidence and Security records a fresh PASS.
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(s["phase"], "security-plan");
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

    // Close the condition with an actor and evidence. A fresh PASS is still
    // required; resolving an obligation never advances a judgment gate.
    let state_path = sb.dir.join(".mpd/state/risky-thing.json");
    let before: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(before["conditions"][0]["closed"], false);
    let out = sb.mpd(&[
        "resolve",
        "1",
        "--by",
        "Security",
        "--evidence",
        "security-plan.md",
    ]);
    assert!(
        out.status.success(),
        "resolve should close condition #1: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
    let after: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(after["conditions"][0]["closed"], true);

    assert!(sb
        .mpd(&["reconcile", "--continue", "condition evidence closed"])
        .status
        .success());
    let fresh_security = sb.mpd(&["gate", "security-plan", "--pass"]);
    assert!(
        fresh_security.status.success(),
        "{}",
        String::from_utf8_lossy(&fresh_security.stderr)
    );
    assert!(sb.mpd(&["gate", "build", "--pass"]).status.success());
    assert!(sb
        .mpd(&["gate", "security-code", "--pass"])
        .status
        .success());
    assert!(sb.mpd(&["gate", "test", "--pass"]).status.success());
    gate_mandatory_documentation(&sb, "risky-thing");
    assert!(sb.mpd(&["gate", "deploy", "--pass"]).status.success());

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

fn author_doc_validation(sb: &Sandbox, change: &str) {
    sb.write(
        &format!("openspec/changes/{change}/doc-validation.md"),
        "# Documentation validation\n\n## Architect lens\nThe documentation matches the implemented scope and architecture.\n\n\
         ## Designer lens\nThe documentation is understandable and presents the operator path clearly.\n\n\
         ## Verdict\nPASS\n",
    );
}

fn author_mandatory_documentation(sb: &Sandbox, change: &str) {
    sb.write(
        &format!("openspec/changes/{change}/documentation.md"),
        "# Change documentation\n\n## Purpose\nRecords the completed change.\n\n\
         ## Value\nMakes the verified behavior durable and discoverable.\n\n\
         ## Scope\nCovers this bounded change and no unrelated behavior.\n\n\
         ## Functional details\nDescribes the implemented behavior, validation, and failure handling.\n\n\
         ## Usage\nRun the documented command and verify its reported result.\n",
    );
    author_doc_validation(sb, change);
}

fn gate_mandatory_documentation(sb: &Sandbox, change: &str) {
    author_mandatory_documentation(sb, change);
    for phase in ["documentation", "doc-validation"] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "gate {phase}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
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
    author_mandatory_documentation(sb, change);
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

/// design.md D1/D2 (proportionate-governance): a docs-only declared scope on
/// a deployment-configured repo — both synthetic signals fire under v1 —
/// resolves an honest derived/effective Low at requested Low; the same repo
/// with the scope widened to a genuinely sensitive path stays High, with no
/// suppression marker present. Exercised purely via `mpd status --json`
/// (classification runs on every status read; no gate/sandbox execution
/// needed).
#[test]
fn documentation_only_scope_resolves_low_on_a_deployment_configured_repo_but_mixed_scope_stays_high(
) {
    let sb = Sandbox::new("docs-risk");
    let out = sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    assert!(out.status.success(), "init failed: {}", stdout(&out));
    write_config_with_deploy(&sb, "install reviewed artifact");

    let out = sb.mpd(&["begin", "doc-change", "--risk", "low"]);
    assert!(out.status.success(), "begin failed: {}", stdout(&out));
    // Narrow the fixture-wide "**" scope `Sandbox::mpd` seeds after `begin`
    // down to a pure documentation-only scope.
    sb.write(
        "openspec/changes/doc-change/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"docs/**\", \"openspec/changes/doc-change/**\"],\n  \"shared_paths\": []\n}\n",
    );

    let status = json(&sb.mpd(&["status", "--json"]));
    let risk = &status["risk_assessment"];
    assert_eq!(risk["requested"], "low", "{risk}");
    assert_eq!(risk["derived"], "low", "{risk}");
    assert_eq!(risk["effective"], "low", "{risk}");
    assert_eq!(risk["classifier_version"], 2, "{risk}");
    let reasons: Vec<&str> = risk["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(reasons.contains(&"documentation-only-scope"), "{reasons:?}");
    assert!(
        reasons.contains(&"suppressed:deployment-configured"),
        "{reasons:?}"
    );

    // Widen to a genuinely sensitive path: full v1-identical derivation
    // returns, unsuppressed, and effective goes back to High.
    sb.write(
        "openspec/changes/doc-change/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"docs/**\", \"crates/**\"],\n  \"shared_paths\": []\n}\n",
    );
    let status = json(&sb.mpd(&["status", "--json"]));
    let risk = &status["risk_assessment"];
    assert_eq!(risk["derived"], "high", "{risk}");
    assert_eq!(risk["effective"], "high", "{risk}");
    let reasons: Vec<&str> = risk["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        !reasons.contains(&"documentation-only-scope"),
        "{reasons:?}"
    );
    assert!(reasons.contains(&"deployment-configured"), "{reasons:?}");
}

/// design.md's self-widening risk: a documentation-only change widens its
/// own manifest after Architecture PASS. Classification is recomputed from
/// the live manifest before every effectful command, and `Scope` is an
/// Architecture dependency, so the widened scope stales evidence and rewinds
/// before any further gate can run — never silently keeping the earlier,
/// narrower approval alive.
#[test]
fn a_doc_only_change_widening_its_own_manifest_after_architecture_pass_stales_evidence_and_rewinds()
{
    let sb = Sandbox::new("docs-widen");
    let out = sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    assert!(out.status.success(), "init failed: {}", stdout(&out));
    let out = sb.mpd(&["begin", "doc-widen", "--risk", "low"]);
    assert!(out.status.success(), "begin failed: {}", stdout(&out));
    sb.write(
        "openspec/changes/doc-widen/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"docs/**\", \"openspec/changes/doc-widen/**\"],\n  \"shared_paths\": []\n}\n",
    );
    fill_artifacts(&sb, "doc-widen");

    let out = sb.mpd(&["gate", "architecture", "--pass"]);
    assert!(out.status.success(), "architecture gate: {}", stdout(&out));
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-plan"
    );

    // Widen the manifest to a sensitive path AFTER the Architecture PASS.
    sb.write(
        "openspec/changes/doc-widen/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"docs/**\", \"crates/**\"],\n  \"shared_paths\": []\n}\n",
    );
    let status = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(
        status["effective_phase"], "architecture",
        "widened scope must rewind to Architecture: {status}"
    );
    let reasons: Vec<&str> = status["blocking_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        reasons.iter().any(|r| r.contains("stale evidence")),
        "{reasons:?}"
    );
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

    // A fresh change reaches Security, where `--exploit` (5 `|`-delimited fields) is
    // REQUIRED on every FAIL — absence and malformed values are both refused
    // (Security-plan Finding 1 / Cond 2).
    sb.mpd(&["begin", "security-case", "--risk", "medium"]);
    sb.mpd(&["gate", "architecture", "--pass"]);
    // (a) a Security FAIL with NO --exploit at all is refused (mandatory presence).
    let absent = sb.mpd(&["gate", "security-plan", "--fail", "--class", "product"]);
    assert!(
        !absent.status.success(),
        "a Security FAIL must require --exploit"
    );
    // (b) a malformed --exploit (too few fields) is refused.
    let incomplete = sb.mpd(&[
        "gate",
        "security-plan",
        "--fail",
        "--class",
        "product",
        "--exploit",
        "contributor|modify repository",
    ]);
    assert!(
        !incomplete.status.success(),
        "a 2-field --exploit must be refused"
    );
    // (c) a blank field is refused.
    let blank = sb.mpd(&[
        "gate",
        "security-plan",
        "--fail",
        "--class",
        "product",
        "--exploit",
        "contributor|modify repository|terminal renderer||strip controls",
    ]);
    assert!(
        !blank.status.success(),
        "a blank --exploit field must be refused"
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["history"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "none of the refused FAILs recorded a gate event"
    );
    // (d) a well-formed --exploit records all five fields.
    let complete = sb.mpd(&[
        "gate",
        "security-plan",
        "--fail",
        "--class",
        "product",
        "--exploit",
        "contributor|modify repository|terminal renderer|misleading output|strip controls",
    ]);
    assert!(
        complete.status.success(),
        "{}",
        String::from_utf8_lossy(&complete.stderr)
    );
    let state = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(state["history"][1]["record"]["attempt"], 1);
    let ex = &state["history"][1]["record"]["exploitability"];
    assert_eq!(ex["attacker"], "contributor");
    assert_eq!(ex["harm"], "misleading output");
    assert_eq!(ex["fix"], "strip controls");
    // A PASS with --class is refused (unchanged).
    assert!(!sb
        .mpd(&["gate", "security-plan", "--pass", "--class", "test"])
        .status
        .success());
    // (e) --exploit outside a Security FAIL (a non-Security phase) is refused.
    assert!(!sb
        .mpd(&[
            "gate",
            "architecture",
            "--fail",
            "--class",
            "product",
            "--exploit",
            "someone|cap|bound|harm|fix",
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
    // The marker is an external deployment receipt, not a product source file.
    // Declare the actual change scope explicitly so creating that receipt does
    // not (correctly) look like post-Test source drift.
    sb.write(
        "openspec/changes/shippable/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"openspec/**\"],\n  \"shared_paths\": []\n}\n",
    );

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
    gate_mandatory_documentation(&sb, "shippable");

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
    gate_mandatory_documentation(&sb, "broken-deploy");

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
    sb.mpd(&["begin", "no-deploy", "--fix"]);
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
    gate_mandatory_documentation(&sb, "no-deploy");
    let out = sb.mpd(&["gate", "deploy", "--pass"]);
    assert!(
        out.status.success(),
        "deploy gate must pass with no deploy configured: {}\n{}",
        stdout(&out),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn strict_build_refuses_legacy_test_config_until_local_validation_is_migrated() {
    let sb = Sandbox::new("strict-local-validation-migration");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "migration-required", "--strict", "--fix"]);
    author_judgment(&sb, "migration-required", "architecture");
    assert_gate_ok(&sb, "architecture");
    author_judgment(&sb, "migration-required", "security-plan");
    assert_gate_ok(&sb, "security-plan");

    let blocked = sb.mpd(&["gate", "build", "--pass"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("local_validation migration"));
    assert_eq!(json(&sb.mpd(&["status", "--json"]))["phase"], "build");
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
    let out = sb.mpd(&[
        "resolve",
        "1",
        "--all",
        "--by",
        "Security",
        "--evidence",
        "security-plan.md",
    ]);
    assert!(!out.status.success(), "index + --all must be rejected");
    assert!(String::from_utf8_lossy(&out.stderr).contains("not both"));
    let out = sb.mpd(&[
        "resolve",
        "--by",
        "Security",
        "--evidence",
        "security-plan.md",
    ]);
    assert!(
        !out.status.success(),
        "no index and no --all must be rejected"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("--all"));
    // Out-of-range index is rejected and mutates nothing.
    let out = sb.mpd(&[
        "resolve",
        "9",
        "--by",
        "Security",
        "--evidence",
        "security-plan.md",
    ]);
    assert!(!out.status.success(), "out-of-range index must be rejected");
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        false,
        "still two open conditions"
    );

    // Close one by index, then the rest with --all → ready.
    assert!(sb
        .mpd(&[
            "resolve",
            "1",
            "--by",
            "Security",
            "--evidence",
            "security-plan.md"
        ])
        .status
        .success());
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["ready_to_archive"],
        false,
        "one condition still open"
    );
    let out = sb.mpd(&[
        "resolve",
        "--all",
        "--by",
        "Security",
        "--evidence",
        "security-plan.md",
    ]);
    assert!(out.status.success(), "resolve --all: {}", stdout(&out));
    assert!(
        stdout(&out).contains("All conditions closed"),
        "stdout: {}",
        stdout(&out)
    );
    assert!(sb
        .mpd(&["reconcile", "--continue", "condition evidence closed"])
        .status
        .success());
    let fresh_security = sb.mpd(&["gate", "security-plan", "--pass"]);
    assert!(
        fresh_security.status.success(),
        "{}",
        String::from_utf8_lossy(&fresh_security.stderr)
    );
    assert!(sb.mpd(&["gate", "build", "--pass"]).status.success());
    assert!(sb
        .mpd(&["gate", "security-code", "--pass"])
        .status
        .success());
    assert!(sb.mpd(&["gate", "test", "--pass"]).status.success());
    gate_mandatory_documentation(&sb, "conds");
    assert!(sb.mpd(&["gate", "deploy", "--pass"]).status.success());
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
    // A defect fix skips only Design; documentation and validation still run.
    sb.mpd(&["begin", "heal-me", "--fix"]);
    fill_artifacts(&sb, "heal-me");
    for p in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "documentation",
        "doc-validation",
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
    author_doc_validation(&sb, "feat-b");
    sb.mpd(&["gate", "doc-validation", "--pass"]);
    sb.mpd(&["gate", "deploy", "--pass"]);
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
    let out = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--by",
        "Security-code reviewer",
    ]);
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
fn typed_deploy_paths_stay_ignored_in_a_linked_worktree() {
    let sb = Sandbox::new("linked-worktree-deploy-paths");
    let linked =
        std::env::temp_dir().join(format!("mpd-e2e-linked-worktree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&linked);
    run(
        "git",
        &[
            "worktree",
            "add",
            "--detach",
            linked.to_str().unwrap(),
            "HEAD",
        ],
        &sb.dir,
    );
    let initialized = Command::new(env!("CARGO_BIN_EXE_mpd"))
        .args(["init", "--test", PASSING_TEST_CMD])
        .current_dir(&linked)
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    run("git", &["add", ".mpd", "openspec"], &linked);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "tracked mpd state"],
        &linked,
    );
    let git_file = std::fs::read_to_string(linked.join(".git")).unwrap();
    assert!(
        git_file.starts_with("gitdir: "),
        "linked worktree must use .git file"
    );
    std::fs::create_dir_all(linked.join(".mpd/build-output")).unwrap();
    std::fs::create_dir_all(linked.join(".mpd/local/bin")).unwrap();
    std::fs::write(linked.join(".mpd/build-output/mpd"), b"built bytes").unwrap();
    std::fs::write(linked.join(".mpd/local/bin/mpd"), b"installed bytes").unwrap();
    let status = run("git", &["status", "--porcelain"], &linked);
    assert!(
        status.stdout.is_empty(),
        "typed Deploy paths must not dirty a linked worktree: {}",
        String::from_utf8_lossy(&status.stdout)
    );
    run(
        "git",
        &["worktree", "remove", "--force", linked.to_str().unwrap()],
        &sb.dir,
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
    // High allows the deliberately required second pass through invalidated
    // gates without an unrelated attempt-limit reconciliation obscuring this
    // freshness regression.
    sb.mpd(&["begin", "stubby", "--fix", "--risk", "high"]);
    write_thing_spec(&sb, "stubby");
    // Walk every gate WITHOUT filling proposal/design/tasks — they stay the
    // template stubs `begin` seeded. Documentation is independently authored
    // because it is mandatory even for this fix.
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        assert!(sb.mpd(&["gate", phase, "--pass"]).status.success());
    }
    gate_mandatory_documentation(&sb, "stubby");
    assert!(sb.mpd(&["gate", "deploy", "--pass"]).status.success());
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
    // Filling Architecture artifacts after downstream PASS evidence makes that
    // evidence stale. Status projects the rewind without mutating; the next
    // effectful command records it, then every invalidated gate must rerun.
    fill_artifacts(&sb, "stubby");
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["effective_phase"],
        "architecture"
    );
    assert!(!sb.mpd(&["next"]).status.success());
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
    ] {
        assert!(sb.mpd(&["gate", phase, "--pass"]).status.success());
    }
    gate_mandatory_documentation(&sb, "stubby");
    assert!(sb.mpd(&["gate", "deploy", "--pass"]).status.success());
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
            "--exploit",
            "contributor|modify source|secret handling|credential exposure|remove credential",
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
    run(
        "git",
        &[
            "add",
            "openspec/changes/scoped",
            ".mpd/config.json",
            ".mpd/state",
            ".mpd/directives",
            "outside.txt",
        ],
        &sb.dir,
    );
    let before = run("git", &["diff", "--cached", "--name-only"], &sb.dir);
    let check = sb.mpd(&["hook", "pre-commit"]);
    assert!(!check.status.success());
    assert!(
        String::from_utf8_lossy(&check.stderr).contains("outside active manifest scope"),
        "stderr={}",
        String::from_utf8_lossy(&check.stderr)
    );
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
        !reused.status.success(),
        "a receipt cannot record a prior phase twice"
    );
    assert!(String::from_utf8_lossy(&reused.stderr).contains("current phase is Security"));

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
        "documentation",
        "doc-validation",
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
        "documentation",
        "doc-validation",
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
        "documentation",
        "doc-validation",
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
    // Keep initialization scaffolding out of the later closure diff. The test
    // invokes the coordinator directly, so this fixture baseline deliberately
    // bypasses any ambient installed hook binary.
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "closure hook baseline"],
        &sb.dir,
    );
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
        "documentation",
        "doc-validation",
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
    // once archived (cli.rs cmd_archive clears `.mpd/current`); pre-commit must
    // still resolve exact index scope via the pending-closure pointer.
    assert!(!sb.dir.join(".mpd/current").exists());

    // Stage exactly the real archived diff plus one genuinely unrelated file.
    run("git", &["add", "-A"], &sb.dir);
    sb.write("unrelated-secret.txt", "not part of this change\n");
    run("git", &["add", "unrelated-secret.txt"], &sb.dir);

    let before = run("git", &["diff", "--cached", "--name-only"], &sb.dir);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    let blocked_stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        blocked_stderr.contains("outside pending closure scope"),
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
    let clean = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
}

#[test]
fn pre_commit_accepts_exact_pending_closure_scope_and_blocks_unrelated_paths() {
    let sb = Sandbox::new("closure-pre-commit-scope");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    // Keep init scaffolding out of the later closure diff. The test invokes the
    // coordinator directly, so its fixture-only baseline commit does not rely
    // on an ambient installed hook binary.
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "hook closure baseline"],
        &sb.dir,
    );
    assert!(sb
        .mpd(&["begin", "hook-closure-thing", "--chore"])
        .status
        .success());
    fill_artifacts(&sb, "hook-closure-thing");
    write_thing_spec(&sb, "hook-closure-thing");
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "documentation",
        "doc-validation",
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
    assert!(!sb.dir.join(".mpd/current").exists());

    // The closure postimage deletes the active change directory; the pending
    // transaction journal, not the deleted manifest, is its narrow authority.
    run(
        "git",
        &["add", "openspec", ".mpd/state", ".mpd/config.json"],
        &sb.dir,
    );
    let before = staged_snapshot(&sb);
    let clean = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_hook_read_only(&sb, &before);

    sb.write(
        "unrelated-closure-file.txt",
        "outside the frozen closure scope\n",
    );
    run("git", &["add", "unrelated-closure-file.txt"], &sb.dir);
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("outside pending closure scope"));
    assert_hook_read_only(&sb, &before);
}

/// Drive a fresh chore change all the way through every gate to
/// `AwaitingCommit` (the state `archive --yes` leaves behind) — the shared
/// setup every archived-closure fallback test below starts from
/// (fix-closure-commit-coherence).
fn drive_change_to_awaiting_commit(sb: &Sandbox, change: &str) {
    assert!(sb.mpd(&["begin", change, "--chore"]).status.success());
    fill_artifacts(sb, change);
    write_thing_spec(sb, change);
    // Commit the change's own WIP state to HEAD before archiving — the
    // realistic shape (a real change accrues commits during Build/Test),
    // and load-bearing here: `archive --yes` moves the active manifest by
    // renaming the change directory. Git's `-M -C` rename detection can only
    // pair that move into a `D`/`R` entry against a path `HEAD` already
    // tracks; an uncommitted manifest simply vanishes from the diff instead
    // (a plain `A` at the new location, no `D`/`R` at the old one), which
    // would make the archived-closure fallback's trigger unforgeable for
    // the wrong reason — it would just never fire.
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &[
            "commit",
            "--no-verify",
            "-q",
            "-m",
            &format!("begin {change}"),
        ],
        &sb.dir,
    );
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "documentation",
        "doc-validation",
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
}

/// design.md Goal 1 / Condition 1 regression: the canonical order (commit
/// BEFORE abandon) must still work through a REAL `git commit` — not just a
/// direct `mpd hook pre-commit` check — proving the untouched AwaitingCommit
/// branch coexists correctly with the new archived-closure fallback arm
/// this change adds to the ELSE branch (fix-closure-commit-coherence).
#[test]
fn correct_flow_closure_commit_succeeds_via_real_git_commit_before_abandon() {
    let sb = Sandbox::new("correct-flow-real-commit");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "correct-flow-thing");

    run("git", &["add", "-A"], &sb.dir);
    let committed = git_commit_through_installed_hook(&sb.dir, "close correct-flow-thing");
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );

    let abandoned = sb.mpd(&["closure", "abandon", "--yes"]);
    assert!(
        abandoned.status.success(),
        "{}",
        String::from_utf8_lossy(&abandoned.stderr)
    );
    assert!(!sb.dir.join(".mpd/pending-closure").exists());
}

/// design.md Goal 1 (the exact footgun this change fixes): a closure commit
/// made AFTER `mpd archive --abandon --yes` must succeed via `mpd use
/// <change>` + a real `git commit` — authorized from the archive record's
/// frozen `system_paths` and its retained Candidate closure plan, with no
/// active manifest anywhere in the index or worktree. Before this change,
/// the ELSE branch hard-errored "active manifest is absent or unreadable in
/// the index" here.
#[test]
fn post_abandon_closure_commit_succeeds_via_use_and_real_git_commit() {
    let sb = Sandbox::new("post-abandon-real-commit");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "post-abandon-thing");

    // The footgun: abandon runs BEFORE the closure commit.
    let abandoned = sb.mpd(&["closure", "abandon", "--yes"]);
    assert!(
        abandoned.status.success(),
        "{}",
        String::from_utf8_lossy(&abandoned.stderr)
    );
    assert!(!sb.dir.join(".mpd/pending-closure").exists());
    assert!(!sb.dir.join(".mpd/current").exists());
    assert!(!sb.dir.join("openspec/changes/post-abandon-thing").exists());

    // Recovery per D5: `mpd use` restores the coordinator pointer. No
    // active manifest is ever re-created.
    let used = sb.mpd(&["use", "post-abandon-thing"]);
    assert!(
        used.status.success(),
        "{}",
        String::from_utf8_lossy(&used.stderr)
    );

    run("git", &["add", "-A"], &sb.dir);
    assert!(!sb
        .dir
        .join("openspec/changes/post-abandon-thing/manifest.json")
        .exists());

    let hook = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        hook.status.success(),
        "fallback must authorize the post-abandon closure commit: {}",
        String::from_utf8_lossy(&hook.stderr)
    );

    let committed = git_commit_through_installed_hook(&sb.dir, "close post-abandon-thing");
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
}

/// Condition 6: even under the fallback arm, every staged path — including
/// one entirely unrelated to the archived closure — must still pass the
/// coverage check. The fallback supplies an authorized scope; it never
/// skips the check.
#[test]
fn post_abandon_fallback_blocks_staged_path_outside_archived_scope() {
    let sb = Sandbox::new("post-abandon-outside-scope");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "outside-scope-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(sb.mpd(&["use", "outside-scope-thing"]).status.success());

    run("git", &["add", "-A"], &sb.dir);
    sb.write(
        "unrelated-post-abandon.txt",
        "outside the frozen archive scope\n",
    );
    run("git", &["add", "unrelated-post-abandon.txt"], &sb.dir);

    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        stderr.contains("outside archived closure scope"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("unrelated-post-abandon.txt"),
        "stderr={stderr}"
    );
    assert_hook_read_only(&sb, &before);

    // Unstaging the unrelated file lets the real archived diff alone
    // through.
    run(
        "git",
        &["restore", "--staged", "unrelated-post-abandon.txt"],
        &sb.dir,
    );
    let clean = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
}

/// Security-plan Condition 10: when the staged diff removes the resolved
/// change's own active manifest but its ledger carries NO archive record
/// (the ordinary in-progress case — nothing has ever been archived), the
/// ordinary path must run byte-identical and block via its existing
/// protected-artifact check — the exact same message as before this change,
/// never a fallback-specific reason, and never a silent fall-through.
#[test]
fn in_progress_change_deleting_own_manifest_without_archive_record_blocks_as_today() {
    let sb = Sandbox::new("in-progress-no-record");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    assert!(sb
        .mpd(&["begin", "in-progress-thing", "--chore"])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "in-progress baseline"],
        &sb.dir,
    );

    run(
        "git",
        &[
            "rm",
            "-q",
            "openspec/changes/in-progress-thing/manifest.json",
        ],
        &sb.dir,
    );

    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr)
            .contains("deletion of required governance artifact"),
        "stderr={}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert_hook_read_only(&sb, &before);
}

/// Security-plan Condition 4/14, and the Q1/Q4 bypass framing: a resolved
/// change whose OWN manifest deletion is staged and whose ledger claims a
/// Candidate-bound archive record must still be blocked outright — never
/// narrowed to `system_paths` alone — the moment its retained plan cannot
/// be trusted (missing, here — the exact "tampered/rebound plan" fail-
/// closed shape; `archived_closure_fallback_scope_blocks_when_plan_binding_
/// differs_from_record` in `cli.rs` covers the loads-but-mismatches variant
/// directly, which needs a byte-valid on-disk plan this black-box e2e test
/// cannot cheaply fabricate). Also proves Condition 12: a hostile
/// `candidate_id` (the worktree ledger is owner-writable, hence attacker-
/// controlled text under this arm's own threat model) never reaches raw
/// hook output, and long record text is length-bounded.
#[test]
fn post_abandon_fallback_blocks_when_candidate_bound_plan_is_missing_and_sanitizes_hostile_text() {
    let sb = Sandbox::new("post-abandon-missing-plan");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "missing-plan-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(sb.mpd(&["use", "missing-plan-thing"]).status.success());

    let ledger_path = sb.dir.join(".mpd/state/missing-plan-thing.json");
    let mut ledger_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    // The default `--chore` (manual-tier) flow produces a legacy record —
    // `candidate_id` absent. Claim a Candidate binding whose plan was never
    // saved (true for every transaction this legacy flow ever produces),
    // with hostile control bytes + a long tail standing in for the
    // candidate ID — worktree-ledger text this arm's own threat model
    // treats as attacker-controlled.
    assert!(
        ledger_json["archive_closure"]["candidate_id"].is_null(),
        "fixture must start legacy (no Candidate) to meaningfully claim one: {ledger_json}"
    );
    let hostile_candidate_id = format!("EVIL\u{7}\u{1b}[31mMARKER{}", "x".repeat(300));
    ledger_json["archive_closure"]["candidate_id"] = Value::String(hostile_candidate_id);
    let mut rewritten = serde_json::to_vec_pretty(&ledger_json).unwrap();
    rewritten.push(b'\n');
    std::fs::write(&ledger_path, rewritten).unwrap();

    run("git", &["add", "-A"], &sb.dir);
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(stderr.contains("pre-commit blocked"), "stderr={stderr}");
    assert!(stderr.contains("missing or invalid"), "stderr={stderr}");
    assert!(
        !stderr.contains('\u{7}'),
        "raw control byte must never reach hook output: {stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "raw ESC byte must never reach hook output: {stderr}"
    );
    assert!(
        stderr.contains("EVIL"),
        "sanitized hint text should still be present: {stderr}"
    );
    assert!(
        stderr.contains('…'),
        "long record text must be bounded: {stderr}"
    );
    assert_hook_read_only(&sb, &before);
}

/// D2.5: a legacy record whose `system_paths` degrades to empty (recorded
/// before that field existed) must fail closed rather than authorize
/// anything.
#[test]
fn post_abandon_fallback_blocks_on_legacy_record_with_empty_system_paths() {
    let sb = Sandbox::new("post-abandon-empty-system-paths");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "empty-system-paths-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(sb
        .mpd(&["use", "empty-system-paths-thing"])
        .status
        .success());

    let ledger_path = sb.dir.join(".mpd/state/empty-system-paths-thing.json");
    let mut ledger_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    ledger_json["archive_closure"]["system_paths"] = Value::Array(Vec::new());
    let mut rewritten = serde_json::to_vec_pretty(&ledger_json).unwrap();
    rewritten.push(b'\n');
    std::fs::write(&ledger_path, rewritten).unwrap();

    run("git", &["add", "-A"], &sb.dir);
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("no concrete recorded scope"),
        "stderr={}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert_hook_read_only(&sb, &before);
}

/// D2.6: a legacy (pre-Candidate) archive record — `candidate_id` absent —
/// must authorize the identical real archived diff from its frozen
/// `system_paths` snapshot alone; no plan is ever consulted. The manual
/// (non-`--strict`) tier this test drives never retains a Build Candidate,
/// so its archive record is legacy-shaped by construction — asserted
/// explicitly here rather than assumed.
#[test]
fn post_abandon_fallback_authorizes_from_legacy_record_with_candidate_id_none() {
    let sb = Sandbox::new("post-abandon-legacy-candidate-none");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "legacy-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(sb.mpd(&["use", "legacy-thing"]).status.success());

    let ledger_path = sb.dir.join(".mpd/state/legacy-thing.json");
    let ledger_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    assert!(
        ledger_json["archive_closure"]["candidate_id"].is_null(),
        "manual-tier archive must be legacy-shaped (no Candidate binding): {ledger_json}"
    );
    assert!(
        !ledger_json["archive_closure"]["system_paths"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the frozen concrete footprint must be non-empty: {ledger_json}"
    );

    run("git", &["add", "-A"], &sb.dir);
    let hook = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        hook.status.success(),
        "legacy candidate_id:None record must authorize from system_paths alone: {}",
        String::from_utf8_lossy(&hook.stderr)
    );
}

/// Condition 1/7 regression: an ordinary in-progress commit — including
/// deleting a DIFFERENT change's stray manifest that this change's own
/// manifest declares verbatim in scope (the real
/// candidate-lifecycle-defects/proportionate-governance shape this fix
/// targets) — must be byte-identical to today. The archived-closure
/// fallback never engages here: the staged manifest deletion belongs to a
/// foreign change, not the resolved coordinator's own `manifest_path`.
#[test]
fn ordinary_in_progress_commit_regression_with_foreign_stray_deletion_in_scope() {
    let sb = Sandbox::new("ordinary-foreign-stray");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    sb.write(
        "openspec/changes/stray-change/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"**\"],\n  \"shared_paths\": []\n}\n",
    );
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline with stray"],
        &sb.dir,
    );

    assert!(sb
        .mpd(&["begin", "cleanup-thing", "--chore"])
        .status
        .success());
    // Declare the stray path verbatim in THIS change's own scope, mirroring
    // the real fix-closure-commit-coherence manifest.
    sb.write(
        "openspec/changes/cleanup-thing/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"openspec/changes/cleanup-thing/**\", \"openspec/changes/stray-change/manifest.json\"],\n  \"shared_paths\": []\n}\n",
    );
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "cleanup-thing begin"],
        &sb.dir,
    );

    run(
        "git",
        &["rm", "-q", "openspec/changes/stray-change/manifest.json"],
        &sb.dir,
    );
    let before = staged_snapshot(&sb);
    let clean = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        clean.status.success(),
        "deleting a foreign stray within this change's declared scope must still pass: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_hook_read_only(&sb, &before);

    // The SAME resolved change's own manifest deletion, with no archive
    // record, still blocks exactly as today (Condition 1's byte-identical
    // guarantee) — the two behaviors must never interfere with each other.
    run(
        "git",
        &["rm", "-q", "openspec/changes/cleanup-thing/manifest.json"],
        &sb.dir,
    );
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr)
            .contains("deletion of required governance artifact"),
        "stderr={}",
        String::from_utf8_lossy(&blocked.stderr)
    );
}

/// D5 / task 4.6: when there is no resolvable coordinator at all (post-
/// abandon, before `mpd use`) and the staged diff is closure-shaped (it
/// removes some change's own active manifest), the pre-commit message must
/// name that change and point at the exact recovery command — never the
/// bare generic "no active change coordinator" alone, and never `mpd
/// archive --recover` (which requires the pointer `abandon` already
/// deleted).
#[test]
fn pre_commit_guidance_names_change_when_no_coordinator_for_closure_shaped_diff() {
    let sb = Sandbox::new("no-coordinator-guidance");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "no-coordinator-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(!sb.dir.join(".mpd/current").exists());

    // Stage the real archived diff WITHOUT ever running `mpd use` — there
    // is no resolvable coordinator at all.
    run("git", &["add", "-A"], &sb.dir);
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        stderr.contains("no active change coordinator"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("mpd use no-coordinator-thing"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("archive --abandon --yes"),
        "stderr={stderr}"
    );
    assert!(!stderr.contains("archive --recover"), "stderr={stderr}");
    assert_hook_read_only(&sb, &before);
}

/// Security-code independent review, pinned as a regression: the fallback
/// trigger is structurally unforgeable AFTER the closure commit lands. The
/// archive record and the `mpd use` coordinator pointer both survive the
/// landing, so if the trigger were replayable the record would authorize
/// smuggling arbitrary content into its frozen footprint forever. It is
/// not: `git diff --cached` reports a `D` only for a path HEAD tracks, the
/// landed commit removed the active manifest from HEAD, and `git rm` cannot
/// even stage the deletion — so a post-landing commit always falls to the
/// ordinary path and blocks on the absent manifest.
#[test]
fn post_landing_fallback_trigger_cannot_be_reforged_for_archived_scope_smuggling() {
    let sb = Sandbox::new("post-landing-replay");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "post-landing-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(sb.mpd(&["use", "post-landing-thing"]).status.success());

    // Land the closure commit through the real installed hook (the fallback
    // authorizes exactly once, from the record+plan pair).
    run("git", &["add", "-A"], &sb.dir);
    let committed = git_commit_through_installed_hook(&sb.dir, "close post-landing-thing");
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );

    // The replay preconditions deliberately survive: the coordinator still
    // names the archived change and its ledger still carries the archive
    // record. Only the trigger is gone.
    assert_eq!(
        std::fs::read_to_string(sb.dir.join(".mpd/current"))
            .unwrap()
            .trim(),
        "post-landing-thing"
    );
    let ledger_json: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.dir.join(".mpd/state/post-landing-thing.json")).unwrap(),
    )
    .unwrap();
    assert!(
        ledger_json["archive_closure"].is_object(),
        "the archive record must still exist for the replay attempt to be meaningful: {ledger_json}"
    );

    // Forging the trigger signature is impossible: the manifest is absent
    // from HEAD, so no `D` of it can be staged at all.
    let forge = run(
        "git",
        &[
            "rm",
            "-q",
            "openspec/changes/post-landing-thing/manifest.json",
        ],
        &sb.dir,
    );
    assert!(
        !forge.status.success(),
        "a D of a non-HEAD path must be unstageable: {}",
        String::from_utf8_lossy(&forge.stderr)
    );

    // Stage smuggled content INSIDE the frozen footprint (the dated archive
    // directory is a prefix entry in `system_paths`, so a replayed fallback
    // WOULD cover it). The hook must fall to the ordinary path and block on
    // the absent manifest — never re-authorize from the record.
    let archive_dir = std::fs::read_dir(sb.dir.join("openspec/changes/archive"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().into_string().unwrap())
        .find(|name| name.ends_with("-post-landing-thing"))
        .expect("landed archive directory exists");
    sb.write(
        &format!("openspec/changes/archive/{archive_dir}/smuggled-after-landing.txt"),
        "content the frozen footprint would cover under a replayed fallback\n",
    );
    run(
        "git",
        &[
            "add",
            &format!("openspec/changes/archive/{archive_dir}/smuggled-after-landing.txt"),
        ],
        &sb.dir,
    );

    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        !blocked.status.success(),
        "post-landing staged content must never be authorized from the archive record"
    );
    assert!(
        String::from_utf8_lossy(&blocked.stderr)
            .contains("active manifest is absent or unreadable in the index"),
        "stderr={}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert_hook_read_only(&sb, &before);
}

/// The §1 footprint-replay containment, gate-side: even under a fully valid
/// fallback trigger (the resolved change's OWN manifest deletion is staged,
/// record+plan bind), the frozen scope never extends to a DIFFERENT
/// change's stray manifest that entered HEAD after the snapshot froze. The
/// fallback supplies a scope; it never grants blanket authority over
/// `openspec/changes/`.
#[test]
fn post_abandon_fallback_blocks_foreign_stray_manifest_deletion_outside_frozen_scope() {
    let sb = Sandbox::new("post-abandon-foreign-stray");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    // `archive --yes` (inside the driver) freezes the concrete scope
    // snapshot HERE — before the foreign stray exists.
    drive_change_to_awaiting_commit(&sb, "replay-source-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(sb.mpd(&["use", "replay-source-thing"]).status.success());

    // A foreign change's stray manifest lands in HEAD AFTER the freeze, so
    // it is outside `system_paths` and outside the plan's post-archive
    // entries. Distinct content on purpose: `-M -C` rename detection must
    // pair the archive move with the change's own manifest, leaving this
    // one a plain `D`.
    sb.write(
        "openspec/changes/foreign-stray/manifest.json",
        "{\n  \"version\": 1,\n  \"paths\": [\"foreign/**\"],\n  \"shared_paths\": []\n}\n",
    );
    run(
        "git",
        &["add", "openspec/changes/foreign-stray/manifest.json"],
        &sb.dir,
    );
    run(
        "git",
        &[
            "commit",
            "--no-verify",
            "-q",
            "-m",
            "foreign stray lands after freeze",
        ],
        &sb.dir,
    );

    // Stage the genuine archived diff (valid trigger) PLUS the foreign
    // stray's deletion — the footprint-replay shape aimed at another
    // change's governance artifact.
    run("git", &["add", "-A"], &sb.dir);
    run(
        "git",
        &["rm", "-q", "openspec/changes/foreign-stray/manifest.json"],
        &sb.dir,
    );

    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        stderr.contains("outside archived closure scope"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("openspec/changes/foreign-stray/manifest.json"),
        "stderr={stderr}"
    );
    assert_hook_read_only(&sb, &before);

    // Unstaging the foreign deletion leaves the genuine archived diff, which
    // the record+plan pair still authorizes — the block was containment, not
    // a broken trigger.
    run(
        "git",
        &[
            "restore",
            "--staged",
            "openspec/changes/foreign-stray/manifest.json",
        ],
        &sb.dir,
    );
    let clean = sb.mpd(&["hook", "pre-commit"]);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
}

/// Security-plan Condition 10, second arm: when the staged diff removes the
/// resolved change's own active manifest but the worktree ledger cannot even
/// be read, the hook must block with its own specific reason — never fall
/// through to the ordinary index-based manifest read, which could disagree
/// with what was just observed in the worktree.
#[test]
fn post_abandon_fallback_blocks_when_worktree_ledger_is_unreadable() {
    let sb = Sandbox::new("post-abandon-unreadable-ledger");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    run("git", &["add", "."], &sb.dir);
    run(
        "git",
        &["commit", "--no-verify", "-q", "-m", "baseline"],
        &sb.dir,
    );

    drive_change_to_awaiting_commit(&sb, "unreadable-ledger-thing");
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());
    assert!(sb.mpd(&["use", "unreadable-ledger-thing"]).status.success());

    // Corrupt the worktree ledger AFTER `mpd use` (which only needs the
    // pointer file) so the fallback's `ledger::load` is the first reader to
    // trip over it.
    std::fs::write(
        sb.dir.join(".mpd/state/unreadable-ledger-thing.json"),
        "not-json{{{\n",
    )
    .unwrap();

    run("git", &["add", "-A"], &sb.dir);
    let before = staged_snapshot(&sb);
    let blocked = sb.mpd(&["hook", "pre-commit"]);
    assert!(!blocked.status.success());
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        stderr.contains("unreadable archive record"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("active manifest is absent"),
        "an unreadable ledger must never fall through to the ordinary index read: {stderr}"
    );
    assert_hook_read_only(&sb, &before);
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
        "documentation",
        "doc-validation",
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
    let (file, actor, sections): (&str, &str, &[&str]) = match phase {
        "architecture" => (
            "design.md",
            "Architect",
            &["Conditions for Builder", "Verdict"],
        ),
        "security-plan" => (
            "security-plan.md",
            "Security-plan reviewer",
            &["Threat model", "Conditions for Builder", "Verdict"],
        ),
        "security-code" => (
            "security-code.md",
            "Security-code reviewer",
            &["Findings", "Conditions verified", "Verdict"],
        ),
        "test" => ("test.md", "Tester", &["Coverage", "Results", "Verdict"]),
        "doc-validation" => (
            "doc-validation.md",
            "Doc validator",
            &["Architect lens", "Designer lens", "Verdict"],
        ),
        other => panic!("author_judgment: unhandled phase {other}"),
    };
    let mut body = format!("# {phase} judgment\n\n## Actor\n\n{actor}\n\n");
    for s in sections {
        if *s == "Verdict" {
            body.push_str(
                "## Verdict\n\nPASS\n\nThe fixture records a canonical passing judgment.\n\n",
            );
        } else {
            body.push_str(&format!(
                "## {s}\n\nReal authored content for the {s} section — substantial enough \
                 to clear the minimum-length floor and carrying no template placeholders \
                 whatsoever.\n\n"
            ));
        }
    }
    sb.write(&format!("openspec/changes/{change}/{file}"), &body);
}

fn author_architecture_verdict(sb: &Sandbox, change: &str, verdict: &str) {
    sb.write(
        &format!("openspec/changes/{change}/design.md"),
        &format!(
            "# Architecture review\n\n## Actor\n\nArchitect\n\n## Conditions for Builder\n\nThis intentionally substantial \n             strict-review artifact binds the complete plan and the stated condition. \n             It contains enough authored text to cross the structural minimum without \n             templates or placeholders.\n\n## Verdict\n\n{verdict}\n"
        ),
    );
}

fn actor_for_phase(phase: &str) -> &'static str {
    match phase {
        "architecture" => "Architect",
        "build" => "Builder",
        "security-plan" => "Security-plan reviewer",
        "security-code" => "Security-code reviewer",
        "test" => "Tester",
        "documentation" => "Documenter",
        "doc-validation" => "Doc validator",
        "deploy" => "Deployer",
        other => panic!("actor_for_phase: unhandled phase {other}"),
    }
}

fn assert_gate_ok(sb: &Sandbox, phase: &str) {
    let out = sb.mpd(&["gate", phase, "--pass", "--by", actor_for_phase(phase)]);
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

/// Drive a fresh strict `--fix` change through Architecture so the next gate is
/// Security(plan). This is the last strict judgment boundary before objective
/// local validation is required, so legacy fixtures can exercise waiver and
/// artifact invariants here without bypassing the migration blocker.
fn strict_to_security_plan(sb: &Sandbox, change: &str, risk: &str) {
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
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-plan"
    );
}

/// As [`strict_to_security_code`], at an explicit risk level (a re-drive after a
/// rewind needs `medium`/`high` so the attempt-2 gates stay within the limit).
fn strict_to_security_code_risk(sb: &Sandbox, change: &str, risk: &str) {
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    // Legacy-only fixtures may exercise strict judgment behavior, but strict
    // objective Build correctly requires structured local_validation. Advance
    // through legacy Build in the manual tier, then promote at Security(code),
    // before the judgment behavior under test.
    assert!(sb
        .mpd(&["begin", change, "--fix", "--risk", risk])
        .status
        .success());
    author_judgment(sb, change, "architecture");
    assert_gate_ok(sb, "architecture");
    author_judgment(sb, change, "security-plan");
    assert_gate_ok(sb, "security-plan");
    // build has no judgment artifact; the passing test command clears it.
    assert_gate_ok(sb, "build");
    assert!(sb.mpd(&["strict", change]).status.success());
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
    strict_to_security_plan(&sb, "guard-me", "low");

    // (1) Refused with no artifact on disk — read_capped("") fails check_sections.
    let bad = sb.mpd(&[
        "gate",
        "security-plan",
        "--pass",
        "--by",
        "Security-plan reviewer",
    ]);
    assert!(
        !bad.status.success(),
        "a missing judgment artifact must refuse the gate"
    );
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(
        err.contains("security-plan.md incomplete"),
        "must fail structurally: {err}"
    );
    // The refusal prints the working escape (Cond 15).
    assert!(
        err.contains("mpd brief security-plan"),
        "no brief escape: {err}"
    );
    assert!(
        !err.contains("--waive-artifact"),
        "strict refusal must not advertise a removed waiver: {err}"
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-plan",
        "a refused gate does not advance"
    );

    // (2) `--evidence smoke` (a non-file pointer) is rejected — the exact CARC hole.
    author_judgment(&sb, "guard-me", "security-plan");
    let smoke = sb.mpd(&[
        "gate",
        "security-plan",
        "--pass",
        "--by",
        "Security-plan reviewer",
        "--evidence",
        "smoke",
    ]);
    assert!(!smoke.status.success(), "--evidence smoke must be rejected");
    assert!(String::from_utf8_lossy(&smoke.stderr).contains("does not exist"));

    // (3) Evidence must be the phase's own artifact, not another real file.
    let alias = sb.mpd(&[
        "gate",
        "security-plan",
        "--pass",
        "--by",
        "Security-plan reviewer",
        "--evidence",
        "design.md",
    ]);
    assert!(
        !alias.status.success(),
        "aliasing another real artifact must be rejected"
    );
    assert!(String::from_utf8_lossy(&alias.stderr).contains("its own artifact"));

    // (4) Passes when authored; omitted evidence defaults to the phase artifact.
    let ok = sb.mpd(&[
        "gate",
        "security-plan",
        "--pass",
        "--by",
        "Security-plan reviewer",
    ]);
    assert!(
        ok.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let st = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(
        st["gates"]["security-plan"]["evidence"], "security-plan.md",
        "omitted --evidence defaults to the phase's own artifact"
    );
}

#[test]
fn strict_gate_exposes_no_artifact_waiver_and_unknown_flag_is_inert() {
    let sb = Sandbox::new("strict-no-waiver");
    strict_to_security_plan(&sb, "no-waiver", "low");
    let help = sb.mpd(&["gate", "--help"]);
    assert!(help.status.success());
    assert!(!stdout(&help).contains("--waive-artifact"));
    let before = std::fs::read(sb.dir.join(".mpd/state/no-waiver.json")).unwrap();
    let refused = sb.mpd(&[
        "gate",
        "security-plan",
        "--pass",
        "--waive-artifact",
        "trust me",
    ]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("unexpected argument"));
    assert_eq!(
        std::fs::read(sb.dir.join(".mpd/state/no-waiver.json")).unwrap(),
        before,
        "removed waiver syntax must have zero ledger effect"
    );
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
    let target = sb.dir.parent().unwrap().join(format!(
        "mpd-e2e-{}-strict-r10-canary.md",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&target);
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
    // Restore the phase artifact first so the explicit evidence-path check is
    // the first failing boundary in this second assertion.
    std::fs::remove_file(&artifact).unwrap();
    author_judgment(&sb, "linky", "security-code");
    // Use a named later-phase process artifact so creating this pointer does
    // not itself constitute product-source drift before the symlink check.
    let ev = sb.dir.join("openspec/changes/linky/test.md");
    symlink(&target, &ev).unwrap();
    let out2 = sb.mpd(&[
        "gate",
        "security-code",
        "--pass",
        "--by",
        "Security-code reviewer",
        "--evidence",
        "test.md",
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
    let _ = std::fs::remove_file(&target);
}

#[test]
fn strict_actor_separation_is_enforced_by_the_real_gate() {
    let sb = Sandbox::new("strict-actor-separation");
    strict_to_security_plan(&sb, "actors", "high");
    author_judgment(&sb, "actors", "security-plan");
    let artifact = sb.dir.join("openspec/changes/actors/security-plan.md");
    let body = std::fs::read_to_string(&artifact).unwrap();
    std::fs::write(
        &artifact,
        body.replace("Security-plan reviewer", "Architect"),
    )
    .unwrap();
    let same = sb.mpd(&["gate", "security-plan", "--pass", "--by", "Architect"]);
    assert!(!same.status.success());
    assert!(String::from_utf8_lossy(&same.stderr).contains("matches"));
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "security-plan"
    );
    author_judgment(&sb, "actors", "security-plan");
    assert_gate_ok(&sb, "security-plan");
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
    assert!(sb
        .mpd(&["gate", "architecture", "--pass", "--by", "Architect"])
        .status
        .success());
    let receipt = json(&sb.mpd(&["status", "--json"]))["gates"]["architecture"]["receipt"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // A receipt may not be replayed against a phase that is no longer current.
    let ok = sb.mpd(&[
        "gate",
        "architecture",
        "--pass",
        "--by",
        "Architect",
        "--reuse",
        &receipt,
    ]);
    assert!(!ok.status.success());
    assert!(String::from_utf8_lossy(&ok.stderr).contains("current phase is Security"));

    // Negative: evaporate the artifact → the reuse path refuses (before any
    // receipt evaluation), with the escape.
    sb.write(
        "openspec/changes/reuse-strict/design.md",
        "# gone\n\nno sections here, no conditions\n",
    );
    let rewind = sb.mpd(&[
        "gate",
        "architecture",
        "--pass",
        "--by",
        "Architect",
        "--reuse",
        &receipt,
    ]);
    assert!(!rewind.status.success());
    assert!(
        String::from_utf8_lossy(&rewind.stderr).contains("rewound Security (plan) to Architecture"),
        "{}",
        String::from_utf8_lossy(&rewind.stderr)
    );
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "architecture"
    );

    // With the stale receipt invalidated and Architecture current again, the
    // reuse path still performs its own structural artifact check.
    let bad = sb.mpd(&[
        "gate",
        "architecture",
        "--pass",
        "--by",
        "Architect",
        "--reuse",
        &receipt,
    ]);
    assert!(
        !bad.status.success(),
        "reuse must not bypass phase ordering"
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
fn release_help_exposes_no_gate_bypass_or_policy_bootstrap() {
    let sb = Sandbox::new("release-surface");
    let gate = sb.mpd(&["gate", "--help"]);
    assert!(gate.status.success());
    let gate_help = stdout(&gate);
    assert!(!gate_help.contains("--waive-artifact"));
    assert!(!gate_help.contains("--autonomous"));

    let policy = sb.mpd(&["policy", "--help"]);
    assert!(policy.status.success());
    let policy_help = stdout(&policy);
    assert!(policy_help.contains("activate"));
    for removed in ["bootstrap", "promote", "pretrust", "first-adoption"] {
        assert!(
            !policy_help.contains(removed),
            "removed policy route leaked: {removed}"
        );
    }
}

#[test]
fn manual_tier_rejects_a_waiver_and_stays_inert() {
    // Removed syntax is inert in the compatibility/manual tier too.
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
    assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected argument"));
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
/// security-plan → build → security-code → test → documentation → doc-validation
/// → final deploy), leaving the phase Done with `ready_to_archive == true`.
/// design.md doubles as the Architecture
/// judgment artifact (it carries `## Conditions for Builder`), so it is authored
/// via `author_judgment` rather than the placeholder-free-but-section-less
/// `fill_artifacts`.
fn strict_fix_to_archive_ready(sb: &Sandbox, change: &str) {
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());
    // Drive the legacy objective gates manually, then promote only for the
    // strict archive recheck. This preserves the archive invariant without
    // weakening the strict Build/Test migration blocker.
    assert!(sb.mpd(&["begin", change, "--fix"]).status.success());
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
    sb.write(
        &format!("openspec/changes/{change}/documentation.md"),
        "# Change documentation\n\n## Purpose\nPurpose.\n\n## Value\nValue.\n\n## Scope\nScope.\n\n## Functional details\nDetails.\n\n## Usage\nUsage.\n",
    );
    assert_gate_ok(sb, "documentation");
    author_judgment(sb, change, "doc-validation");
    assert_gate_ok(sb, "doc-validation");
    assert_gate_ok(sb, "deploy");
    assert!(sb.mpd(&["strict", change]).status.success());
    let s = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(
        s["phase"], "done",
        "a fix is done only after final Deploy: {s}"
    );
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
fn removed_waiver_cannot_bypass_strict_local_validation() {
    let sb = Sandbox::new("archive-r12");
    strict_to_security_plan(&sb, "waive-archive", "low");
    let before = std::fs::read(sb.dir.join(".mpd/state/waive-archive.json")).unwrap();
    let removed = sb.mpd(&[
        "gate",
        "security-plan",
        "--pass",
        "--waive-artifact",
        "trust me",
    ]);
    assert!(!removed.status.success());
    assert_eq!(
        std::fs::read(sb.dir.join(".mpd/state/waive-archive.json")).unwrap(),
        before
    );
    author_judgment(&sb, "waive-archive", "security-plan");
    assert_gate_ok(&sb, "security-plan");
    let blocked = sb.mpd(&["gate", "build", "--pass"]);
    assert!(
        !blocked.status.success(),
        "strict Build must require structured local validation"
    );
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("local_validation migration"));
    assert_eq!(json(&sb.mpd(&["status", "--json"]))["phase"], "build");
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
fn gate_rejects_removed_autonomous_and_waiver_flags_without_state_change() {
    let sb = Sandbox::new("auto-gate");
    strict_to_security_plan(&sb, "sec", "low");
    let before = std::fs::read(sb.dir.join(".mpd/state/sec.json")).unwrap();
    let refused = sb.mpd(&[
        "gate",
        "security-plan",
        "--pass",
        "--autonomous",
        "--waive-artifact",
        "trust me",
    ]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("unexpected argument"));
    assert_eq!(
        std::fs::read(sb.dir.join(".mpd/state/sec.json")).unwrap(),
        before,
        "removed flags must have zero ledger effect"
    );
}

#[test]
fn strict_next_surfaces_human_decision_at_the_attempt_limit() {
    // Task 3.4: a strict change that FAILs its only allowed attempt reaches a
    // reconciliation the harness may not self-authorize; `mpd next` surfaces the
    // human-decision halt rather than silently offering another attempt.
    let sb = Sandbox::new("strict-next-halt");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "limit", "--strict", "--fix", "--risk", "low"]);
    author_architecture_verdict(&sb, "limit", "FAIL");
    let fail = sb.mpd(&[
        "gate",
        "architecture",
        "--fail",
        "--by",
        "Architect",
        "--class",
        "product",
    ]);
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
fn untuned_next_records_risk_once_then_leaves_the_ledger_byte_identical() {
    // Risk assessment is durable gate evidence. The first mutating `next`
    // records it; subsequent render modes are inert when inputs are unchanged.
    let sb = Sandbox::new("pt-inert");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "thing"]);
    let path = sb.dir.join(".mpd/state/thing.json");
    let before = ledger_json(&sb, "thing");
    sb.mpd(&["next"]);
    let after_first = std::fs::read(&path).unwrap();
    let after_json = ledger_json(&sb, "thing");
    assert!(before.get("risk_assessment").is_none());
    assert_eq!(after_json["risk_assessment"]["effective"], "low");
    sb.mpd(&["next", "--json"]);
    sb.mpd(&["next", "--full"]);
    sb.mpd(&["next", "--context"]);
    assert_eq!(
        after_first,
        std::fs::read(&path).unwrap(),
        "unchanged risk/tuning inputs must not rewrite the ledger"
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

    // Current-only transition enforcement rejects replaying a completed phase,
    // even if its persona tuning remains identical.
    let reused = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(!reused.status.success());
    assert!(String::from_utf8_lossy(&reused.stderr).contains("current phase is Build"));
}

#[test]
fn governed_tuning_or_directive_change_stales_reuse_but_unrelated_edit_does_not() {
    // A completed phase cannot be replayed, even after an unrelated config edit.
    // This is stricter than receipt reuse and closes the former future/prior-gate
    // escape; receipt validity itself remains visible in status for audit.
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

    // Control: a prior phase is always rejected rather than being re-recorded.
    let ok = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(!ok.status.success());
    assert!(String::from_utf8_lossy(&ok.stderr).contains("current phase is Build"));
    edit_config(&sb, |v| {
        v["test"] = serde_json::json!("a totally different test command");
        v["models"] = serde_json::json!({"claude-code": {"Builder": "some-other-model"}});
    });
    let blocked = sb.mpd(&["gate", "security-plan", "--pass", "--reuse", &receipt]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("current phase is Build"));
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

// ===================================================================
// simplify-command-surface: the merged/folded verbs (archive --recover/
// --abandon routed before the pending-closure refusal), hidden-but-
// functional `begin`, and the flattened `manifest`.
// ===================================================================

/// Drive a change to the AwaitingCommit pending-closure state (mirrors
/// `closure_recover_and_abandon_via_binary`'s setup).
fn reach_pending_closure(sb: &Sandbox, change: &str) {
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", change, "--fix"]);
    let mpath = sb
        .dir
        .join(format!("openspec/changes/{change}/manifest.json"));
    let mut m: Value = serde_json::from_str(&std::fs::read_to_string(&mpath).unwrap()).unwrap();
    m["paths"] = serde_json::json!(["crates/**"]);
    std::fs::write(&mpath, serde_json::to_string_pretty(&m).unwrap()).unwrap();
    fill_artifacts(sb, change);
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "documentation",
        "doc-validation",
        "deploy",
    ] {
        let out = sb.mpd(&["gate", phase, "--pass"]);
        assert!(
            out.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let archived = sb.mpd(&["archive", "--yes", "--skip-specs"]);
    assert!(
        archived.status.success(),
        "{}",
        String::from_utf8_lossy(&archived.stderr)
    );
    assert!(sb.dir.join(".mpd/pending-closure").is_file());
}

#[test]
fn archive_recover_and_abandon_reach_the_closure_logic_not_the_pending_refusal() {
    // Finding 2 (load-bearing): `mpd archive --recover`/`--abandon` must route to the
    // recovery logic BEFORE cmd_archive's "already pending" early-return — a pending
    // closure is exactly the state they exist for. If the routing sat inside
    // cmd_archive after that refusal, this test would fail with "pending".
    let sb = Sandbox::new("archive-recover");
    reach_pending_closure(&sb, "recover-thing");

    // `archive --recover` (preview) reaches the SAME facts as `closure recover`,
    // NOT the pending refusal.
    let preview = sb.mpd(&["archive", "--recover"]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let text = stdout(&preview);
    assert!(
        text.contains("recover-thing") && text.contains("awaiting-commit"),
        "archive --recover must reach the closure preview, not the pending refusal: {text}"
    );
    let pj = json(&sb.mpd(&["archive", "--recover", "--json"]));
    assert_eq!(pj["change"], "recover-thing");
    assert_eq!(pj["stage"], "awaiting-commit");

    // `archive --abandon --yes` clears the pointer (same as `closure abandon --yes`).
    let abandoned = sb.mpd(&["archive", "--abandon", "--yes"]);
    assert!(
        abandoned.status.success(),
        "{}",
        String::from_utf8_lossy(&abandoned.stderr)
    );
    assert!(!sb.dir.join(".mpd/pending-closure").exists());
}

#[test]
fn archive_recovery_flags_are_mutually_exclusive_and_scoped() {
    // Cond 3 guards: recover XOR abandon; neither with --skip-specs or --change;
    // --json only with recover/abandon.
    let sb = Sandbox::new("archive-guards");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    for (args, why) in [
        (vec!["archive", "--recover", "--abandon"], "recover+abandon"),
        (
            vec!["archive", "--recover", "--skip-specs"],
            "recover+skip-specs",
        ),
        (
            vec!["archive", "--abandon", "--change", "x"],
            "abandon+change",
        ),
        (vec!["archive", "--json"], "json without recover/abandon"),
    ] {
        let out = sb.mpd(&args);
        assert!(!out.status.success(), "{why} must be refused");
    }
}

#[test]
fn begin_is_hidden_but_still_starts_a_manual_change() {
    // D5/Cond 1: `begin` is hidden from --help but fully functional (the manual tier).
    let sb = Sandbox::new("begin-hidden");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    // Hidden = not listed as a command (its name never starts a command-list line);
    // "begin" still appears inside conduct's DESCRIPTION, which is fine.
    let help = stdout(&sb.mpd(&["--help"]));
    assert!(
        !help.lines().any(|l| l.trim_start().starts_with("begin ")),
        "begin must not be listed as a command: {help}"
    );
    assert!(
        sb.mpd(&["begin", "manual-thing"]).status.success(),
        "begin must still work"
    );
    let state = std::fs::read_to_string(sb.dir.join(".mpd/state/manual-thing.json")).unwrap();
    let v: Value = serde_json::from_str(&state).unwrap();
    assert_eq!(
        v["strict"],
        serde_json::json!(false),
        "plain begin is the manual (non-strict) tier"
    );
}

#[test]
fn manifest_is_flattened_and_seeds_the_stub() {
    // D2/Cond 1: `mpd manifest` (no `init` subcommand) seeds the stub — byte-for-byte
    // the old `manifest init`.
    let sb = Sandbox::new("manifest-flat");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["begin", "scoped"]);
    let mpath = sb.dir.join("openspec/changes/scoped/manifest.json");
    std::fs::remove_file(&mpath).unwrap();
    let out = sb.mpd(&["manifest", "--change", "scoped"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(mpath.is_file(), "manifest must seed manifest.json");
    // The old grouped form no longer exists.
    assert!(!sb
        .mpd(&["manifest", "init", "--change", "scoped"])
        .status
        .success());
}

#[test]
fn help_leads_with_the_core_loop() {
    // D1/Cond 4: `mpd --help` surfaces the tiered command guide, core loop first.
    let sb = Sandbox::new("help-tier");
    let help = stdout(&sb.mpd(&["--help"]));
    assert!(
        help.contains("Core loop") && help.contains("conduct"),
        "help must show the Core loop group: {help}"
    );
    assert!(help.contains("Author/govern") && help.contains("Setup/recovery"));
}

#[test]
fn conduct_nudges_toward_high_risk_below_high_but_stays_silent_at_high() {
    // B (sharpen-harness-guidance): `mpd conduct` prints a once-per-change risk-high
    // tip when the conducted change is below high risk, and stays silent at
    // --risk high. Load-bearing: dropping the `rank() < High` guard makes the
    // high-risk case ALSO print the tip, reddening the negative assertion.
    let sb = Sandbox::new("conduct-nudge");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    let low = sb.mpd(&["conduct", "lowrisk", "--chore", "--risk", "low"]);
    assert!(
        stdout(&low).contains("Tip: risk=low") && stdout(&low).contains("full-depth review"),
        "conduct below high must nudge toward --risk high: {}",
        stdout(&low)
    );
    // The nudge must NOT prescribe the (buggy pre-Security) reconcile remedy.
    assert!(
        !stdout(&low).contains("reconcile"),
        "the nudge must not recommend reconcile"
    );
    let high = sb.mpd(&["conduct", "highrisk", "--chore", "--risk", "high"]);
    assert!(
        !stdout(&high).contains("Tip: risk="),
        "conduct at --risk high must NOT print the risk nudge: {}",
        stdout(&high)
    );
}

#[test]
fn reconcile_before_security_does_not_skip_architecture() {
    // reconcile-phase-skip fix: raising risk (or threat-profile) while at Architecture
    // — BEFORE the Security phase — must keep the phase at `architecture`, not jump
    // forward to `security-plan` (which skipped the ungated Architecture gate).
    let sb = Sandbox::new("reconcile-noskip");
    sb.mpd(&["init", "--test", PASSING_TEST_CMD]);
    sb.mpd(&["conduct", "thing", "--fix", "--risk", "low"]);
    assert_eq!(
        json(&sb.mpd(&["status", "--json"]))["phase"],
        "architecture"
    );
    let out = sb.mpd(&["reconcile", "--risk", "high", "novel surface"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(
        after["phase"],
        serde_json::json!("architecture"),
        "reconcile at Architecture must not skip forward to security-plan"
    );
    assert_eq!(after["governance"]["risk"], "high");
}

/// D8: `--introduced-by` validates before anything is created (no ledger, no
/// scaffold, no `.mpd/current` change on an unresolvable target), then a
/// valid link persists, surfaces in `mpd status`, and is grouped by
/// originating change in `mpd stats --json`.
#[test]
fn introduced_by_validates_before_creating_anything_and_surfaces_downstream() {
    let sb = Sandbox::new("introduced-by");
    assert!(sb
        .mpd(&["init", "--test", PASSING_TEST_CMD])
        .status
        .success());

    // `--introduced-by` requires `--fix` at the clap level.
    let requires_fix = sb.mpd(&["begin", "no-fix-flag", "--introduced-by", "whatever"]);
    assert!(!requires_fix.status.success());

    // An unresolvable target fails closed: no ledger, no scaffold, no
    // `.mpd/current` change (Cond 8).
    let rejected = sb.mpd(&[
        "begin",
        "orphan-fix",
        "--fix",
        "--introduced-by",
        "never-archived",
    ]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("never-archived"));
    assert!(!sb.dir.join("openspec/changes/orphan-fix").exists());
    assert!(!sb.dir.join(".mpd/state/orphan-fix.json").exists());
    assert!(!sb.dir.join(".mpd/current").exists());

    // Archive a real change so there is something legitimate to cite.
    assert!(sb
        .mpd(&["begin", "original-feature", "--chore"])
        .status
        .success());
    fill_artifacts(&sb, "original-feature");
    write_thing_spec(&sb, "original-feature");
    for phase in [
        "architecture",
        "security-plan",
        "build",
        "security-code",
        "test",
        "documentation",
        "doc-validation",
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
    // Clear the pending-closure pointer so a new change can begin; the
    // archived ledger content (with `archive_closure` set) stays exactly
    // where the transaction put it.
    assert!(sb.mpd(&["closure", "abandon", "--yes"]).status.success());

    // Now `--introduced-by` resolves against the just-archived change.
    let ok = sb.mpd(&[
        "begin",
        "fix-the-bug",
        "--fix",
        "--introduced-by",
        "original-feature",
    ]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(stdout(&ok).contains("Introduced by: original-feature"));

    let status = json(&sb.mpd(&["status", "--json"]));
    assert_eq!(status["introduced_by"], "original-feature");

    let stats = json(&sb.mpd(&["stats", "--json"]));
    assert_eq!(
        stats["aggregate"]["defect_escapes_by_originating_change"]["original-feature"],
        1
    );
    let fix_row = stats["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["change"] == "fix-the-bug")
        .expect("fix-the-bug row present");
    assert_eq!(fix_row["introduced_by"], "original-feature");
}
