//! Deterministic gate checks: secret scanning and test verification.
//!
//! These back the enforcement gates and the git `pre-commit` hook. External
//! best-of-breed tools (gitleaks, Semgrep) are used when present; the built-in
//! [`secrets`] scanner is the always-available floor so coverage is never zero.

pub mod secrets;
pub mod tests_runner;

use std::path::{Path, PathBuf};
use std::process::Command;

/// Whether an external tool is on `PATH` (probed via `--version`).
pub fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run an external scanner over `root` if it is installed. Returns `None` when
/// the tool is absent, `Some(true)` when it reported clean, `Some(false)` when
/// it reported findings (nonzero exit).
fn run_tool(root: &Path, name: &str, args: &[&str]) -> Option<bool> {
    if !tool_available(name) {
        return None;
    }
    let out = Command::new(name)
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    Some(out.status.success())
}

/// The result of running the available external scanners.
#[derive(Debug, Clone, Default)]
pub struct ExternalScan {
    /// Scanners that actually ran (e.g. `gitleaks`, `semgrep`).
    pub ran: Vec<String>,
    /// Human-readable failure messages from scanners that reported findings.
    pub failures: Vec<String>,
}

/// Run gitleaks and Semgrep over `root` when present. Absent tools are silently
/// skipped (their absence is surfaced by `mpd doctor`, never as a clean pass).
pub fn run_external_scanners(root: &Path) -> ExternalScan {
    let mut scan = ExternalScan::default();
    if let Some(clean) = run_gitleaks(root, ".") {
        scan.ran.push("gitleaks".to_string());
        if !clean {
            scan.failures.push("gitleaks reported findings".to_string());
        }
    }
    if let Some(clean) = run_tool(
        root,
        "semgrep",
        &["--error", "--quiet", "--config", "auto", "."],
    ) {
        scan.ran.push("semgrep".to_string());
        if !clean {
            scan.failures.push("semgrep reported findings".to_string());
        }
    }
    scan
}

/// The minimal ephemeral exclusion (D4): extend gitleaks' default ruleset —
/// never replace it — and allowlist only the Rust build-artifact directory,
/// whose bytes gitleaks' own `.gitleaks.toml` resolution otherwise has no way
/// to know are exempt for this repo.
const EPHEMERAL_GITLEAKS_CONFIG: &str =
    "[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['''^target/''', '''/target/''']\n";

/// Run gitleaks over `source_dir` (repo-relative to `root`; `"."` for the
/// whole worktree, or `openspec/changes/<change>` for the D4 prose lane),
/// ALWAYS passing an explicit `-c` so gitleaks can never resolve
/// `.gitleaks.toml`/`.gitleaksignore` from the scanned SOURCE directory
/// itself (security-plan.md Condition 1) — this matters once `source_dir` is
/// no longer the repo root, where a change author could otherwise plant a
/// rule-disabling config alongside the very prose being scanned. A repo-owned
/// root config is passed as an explicit path (byte-identical governance to
/// gitleaks' own auto-resolution when scanning the repo root, since `-c`
/// names that exact file); otherwise the ephemeral extend-default config is
/// written and passed explicitly. If NEITHER a repo-owned config exists NOR
/// the ephemeral config can be written (temp-file create/write/sync
/// failure), gitleaks is treated as unavailable for this call (`None`)
/// rather than ever being invoked without an explicit `-c` — degraded
/// exclusion must never become a scan that resolves configuration from an
/// arbitrary scanned directory.
pub(crate) fn run_gitleaks(root: &Path, source_dir: &str) -> Option<bool> {
    if !tool_available("gitleaks") {
        return None;
    }
    let repo_config = root.join(".gitleaks.toml");
    // Trust the repo-root config only when it is a genuine regular file:
    // `symlink_metadata` (never `exists()`, which follows symlinks) plus an
    // explicit non-symlink + `is_file()` check, so a symlinked or non-regular
    // `.gitleaks.toml` cannot substitute an attacker-controlled config for the
    // ephemeral extend-default one this function would otherwise write.
    let repo_config_is_trusted = std::fs::symlink_metadata(&repo_config)
        .map(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
        .unwrap_or(false);
    if repo_config_is_trusted {
        let config_arg = repo_config.to_str()?.to_string();
        return run_tool(
            root,
            "gitleaks",
            &[
                "detect",
                "--no-banner",
                "--no-git",
                "-c",
                config_arg.as_str(),
                "-s",
                source_dir,
            ],
        );
    }
    let config_path = write_ephemeral_gitleaks_config()?;
    let config_arg = config_path.to_string_lossy().into_owned();
    let args = [
        "detect",
        "--no-banner",
        "--no-git",
        "-c",
        config_arg.as_str(),
        "-s",
        source_dir,
    ];
    let result = run_tool(root, "gitleaks", &args);
    let _ = std::fs::remove_file(&config_path);
    result
}

/// Write the ephemeral gitleaks config to an unpredictable pid+nonce-named
/// file under the session temp area, created exclusively (`O_EXCL`/
/// `create_new`) with 0600 permissions so a shared-host attacker cannot
/// pre-place or symlink the path to substitute a scan-weakening config
/// (Cond 14). `None` on any failure — create, write, or sync.
fn write_ephemeral_gitleaks_config() -> Option<PathBuf> {
    use std::io::{Read, Write};
    let mut nonce_bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .ok()?
        .read_exact(&mut nonce_bytes)
        .ok()?;
    let nonce: String = nonce_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let path =
        std::env::temp_dir().join(format!("mpd-gitleaks-{}-{nonce}.toml", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options.open(&path).ok()?;
    file.write_all(EPHEMERAL_GITLEAKS_CONFIG.as_bytes()).ok()?;
    file.sync_all().ok()?;
    Some(path)
}

/// All git-tracked files, as absolute paths. Fails closed: any enumeration
/// failure (git spawn failure, non-zero exit, oversized or non-UTF-8 listing)
/// is an `Err` — never an empty, falsely-scannable set. Paths come NUL-delimited
/// (`git ls-files -z` via `crate::git::ls_files`) so unusual name bytes are never
/// quoted or dropped. The single intentional omission is a tracked path with no
/// worktree entry at all (an unstaged deletion or sparse checkout) — no worktree
/// bytes to scan; everything with an lstat entry, including a dangling symlink,
/// is retained for `secrets::scan_paths`'s own fail-closed handling. A repo with
/// zero tracked files legitimately returns `Ok(vec![])` (clean), never an error.
pub fn git_tracked_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let rels =
        crate::git::ls_files(root).map_err(|e| format!("cannot enumerate tracked files: {e}"))?;
    Ok(rels
        .into_iter()
        .map(|rel| root.join(rel))
        .filter(|p| p.symlink_metadata().is_ok()) // lstat-presence, NEVER exists()
        .collect())
}

/// Result of a secret scan.
#[derive(Debug, Clone)]
pub struct SecretReport {
    /// Which scanner produced the result.
    pub scanner: &'static str,
    /// The findings (empty ⇒ clean).
    pub findings: Vec<secrets::Finding>,
}

/// Scan the given files for secrets using the built-in scanner. The report is
/// labeled `builtin` honestly — this is exactly the scanner that produced the
/// findings. External scanners (gitleaks/Semgrep) run separately via
/// [`run_external_scanners`] and are reported as themselves.
///
/// Fails closed: any [`secrets::scan_paths`] error (a symlink or other
/// non-regular tracked path, a file over its size cap, aggregate-size
/// overflow, or an unreadable path) is propagated as `Err` — never collapsed
/// into an empty, falsely-clean report. Callers must treat `Err` as blocking.
pub fn scan_secrets(paths: &[PathBuf]) -> Result<SecretReport, String> {
    let findings = secrets::scan_paths(paths)
        .map_err(|e| format!("built-in secret scan failed closed: {e}"))?;
    Ok(SecretReport {
        scanner: "builtin",
        findings,
    })
}

/// Mirrors `secrets::scan_paths`'s own per-file size cap (that constant is
/// private to the `secrets` module). Kept in sync manually; a divergence
/// only ever makes this lane MORE conservative than `scan_paths`, never
/// less, since both values are `16 * 1024 * 1024`.
const PROSE_ARTIFACT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Scan an already-read, already-validated byte buffer for secrets, without
/// touching disk again. `scan_change_prose` reads and UTF-8-validates each
/// process artifact exactly once; scanning THAT buffer directly (rather than
/// handing `secrets::scan_paths` the path to `fs::read` a second time) closes
/// the TOCTOU where a co-writer with access to the same working tree could
/// swap the file's content between the validating read and a second
/// scanning read (Finding 5; security-plan.md Condition 3/9). Built from
/// `secrets`'s own already-public primitives (`suspicious_filename`,
/// `scan_text`) rather than a new `secrets` API, so filename and content
/// rules stay byte-for-byte identical to `scan_paths`.
fn scan_validated_bytes(path_label: &str, bytes: &[u8]) -> Result<Vec<secrets::Finding>, String> {
    let mut findings = Vec::new();
    if let Some(rule) = secrets::suspicious_filename(Path::new(path_label)) {
        findings.push(secrets::Finding {
            path: path_label.to_string(),
            line: 0,
            rule,
        });
    }
    if bytes.len() as u64 > PROSE_ARTIFACT_MAX_BYTES {
        return Err(format!(
            "secret scanner file exceeds {PROSE_ARTIFACT_MAX_BYTES} byte cap: {path_label}"
        ));
    }
    let text = String::from_utf8_lossy(bytes);
    findings.extend(secrets::scan_text(path_label, &text));
    Ok(findings)
}

/// Scan `change`'s own eleven canonical process artifacts for secrets,
/// enumerated by PATH via [`crate::closure::change_process_artifact_paths`]
/// — never by `git ls-files` — so untracked and uncommitted prose is
/// covered (design.md D4; security-plan.md Conditions 3/6/9). For each
/// artifact: `symlink_metadata`'s `NotFound` is the only stat error that is
/// legitimately skipped (the artifact simply hasn't been authored for this
/// attempt yet); every other stat error blocks. A symlinked artifact is
/// deliberately RETAINED (never skipped) so [`secrets::scan_paths`] fails
/// the scan closed on it below, rather than silently omitting it. Non-UTF-8
/// bytes in a regular-file artifact are a hard refusal here — never a
/// silent content-rules skip the way a lossy conversion would be.
///
/// A regular-file artifact's bytes are read and UTF-8-validated exactly
/// ONCE, then scanned via [`scan_validated_bytes`] against that SAME
/// buffer — never re-read from disk — so a co-writer cannot race a content
/// swap between the validating read and the scan (Finding 5 / TOCTOU).
/// Symlinked artifacts still flow through [`secrets::scan_paths`] (via
/// [`scan_secrets`]) for its own fail-closed non-regular-path refusal,
/// unchanged.
pub fn scan_change_prose(root: &Path, change: &str) -> Result<SecretReport, String> {
    let mut symlinked_paths = Vec::new();
    let mut findings = Vec::new();
    for relative in crate::closure::change_process_artifact_paths(change) {
        let full = root.join(&relative);
        match std::fs::symlink_metadata(&full) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                symlinked_paths.push(full);
            }
            Ok(metadata) if metadata.is_file() => {
                let bytes = std::fs::read(&full).map_err(|e| {
                    format!("cannot read change process artifact {relative:?}: {e}")
                })?;
                std::str::from_utf8(&bytes).map_err(|_| {
                    format!("change process artifact is not valid UTF-8: {relative:?}")
                })?;
                let file_findings = scan_validated_bytes(&full.display().to_string(), &bytes)
                    .map_err(|e| format!("built-in secret scan failed closed: {e}"))?;
                findings.extend(file_findings);
            }
            Ok(_) => {
                return Err(format!(
                    "change process artifact is not a regular file: {relative:?}"
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "cannot inspect change process artifact {relative:?}: {e}"
                ))
            }
        }
    }
    if !symlinked_paths.is_empty() {
        // Never reached with a clean result: `scan_secrets`/`scan_paths`
        // always fails closed on a symlinked path. Kept as a call (not an
        // inline refusal) so this lane matches `scan_secrets`'s own
        // non-regular-path error text exactly.
        scan_secrets(&symlinked_paths)?;
    }
    Ok(SecretReport {
        scanner: "builtin",
        findings,
    })
}

/// Whether `change`'s own directory carries its own `.gitleaks.toml` or
/// `.gitleaksignore`. Presence of either is itself treated as a gate refusal
/// by `cli::enforce_prose_secret_scan` (security-plan.md Condition 1): a
/// change author must never be able to plant a rule-disabling config
/// alongside the prose the D4 lane reviews, even though `run_gitleaks` can no
/// longer be tricked into resolving it via `-s`.
pub fn change_owns_gitleaks_config(root: &Path, change: &str) -> Result<bool, String> {
    let dir = root.join("openspec/changes").join(change);
    for name in [".gitleaks.toml", ".gitleaksignore"] {
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot inspect change directory for {name}: {e}")),
        }
    }
    Ok(false)
}

/// Scan exactly the staged index postimages, never the possibly-different
/// working-tree files. This is the fast pre-commit authority: Git plumbing is
/// read-only and a malformed path/blob makes the caller fail closed.
pub fn scan_staged_postimages(root: &Path) -> Result<SecretReport, String> {
    let mut findings = Vec::new();
    for entry in crate::git::diff_cached_name_status(root)
        .map_err(|e| format!("cannot enumerate staged postimages: {e}"))?
    {
        if !matches!(entry.status, 'A' | 'C' | 'M' | 'R' | 'T') {
            continue;
        }
        let path = entry.path;
        crate::digest::validate_canonical_path(&path)
            .map_err(|_| "unsafe staged path".to_string())?;
        let path_buf = Path::new(&path);
        if let Some(rule) = secrets::suspicious_filename(path_buf) {
            findings.push(secrets::Finding {
                path: path.clone(),
                line: 0,
                rule,
            });
        }
        let blob = crate::git::staged_blob(root, &path)
            .map_err(|_| "cannot read bounded staged postimage".to_string())?;
        if let Ok(text) = std::str::from_utf8(&blob) {
            findings.extend(secrets::scan_text(&path, text));
        }
    }
    Ok(SecretReport {
        scanner: "builtin-staged",
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn gitleaks_fixture_dir(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-gitleaks-fixture-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    // A real gitleaks default-ruleset pattern (a private-key block with a
    // realistic-looking body — gitleaks' default AWS rule specifically
    // recognizes and ignores the well-known "IOSFODNN7EXAMPLE" documentation
    // placeholder, so that shape can't be used as a fixture here). Assembled
    // from split literals so this source file itself contains no contiguous
    // credential pattern (keeps this file's own commit gate from flagging it).
    fn fixture_secret_line() -> String {
        format!(
            "-----BEGIN RSA PRIVATE {}-----\n\
             MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumju4GeuQiCqXNjrdiJn9uz8B\n\
             MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumju4GeuQiCqXNjrdiJn9uz8B\n\
             -----END RSA PRIVATE {}-----\n",
            "KEY", "KEY"
        )
    }

    #[test]
    fn write_ephemeral_gitleaks_config_creates_a_private_extend_default_file() {
        let path = write_ephemeral_gitleaks_config().expect("write ephemeral gitleaks config");
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("useDefault = true"));
        assert!(content.contains("^target/"));
        // Two calls must never collide on the same unpredictable path.
        let second = write_ephemeral_gitleaks_config().unwrap();
        assert_ne!(path, second);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&second).unwrap();
    }

    #[test]
    fn run_gitleaks_excludes_target_but_still_catches_real_secrets_elsewhere() {
        if !tool_available("gitleaks") {
            eprintln!("skipped: gitleaks is not installed in this environment");
            return;
        }
        let root = gitleaks_fixture_dir("exclude-target");
        std::fs::create_dir_all(root.join("target/debug/build")).unwrap();
        std::fs::write(
            root.join("target/debug/build/fake-secret.rs"),
            fixture_secret_line(),
        )
        .unwrap();
        // Only a `target/`-scoped secret exists: the D4 exclusion must make
        // this a clean scan (Cond 9's "louder, never quieter" cuts only one
        // direction — the exclusion itself is intentionally narrow).
        assert_eq!(
            run_gitleaks(&root, "."),
            Some(true),
            "a secret confined to target/ must be excluded, not scanned"
        );

        // The SAME pattern outside target/ must still be caught — the
        // exclusion is scoped to the build-artifact directory only.
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/leak.rs"), fixture_secret_line()).unwrap();
        assert_eq!(
            run_gitleaks(&root, "."),
            Some(false),
            "a real secret outside target/ must still be reported"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn run_gitleaks_defers_to_a_repo_owned_gitleaks_toml_unmodified() {
        if !tool_available("gitleaks") {
            eprintln!("skipped: gitleaks is not installed in this environment");
            return;
        }
        let root = gitleaks_fixture_dir("repo-owned-config");
        // A repo-owned config that disables every default rule and adds none
        // of its own: if the ephemeral extend-default config were used
        // instead, this same fixture secret would be caught (as the sibling
        // test proves). Passing clean here proves gitleaks resolved the
        // repo's OWN `.gitleaks.toml` — an explicit `-c` now always names it,
        // but that is the SAME file gitleaks would have auto-resolved before
        // this generalization, so governance is unchanged.
        std::fs::write(
            root.join(".gitleaks.toml"),
            "[extend]\nuseDefault = false\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/leak.rs"), fixture_secret_line()).unwrap();
        assert_eq!(
            run_gitleaks(&root, "."),
            Some(true),
            "a repo-owned .gitleaks.toml must govern the scan unmodified"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Security(code) Finding 4: a symlinked repo-root `.gitleaks.toml` must
    /// NEVER be trusted — `run_gitleaks` used to decide via `Path::exists`,
    /// which follows symlinks, so a symlink pointing at an attacker-planted
    /// rule-disabling config would be handed to gitleaks as the repo's own
    /// governance. With `symlink_metadata`-based detection the symlink is
    /// refused and the scan falls back to the ephemeral extend-default
    /// config, so the SAME fixture secret that a followed symlink would hide
    /// is still caught.
    #[cfg(unix)]
    #[test]
    fn run_gitleaks_refuses_a_symlinked_repo_root_config_and_falls_back_to_ephemeral() {
        if !tool_available("gitleaks") {
            eprintln!("skipped: gitleaks is not installed in this environment");
            return;
        }
        let root = gitleaks_fixture_dir("symlinked-root-config");
        // A real, rule-disabling config living OUTSIDE the trusted position.
        std::fs::write(root.join("evil.toml"), "[extend]\nuseDefault = false\n").unwrap();
        // `.gitleaks.toml` at the repo root is a SYMLINK to it, not a regular
        // file planted there directly.
        std::os::unix::fs::symlink(root.join("evil.toml"), root.join(".gitleaks.toml")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/leak.rs"), fixture_secret_line()).unwrap();
        assert_eq!(
            run_gitleaks(&root, "."),
            Some(false),
            "a symlinked .gitleaks.toml must be refused, falling back to the \
             ephemeral extend-default config that still catches the fixture secret"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Security-plan.md Condition 1's mechanism-level pin: a `.gitleaks.toml`
    /// planted INSIDE the scanned source directory (not the repo root) must
    /// never blind the scan — `run_gitleaks` must always pass an explicit
    /// `-c`, so gitleaks cannot auto-resolve a config from `source_dir`. This
    /// is the exact shape `checks::scan_change_prose`'s change-directory scan
    /// exposes that a root-only scan (`source_dir = "."`) never could.
    #[test]
    fn run_gitleaks_over_a_subdirectory_ignores_that_subdirectorys_own_config() {
        if !tool_available("gitleaks") {
            eprintln!("skipped: gitleaks is not installed in this environment");
            return;
        }
        let root = gitleaks_fixture_dir("subdir-config-evasion");
        let change_dir = root.join("openspec/changes/example-change");
        std::fs::create_dir_all(&change_dir).unwrap();
        // A rule-disabling config planted alongside the scanned prose, not at
        // the repo root.
        std::fs::write(
            change_dir.join(".gitleaks.toml"),
            "[extend]\nuseDefault = false\n",
        )
        .unwrap();
        std::fs::write(change_dir.join("design.md"), fixture_secret_line()).unwrap();
        assert_eq!(
            run_gitleaks(&root, "openspec/changes/example-change"),
            Some(false),
            "a .gitleaks.toml inside the scanned source directory must not blind the scan"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn staged_scan_reads_index_postimage_not_dirty_worktree() {
        let root = std::env::temp_dir().join(format!(
            "mpd-staged-scan-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "test@example.invalid"],
            vec!["config", "user.name", "test"],
        ] {
            assert!(Command::new("git")
                .args(args)
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        std::fs::write(root.join("input.txt"), "safe staged bytes\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "input.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        std::fs::write(
            root.join("input.txt"),
            "token = \"abc123abc123abc123abc123\"\n",
        )
        .unwrap();
        let report = scan_staged_postimages(&root).unwrap();
        assert!(
            report.findings.is_empty(),
            "dirty worktree bytes must be excluded"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A tracked symlink must fail the built-in scan closed, end-to-end through
    /// the real caller composition (`git_tracked_files` → `scan_secrets`), not
    /// be silently dropped into an empty "clean" report.
    #[cfg(unix)]
    #[test]
    fn scan_secrets_fails_closed_on_tracked_symlink() {
        let root = std::env::temp_dir().join(format!(
            "mpd-symlink-scan-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "test@example.invalid"],
            vec!["config", "user.name", "test"],
        ] {
            assert!(Command::new("git")
                .args(args)
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        std::fs::write(root.join("safe.txt"), "safe bytes\n").unwrap();
        std::os::unix::fs::symlink("safe.txt", root.join("link.txt")).unwrap();
        assert!(Command::new("git")
            .args(["add", "safe.txt", "link.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        let files = git_tracked_files(&root).expect("enumeration must succeed in a real repo");
        assert!(
            files.iter().any(|p| p == &root.join("link.txt")),
            "the tracked symlink (target exists) must survive enumeration, \
             else this test proves nothing: {files:?}"
        );

        let err = scan_secrets(&files).unwrap_err();
        assert!(
            err.contains("non-regular"),
            "error must name the non-regular cause: {err}"
        );
        assert!(
            !err.contains("safe bytes"),
            "error must not leak scanned file content: {err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Shared temp-git-repo fixture for the `git_tracked_files` regression
    /// pins below: an initialized repo with a committer identity configured,
    /// ready for the caller to write/add/commit fixture content.
    fn init_repo_fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "test@example.invalid"],
            vec!["config", "user.name", "test"],
        ] {
            assert!(Command::new("git")
                .args(args)
                .current_dir(&root)
                .status()
                .unwrap()
                .success());
        }
        root
    }

    /// A `.git` FILE (not a directory) pointing at a nonexistent gitdir makes
    /// `git ls-files` exit non-zero deterministically (design D7), without
    /// depending on any outer repo. The enumeration boundary must refuse
    /// rather than fall back to an empty, falsely-clean set.
    #[test]
    fn git_tracked_files_fails_closed_when_git_fails() {
        let root = std::env::temp_dir().join(format!(
            "mpd-broken-git-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".git"), "gitdir: /nonexistent/does-not-exist\n").unwrap();

        let err = git_tracked_files(&root)
            .expect_err("a broken .git must fail closed, never enumerate an empty set");
        assert!(
            err.starts_with("cannot enumerate tracked files"),
            "error must carry the enumeration-boundary prefix: {err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// `git ls-files -z` emits pathnames verbatim; `core.quotepath` governs
    /// only line-mode output (D2). Must FAIL against the pre-fix line-mode
    /// enumeration, which drops any name git's line-mode output quotes.
    #[test]
    fn git_tracked_files_retains_quotepath_quoted_names() {
        let root = init_repo_fixture("quotepath");
        assert!(Command::new("git")
            .args(["config", "core.quotepath", "true"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        let name = "sécrets.txt";
        std::fs::write(root.join(name), "benign fixture bytes\n").unwrap();
        assert!(Command::new("git")
            .args(["add", name])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        // Vacuity guard: line-mode `git ls-files` really does octal-quote this
        // name — else this fixture doesn't exercise quoting and proves nothing.
        let ls = Command::new("git")
            .args(["ls-files"])
            .current_dir(&root)
            .output()
            .unwrap();
        let ls_stdout = String::from_utf8_lossy(&ls.stdout);
        assert!(
            ls_stdout.contains("\\303\\251"),
            "git line-mode output must quote the non-ASCII name: {ls_stdout}"
        );

        let files = git_tracked_files(&root).expect("enumeration must succeed in a real repo");
        assert!(
            files.iter().any(|p| p == &root.join(name)),
            "the quotepath-quoted name must survive -z enumeration verbatim: {files:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A dangling tracked symlink (D4) must be RETAINED by lstat-presence
    /// filtering and fail the scan closed — never dropped by an `exists()`-style
    /// filter, which would let breaking the link silently un-block the gate.
    /// Must FAIL against the pre-fix `exists()` filter.
    #[cfg(unix)]
    #[test]
    fn git_tracked_files_retains_dangling_symlink_and_scan_fails_closed() {
        let root = init_repo_fixture("dangling-symlink");
        std::os::unix::fs::symlink("no-such-target", root.join("gone.txt")).unwrap();
        assert!(Command::new("git")
            .args(["add", "gone.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        let files = git_tracked_files(&root).expect("enumeration must succeed in a real repo");
        assert!(
            files.iter().any(|p| p == &root.join("gone.txt")),
            "a dangling tracked symlink must be retained (lstat-presence, never exists()): {files:?}"
        );
        assert!(
            std::fs::symlink_metadata(root.join("gone.txt"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "gone.txt must still be a symlink on disk"
        );

        let err = scan_secrets(&files).unwrap_err();
        assert!(
            err.contains("non-regular"),
            "error must name the non-regular cause: {err}"
        );
        assert!(
            !err.contains("no-such-target"),
            "error must not leak the dangling symlink's target: {err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A tracked path with no worktree entry at all (an unstaged deletion) is
    /// the single intentional enumeration-time omission (D5): no worktree
    /// bytes to scan, and the name is still covered by the staged and egress
    /// scans. It must be excluded without disturbing sibling tracked paths.
    #[test]
    fn git_tracked_files_skips_worktree_absent_tracked_path() {
        let root = init_repo_fixture("worktree-absent");
        std::fs::write(root.join("a.txt"), "safe bytes a\n").unwrap();
        std::fs::write(root.join("b.txt"), "safe bytes b\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "a.txt", "b.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-q", "-m", "add a.txt and b.txt"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());

        // Unstaged deletion: still tracked (in HEAD and the index), but the
        // worktree entry is gone.
        std::fs::remove_file(root.join("a.txt")).unwrap();

        let files = git_tracked_files(&root).expect("enumeration must succeed in a real repo");
        assert!(
            !files.iter().any(|p| p == &root.join("a.txt")),
            "a worktree-absent tracked path must be omitted: {files:?}"
        );
        assert!(
            files.iter().any(|p| p == &root.join("b.txt")),
            "the sibling tracked path must remain: {files:?}"
        );

        let report = scan_secrets(&files).expect("the remaining regular file set must scan clean");
        assert!(report.findings.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Advisory A2 (security-plan.md): a repo with zero tracked files must
    /// enumerate `Ok(vec![])`, never `Err` — pins that "empty" and "failed" stay
    /// structurally distinct so a future stricter check can't break fresh repos.
    #[test]
    fn git_tracked_files_ok_empty_for_zero_tracked_files() {
        let root = init_repo_fixture("empty-repo");
        let files = git_tracked_files(&root)
            .expect("a clean fresh repo with zero tracked files must enumerate Ok, never Err");
        assert!(
            files.is_empty(),
            "a repo with zero tracked files must enumerate empty: {files:?}"
        );
        let report = scan_secrets(&files).expect("an empty scan set must report clean");
        assert!(report.findings.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Guards against inverting the fail-closed fix: a clean set of regular
    /// files must still report `Ok` with no findings under the `builtin` label.
    #[test]
    fn scan_secrets_reports_clean_on_regular_files() {
        let root = std::env::temp_dir().join(format!(
            "mpd-clean-scan-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("safe.txt");
        std::fs::write(&file, "safe bytes\n").unwrap();

        let report = scan_secrets(&[file]).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.scanner, "builtin");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Table test for the fail-closed invariant across the OTHER error
    /// classes (`scan_paths` can also refuse a missing/unreadable path, a
    /// non-regular directory, and an oversize file — not just a symlink),
    /// and across positions: a bad entry anywhere in the set must yield
    /// `Err`, never a partial "clean" report from the entries before it.
    #[test]
    fn scan_secrets_fails_closed_on_every_error_class_at_any_position() {
        let root = std::env::temp_dir().join(format!(
            "mpd-error-class-scan-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let regulars: Vec<PathBuf> = ["a.txt", "b.txt", "c.txt"]
            .iter()
            .map(|name| {
                let path = root.join(name);
                std::fs::write(&path, "safe bytes\n").unwrap();
                path
            })
            .collect();

        // Control first: the regular set alone is clean, so any `Err` below
        // is attributable to the injected entry, not the fixtures.
        let report = scan_secrets(&regulars).unwrap();
        assert!(report.findings.is_empty());

        // (1) Missing path (TOCTOU: a file can vanish between `git ls-files`
        // enumeration and the scan) — fails closed at EVERY position. The
        // cause is an OS message without the path, so only the wrapper's
        // fixed prefix is asserted.
        let missing = root.join("vanished.txt");
        for position in 0..=regulars.len() {
            let mut set = regulars.clone();
            set.insert(position, missing.clone());
            let err = scan_secrets(&set).unwrap_err();
            assert!(
                err.starts_with("built-in secret scan failed closed:"),
                "missing path at position {position} must fail closed: {err}"
            );
        }

        // (2) A directory is non-regular even where symlinks are unavailable.
        let dir = root.join("subdir");
        std::fs::create_dir(&dir).unwrap();
        let mut set = regulars.clone();
        set.insert(1, dir);
        let err = scan_secrets(&set).unwrap_err();
        assert!(
            err.starts_with("built-in secret scan failed closed:") && err.contains("non-regular"),
            "a directory in the scan set must fail closed as non-regular: {err}"
        );

        // (3) Over the 16 MiB per-file content cap (secrets.rs
        // MAX_FILE_BYTES). `set_len` makes the file sparse — the length check
        // fires before any read, so no bytes are actually written or read.
        let big = root.join("big.txt");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(16 * 1024 * 1024 + 1)
            .unwrap();
        let mut set = regulars.clone();
        set.insert(1, big);
        let err = scan_secrets(&set).unwrap_err();
        assert!(
            err.starts_with("built-in secret scan failed closed:") && err.contains("byte cap"),
            "an oversize file must fail closed on the size cap: {err}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    fn prose_fixture_dir(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mpd-prose-lane-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// security-plan.md Condition 3: only `NotFound` is skipped by
    /// `scan_change_prose`; every other `symlink_metadata` error blocks, and
    /// non-UTF-8 bytes in a regular-file artifact are a hard refusal — never
    /// a silent lossy-conversion content-rules skip.
    #[test]
    fn scan_change_prose_skips_absent_artifacts_but_fails_closed_on_other_errors() {
        let root = prose_fixture_dir("stat-and-encoding");
        let change = "example-change";

        // No artifacts exist at all: clean, not an error.
        let report = scan_change_prose(&root, change).expect("absent artifacts must be skipped");
        assert!(report.findings.is_empty());

        // A change directory that is itself a PLAIN FILE (not a directory)
        // makes every artifact path under it fail `symlink_metadata` with a
        // non-`NotFound` error (ENOTDIR) — must block, not skip.
        std::fs::create_dir_all(root.join("openspec/changes")).unwrap();
        std::fs::write(
            root.join(format!("openspec/changes/{change}")),
            b"not a dir",
        )
        .unwrap();
        let error = scan_change_prose(&root, change).unwrap_err();
        assert!(
            error.contains("cannot inspect change process artifact"),
            "{error}"
        );
        std::fs::remove_file(root.join(format!("openspec/changes/{change}"))).unwrap();

        // Non-UTF-8 bytes in a regular-file artifact are a hard refusal.
        std::fs::create_dir_all(root.join(format!("openspec/changes/{change}"))).unwrap();
        std::fs::write(
            root.join(format!("openspec/changes/{change}/design.md")),
            [0x66, 0x6f, 0x6f, 0xff, 0xfe, 0x0a],
        )
        .unwrap();
        let error = scan_change_prose(&root, change).unwrap_err();
        assert!(
            error.contains("not valid UTF-8") && error.contains("design.md"),
            "{error}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// security-plan.md Condition 3/9: a symlinked process artifact is
    /// RETAINED (never skipped as absent) so the downstream `scan_paths`
    /// call fails the scan closed on it — mirroring the tracked-symlink
    /// fail-closed guarantee `scan_secrets` already provides.
    #[cfg(unix)]
    #[test]
    fn scan_change_prose_retains_a_symlinked_artifact_so_the_scan_fails_closed() {
        let root = prose_fixture_dir("symlinked-artifact");
        let change = "symlink-change";
        std::fs::create_dir_all(root.join(format!("openspec/changes/{change}"))).unwrap();
        std::fs::write(root.join("elsewhere.md"), b"# elsewhere\n").unwrap();
        std::os::unix::fs::symlink(
            root.join("elsewhere.md"),
            root.join(format!("openspec/changes/{change}/design.md")),
        )
        .unwrap();
        let error = scan_change_prose(&root, change).unwrap_err();
        assert!(
            error.contains("non-regular"),
            "a symlinked artifact must fail the scan closed: {error}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Security(code) Finding 5: `scan_validated_bytes` scans EXACTLY the
    /// bytes handed to it — it must never reopen/re-read `path_label` from
    /// disk. A label naming a path that has never existed anywhere on disk
    /// proves this: if the implementation re-read from disk (the TOCTOU
    /// `scan_paths` would otherwise create by reopening between the prose
    /// lane's validating read and its scan), this call would fail on the
    /// missing path; instead it succeeds and finds the secret embedded only
    /// in the in-memory buffer.
    #[test]
    fn scan_validated_bytes_scans_the_given_buffer_never_touching_disk() {
        let never_on_disk = "/this/path/has/never/existed-on-disk/design.md";
        let bytes = fixture_secret_line().into_bytes();
        let findings = scan_validated_bytes(never_on_disk, &bytes)
            .expect("scan_validated_bytes must operate purely on the given buffer, never disk");
        assert!(
            findings.iter().any(|f| f.rule == "private-key-block"),
            "{findings:?}"
        );
        assert!(findings.iter().all(|f| f.path == never_on_disk));
    }

    /// Security(code) Finding 5 (positive path): a real secret embedded in a
    /// regular-file process artifact is still detected end-to-end through
    /// the rewritten byte-threading lane — the TOCTOU fix must never
    /// silently swallow a genuine finding.
    #[test]
    fn scan_change_prose_detects_a_real_secret_in_a_regular_artifact() {
        let root = prose_fixture_dir("real-secret-detected");
        let change = "secret-change";
        std::fs::create_dir_all(root.join(format!("openspec/changes/{change}"))).unwrap();
        std::fs::write(
            root.join(format!("openspec/changes/{change}/design.md")),
            fixture_secret_line(),
        )
        .unwrap();
        let report = scan_change_prose(&root, change)
            .expect("a readable UTF-8 artifact must scan, not fail closed");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "private-key-block"),
            "{:?}",
            report.findings
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// security-plan.md Condition 1: `change_owns_gitleaks_config` detects
    /// either `.gitleaks.toml` or `.gitleaksignore` inside the change
    /// directory, and reports `false` when neither exists.
    #[test]
    fn change_owns_gitleaks_config_detects_either_file_and_is_false_when_absent() {
        let root = prose_fixture_dir("owns-gitleaks-config");
        let change = "config-change";
        std::fs::create_dir_all(root.join(format!("openspec/changes/{change}"))).unwrap();

        assert!(!change_owns_gitleaks_config(&root, change).unwrap());

        std::fs::write(
            root.join(format!("openspec/changes/{change}/.gitleaks.toml")),
            b"[extend]\nuseDefault = false\n",
        )
        .unwrap();
        assert!(change_owns_gitleaks_config(&root, change).unwrap());
        std::fs::remove_file(root.join(format!("openspec/changes/{change}/.gitleaks.toml")))
            .unwrap();
        assert!(!change_owns_gitleaks_config(&root, change).unwrap());

        std::fs::write(
            root.join(format!("openspec/changes/{change}/.gitleaksignore")),
            b"",
        )
        .unwrap();
        assert!(change_owns_gitleaks_config(&root, change).unwrap());

        let _ = std::fs::remove_dir_all(root);
    }
}
