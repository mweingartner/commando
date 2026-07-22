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
    if let Some(clean) = run_gitleaks(root) {
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

const GITLEAKS_DEFAULT_ARGS: &[&str] = &["detect", "--no-banner", "--no-git", "-s", "."];

/// The minimal ephemeral exclusion (D4): extend gitleaks' default ruleset —
/// never replace it — and allowlist only the Rust build-artifact directory,
/// whose bytes gitleaks' own `.gitleaks.toml` resolution otherwise has no way
/// to know are exempt for this repo.
const EPHEMERAL_GITLEAKS_CONFIG: &str =
    "[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['''^target/''', '''/target/''']\n";

/// Run gitleaks, scoping out `target/` UNLESS the repo owns its own
/// `.gitleaks.toml` — gitleaks resolves `(target dir)/.gitleaks.toml`
/// natively, so a repo-owned config is honored byte-identically to before
/// this exclusion existed, no trust change. Otherwise write an ephemeral
/// extend-default config and pass it via `-c`; ANY failure producing that
/// config (temp-file create/write/sync) falls back to the unexcluded scan —
/// degraded exclusion must never become a skipped scan, only a louder one.
fn run_gitleaks(root: &Path) -> Option<bool> {
    if !tool_available("gitleaks") {
        return None;
    }
    if root.join(".gitleaks.toml").exists() {
        return run_tool(root, "gitleaks", GITLEAKS_DEFAULT_ARGS);
    }
    match write_ephemeral_gitleaks_config() {
        Some(config_path) => {
            let config_arg = config_path.to_string_lossy().into_owned();
            let args = [
                "detect",
                "--no-banner",
                "--no-git",
                "-c",
                config_arg.as_str(),
                "-s",
                ".",
            ];
            let result = run_tool(root, "gitleaks", &args);
            let _ = std::fs::remove_file(&config_path);
            result
        }
        None => run_tool(root, "gitleaks", GITLEAKS_DEFAULT_ARGS),
    }
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
            run_gitleaks(&root),
            Some(true),
            "a secret confined to target/ must be excluded, not scanned"
        );

        // The SAME pattern outside target/ must still be caught — the
        // exclusion is scoped to the build-artifact directory only.
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/leak.rs"), fixture_secret_line()).unwrap();
        assert_eq!(
            run_gitleaks(&root),
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
        // repo's OWN `.gitleaks.toml` — the invocation was byte-identical to
        // before this exclusion existed, no `-c` override applied.
        std::fs::write(
            root.join(".gitleaks.toml"),
            "[extend]\nuseDefault = false\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/leak.rs"), fixture_secret_line()).unwrap();
        assert_eq!(
            run_gitleaks(&root),
            Some(true),
            "a repo-owned .gitleaks.toml must govern the scan unmodified"
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
}
