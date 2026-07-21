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

/// All git-tracked files, as absolute paths.
pub fn git_tracked_files(root: &Path) -> Vec<PathBuf> {
    git_files(root, &["ls-files"])
}

fn git_files(root: &Path, args: &[&str]) -> Vec<PathBuf> {
    let output = Command::new("git").args(args).current_dir(root).output();
    let Ok(out) = output else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| root.join(l))
        .filter(|p| p.exists())
        .collect()
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
pub fn scan_secrets(paths: &[PathBuf]) -> SecretReport {
    let findings = secrets::scan_paths(paths).unwrap_or_default();
    SecretReport {
        scanner: "builtin",
        findings,
    }
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
}
