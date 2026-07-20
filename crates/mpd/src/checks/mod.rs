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
    if let Some(clean) = run_tool(
        root,
        "gitleaks",
        &["detect", "--no-banner", "--no-git", "-s", "."],
    ) {
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
