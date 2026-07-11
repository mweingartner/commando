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

/// Files staged for commit (`ACMR` filter), as absolute paths that still exist.
pub fn git_staged_files(root: &Path) -> Vec<PathBuf> {
    git_files(
        root,
        &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
    )
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

impl SecretReport {
    /// Whether the scan came back clean.
    pub fn clean(&self) -> bool {
        self.findings.is_empty()
    }
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
