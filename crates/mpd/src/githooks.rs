//! Installing the git `pre-commit` hook — the harness-agnostic enforcement
//! floor.
//!
//! Every harness eventually calls `git commit`, so a git hook enforces the
//! staged gate regardless of which tool (or human) drove the change. The hook
//! shells out only to the typed `mpd hook pre-commit` coordinator.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Run a git command in `root`, returning trimmed stdout on success.
fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Resolve the hooks directory git actually uses — honoring `core.hooksPath`
/// and worktree/common-dir layout (so a worktree or submodule, where `.git` is
/// a file, still resolves correctly).
fn hooks_dir(root: &Path) -> Option<PathBuf> {
    let resolve = |p: String| -> PathBuf {
        let path = PathBuf::from(&p);
        if path.is_absolute() {
            path
        } else {
            root.join(path)
        }
    };
    if let Some(hp) = git_output(root, &["config", "--get", "core.hooksPath"]) {
        if !hp.is_empty() {
            return Some(resolve(hp));
        }
    }
    git_output(root, &["rev-parse", "--git-path", "hooks"]).map(resolve)
}

/// The legacy-installed pre-commit hook.  It is deliberately fail-closed: an
/// unavailable coordinator is a broken local policy, not permission to commit.
/// Trusted clone-private launchers installed by the local-validation activation
/// path supersede this compatibility hook.
pub const PRE_COMMIT: &str = r#"#!/bin/sh
# mpd pre-commit gate: fast secret scan on staged changes (tests run at the
# Build/Test gate and local pre-push validation, not on every commit).
if command -v mpd >/dev/null 2>&1; then
    mpd hook pre-commit || {
        echo "mpd: commit blocked by pre-commit gate (run 'mpd hook pre-commit' for detail)"
        exit 1
    }
else
    echo "mpd: binary not on PATH; commit blocked (restore the approved coordinator)"
    exit 1
fi
exit 0
"#;

/// Whether `root` is inside a git working tree (worktrees and submodules
/// included — `.git` may be a gitlink file, not a directory).
pub fn is_git_repo(root: &Path) -> bool {
    git_output(root, &["rev-parse", "--is-inside-work-tree"]).as_deref() == Some("true")
}

/// Install the pre-commit hook, returning the path it was written to. Returns
/// `Ok(None)` (no-op) when `root` is not a git repo. Refuses to clobber a
/// non-mpd hook, returning an error instead.
pub fn install(root: &Path) -> io::Result<Option<PathBuf>> {
    if !is_git_repo(root) {
        return Ok(None);
    }
    let dir = match hooks_dir(root) {
        Some(d) => d,
        None => return Ok(None),
    };
    std::fs::create_dir_all(&dir)?;
    let hook = dir.join("pre-commit");
    if hook.exists() {
        let existing = std::fs::read_to_string(&hook).unwrap_or_default();
        if !existing.contains("mpd pre-commit gate") {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "a non-mpd pre-commit hook already exists at {}; leaving it untouched",
                    hook.display()
                ),
            ));
        }
    }
    std::fs::write(&hook, PRE_COMMIT)?;
    make_executable(&hook)?;
    Ok(Some(hook))
}

/// Whether the mpd pre-commit hook is installed.
pub fn is_installed(root: &Path) -> bool {
    hooks_dir(root)
        .map(|d| d.join("pre-commit"))
        .and_then(|h| std::fs::read_to_string(h).ok())
        .map(|s| s.contains("mpd pre-commit gate"))
        .unwrap_or(false)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}
