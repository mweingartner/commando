//! Installing the git `pre-commit` hook — the harness-agnostic enforcement
//! floor.
//!
//! Every harness eventually calls `git commit`, so a git hook enforces the
//! secret-scan and test gates regardless of which tool (or human) drove the
//! change. The hook shells out to `mpd check --staged`.

use std::io;
use std::path::Path;

/// The `pre-commit` hook script. `MPD_GATE_SKIP=1` bypasses one commit.
pub const PRE_COMMIT: &str = r#"#!/bin/sh
# mpd pre-commit gate: secret scan (+ optional test verification) on staged changes.
# Bypass a single commit with MPD_GATE_SKIP=1.
if [ "$MPD_GATE_SKIP" = "1" ]; then
    echo "mpd: pre-commit gate skipped (MPD_GATE_SKIP=1)"
    exit 0
fi
if command -v mpd >/dev/null 2>&1; then
    mpd check --staged || {
        echo "mpd: commit blocked by pre-commit gate (run 'mpd check --staged' for detail)"
        exit 1
    }
else
    echo "mpd: binary not on PATH; pre-commit gate not enforced"
fi
exit 0
"#;

/// Whether `root` is a git working tree with a hooks directory.
pub fn is_git_repo(root: &Path) -> bool {
    root.join(".git").is_dir()
}

/// Install the pre-commit hook. Returns `Ok(false)` (no-op) when `root` is not a
/// git repo. Refuses to clobber a non-mpd hook, returning an error instead.
pub fn install(root: &Path) -> io::Result<bool> {
    if !is_git_repo(root) {
        return Ok(false);
    }
    let hooks_dir = root.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    let hook = hooks_dir.join("pre-commit");
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
    Ok(true)
}

/// Whether the mpd pre-commit hook is installed.
pub fn is_installed(root: &Path) -> bool {
    let hook = root.join(".git").join("hooks").join("pre-commit");
    std::fs::read_to_string(hook)
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
