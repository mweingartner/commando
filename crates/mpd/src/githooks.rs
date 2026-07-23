//! Installing the git `pre-commit` hook — the harness-agnostic enforcement
//! floor.
//!
//! Every harness eventually calls `git commit`, so a git hook enforces the
//! staged gate regardless of which tool (or human) drove the change. The hook
//! shells out only to the typed `mpd hook pre-commit` coordinator.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The observed installation state of the commit gate.  This deliberately
/// keeps the legacy marker hook distinct from the policy-activated wrapper:
/// the latter is healthy only after the local-validation activation identity
/// has been checked read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookInstallation {
    /// `root` is not a Git worktree or Git did not disclose a hooks directory.
    NotApplicable,
    /// No `pre-commit` hook was observed at the configured hooks path.
    Missing,
    /// The compatibility marker hook installed by [`install`].
    ManualMpd { path: PathBuf },
    /// The clone-private activated wrapper and its trusted coordinator/policy
    /// bindings were all verified by `local_validation`.
    ActivatedTrusted { path: PathBuf },
    /// A hook exists but is neither a recognized manual hook nor a healthy
    /// activated wrapper.  `reason` is local, bounded diagnostic text; it is
    /// never a policy authorization.
    Drifted { path: PathBuf, reason: String },
}

impl HookInstallation {
    /// Compatibility projection for existing callers.  A manual marker hook
    /// remains installed, while a drifted activated wrapper intentionally does
    /// not become healthy merely because a file is present.
    pub fn is_installed(&self) -> bool {
        matches!(self, Self::ManualMpd { .. } | Self::ActivatedTrusted { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not-applicable",
            Self::Missing => "missing",
            Self::ManualMpd { .. } => "manual-mpd",
            Self::ActivatedTrusted { .. } => "activated-trusted",
            Self::Drifted { .. } => "drifted",
        }
    }
}

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

/// Inspect the configured pre-commit hook without changing Git configuration,
/// hook files, or trusted-policy state.  Marker text is sufficient only for
/// the explicit compatibility hook; activated wrappers are accepted solely
/// when the established activation/coordinator/policy health check succeeds.
pub fn inspect_installation(root: &Path) -> HookInstallation {
    if !is_git_repo(root) {
        return HookInstallation::NotApplicable;
    }
    let Some(dir) = hooks_dir(root) else {
        return HookInstallation::NotApplicable;
    };
    let hook = dir.join("pre-commit");
    let metadata = match std::fs::symlink_metadata(&hook) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return HookInstallation::Missing,
        Err(error) => {
            return HookInstallation::Drifted {
                path: hook,
                reason: format!("cannot inspect hook: {error}"),
            }
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return HookInstallation::Drifted {
            path: hook,
            reason: "hook is not a regular non-symlink file".into(),
        };
    }
    let contents = match std::fs::read_to_string(&hook) {
        Ok(contents) => contents,
        Err(error) => {
            return HookInstallation::Drifted {
                path: hook,
                reason: format!("cannot read hook: {error}"),
            }
        }
    };
    if contents == PRE_COMMIT {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return HookInstallation::Drifted {
                    path: hook,
                    reason: "manual MPD hook is not executable".into(),
                };
            }
        }
        return HookInstallation::ManualMpd { path: hook };
    }
    if contents.contains("mpd pre-commit gate") {
        return HookInstallation::Drifted {
            path: hook,
            reason: "manual MPD marker exists but hook bytes differ from the installed template"
                .into(),
        };
    }

    match crate::local_validation::doctor_activation_health(root) {
        Ok(()) => HookInstallation::ActivatedTrusted { path: hook },
        Err(reason) => HookInstallation::Drifted { path: hook, reason },
    }
}

/// Whether an MPD pre-commit hook is installed.  This compatibility wrapper
/// intentionally delegates to the typed diagnosis instead of trusting marker
/// text for activated trusted hooks.
#[allow(dead_code)]
pub fn is_installed(root: &Path) -> bool {
    inspect_installation(root).is_installed()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    fn repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Command::new("git")
            .arg("init")
            .current_dir(&dir)
            .status()
            .unwrap();
        dir
    }

    #[test]
    fn missing_and_manual_hooks_are_distinguished() {
        let dir = repo("mpd-hook-inspection");
        assert_eq!(inspect_installation(&dir), HookInstallation::Missing);
        let installed = install(&dir).unwrap().unwrap();
        assert_eq!(
            inspect_installation(&dir),
            HookInstallation::ManualMpd { path: installed }
        );
        assert!(is_installed(&dir));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unrecognized_hook_is_drifted_not_installed() {
        let dir = repo("mpd-hook-drift");
        let hook = hooks_dir(&dir).unwrap().join("pre-commit");
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
        let observed = inspect_installation(&dir);
        assert!(matches!(observed, HookInstallation::Drifted { ref path, .. } if path == &hook));
        assert!(!observed.is_installed());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn marker_text_does_not_authorize_modified_manual_hook() {
        let dir = repo("mpd-hook-marker-drift");
        let hook = hooks_dir(&dir).unwrap().join("pre-commit");
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, "#!/bin/sh\n# mpd pre-commit gate\nexit 0\n").unwrap();
        make_executable(&hook).unwrap();
        assert!(matches!(
            inspect_installation(&dir),
            HookInstallation::Drifted { .. }
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
