//! Scaffolding: `mpd init` (project setup) and `mpd begin` (new change).
//!
//! Bundled schema and templates are embedded at compile time so a fresh binary
//! can initialize a project with no network or Node dependency.

use crate::config::Config;
use crate::ledger::{self, ChangeKind, Ledger};
use crate::{githooks, phase::Phase};
use openspec_core::date;
use openspec_core::schema::ChangeMeta;
use std::io;
use std::path::{Path, PathBuf};

const MPD_SCHEMA: &str = include_str!("../assets/mpd.schema.yaml");
const T_PROPOSAL: &str = include_str!("../assets/templates/proposal.md");
const T_SPEC: &str = include_str!("../assets/templates/spec.md");
const T_DESIGN: &str = include_str!("../assets/templates/design.md");
const T_TASKS: &str = include_str!("../assets/templates/tasks.md");
const T_DOCUMENTATION: &str = include_str!("../assets/templates/documentation.md");

const PROJECT_MD: &str = "# Project Context\n\n\
<!-- Project-specific context for humans and agents. -->\n";
const AGENTS_MD: &str = "# Agent Instructions\n\n\
This project uses mpd (Model-Paired Development) over the OpenSpec format.\n\
Run `mpd status` to see the current phase and `mpd next` for the next step.\n";

/// Outcome of an `init`.
#[derive(Debug, Default)]
pub struct InitReport {
    /// Directories/files created.
    pub created: Vec<String>,
    /// Repo-relative path where the git hook was installed, if any.
    pub hook_path: Option<String>,
    /// A note if the hook could not be installed.
    pub hook_note: Option<String>,
}

/// Initialize an OpenSpec+mpd project rooted at `root`.
pub fn init(root: &Path, test_cmd: Option<String>) -> io::Result<InitReport> {
    let mut report = InitReport::default();
    let mkdir = |p: PathBuf, report: &mut InitReport| -> io::Result<()> {
        if !p.exists() {
            std::fs::create_dir_all(&p)?;
            report.created.push(display_rel(root, &p));
        }
        Ok(())
    };

    let openspec = root.join("openspec");
    mkdir(openspec.join("specs"), &mut report)?;
    mkdir(openspec.join("changes").join("archive"), &mut report)?;
    let schema_dir = openspec.join("schemas").join("mpd");
    mkdir(schema_dir.join("templates"), &mut report)?;

    write_new(
        &schema_dir.join("schema.yaml"),
        MPD_SCHEMA,
        root,
        &mut report,
    )?;
    write_new(
        &schema_dir.join("templates").join("proposal.md"),
        T_PROPOSAL,
        root,
        &mut report,
    )?;
    write_new(
        &schema_dir.join("templates").join("spec.md"),
        T_SPEC,
        root,
        &mut report,
    )?;
    write_new(
        &schema_dir.join("templates").join("design.md"),
        T_DESIGN,
        root,
        &mut report,
    )?;
    write_new(
        &schema_dir.join("templates").join("tasks.md"),
        T_TASKS,
        root,
        &mut report,
    )?;
    write_new(
        &schema_dir.join("templates").join("documentation.md"),
        T_DOCUMENTATION,
        root,
        &mut report,
    )?;
    write_new(&openspec.join("project.md"), PROJECT_MD, root, &mut report)?;
    write_new(&openspec.join("AGENTS.md"), AGENTS_MD, root, &mut report)?;

    // .mpd config, with the per-persona model map seeded explicitly.
    mkdir(ledger::mpd_dir(root).join("state"), &mut report)?;
    let (models, model_fallbacks) = crate::config::default_models();
    let cfg = Config {
        test: test_cmd,
        deploy: None,
        docs_dir: None,
        models,
        model_fallbacks,
    };
    let cfg_path = crate::config::config_path(root);
    if !cfg_path.exists() {
        openspec_core::assert_contained(root, &cfg_path).map_err(io::Error::other)?;
        cfg.save(root)?;
        report.created.push(".mpd/config.json".to_string());
    }

    // Gitignore the transient per-developer state (the current-change pointer and
    // any scratch tmp), while the durable ledger (.mpd/state/), config, and
    // directives stay tracked. Scoped to .mpd/ so the project's root .gitignore is
    // left untouched. Without this, `.mpd/current` reads as an uncommitted file and
    // the commit/stop hooks nag about it every turn.
    write_new(
        &ledger::mpd_dir(root).join(".gitignore"),
        "/current\n/tmp/\n",
        root,
        &mut report,
    )?;

    // Install the bundled MPD doctrine directives (non-destructive).
    for (rel, content) in crate::directives::bundled() {
        write_new(
            &ledger::mpd_dir(root).join("directives").join(rel),
            content,
            root,
            &mut report,
        )?;
    }

    // git hook.
    match githooks::install(root) {
        Ok(Some(path)) => report.hook_path = Some(display_rel(root, &path)),
        Ok(None) => {}
        Err(e) => report.hook_note = Some(e.to_string()),
    }
    Ok(report)
}

/// Validate a change name (delegates to the shared `openspec-core` validator so
/// creation and every later use site enforce the identical rule).
pub fn validate_change_name(name: &str) -> Result<(), String> {
    openspec_core::validate_change_name(name)
}

/// Create a new change and seed its ledger. Returns the seeded ledger.
pub fn begin(root: &Path, change: &str, ui: bool, kind: ChangeKind) -> io::Result<Ledger> {
    validate_change_name(change).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let change_dir = root.join("openspec").join("changes").join(change);
    if change_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("change {change:?} already exists"),
        ));
    }
    std::fs::create_dir_all(change_dir.join("specs"))?;

    let meta = ChangeMeta {
        schema: "mpd".to_string(),
        created: date::today_utc(),
    };
    let meta_yaml = meta
        .to_yaml()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(change_dir.join(".openspec.yaml"), meta_yaml)?;
    std::fs::write(change_dir.join("proposal.md"), T_PROPOSAL)?;
    std::fs::write(change_dir.join("design.md"), T_DESIGN)?;
    std::fs::write(change_dir.join("tasks.md"), T_TASKS)?;
    // Seed the documentation stub only for documented (feature) changes.
    if kind.documents() {
        std::fs::write(change_dir.join("documentation.md"), T_DOCUMENTATION)?;
    }

    let ledger = Ledger::new(change, "mpd", ui, kind);
    // Assert the seeded phase is sane (first applicable phase).
    debug_assert_eq!(ledger.phase, Phase::first(ledger.applicability()));
    ledger::save(root, &ledger)?;
    ledger::set_current(root, change)?;
    Ok(ledger)
}

fn write_new(path: &Path, content: &str, root: &Path, report: &mut InitReport) -> io::Result<()> {
    if !path.exists() {
        // `exists()` follows symlinks, so a *dangling* symlink reads as absent —
        // writing would then follow it to an arbitrary target. Refuse any symlink
        // (target or intermediate component) before creating dirs or writing.
        openspec_core::assert_contained(root, path).map_err(io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        openspec_core::assert_contained(root, path).map_err(io::Error::other)?;
        std::fs::write(path, content)?;
        report.created.push(display_rel(root, path));
    }
    Ok(())
}

fn display_rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::validate_change_name;

    #[test]
    fn accepts_valid_names() {
        assert!(validate_change_name("add-rate-limiter").is_ok());
        assert!(validate_change_name("fix-parser-fidelity").is_ok());
        assert!(validate_change_name("v2-export").is_ok());
    }

    #[test]
    fn rejects_invalid_names() {
        assert!(validate_change_name("").is_err());
        assert!(validate_change_name("Add-Thing").is_err()); // uppercase
        assert!(validate_change_name("1-thing").is_err()); // leading digit
        assert!(validate_change_name("add_thing").is_err()); // underscore
        assert!(validate_change_name("add--thing").is_err()); // double dash
        assert!(validate_change_name("add-thing-").is_err()); // trailing dash
        assert!(validate_change_name("add thing").is_err()); // space
    }

    #[cfg(unix)]
    #[test]
    fn write_new_refuses_dangling_symlink() {
        use super::{write_new, InitReport};
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("mpd-write-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // A dangling symlink reads as absent to `exists()`; a naive write would
        // follow it to `target` (outside the project). write_new must refuse.
        let target = root.join("target-outside");
        let link = root.join("directives").join("protocol.md");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&target, &link).unwrap();
        let mut report = InitReport::default();
        let err = write_new(&link, "DOCTRINE", &root, &mut report).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(!target.exists(), "must not create the symlink target");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn init_gitignores_transient_state() {
        use super::init;
        let root = std::env::temp_dir().join(format!("mpd-init-gi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        init(&root, Some("cargo test".into())).unwrap();
        let gi = std::fs::read_to_string(root.join(".mpd").join(".gitignore")).unwrap();
        assert!(
            gi.lines().any(|l| l.trim() == "/current"),
            "init must gitignore the transient current-change pointer: {gi:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
