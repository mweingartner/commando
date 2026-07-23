//! Scaffolding: `mpd init` (project setup) and `mpd begin` (new change).
//!
//! Bundled schema and templates are embedded at compile time so a fresh binary
//! can initialize a project with no network or Node dependency.

use crate::config::Config;
use crate::ledger::{self, ChangeKind, Governance, Ledger};
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

// Strict-tier judgment-artifact templates. Each carries the `##` sections its
// phase's `judgment_artifact()` requires, plus `<!-- guidance -->` placeholders
// so an unfilled stub fails `check_sections` until a persona authors it.
const T_JUDGMENT_SECURITY_PLAN: &str =
    include_str!("../assets/templates/judgment/security-plan.md");
const T_JUDGMENT_DESIGN_MOCK: &str = include_str!("../assets/templates/judgment/design-mock.md");
const T_JUDGMENT_SECURITY_CODE: &str =
    include_str!("../assets/templates/judgment/security-code.md");
const T_JUDGMENT_DESIGN_REVIEW: &str =
    include_str!("../assets/templates/judgment/design-review.md");
const T_JUDGMENT_DESIGN_SIGNOFF: &str =
    include_str!("../assets/templates/judgment/design-signoff.md");
const T_JUDGMENT_TEST: &str = include_str!("../assets/templates/judgment/test.md");
const T_JUDGMENT_DOC_VALIDATION: &str =
    include_str!("../assets/templates/judgment/doc-validation.md");

/// The transient `.mpd/` paths that must never be committed — the single source
/// of truth consumed by `init`'s `.mpd/.gitignore`, `mpd doctor --fix`'s heal,
/// and the archive transient-path pre-flight (design.md Cond 8), so `--fix`
/// always fully clears what the pre-flight demands. Each entry is a `.gitignore`
/// pattern relative to `.mpd/` (leading `/` anchors it to the `.mpd/` root).
pub const TRANSIENT_GITIGNORE_ENTRIES: &[&str] = &[
    "/current",
    "/tmp/",
    "/build-output/",
    "/local/",
    "/pending-closure",
    "/parity-observations.json",
];

const PROJECT_MD: &str = "# Project Context\n\n\
<!-- Project-specific context for humans and agents. -->\n";
const AGENTS_MD: &str = r#"# Agent Instructions

This project uses local-only MPD over OpenSpec and Git. Hosted CI is not validation
authority. Start non-trivial work with `mpd conduct <change> --harness codex`, then
repeat `mpd next --harness codex --context`, perform exactly the current role, and
record `mpd gate <phase> --pass --by <actor> --evidence <artifact>`.

The ordered gates are Design Mock, Architecture, Design Review, Security(plan), Build,
Security(code), Design Sign-off, Test, Documentation, Doc Validation, and Deploy. Only
Design phases may be N/A with a written rationale. Strict judgment artifacts require
one exact Actor and canonical Verdict; actors differ from the latest upstream gate.
There is no artifact waiver.

Declare scope in `manifest.json`. Build, Security(code), and Test use one immutable
exact Candidate; Candidate and Commit receipts are different. Stale causal inputs rewind
before effects. Keep worktree, gates, validation, archive, commit, push authorization,
transfer, parity, readiness, and installation separate in every report.

Authoritative checks are local, typed, pinned, offline, resource-bounded, and network
denied. Never add a shell-string, ambient-PATH, hosted, unsandboxed, broad-read, or
weaker-platform fallback. After Done: `mpd archive --yes`, commit and push normally
through the local hooks, then `mpd publish --verify`.
"#;

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
        governance: None,
        governance_economics: None,
        routing: None,
        deploy: None,
        docs_dir: None,
        models,
        model_fallbacks,
        hermetic_reuse: None,
        closure: None,
        personas: std::collections::BTreeMap::new(),
        local_validation: None,
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
        &format!("{}\n", TRANSIENT_GITIGNORE_ENTRIES.join("\n")),
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
pub fn begin(
    root: &Path,
    change: &str,
    ui: bool,
    kind: ChangeKind,
    governance: Governance,
) -> io::Result<Ledger> {
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
    std::fs::write(
        change_dir.join("manifest.json"),
        crate::closure::ChangeManifest::seed_json(),
    )?;
    // Seed the documentation stub only for documented (feature) changes.
    if kind.documents() {
        std::fs::write(change_dir.join("documentation.md"), T_DOCUMENTATION)?;
    }

    let ledger = Ledger::new_with_governance(change, "mpd", ui, kind, governance);
    // Assert the seeded phase is sane (first applicable phase).
    debug_assert_eq!(ledger.phase, Phase::first(ledger.applicability()));
    ledger::save(root, &ledger)?;
    ledger::set_current(root, change)?;
    Ok(ledger)
}

/// The bundled judgment-artifact template body for `phase`, if the strict tier
/// requires one. The *filename* is owned by [`Phase::judgment_artifact`] (the
/// single source of truth); this maps the same phase to the template seeded into
/// the change dir. Architecture's artifact is the core `design.md` already seeded
/// at `begin`, so it reuses the design template (re-seeding is a no-op).
fn judgment_template(phase: Phase) -> Option<&'static str> {
    Some(match phase {
        Phase::DesignMock => T_JUDGMENT_DESIGN_MOCK,
        Phase::SecurityPlan => T_JUDGMENT_SECURITY_PLAN,
        Phase::SecurityCode => T_JUDGMENT_SECURITY_CODE,
        Phase::DesignReview => T_JUDGMENT_DESIGN_REVIEW,
        Phase::DesignSignoff => T_JUDGMENT_DESIGN_SIGNOFF,
        Phase::Test => T_JUDGMENT_TEST,
        Phase::DocValidation => T_JUDGMENT_DOC_VALIDATION,
        Phase::Architecture => T_DESIGN,
        _ => return None,
    })
}

/// Seed `phase`'s judgment-artifact template into the change dir when the strict
/// tier requires one and it is absent. Uses [`write_new`] — symlink-refusing and
/// never overwriting authored content — so re-seeding an already-filled artifact
/// is a no-op. Returns the repo-relative path if a file was actually created, or
/// `None` (phase has no judgment artifact, or the artifact already exists). The
/// stub deliberately fails `check_sections` (unfilled `<!-- … -->` placeholders)
/// until a persona authors it, so seeding can never satisfy the gate by itself.
pub fn seed_judgment_template(
    root: &Path,
    change: &str,
    phase: Phase,
) -> io::Result<Option<String>> {
    validate_change_name(change).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let (filename, _sections) = match phase.judgment_artifact() {
        Some(a) => a,
        None => return Ok(None),
    };
    let content = match judgment_template(phase) {
        Some(c) => c,
        None => return Ok(None),
    };
    let path = root
        .join("openspec")
        .join("changes")
        .join(change)
        .join(filename);
    let mut report = InitReport::default();
    write_new(&path, content, root, &mut report)?;
    Ok(report.created.into_iter().next())
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
    fn judgment_templates_carry_their_required_sections() {
        use super::judgment_template;
        use crate::phase::{Phase, PIPELINE};
        // Every phase whose strict gate demands a judgment artifact must have a
        // bundled template, and that template must contain each required `##`
        // section verbatim — else a seeded stub could never pass the gate even
        // when authored. (Single source of truth: judgment_artifact.)
        for &p in PIPELINE.iter().chain(std::iter::once(&Phase::Done)) {
            match p.judgment_artifact() {
                Some((_file, sections)) => {
                    let body =
                        judgment_template(p).unwrap_or_else(|| panic!("{p:?} has no template"));
                    for section in sections {
                        assert!(
                            body.contains(&format!("## {section}")),
                            "{p:?} template missing `## {section}`"
                        );
                    }
                }
                None => assert!(
                    judgment_template(p).is_none(),
                    "{p:?} has no judgment artifact but carries a template"
                ),
            }
        }
        // The high-risk-only sections live in the security-code template.
        let sc = judgment_template(Phase::SecurityCode).unwrap();
        assert!(sc.contains("## Independent review") && sc.contains("## Refutation"));
    }

    #[test]
    fn seed_judgment_template_writes_then_is_a_noop() {
        use super::{init, seed_judgment_template};
        use crate::ledger::{ChangeKind, Governance};
        use crate::phase::Phase;
        let root = std::env::temp_dir().join(format!("mpd-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap()
            .success());
        init(&root, Some("cargo test".into())).unwrap();
        super::begin(
            &root,
            "seed-me",
            false,
            ChangeKind::Feature,
            Governance::default(),
        )
        .unwrap();

        // A judgment phase seeds its stub and reports the created path.
        let created = seed_judgment_template(&root, "seed-me", Phase::SecurityCode).unwrap();
        assert_eq!(
            created.as_deref(),
            Some("openspec/changes/seed-me/security-code.md")
        );
        let path = root.join("openspec/changes/seed-me/security-code.md");
        let first = std::fs::read_to_string(&path).unwrap();

        // Re-seeding is a no-op — never overwrites, reports nothing created.
        std::fs::write(&path, "# authored\n").unwrap();
        assert_eq!(
            seed_judgment_template(&root, "seed-me", Phase::SecurityCode).unwrap(),
            None
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# authored\n");
        assert_ne!(first, "# authored\n");

        // A non-judgment phase seeds nothing.
        assert_eq!(
            seed_judgment_template(&root, "seed-me", Phase::Build).unwrap(),
            None
        );
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
        for entry in ["/build-output/", "/local/"] {
            assert!(
                gi.lines().any(|line| line.trim() == entry),
                "init must gitignore typed deployment artifact {entry}: {gi:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
