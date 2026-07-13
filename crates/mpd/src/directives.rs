//! The Model-Paired Development doctrine, bundled into mpd and installed per
//! project.
//!
//! mpd carries the canonical directives (`protocol.md` + one per persona) as
//! `include_str!`-embedded content — the doctrine is part of the binary. `mpd
//! init` installs them to `.mpd/directives/` (editable per project), and
//! [`for_persona`] resolves the active persona's directive project-first,
//! falling back to the bundled default. Project reads are symlink-refusing and
//! size-capped (reusing [`openspec_core::read_capped`]); any read failure falls
//! back to the bundled default — never fails open to an arbitrary file.

use crate::ledger::mpd_dir;
use std::path::Path;

const PROTOCOL: &str = include_str!("../assets/directives/protocol.md");
const ARCHITECT: &str = include_str!("../assets/directives/personas/architect.md");
const DESIGNER: &str = include_str!("../assets/directives/personas/designer.md");
const SECURITY: &str = include_str!("../assets/directives/personas/security.md");
const BUILDER: &str = include_str!("../assets/directives/personas/builder.md");
const TESTER: &str = include_str!("../assets/directives/personas/tester.md");
const DOCUMENTER: &str = include_str!("../assets/directives/personas/documenter.md");

/// The bundled directive files as `(relative path under .mpd/directives/,
/// content)` — the install manifest.
pub fn bundled() -> Vec<(&'static str, &'static str)> {
    vec![
        ("protocol.md", PROTOCOL),
        ("personas/architect.md", ARCHITECT),
        ("personas/designer.md", DESIGNER),
        ("personas/security.md", SECURITY),
        ("personas/builder.md", BUILDER),
        ("personas/tester.md", TESTER),
        ("personas/documenter.md", DOCUMENTER),
    ]
}

/// The bundled directive + filename slug for a persona display name, if the
/// persona has one (e.g. `main-session` does not).
fn persona_directive(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "Architect" => Some(("architect", ARCHITECT)),
        "Designer" => Some(("designer", DESIGNER)),
        "Security" => Some(("security", SECURITY)),
        "Builder" => Some(("builder", BUILDER)),
        "Tester" => Some(("tester", TESTER)),
        "Documenter" => Some(("documenter", DOCUMENTER)),
        _ => None,
    }
}

/// A resolved persona directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// The directive text (project copy or bundled default).
    pub text: String,
    /// True when a project copy was used AND it differs from the bundled default
    /// — i.e. it was locally modified and should be reviewed before it is
    /// trusted (Directive Content Trust: the file is untrusted branch content
    /// inlined as the persona's instructions).
    pub modified: bool,
}

/// Resolve a persona's directive: the project copy if present, readable, and
/// contained (symlink-refusing at *every* path component), else the bundled
/// default. Returns `None` only for personas that have no directive (e.g. the
/// Deploy main-session, or a composite name like "Architect & Designer" —
/// resolve its parts individually).
pub fn for_persona(root: &Path, name: &str) -> Option<Directive> {
    let (slug, bundled) = persona_directive(name)?;
    let dir = mpd_dir(root).join("directives");
    let path = dir.join("personas").join(format!("{slug}.md"));
    if path.exists() {
        // assert_contained walks every component (catching a symlinked
        // intermediate directory that read_capped alone would follow);
        // read_capped refuses a symlinked leaf and caps size. Any failure keeps
        // the bundled default — never read a redirected/oversized target.
        if openspec_core::assert_contained(&dir, &path).is_ok() {
            if let Ok(text) = openspec_core::read_capped(&path) {
                let modified = text != bundled;
                return Some(Directive { text, modified });
            }
        }
    }
    Some(Directive {
        text: bundled.to_string(),
        modified: false,
    })
}

/// Whether the project has installed directives. Uses `symlink_metadata` (not
/// `is_file`, which follows symlinks) so a symlinked `protocol.md` does not
/// report a falsely-healthy status.
pub fn is_installed(root: &Path) -> bool {
    let p = mpd_dir(root).join("directives").join("protocol.md");
    std::fs::symlink_metadata(&p)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_covers_every_persona() {
        for p in [
            "Architect",
            "Designer",
            "Security",
            "Builder",
            "Tester",
            "Documenter",
        ] {
            assert!(persona_directive(p).is_some(), "missing directive for {p}");
        }
        assert!(persona_directive("main-session").is_none());
        assert_eq!(bundled().len(), 7); // protocol + 6 personas
    }

    #[test]
    fn resolves_bundled_when_no_project_copy() {
        let dir = std::env::temp_dir().join(format!("mpd-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = for_persona(&dir, "Architect").unwrap();
        assert!(d.text.contains("Persona: Architect"));
        assert!(!d.modified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_copy_overrides_and_flags_modified() {
        let dir = std::env::temp_dir().join(format!("mpd-dir-ov-{}", std::process::id()));
        let personas = mpd_dir(&dir).join("directives").join("personas");
        std::fs::create_dir_all(&personas).unwrap();
        std::fs::write(personas.join("architect.md"), "# CUSTOM ARCHITECT\n").unwrap();
        let d = for_persona(&dir, "Architect").unwrap();
        assert_eq!(d.text.trim(), "# CUSTOM ARCHITECT");
        assert!(d.modified, "a divergent project copy must be flagged");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_project_copy_is_not_flagged_modified() {
        // Only *divergent* copies are flagged — a project copy that happens to
        // match the bundled default byte-for-byte must resolve as unmodified.
        let dir = std::env::temp_dir().join(format!("mpd-dir-identical-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let personas = mpd_dir(&dir).join("directives").join("personas");
        std::fs::create_dir_all(&personas).unwrap();
        std::fs::write(personas.join("architect.md"), ARCHITECT).unwrap();
        let d = for_persona(&dir, "Architect").unwrap();
        assert_eq!(d.text, ARCHITECT);
        assert!(
            !d.modified,
            "a project copy identical to the bundled default must not be flagged"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn for_persona_returns_none_for_personas_without_directive() {
        let dir = std::env::temp_dir().join(format!("mpd-dir-noneperso-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(for_persona(&dir, "main-session").is_none());
        assert!(for_persona(&dir, "Architect & Designer").is_none());
        assert!(for_persona(&dir, "nonexistent-persona").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_installed_reports_false_then_true() {
        let dir = std::env::temp_dir().join(format!("mpd-dir-installed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            !is_installed(&dir),
            "a fresh dir has no installed directives"
        );

        for (rel, content) in bundled() {
            let path = mpd_dir(&dir).join("directives").join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
        }
        assert!(
            is_installed(&dir),
            "after writing the bundled files, protocol.md must be reported installed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_project_directive_falls_back_to_bundled() {
        // Resource bound: an adversarially large project directive must not be
        // read into memory — read_capped refuses it and for_persona falls back
        // to the bundled default rather than erroring out.
        let dir = std::env::temp_dir().join(format!("mpd-dir-oversized-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let personas = mpd_dir(&dir).join("directives").join("personas");
        std::fs::create_dir_all(&personas).unwrap();
        let oversized = "A".repeat(16 * 1024 * 1024 + 1);
        std::fs::write(personas.join("architect.md"), &oversized).unwrap();
        let d = for_persona(&dir, "Architect").unwrap();
        assert_eq!(
            d.text, ARCHITECT,
            "an oversized project directive must fall back to the bundled default"
        );
        assert!(!d.modified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_intermediate_dir_falls_back_to_bundled() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("mpd-dir-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Plant a secret directory outside, with a lookalike directive in it.
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("architect.md"), "# EXFIL\n").unwrap();
        let directives = mpd_dir(&dir).join("directives");
        std::fs::create_dir_all(&directives).unwrap();
        // `.mpd/directives/personas` is a symlink to the outside dir.
        symlink(&outside, directives.join("personas")).unwrap();
        let d = for_persona(&dir, "Architect").unwrap();
        assert!(
            !d.text.contains("EXFIL"),
            "must not read through symlinked dir"
        );
        assert!(d.text.contains("Persona: Architect")); // bundled default
        let _ = std::fs::remove_dir_all(&dir);
    }
}
