//! The secret-scanner allowlist: acknowledge known false positives so a repo
//! with intentional fixture secrets can pass the security-code gate.
//!
//! # Trust & transparency
//!
//! An allowlist is a *bypass*, so two rules are non-negotiable:
//! - Suppressions are always **counted and reported** — never silently hidden.
//! - The allowlist file (`.mpd/secret-allowlist.json`) is version-controlled
//!   trust: committing an entry is an explicit statement that a finding is a
//!   verified false positive, reviewable in a diff.
//!
//! Matching is by repo-relative path (with a small `*`/`**` glob), optionally
//! narrowed to a specific rule and/or line. gitleaks, when it is the active
//! external scanner, honors its own `.gitleaksignore` independently.

use crate::checks::secrets::Finding;
use crate::ledger::mpd_dir;
use crate::pathmatch::glob_match;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A precise allow entry: a path glob, optionally narrowed by rule and line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowEntry {
    /// Path glob (repo-relative, `*`/`**` supported).
    pub path: String,
    /// If set, only findings from this rule are allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// If set, only this 1-based line (0 for filename rules) is allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

/// The allowlist loaded from `.mpd/secret-allowlist.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowlist {
    /// Path globs whose findings are suppressed regardless of rule.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Precise allow entries.
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
}

/// Path to the allowlist file.
pub fn allowlist_path(root: &Path) -> PathBuf {
    mpd_dir(root).join("secret-allowlist.json")
}

impl Allowlist {
    /// Load the allowlist, returning an empty allowlist if the file is absent
    /// or malformed (a broken allowlist must not silently disable scanning —
    /// an empty allowlist suppresses nothing).
    pub fn load(root: &Path) -> Allowlist {
        match std::fs::read_to_string(allowlist_path(root)) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Allowlist::default(),
        }
    }

    /// Whether a finding at `rel_path` (repo-relative, `/`-separated) is allowed.
    pub fn is_allowed(&self, rel_path: &str, line: usize, rule: &str) -> bool {
        if self.paths.iter().any(|p| glob_match(p, rel_path)) {
            return true;
        }
        self.allow.iter().any(|e| {
            glob_match(&e.path, rel_path)
                && e.rule.as_deref().map_or(true, |r| r == rule)
                && e.line.map_or(true, |l| l == line)
        })
    }

    /// Partition findings into (kept, suppressed-count), computing each
    /// finding's repo-relative path against `root`.
    pub fn filter(&self, findings: Vec<Finding>, root: &Path) -> (Vec<Finding>, usize) {
        let root_str = root.display().to_string();
        let mut kept = Vec::new();
        let mut suppressed = 0usize;
        for f in findings {
            let rel = relative(&f.path, &root_str);
            if self.is_allowed(rel, f.line, f.rule) {
                suppressed += 1;
            } else {
                kept.push(f);
            }
        }
        (kept, suppressed)
    }
}

/// Strip a `root/` prefix from an absolute finding path, yielding a
/// `/`-separated repo-relative path. Only strips on a path-component boundary:
/// if `path` does not equal `root` or continue with `/`, the full path is
/// returned rather than a mis-attributed substring (fail-safe against
/// `/repo` vs `/repo-staging`).
fn relative<'a>(path: &'a str, root: &str) -> &'a str {
    match path.strip_prefix(root) {
        Some(rest) if rest.is_empty() => rest,
        Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_path_and_rule_matching() {
        let al = Allowlist {
            paths: vec!["Tests/**".to_string()],
            allow: vec![AllowEntry {
                path: "Sources/AI/Ctx.swift".to_string(),
                rule: Some("private-key-block".to_string()),
                line: None,
            }],
        };
        // Path glob suppresses any rule under Tests/.
        assert!(al.is_allowed("Tests/FooTests.swift", 12, "generic-secret-assignment"));
        // Precise entry: only the named rule at that path.
        assert!(al.is_allowed("Sources/AI/Ctx.swift", 324, "private-key-block"));
        assert!(!al.is_allowed("Sources/AI/Ctx.swift", 324, "openai-key"));
        // Unlisted path is not allowed.
        assert!(!al.is_allowed("Sources/Other.swift", 1, "private-key-block"));
    }

    #[test]
    fn load_is_fail_closed_on_malformed() {
        let dir = std::env::temp_dir().join(format!("mpd-al-{}", std::process::id()));
        let mpd = dir.join(".mpd");
        std::fs::create_dir_all(&mpd).unwrap();
        // Invalid JSON must not suppress anything.
        std::fs::write(mpd.join("secret-allowlist.json"), "{ not valid json").unwrap();
        assert_eq!(Allowlist::load(&dir), Allowlist::default());
        // Wrong field type must not suppress anything.
        std::fs::write(mpd.join("secret-allowlist.json"), "{\"paths\": \"nope\"}").unwrap();
        assert_eq!(Allowlist::load(&dir), Allowlist::default());
        // Absent file: default.
        std::fs::remove_file(mpd.join("secret-allowlist.json")).unwrap();
        assert_eq!(Allowlist::load(&dir), Allowlist::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_respects_path_boundary() {
        assert_eq!(relative("/repo/Tests/x", "/repo"), "Tests/x");
        assert_eq!(relative("/repo", "/repo"), "");
        // Shared textual prefix that diverges at a non-'/' boundary must NOT be
        // truncated to a repo-relative path (would mis-attribute the finding).
        assert_eq!(
            relative("/repo-staging/Tests/x", "/repo"),
            "/repo-staging/Tests/x"
        );
        // Unrelated path is returned whole.
        assert_eq!(relative("/other/x", "/repo"), "/other/x");
    }

    #[test]
    fn filter_reports_suppression_count() {
        let al = Allowlist {
            paths: vec!["Tests/**".to_string()],
            allow: vec![],
        };
        let findings = vec![
            Finding {
                path: "/repo/Tests/A.swift".to_string(),
                line: 5,
                rule: "generic-secret-assignment",
            },
            Finding {
                path: "/repo/Sources/B.swift".to_string(),
                line: 9,
                rule: "aws-access-key-id",
            },
        ];
        let (kept, suppressed) = al.filter(findings, Path::new("/repo"));
        assert_eq!(suppressed, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].rule, "aws-access-key-id");
    }
}
