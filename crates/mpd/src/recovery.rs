//! Read-only recovery projections for status and finite doctrine checks.
//!
//! These are deliberately separate from CLI rendering and archive mutation so
//! a stale `.mpd/current` can be diagnosed without fabricating an active
//! manifest, Candidate, or gate permission.

use crate::ledger;
use openspec_core::transaction::TransactionState;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum CurrentSelection {
    None,
    Active { change: String },
    ArchivedCurrent { change: String, next_action: String },
    PendingArchive { change: String },
    AwaitingCommit { change: String },
    Closed { change: String },
    Invalid { reason: String },
}

/// The facts required to select a status surface.  Keeping this value pure
/// lets status, JSON, and tests agree without performing any writes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurrentFacts {
    pub current: Option<String>,
    pub active_manifest_exists: bool,
    pub archive_exists: bool,
    pub archive_closed: bool,
    pub pending_stage: Option<TransactionState>,
}

pub fn select_current(facts: &CurrentFacts) -> CurrentSelection {
    let Some(change) = facts.current.clone() else {
        return CurrentSelection::None;
    };
    if change.is_empty() {
        return CurrentSelection::Invalid {
            reason: "current change name is empty".into(),
        };
    }
    if let Some(stage) = facts.pending_stage {
        return if stage == TransactionState::AwaitingCommit {
            CurrentSelection::AwaitingCommit { change }
        } else {
            CurrentSelection::PendingArchive { change }
        };
    }
    if facts.active_manifest_exists {
        return CurrentSelection::Active { change };
    }
    if facts.archive_closed && facts.archive_exists {
        return CurrentSelection::Closed { change };
    }
    if facts.archive_exists {
        return CurrentSelection::ArchivedCurrent {
            change,
            next_action: "commit the archived result, then run mpd closure close --yes or mpd publish --verify".into(),
        };
    }
    CurrentSelection::Invalid {
        reason: "current pointer names neither an active nor archived change".into(),
    }
}

/// Read the current pointer and archive state without calling `set_current`,
/// loading an active manifest, or creating any process paths.
pub fn inspect_current(root: &Path) -> CurrentSelection {
    let current = match ledger::current(root) {
        Some(change) => change,
        None => return CurrentSelection::None,
    };
    let active_manifest = root
        .join("openspec/changes")
        .join(&current)
        .join("manifest.json");
    let active_manifest_exists = fs::symlink_metadata(&active_manifest)
        .ok()
        .is_some_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink());
    let archive_exists = match inspect_archive_exists(root, &current) {
        Ok(exists) => exists,
        Err(reason) => return CurrentSelection::Invalid { reason },
    };
    let archive_closed = ledger::load(root, &current)
        .ok()
        .is_some_and(|record| record.archive_closure.is_some());
    let pending_stage = openspec_core::inspect(root)
        .ok()
        .flatten()
        .and_then(|view| (view.change == current).then_some(view.stage));
    select_current(&CurrentFacts {
        current: Some(current),
        active_manifest_exists,
        archive_exists,
        archive_closed,
        pending_stage,
    })
}

fn inspect_archive_exists(root: &Path, current: &str) -> Result<bool, String> {
    const MAX_ARCHIVE_ENTRIES: usize = 10_000;
    let archive = root.join("openspec/changes/archive");
    let entries = match fs::read_dir(&archive) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot enumerate archive: {error}")),
    };
    let suffix = format!("-{current}");
    for (index, entry) in entries.enumerate() {
        if index >= MAX_ARCHIVE_ENTRIES {
            return Err("archive inventory exceeds its fixed cap".into());
        }
        let entry = entry.map_err(|error| format!("cannot enumerate archive: {error}"))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot classify archive entry: {error}"))?;
        if kind.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(&suffix))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A deliberately finite doctrine check.  `claim` is an exact normalized
/// phrase that must no longer appear unmarked outside its canonical target;
/// it is not a semantic/NLP assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctrineRule {
    pub key: String,
    pub claim: String,
    pub canonical_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctrineDocument {
    pub path: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctrineCheck {
    pub errors: Vec<String>,
}

impl DoctrineCheck {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Check direct visible supersession banners plus a finite configured set of
/// known doctrine contradictions.  The parser accepts only exact whole lines
/// (`Status: SUPERSEDED` and `Superseded by: <path>`), preventing a prose
/// mention from silently becoming authority.
pub fn check_doctrine(documents: &[DoctrineDocument], rules: &[DoctrineRule]) -> DoctrineCheck {
    let mut errors = Vec::new();
    let paths: BTreeSet<&str> = documents
        .iter()
        .map(|document| document.path.as_str())
        .collect();
    let mut edges = BTreeMap::new();
    for document in documents {
        let statuses = exact_fields(&document.text, "Status");
        let targets = exact_fields(&document.text, "Superseded by");
        if statuses.len() > 1 || targets.len() > 1 {
            errors.push(format!(
                "{} has duplicate supersession control fields",
                document.path
            ));
            continue;
        }
        let status = statuses.into_iter().next();
        let target = targets.into_iter().next();
        match (status.as_deref(), target) {
            (Some("SUPERSEDED"), Some(target)) => {
                if !paths.contains(target.as_str()) {
                    errors.push(format!(
                        "{} supersedes to missing target {target}",
                        document.path
                    ));
                } else if target == document.path {
                    errors.push(format!("{} supersedes itself", document.path));
                } else {
                    edges.insert(document.path.as_str(), target);
                }
            }
            (Some("SUPERSEDED"), None) => errors.push(format!(
                "{} is SUPERSEDED without Superseded by",
                document.path
            )),
            (Some(_), Some(_)) => errors.push(format!(
                "{} has Superseded by without Status: SUPERSEDED",
                document.path
            )),
            (None, Some(_)) => errors.push(format!(
                "{} has Superseded by without Status: SUPERSEDED",
                document.path
            )),
            _ => {}
        }
    }
    for start in edges.keys() {
        let mut seen = BTreeSet::new();
        let mut next = *start;
        while let Some(target) = edges.get(next) {
            if !seen.insert(next) {
                errors.push(format!("supersession cycle starting at {start}"));
                break;
            }
            if edges.contains_key(target.as_str()) {
                errors.push(format!(
                    "{} supersedes to {} which is itself superseded",
                    start, target
                ));
                break;
            }
            next = target;
        }
    }
    for rule in rules {
        if rule.key.is_empty()
            || rule.claim.is_empty()
            || !paths.contains(rule.canonical_path.as_str())
        {
            errors.push(format!(
                "doctrine rule {} is malformed or has no canonical target",
                rule.key
            ));
            continue;
        }
        for document in documents {
            if document.path != rule.canonical_path
                && document.text.contains(&rule.claim)
                && !edges.contains_key(document.path.as_str())
            {
                errors.push(format!(
                    "{} asserts superseded doctrine key {} (canonical: {})",
                    document.path, rule.key, rule.canonical_path
                ));
            }
        }
    }
    errors.sort();
    errors.dedup();
    DoctrineCheck { errors }
}

fn exact_fields(text: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}:");
    text.lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Repository-specific finite doctrine check used by the trusted docs lane.
/// It reads only bounded Markdown files from the repository root and `docs/`;
/// it does not attempt natural-language inference.
pub fn check_repository_doctrine(root: &Path) -> Result<DoctrineCheck, String> {
    const MAX_DOCS: usize = 512;
    const MAX_DOC_BYTES: u64 = 4 * 1024 * 1024;
    let mut paths = vec![
        "README.md".to_string(),
        "ARCHITECTURE.md".to_string(),
        "SECURITY.md".to_string(),
        "CONTRIBUTING.md".to_string(),
    ];
    let mut entries = fs::read_dir(root.join("docs"))
        .map_err(|error| format!("cannot enumerate docs/: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate docs/: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if paths.len() >= MAX_DOCS {
            return Err("documentation inventory exceeds its fixed cap".into());
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot classify docs entry: {error}"))?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            return Err("documentation path is not UTF-8".into());
        };
        if file_type.is_symlink() {
            return Err(format!("documentation path is a symlink: docs/{name}"));
        }
        if file_type.is_file() && name.ends_with(".md") {
            paths.push(format!("docs/{name}"));
        }
    }
    let mut documents = Vec::with_capacity(paths.len());
    for path in paths {
        let text = openspec_core::read_contained_capped(root, &root.join(&path), MAX_DOC_BYTES)
            .map_err(|error| format!("cannot read {path}: {error}"))?;
        documents.push(DoctrineDocument { path, text });
    }
    Ok(check_doctrine(
        &documents,
        &[DoctrineRule {
            key: "candidate-process-prose-scope".into(),
            claim: "prose included — changes the Candidate id".into(),
            canonical_path: "docs/candidate-scope-integrity.md".into(),
        }],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archived_current_does_not_become_active() {
        assert_eq!(
            select_current(&CurrentFacts {
                current: Some("archived".into()),
                archive_exists: true,
                ..CurrentFacts::default()
            }),
            CurrentSelection::ArchivedCurrent {
                change: "archived".into(),
                next_action: "commit the archived result, then run mpd closure close --yes or mpd publish --verify".into(),
            }
        );
    }

    #[test]
    fn awaiting_commit_wins_over_archived_projection() {
        assert_eq!(
            select_current(&CurrentFacts {
                current: Some("archive".into()),
                archive_exists: true,
                pending_stage: Some(TransactionState::AwaitingCommit),
                ..CurrentFacts::default()
            }),
            CurrentSelection::AwaitingCommit {
                change: "archive".into()
            }
        );
    }

    #[test]
    fn closure_record_without_archive_does_not_fabricate_closed_state() {
        assert_eq!(
            select_current(&CurrentFacts {
                current: Some("missing-archive".into()),
                archive_closed: true,
                ..CurrentFacts::default()
            }),
            CurrentSelection::Invalid {
                reason: "current pointer names neither an active nor archived change".into(),
            }
        );
    }

    #[test]
    fn doctrine_rejects_chains_cycles_and_unmarked_known_conflicts() {
        let documents = vec![
            DoctrineDocument {
                path: "old.md".into(),
                text: "Status: SUPERSEDED\nSuperseded by: middle.md\n".into(),
            },
            DoctrineDocument {
                path: "middle.md".into(),
                text: "Status: SUPERSEDED\nSuperseded by: current.md\n".into(),
            },
            DoctrineDocument {
                path: "current.md".into(),
                text: "current truth".into(),
            },
            DoctrineDocument {
                path: "conflict.md".into(),
                text: "legacy exact claim".into(),
            },
        ];
        let result = check_doctrine(
            &documents,
            &[DoctrineRule {
                key: "legacy-rule".into(),
                claim: "legacy exact claim".into(),
                canonical_path: "current.md".into(),
            }],
        );
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("which is itself superseded")));
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("legacy-rule")));

        let duplicate = check_doctrine(
            &[
                DoctrineDocument {
                    path: "old.md".into(),
                    text: "Status: SUPERSEDED\nStatus: CURRENT\nSuperseded by: current.md\n".into(),
                },
                DoctrineDocument {
                    path: "current.md".into(),
                    text: "current truth".into(),
                },
            ],
            &[],
        );
        assert!(duplicate
            .errors
            .iter()
            .any(|error| error.contains("duplicate supersession")));
    }

    #[test]
    fn current_selection_covers_active_pending_closed_and_invalid_states() {
        assert_eq!(
            select_current(&CurrentFacts {
                current: Some("active".into()),
                active_manifest_exists: true,
                ..CurrentFacts::default()
            }),
            CurrentSelection::Active {
                change: "active".into()
            }
        );
        assert_eq!(
            select_current(&CurrentFacts {
                current: Some("pending".into()),
                pending_stage: Some(TransactionState::Prepared),
                ..CurrentFacts::default()
            }),
            CurrentSelection::PendingArchive {
                change: "pending".into()
            }
        );
        assert_eq!(
            select_current(&CurrentFacts {
                current: Some("closed".into()),
                archive_exists: true,
                archive_closed: true,
                ..CurrentFacts::default()
            }),
            CurrentSelection::Closed {
                change: "closed".into()
            }
        );
        assert!(matches!(
            select_current(&CurrentFacts {
                current: Some(String::new()),
                ..CurrentFacts::default()
            }),
            CurrentSelection::Invalid { .. }
        ));
    }

    #[test]
    fn doctrine_accepts_direct_relation_and_refuses_missing_or_noncanonical_targets() {
        let valid = check_doctrine(
            &[
                DoctrineDocument {
                    path: "old.md".into(),
                    text: "Status: SUPERSEDED\nSuperseded by: current.md\n".into(),
                },
                DoctrineDocument {
                    path: "current.md".into(),
                    text: "current truth".into(),
                },
            ],
            &[],
        );
        assert!(valid.is_valid(), "{:#?}", valid.errors);

        for target in ["missing.md", "../current.md", "docs/../current.md"] {
            let invalid = check_doctrine(
                &[
                    DoctrineDocument {
                        path: "old.md".into(),
                        text: format!("Status: SUPERSEDED\nSuperseded by: {target}\n"),
                    },
                    DoctrineDocument {
                        path: "current.md".into(),
                        text: "current truth".into(),
                    },
                ],
                &[],
            );
            assert!(
                invalid
                    .errors
                    .iter()
                    .any(|error| error.contains("missing target")),
                "target {target:?} unexpectedly accepted: {:#?}",
                invalid.errors
            );
        }
    }
}
