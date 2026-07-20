//! The on-disk OpenSpec project: discovery, reading, status, and archiving.
//!
//! A [`Project`] is rooted at the directory that *contains* an `openspec/`
//! folder. All path conventions (`specs/<cap>/spec.md`,
//! `changes/<name>/specs/<cap>/spec.md`, `changes/archive/YYYY-MM-DD-<name>/`)
//! live here so the rest of the system never hard-codes layout.

use crate::date;
use crate::error::{CoreError, Result};
use crate::merge::{merge, MergeStats};
use crate::model::Spec;
use crate::names::{validate_capability_name, validate_change_name};
use crate::parse::{parse_delta, parse_spec};
use crate::render::render_spec;
use crate::schema::ChangeMeta;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Maximum size of any spec/delta/metadata file the engine will read. Bounds
/// memory against adversarial multi-hundred-MB markdown (defense in depth).
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Ensure `target` is lexically within `base` and that no existing path
/// component below `base` is a symlink — refusing to follow links out of the
/// tree (CWE-59). Rejects `..` and other non-normal components.
pub fn assert_contained(base: &Path, target: &Path) -> Result<()> {
    let rel = target.strip_prefix(base).map_err(|_| {
        CoreError::Io(format!(
            "path {} escapes {}",
            target.display(),
            base.display()
        ))
    })?;
    let mut cur = base.to_path_buf();
    for comp in rel.components() {
        if !matches!(comp, Component::Normal(_)) {
            return Err(CoreError::Io(format!(
                "illegal path component in {}",
                target.display()
            )));
        }
        cur.push(comp);
        if let Ok(md) = fs::symlink_metadata(&cur) {
            if md.file_type().is_symlink() {
                return Err(CoreError::Io(format!(
                    "refusing to follow symlink at {}",
                    cur.display()
                )));
            }
        }
    }
    Ok(())
}

/// Read a file, refusing symlinks and capping size.
pub fn read_capped(path: &Path) -> Result<String> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Err(CoreError::Io(format!(
            "refusing to read symlink {}",
            path.display()
        )));
    }
    if md.len() > MAX_FILE_BYTES {
        return Err(CoreError::Io(format!(
            "{} exceeds the {MAX_FILE_BYTES}-byte limit",
            path.display()
        )));
    }
    Ok(fs::read_to_string(path)?)
}

/// A discovered OpenSpec project.
#[derive(Debug, Clone)]
pub struct Project {
    /// The directory containing `openspec/`.
    pub root: PathBuf,
}

/// An empty canonical spec for a not-yet-existing capability, ready to receive
/// ADDED requirements during a merge.
pub fn empty_spec(title: impl Into<String>) -> Spec {
    Spec {
        title: title.into(),
        lead: "## Requirements".to_string(),
        requirements: Vec::new(),
        tail: String::new(),
    }
}

/// Convert a kebab/snake capability id to a Title Case heading.
pub fn titleize(capability: &str) -> String {
    capability
        .split(['-', '_'])
        .filter(|s| !s.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Task-completion counts parsed from a `tasks.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskStatus {
    /// Checked tasks (`- [x]`).
    pub done: usize,
    /// Total tasks (checked + unchecked).
    pub total: usize,
}

/// A canonical Builder task parsed from a strict `tasks.md` plan.
///
/// Strict task identifiers are intentionally an ASCII, two-segment positive
/// integer grammar (`1.1`, `12.4`).  They are machine addresses for later
/// obligation evidence, rather than prose labels that can be duplicated or
/// normalized differently by separate readers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEntry {
    /// The checked task's stable, canonical identifier.
    pub id: String,
    /// Whether the task is marked complete.
    pub done: bool,
    /// The task text after its identifier, preserved for evidence binding.
    pub text: String,
    /// Complete normalized task record, including continuation text, with the
    /// progress marker canonicalized to unchecked.
    pub normalized_record: String,
    /// SHA-256 of `normalized_record`; ledger events bind this and the ID.
    pub record_digest: String,
    /// One-based source line, retained only for diagnostics.
    pub source_line: usize,
}

/// The parsed form of a strict task plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskPlan {
    /// Whether this document opts into canonical task IDs.
    pub strict: bool,
    /// Every parsed checkbox task in source order.
    pub entries: Vec<TaskEntry>,
}

impl TaskPlan {
    /// Whether every parsed task has been completed.
    pub fn complete(&self) -> bool {
        self.entries.iter().all(|entry| entry.done)
    }

    /// The canonical IDs still preventing Test/archive readiness.
    pub fn open_ids(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|entry| !entry.done)
            .map(|entry| entry.id.as_str())
            .collect()
    }

    /// Stable, progress-insensitive complete-plan representation. Source order
    /// remains significant, so a reorder is a contract edit while `[x]` flips
    /// are not.
    pub fn normalized_progress_record(&self) -> String {
        self.entries
            .iter()
            .map(|entry| entry.normalized_record.as_str())
            .collect::<Vec<_>>()
            .join("\n\u{1e}\n")
    }
}

impl TaskStatus {
    /// `true` when every task is checked (or there are none).
    pub fn complete(&self) -> bool {
        self.done == self.total
    }
}

/// A single spec file to be written during archiving.
#[derive(Debug, Clone)]
pub struct SpecUpdate {
    /// Capability name.
    pub capability: String,
    /// Destination path in the main `specs/` tree.
    pub target_path: PathBuf,
    /// Whether this creates a new capability spec.
    pub is_new: bool,
    /// Operation counts from the merge.
    pub stats: MergeStats,
    /// The rendered merged spec content.
    pub content: String,
}

/// A previewable, not-yet-applied archive operation.
#[derive(Debug, Clone)]
pub struct ArchivePlan {
    /// The change being archived.
    pub change: String,
    /// Spec files that will be created/updated (empty when specs are skipped).
    pub updates: Vec<SpecUpdate>,
    /// The archive destination directory.
    pub archive_target: PathBuf,
    /// Whether spec updates were skipped.
    pub skip_specs: bool,
}

impl Project {
    /// Create a project rooted at `root` (the directory containing `openspec/`).
    pub fn new(root: impl Into<PathBuf>) -> Project {
        Project { root: root.into() }
    }

    /// Walk up from `start` looking for a directory containing `openspec/`.
    pub fn discover(start: &Path) -> Option<Project> {
        let mut dir = Some(start);
        while let Some(d) = dir {
            if d.join("openspec").is_dir() {
                return Some(Project::new(d));
            }
            dir = d.parent();
        }
        None
    }

    /// `<root>/openspec`.
    pub fn openspec_dir(&self) -> PathBuf {
        self.root.join("openspec")
    }
    /// `<root>/openspec/specs`.
    pub fn specs_dir(&self) -> PathBuf {
        self.openspec_dir().join("specs")
    }
    /// `<root>/openspec/changes`.
    pub fn changes_dir(&self) -> PathBuf {
        self.openspec_dir().join("changes")
    }
    /// `<root>/openspec/changes/archive`.
    pub fn archive_dir(&self) -> PathBuf {
        self.changes_dir().join("archive")
    }
    /// Canonical spec path for a capability.
    pub fn spec_path(&self, capability: &str) -> PathBuf {
        self.specs_dir().join(capability).join("spec.md")
    }
    /// A change's directory.
    pub fn change_dir(&self, change: &str) -> PathBuf {
        self.changes_dir().join(change)
    }
    /// A change's `.openspec.yaml`.
    pub fn change_meta_path(&self, change: &str) -> PathBuf {
        self.change_dir(change).join(".openspec.yaml")
    }
    /// A change's `tasks.md`.
    pub fn tasks_path(&self, change: &str) -> PathBuf {
        self.change_dir(change).join("tasks.md")
    }
    /// A change's delta-specs directory.
    pub fn change_specs_dir(&self, change: &str) -> PathBuf {
        self.change_dir(change).join("specs")
    }

    /// List capability names that have a `specs/<cap>/spec.md`.
    pub fn list_specs(&self) -> Result<Vec<String>> {
        let mut names = child_dirs(&self.specs_dir())?
            .into_iter()
            .filter(|name| self.spec_path(name).is_file())
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }

    /// List active change names (excludes `archive/`; must have `.openspec.yaml`
    /// or `proposal.md`).
    pub fn list_changes(&self) -> Result<Vec<String>> {
        let mut names = child_dirs(&self.changes_dir())?
            .into_iter()
            .filter(|name| name != "archive")
            .filter(|name| {
                self.change_meta_path(name).is_file()
                    || self.change_dir(name).join("proposal.md").is_file()
            })
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }

    /// Read and parse a canonical capability spec.
    pub fn read_spec(&self, capability: &str) -> Result<Spec> {
        validate_capability_name(capability).map_err(CoreError::Io)?;
        let path = self.spec_path(capability);
        if !path.exists() {
            return Err(CoreError::NotFound(format!("spec {capability:?}")));
        }
        assert_contained(&self.specs_dir(), &path)?;
        let text = read_capped(&path)?;
        Ok(parse_spec(&text)?)
    }

    /// Read a change's metadata.
    pub fn read_change_meta(&self, change: &str) -> Result<ChangeMeta> {
        validate_change_name(change).map_err(CoreError::Io)?;
        let path = self.change_meta_path(change);
        if !path.exists() {
            return Err(CoreError::NotFound(format!(
                "change metadata for {change:?}"
            )));
        }
        assert_contained(&self.changes_dir(), &path)?;
        let text = read_capped(&path)?;
        Ok(ChangeMeta::parse(&text)?)
    }

    /// The `(capability, delta_path)` pairs a change proposes. Capability
    /// directories with names that are not valid identifiers are rejected
    /// rather than silently skipped, so a crafted directory cannot smuggle a
    /// path through.
    pub fn change_delta_specs(&self, change: &str) -> Result<Vec<(String, PathBuf)>> {
        validate_change_name(change).map_err(CoreError::Io)?;
        let dir = self.change_specs_dir(change);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for cap in child_dirs(&dir)? {
            validate_capability_name(&cap).map_err(CoreError::Io)?;
            let path = dir.join(&cap).join("spec.md");
            if path.is_file() {
                out.push((cap, path));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// Parse a change's `tasks.md` checkbox status.
    pub fn task_status(&self, change: &str) -> Result<TaskStatus> {
        validate_change_name(change).map_err(CoreError::Io)?;
        let path = self.tasks_path(change);
        if !path.exists() {
            return Ok(TaskStatus::default());
        }
        // Refuse a symlinked change directory or tasks.md (matches read_change_meta):
        // a directory symlink at changes/<name> must not be followed out of tree.
        if assert_contained(&self.changes_dir(), &path).is_err() {
            return Ok(TaskStatus::default());
        }
        let text = match read_capped(&path) {
            Ok(t) => t,
            Err(_) => return Ok(TaskStatus::default()),
        };
        Ok(count_tasks(&text))
    }

    /// Parse the stable-ID task contract when a plan opts into it.
    ///
    /// Existing OpenSpec changes which predate the contract remain readable:
    /// they return a non-strict empty plan and retain their historical checkbox
    /// status. Once a document declares the stable-ID contract, however, every
    /// parsed checkbox must use a unique canonical ID; ambiguity is an error
    /// before a caller can record a Test or archive side effect.
    pub fn task_plan(&self, change: &str) -> Result<TaskPlan> {
        validate_change_name(change).map_err(CoreError::Io)?;
        let path = self.tasks_path(change);
        if !path.exists() || assert_contained(&self.changes_dir(), &path).is_err() {
            return Ok(TaskPlan::default());
        }
        let text = read_capped(&path)?;
        parse_task_plan_text(&text).map_err(CoreError::Io)
    }

    /// Plan (but do not apply) archiving `change`. Reads deltas, merges each
    /// against the current spec (or an empty base for new capabilities), and
    /// returns the resulting content plus the archive destination — with no
    /// filesystem mutation.
    pub fn plan_archive(&self, change: &str, skip_specs: bool) -> Result<ArchivePlan> {
        validate_change_name(change).map_err(CoreError::Io)?;
        if !self.change_dir(change).is_dir() {
            return Err(CoreError::NotFound(format!("change {change:?}")));
        }
        // Refuse to traverse a change directory that is itself a symlink.
        assert_contained(&self.changes_dir(), &self.change_dir(change))?;
        let target = self
            .archive_dir()
            .join(format!("{}-{}", date::today_utc(), change));
        if target.exists() {
            return Err(CoreError::AlreadyExists(format!(
                "archive target {}",
                target.display()
            )));
        }

        let mut updates = Vec::new();
        if !skip_specs {
            for (capability, delta_path) in self.change_delta_specs(change)? {
                assert_contained(&self.change_dir(change), &delta_path)?;
                let delta_text = read_capped(&delta_path)?;
                let delta = parse_delta(&delta_text)?;
                let (base, is_new) = match self.read_spec(&capability) {
                    Ok(spec) => (spec, false),
                    Err(CoreError::NotFound(_)) => (empty_spec(titleize(&capability)), true),
                    Err(e) => return Err(e),
                };
                let (merged, stats) = merge(&base, &delta)?;
                updates.push(SpecUpdate {
                    capability: capability.clone(),
                    target_path: self.spec_path(&capability),
                    is_new,
                    stats,
                    content: render_spec(&merged),
                });
            }
        }

        Ok(ArchivePlan {
            change: change.to_string(),
            updates,
            archive_target: target,
            skip_specs,
        })
    }

    /// Apply a previously computed [`ArchivePlan`]: write merged specs, then
    /// move the change directory into the archive.
    ///
    /// Every write target is re-checked for symlink escape immediately before
    /// writing (not merely at plan time), closing the TOCTOU window against a
    /// symlink planted between planning and commit.
    pub fn commit_archive(&self, plan: &ArchivePlan) -> Result<()> {
        let specs_dir = self.specs_dir();
        for update in &plan.updates {
            // Contain BEFORE creating or following any directory (so a symlinked
            // intermediate component can't tunnel a mkdir outside the tree)...
            assert_contained(&specs_dir, &update.target_path)?;
            if let Some(parent) = update.target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            // ...and again at write time (TOCTOU): refuse to follow a symlink
            // planted at specs/<cap>/ or specs/<cap>/spec.md.
            assert_contained(&specs_dir, &update.target_path)?;
            fs::write(&update.target_path, &update.content)?;
        }
        fs::create_dir_all(self.archive_dir())?;
        if plan.archive_target.exists() {
            return Err(CoreError::AlreadyExists(format!(
                "archive target {}",
                plan.archive_target.display()
            )));
        }
        assert_contained(&self.changes_dir(), &plan.archive_target)?;
        fs::rename(self.change_dir(&plan.change), &plan.archive_target)?;
        Ok(())
    }
}

/// The immediate child directory names of `dir` (empty if `dir` is absent).
fn child_dirs(dir: &Path) -> Result<Vec<String>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
    }
    Ok(out)
}

/// Count `- [ ]` / `- [x]` task checkboxes, ignoring fenced code blocks.
fn count_tasks(text: &str) -> TaskStatus {
    let mut status = TaskStatus::default();
    let mut in_fence = false;
    for line in text.split('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        // Accept `- [ ]`, `* [ ]`, `+ [ ]` with any leading indentation.
        let bullet = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .or_else(|| trimmed.strip_prefix("+ "));
        if let Some(rest) = bullet {
            let rest = rest.trim_start();
            if let Some(after) = rest.strip_prefix('[') {
                let mut chars = after.chars();
                if let (Some(mark), Some(']')) = (chars.next(), chars.next()) {
                    match mark {
                        ' ' => status.total += 1,
                        'x' | 'X' => {
                            status.total += 1;
                            status.done += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    status
}

/// Parse a stable-ID task document without treating examples in fenced code as
/// obligations. A document opts in by containing the exact phrase
/// `Every box is required and has a stable ID` in non-fenced prose. This explicit
/// opt-in keeps historical OpenSpec templates (which happened to number ordinary
/// checklist items) readable while making new high-assurance plans fail closed.
pub fn parse_task_plan_text(text: &str) -> std::result::Result<TaskPlan, String> {
    let mut plan = TaskPlan::default();
    let mut in_fence = false;
    let mut candidate_lines = Vec::new();
    let mut in_html_comment = false;
    for (index, line) in text.split('\n').enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if in_html_comment {
            if trimmed.contains("-->") {
                in_html_comment = false;
            }
            continue;
        }
        if trimmed.starts_with("<!--") {
            if !trimmed.contains("-->") {
                in_html_comment = true;
            }
            continue;
        }
        if trimmed
            .to_ascii_lowercase()
            .contains("every box is required and has a stable id")
        {
            plan.strict = true;
        }
        let bullet = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .or_else(|| trimmed.strip_prefix("+ "));
        let Some(rest) = bullet else { continue };
        let Some(after_bracket) = rest.trim_start().strip_prefix('[') else {
            continue;
        };
        let mut chars = after_bracket.chars();
        let Some(mark) = chars.next() else { continue };
        if chars.next() != Some(']') || !matches!(mark, ' ' | 'x' | 'X') {
            continue;
        }
        let body = chars.as_str().trim_start();
        candidate_lines.push((index, mark, body.to_string()));
    }
    if !plan.strict {
        return Ok(plan);
    }
    let mut seen = BTreeSet::new();
    for (entry_index, (line_index, mark, body)) in candidate_lines.iter().enumerate() {
        let line = line_index + 1;
        let Some((id, task_text)) = body.split_once(char::is_whitespace) else {
            return Err(format!(
                "tasks.md line {line}: stable task requires `N.N text`"
            ));
        };
        if !is_task_id(id) {
            return Err(format!(
                "tasks.md line {line}: task id {id:?} must be canonical ASCII `N.N`"
            ));
        }
        let task_text = task_text.trim();
        if task_text.is_empty() || task_text.len() > 4_096 {
            return Err(format!(
                "tasks.md line {line}: task text must be 1..=4096 bytes"
            ));
        }
        if !seen.insert(id.to_string()) {
            return Err(format!("tasks.md line {line}: duplicate task id {id:?}"));
        }
        // Continuations are intentionally limited to indented Markdown lines
        // before the next checkbox. This retains multi-line task contracts but
        // cannot turn ordinary numbered closure-runbook prose into a task.
        let end = candidate_lines
            .get(entry_index + 1)
            .map(|(next, _, _)| *next)
            .unwrap_or_else(|| text.lines().count());
        let mut record_text = task_text.to_string();
        for continuation in text.lines().skip(line_index + 1).take(end - line_index - 1) {
            if continuation.trim().is_empty() {
                continue;
            }
            if continuation.starts_with(' ') || continuation.starts_with('\t') {
                record_text.push('\n');
                record_text.push_str(continuation.trim());
            }
        }
        let normalized_record = format!("- [ ] {id} {record_text}");
        let record_digest = format!("{:x}", Sha256::digest(normalized_record.as_bytes()));
        plan.entries.push(TaskEntry {
            id: id.to_string(),
            done: matches!(mark, 'x' | 'X'),
            text: record_text,
            normalized_record,
            record_digest,
            source_line: line,
        });
    }
    if plan.entries.is_empty() {
        return Err("strict tasks.md contains no canonical checkbox tasks".into());
    }
    Ok(plan)
}

fn is_task_id(value: &str) -> bool {
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    let Some(second) = segments.next() else {
        return false;
    };
    if segments.next().is_some() {
        return false;
    }
    [first, second].into_iter().all(|segment| {
        !segment.is_empty()
            && segment.len() <= 4
            && !segment.starts_with('0')
            && segment.bytes().all(|byte| byte.is_ascii_digit())
            && segment.parse::<u32>().is_ok_and(|number| number > 0)
    })
}

#[cfg(all(test, unix))]
mod containment_tests {
    use super::assert_contained;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn refuses_an_intermediate_directory_symlink() {
        // `read_capped`'s final-only lstat misses an intermediate-directory
        // symlink; `assert_contained` (which `read_contained` relies on) must
        // refuse every symlinked component, including the change-dir one.
        let base = std::env::temp_dir().join(format!(
            "mpd-contain-int-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("changes")).unwrap();
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("design.md"), "secret").unwrap();
        symlink(&outside, base.join("changes/c")).unwrap(); // intermediate component
        assert!(
            assert_contained(&base, &base.join("changes/c/design.md")).is_err(),
            "an intermediate-directory symlink escaping base must be refused"
        );
        // Control: a real in-base path passes every component check.
        fs::create_dir_all(base.join("changes/real")).unwrap();
        fs::write(base.join("changes/real/design.md"), "ok").unwrap();
        assert!(assert_contained(&base, &base.join("changes/real/design.md")).is_ok());
        let _ = fs::remove_dir_all(&base);
    }
}
