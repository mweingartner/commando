//! Coverage for `Project`: discovery, task-status parsing, and the
//! archive-planning error paths. None of these were previously exercised
//! directly against `openspec-core` (only indirectly through the `mpd`
//! binary's e2e tests), so this file closes that white-box gap.

use openspec_core::project::empty_spec;
use openspec_core::{CoreError, Project};
use proptest::prelude::*;
use std::path::PathBuf;

/// A unique temp directory for one test.
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!(
            "openspec-core-project-test-{}-{tag}-{}",
            std::process::id(),
            tag.len() // cheap extra uniqueness beyond pid+tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Sandbox { dir }
    }

    fn write(&self, rel: &str, content: &str) {
        let path = self.dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---- task_status / count_tasks --------------------------------------------

#[test]
fn task_status_defaults_when_tasks_file_is_absent() {
    let sb = Sandbox::new("no-tasks");
    sb.write(
        "openspec/changes/c/.openspec.yaml",
        "schema: mpd\ncreated: 2026-01-01\n",
    );
    let project = Project::new(&sb.dir);
    let status = project.task_status("c").unwrap();
    assert_eq!(status.done, 0);
    assert_eq!(status.total, 0);
    assert!(status.complete(), "zero of zero must count as complete");
}

#[test]
fn task_status_counts_mixed_bullets_and_case() {
    let sb = Sandbox::new("mixed");
    sb.write(
        "openspec/changes/c/tasks.md",
        "# Tasks\n\n\
         - [x] done with a dash\n\
         - [ ] pending with a dash\n\
         * [X] done with a star, uppercase mark\n\
         + [ ] pending with a plus\n\
         not a task line at all\n",
    );
    let project = Project::new(&sb.dir);
    let status = project.task_status("c").unwrap();
    assert_eq!(status.total, 4);
    assert_eq!(status.done, 2);
    assert!(!status.complete());
}

#[test]
fn task_status_ignores_checkbox_lookalikes_inside_fenced_code() {
    let sb = Sandbox::new("fenced");
    sb.write(
        "openspec/changes/c/tasks.md",
        "# Tasks\n\n\
         - [x] a real done task\n\n\
         ```markdown\n\
         - [ ] this is example markdown inside a fence, not a real task\n\
         - [x] neither is this\n\
         ```\n\n\
         - [ ] a real pending task\n",
    );
    let project = Project::new(&sb.dir);
    let status = project.task_status("c").unwrap();
    assert_eq!(status.total, 2, "fenced lookalikes must not be counted");
    assert_eq!(status.done, 1);
}

#[test]
fn task_status_all_done_is_complete() {
    let sb = Sandbox::new("all-done");
    sb.write(
        "openspec/changes/c/tasks.md",
        "- [x] one\n- [x] two\n- [x] three\n",
    );
    let project = Project::new(&sb.dir);
    let status = project.task_status("c").unwrap();
    assert_eq!(status, openspec_core::TaskStatus { done: 3, total: 3 });
    assert!(status.complete());
}

#[test]
fn task_status_malformed_brackets_are_not_counted() {
    let sb = Sandbox::new("malformed");
    sb.write(
        "openspec/changes/c/tasks.md",
        "- [xx] not a valid single-char mark\n\
         - [] missing the mark entirely\n\
         - [ ] a genuinely valid pending task\n",
    );
    let project = Project::new(&sb.dir);
    let status = project.task_status("c").unwrap();
    assert_eq!(status.total, 1);
    assert_eq!(status.done, 0);
}

#[test]
fn strict_task_plan_rejects_duplicate_alias_unicode_and_overflow_ids() {
    let sb = Sandbox::new("strict-invalid");
    let project = Project::new(&sb.dir);
    for (name, body, needle) in [
        (
            "duplicate",
            "Every box is required and has a stable ID.\n- [ ] 1.1 first\n- [ ] 1.1 second\n",
            "duplicate task id",
        ),
        (
            "alias",
            "Every box is required and has a stable ID.\n- [ ] 01.1 alias\n",
            "canonical ASCII",
        ),
        (
            "unicode",
            "Every box is required and has a stable ID.\n- [ ] １.1 unicode\n",
            "canonical ASCII",
        ),
        (
            "overflow",
            "Every box is required and has a stable ID.\n- [ ] 4294967296.1 too-large\n",
            "canonical ASCII",
        ),
    ] {
        sb.write(&format!("openspec/changes/{name}/tasks.md"), body);
        let error = project.task_plan(name).unwrap_err();
        assert!(error.to_string().contains(needle), "{error}");
    }
}

#[test]
fn strict_task_plan_ignores_fences_and_exposes_open_ids() {
    let sb = Sandbox::new("strict-valid");
    sb.write(
        "openspec/changes/c/tasks.md",
        "Every box is required and has a stable ID.\n\
         - [x] 1.1 finished\n\
         ```markdown\n\
         - [ ] 99.1 example only\n\
         ```\n\
         - [ ] 2.3 pending\n",
    );
    let plan = Project::new(&sb.dir).task_plan("c").unwrap();
    assert!(plan.strict);
    assert_eq!(plan.entries.len(), 2);
    assert_eq!(plan.open_ids(), vec!["2.3"]);
    assert!(!plan.complete());
}

#[test]
fn strict_task_plan_ignores_commented_checkbox_aliases() {
    let sb = Sandbox::new("strict-commented");
    sb.write(
        "openspec/changes/c/tasks.md",
        "Every box is required and has a stable ID.\n<!--\n- [ ] 1.1 hidden\n-->\n- [ ] 2.1 real\n",
    );
    let plan = Project::new(&sb.dir).task_plan("c").unwrap();
    assert_eq!(plan.open_ids(), vec!["2.1"]);
}

#[test]
fn legacy_task_plan_is_readable_without_stable_id_contract() {
    let sb = Sandbox::new("legacy-plan");
    sb.write("openspec/changes/c/tasks.md", "- [ ] old task\n");
    let plan = Project::new(&sb.dir).task_plan("c").unwrap();
    assert!(!plan.strict);
    assert!(plan.entries.is_empty());
    assert!(plan.complete());
}

proptest! {
    /// Stable task targeting is tied to the normalized full record, not the
    /// checkbox marker or an ID that could otherwise be silently retargeted.
    /// This seeded generator covers progress flips, changed text, and reorder
    /// independently of the parser implementation's example tests.
    #[test]
    fn strict_task_record_binding_is_progress_insensitive_but_contract_sensitive(
        first in "[a-z]{1,30}",
        second in "[a-z]{1,30}",
    ) {
        prop_assume!(first != second);
        let sb = Sandbox::new("task-binding-prop");
        let header = "Every box is required and has a stable ID.\n";
        sb.write(
            "openspec/changes/c/tasks.md",
            &format!("{header}- [ ] 1.1 {first}\n  continuation\n- [x] 2.2 {second}\n"),
        );
        let project = Project::new(&sb.dir);
        let original = project.task_plan("c").unwrap();
        sb.write(
            "openspec/changes/c/tasks.md",
            &format!("{header}- [x] 1.1 {first}\n  continuation\n- [ ] 2.2 {second}\n"),
        );
        let progress_only = project.task_plan("c").unwrap();
        prop_assert_eq!(original.normalized_progress_record(), progress_only.normalized_progress_record());
        prop_assert_eq!(&original.entries[0].record_digest, &progress_only.entries[0].record_digest);

        sb.write(
            "openspec/changes/c/tasks.md",
            &format!("{header}- [x] 1.1 {first}changed\n  continuation\n- [ ] 2.2 {second}\n"),
        );
        let changed = project.task_plan("c").unwrap();
        prop_assert_ne!(&original.entries[0].record_digest, &changed.entries[0].record_digest);

        sb.write(
            "openspec/changes/c/tasks.md",
            &format!("{header}- [ ] 2.2 {second}\n- [ ] 1.1 {first}\n  continuation\n"),
        );
        let reordered = project.task_plan("c").unwrap();
        prop_assert_ne!(original.normalized_progress_record(), reordered.normalized_progress_record());
    }
}

// ---- discover ---------------------------------------------------------------

#[test]
fn discover_finds_project_root_from_nested_subdirectory() {
    let sb = Sandbox::new("discover");
    sb.write("openspec/specs/thing/spec.md", "# Thing\n");
    let nested = sb.dir.join("some/deeply/nested/working/dir");
    std::fs::create_dir_all(&nested).unwrap();
    let found = Project::discover(&nested).expect("must find the project root above");
    assert_eq!(found.root, sb.dir);
}

#[test]
fn discover_returns_none_below_a_dir_with_no_openspec_ancestor() {
    // An isolated temp tree with no `openspec/` anywhere above it (unlike the
    // repo checkout, which does have one) must report no project.
    let sb = Sandbox::new("no-project");
    let leaf = sb.dir.join("just/a/plain/directory");
    std::fs::create_dir_all(&leaf).unwrap();
    assert!(Project::discover(&leaf).is_none());
}

// ---- list_specs / list_changes ----------------------------------------------

#[test]
fn list_specs_only_includes_dirs_with_a_spec_file_and_sorts_them() {
    let sb = Sandbox::new("list-specs");
    sb.write("openspec/specs/zebra/spec.md", "# Zebra\n");
    sb.write("openspec/specs/alpha/spec.md", "# Alpha\n");
    // A capability directory with no spec.md must be excluded.
    std::fs::create_dir_all(sb.dir.join("openspec/specs/empty-dir")).unwrap();
    let project = Project::new(&sb.dir);
    assert_eq!(project.list_specs().unwrap(), vec!["alpha", "zebra"]);
}

#[test]
fn list_changes_excludes_archive_and_requires_metadata() {
    let sb = Sandbox::new("list-changes");
    sb.write(
        "openspec/changes/real-change/.openspec.yaml",
        "schema: mpd\ncreated: 2026-01-01\n",
    );
    sb.write("openspec/changes/proposal-only/proposal.md", "# Proposal\n");
    // No metadata and no proposal.md: must be excluded.
    std::fs::create_dir_all(sb.dir.join("openspec/changes/incomplete")).unwrap();
    // `archive` must never be listed as an active change.
    std::fs::create_dir_all(sb.dir.join("openspec/changes/archive")).unwrap();

    let project = Project::new(&sb.dir);
    let changes = project.list_changes().unwrap();
    assert_eq!(changes, vec!["proposal-only", "real-change"]);
}

// ---- plan_archive / commit_archive error paths -------------------------------

#[test]
fn plan_archive_rejects_a_nonexistent_change() {
    let sb = Sandbox::new("no-change");
    // Project root must at least exist for discovery elsewhere, but plan_archive
    // itself just checks the change directory.
    let project = Project::new(&sb.dir);
    let err = project.plan_archive("does-not-exist", false).unwrap_err();
    assert!(matches!(err, CoreError::NotFound(_)), "{err:?}");
}

#[test]
fn plan_archive_new_capability_uses_empty_spec_base() {
    let sb = Sandbox::new("new-cap");
    sb.write(
        "openspec/changes/add-thing/specs/thing/spec.md",
        "## ADDED Requirements\n\n\
         ### Requirement: Thing works\n\
         The system SHALL do the thing.\n\n\
         #### Scenario: It works\n\
         - **WHEN** invoked\n\
         - **THEN** it works\n",
    );
    let project = Project::new(&sb.dir);
    let plan = project.plan_archive("add-thing", false).unwrap();
    assert_eq!(plan.updates.len(), 1);
    let update = &plan.updates[0];
    assert!(update.is_new, "no prior spec.md ⇒ new-capability path");
    assert_eq!(update.stats.added, 1);
    assert!(update.content.starts_with("# Thing"), "{}", update.content);
}

#[test]
fn plan_archive_skip_specs_produces_no_updates() {
    let sb = Sandbox::new("skip-specs");
    sb.write(
        "openspec/changes/tool-change/specs/thing/spec.md",
        "## ADDED Requirements\n\n### Requirement: X\nThe system SHALL x.\n\n#### Scenario: s\n- **WHEN** a\n- **THEN** b\n",
    );
    let project = Project::new(&sb.dir);
    let plan = project.plan_archive("tool-change", true).unwrap();
    assert!(plan.skip_specs);
    assert!(plan.updates.is_empty());
}

#[test]
fn commit_archive_refuses_when_archive_target_already_exists() {
    let sb = Sandbox::new("archive-exists");
    sb.write("openspec/changes/c/tasks.md", "- [ ] a task\n");
    let project = Project::new(&sb.dir);
    let plan = project.plan_archive("c", true).unwrap();
    // Pre-create the archive destination out from under the plan.
    std::fs::create_dir_all(&plan.archive_target).unwrap();
    let err = project.commit_archive(&plan).unwrap_err();
    assert!(matches!(err, CoreError::AlreadyExists(_)), "{err:?}");
}

#[test]
fn plan_archive_rejects_when_archive_target_already_exists() {
    let sb = Sandbox::new("plan-archive-exists");
    sb.write("openspec/changes/c/tasks.md", "- [ ] a task\n");
    let project = Project::new(&sb.dir);
    let target = project
        .archive_dir()
        .join(format!("{}-c", openspec_core::date::today_utc()));
    std::fs::create_dir_all(&target).unwrap();
    let err = project.plan_archive("c", true).unwrap_err();
    assert!(matches!(err, CoreError::AlreadyExists(_)), "{err:?}");
}

#[test]
fn empty_spec_helper_produces_a_valid_seed_for_a_new_capability() {
    let spec = empty_spec("Some New Capability");
    assert_eq!(spec.title, "Some New Capability");
    assert_eq!(spec.lead, "## Requirements");
    assert!(spec.requirements.is_empty());
    assert!(spec.tail.is_empty());
}
