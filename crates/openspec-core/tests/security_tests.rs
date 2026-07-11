//! Regression tests for the Security (code) findings: path traversal (H-2) and
//! symlink-following writes/reads (C-1).

use openspec_core::{validate_capability_name, validate_change_name, Project};
use std::fs;
use std::path::{Path, PathBuf};

fn sandbox(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mpd-sec-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("openspec/specs")).unwrap();
    fs::create_dir_all(dir.join("openspec/changes/archive")).unwrap();
    dir
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

const DELTA: &str = "## ADDED Requirements

### Requirement: Cap works
The system SHALL work.

#### Scenario: works
- **WHEN** used
- **THEN** ok
";

#[test]
fn traversal_names_are_rejected() {
    assert!(validate_change_name("../../etc/passwd").is_err());
    assert!(validate_capability_name("../secrets").is_err());
    assert!(validate_change_name("a/b").is_err());

    let dir = sandbox("traversal");
    let project = Project::new(&dir);
    // A capability name with traversal must never reach a filesystem read.
    assert!(project.read_spec("../../etc/passwd").is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn change_delta_specs_rejects_invalid_capability_dir() {
    let dir = sandbox("badcap");
    // A capability directory whose name is not a valid identifier is rejected,
    // not silently skipped.
    write(
        &dir.join("openspec/changes/thing/specs/Bad_Cap/spec.md"),
        DELTA,
    );
    fs::write(
        dir.join("openspec/changes/thing/.openspec.yaml"),
        "schema: mpd\ncreated: 2026-07-11\n",
    )
    .unwrap();
    let project = Project::new(&dir);
    assert!(project.change_delta_specs("thing").is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn commit_archive_refuses_symlinked_spec_target() {
    use std::os::unix::fs::symlink;

    let dir = sandbox("symlink");
    // A change that introduces a NEW capability `cap`.
    write(&dir.join("openspec/changes/thing/specs/cap/spec.md"), DELTA);
    fs::write(
        dir.join("openspec/changes/thing/.openspec.yaml"),
        "schema: mpd\ncreated: 2026-07-11\n",
    )
    .unwrap();

    let project = Project::new(&dir);
    let plan = project
        .plan_archive("thing", false)
        .expect("plan should succeed for a new capability");

    // Now an attacker plants a symlink where the merged spec would be written,
    // pointing at a sensitive file outside the tree.
    let secret = dir.join("outside_secret.txt");
    fs::write(&secret, "DO NOT OVERWRITE\n").unwrap();
    let target_dir = dir.join("openspec/specs/cap");
    fs::create_dir_all(&target_dir).unwrap();
    symlink(&secret, target_dir.join("spec.md")).unwrap();

    // commit_archive must refuse to follow the symlink.
    let result = project.commit_archive(&plan);
    assert!(result.is_err(), "commit_archive should refuse the symlink");
    // The outside file is untouched.
    assert_eq!(fs::read_to_string(&secret).unwrap(), "DO NOT OVERWRITE\n");
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn task_status_refuses_symlinked_change_dir() {
    use std::os::unix::fs::symlink;

    let dir = sandbox("taskslink");
    // An external directory holding a real (non-symlink) tasks.md.
    let outside = dir.join("outside_change");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("tasks.md"), "- [x] 1.1 done\n- [ ] 1.2 todo\n").unwrap();
    // Plant a directory symlink at changes/evil -> outside.
    let changes = dir.join("openspec/changes");
    fs::create_dir_all(&changes).unwrap();
    symlink(&outside, changes.join("evil")).unwrap();

    let project = Project::new(&dir);
    // The symlinked change directory must not be followed; counts must not leak.
    let status = project.task_status("evil").unwrap();
    assert_eq!(status.total, 0, "symlinked change dir must not be read");
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn read_spec_refuses_symlinked_spec() {
    use std::os::unix::fs::symlink;

    let dir = sandbox("readlink");
    let secret = dir.join("outside_secret.txt");
    fs::write(&secret, "secret contents\n").unwrap();
    let cap_dir = dir.join("openspec/specs/cap");
    fs::create_dir_all(&cap_dir).unwrap();
    symlink(&secret, cap_dir.join("spec.md")).unwrap();

    let project = Project::new(&dir);
    // Reading a symlinked spec must error, not exfiltrate the target's content.
    assert!(project.read_spec("cap").is_err());
    let _ = fs::remove_dir_all(&dir);
}
