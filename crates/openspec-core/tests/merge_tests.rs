//! Merge-algorithm correctness: ordering, matching, and conflict detection.

use openspec_core::{merge, parse_delta, parse_spec, render_spec, DeltaSpec, MergeError};

const BASE: &str = "# Widget Spec

## Requirements

### Requirement: Alpha
The system SHALL do alpha.

#### Scenario: Alpha works
- **WHEN** alpha
- **THEN** ok

### Requirement: Beta
The system SHALL do beta.

#### Scenario: Beta works
- **WHEN** beta
- **THEN** ok
";

fn base() -> openspec_core::Spec {
    parse_spec(BASE).unwrap()
}

#[test]
fn added_appends_new_requirement() {
    let delta = parse_delta(
        "## ADDED Requirements

### Requirement: Gamma
The system SHALL do gamma.

#### Scenario: Gamma works
- **WHEN** gamma
- **THEN** ok
",
    )
    .unwrap();
    let (merged, stats) = merge(&base(), &delta).unwrap();
    assert_eq!(stats.added, 1);
    assert_eq!(merged.requirements.len(), 3);
    assert_eq!(merged.requirements[2].name, "Gamma");
}

#[test]
fn added_conflict_is_rejected() {
    let delta = parse_delta(
        "## ADDED Requirements

### Requirement: Alpha
The system SHALL redo alpha.

#### Scenario: dup
- **WHEN** x
- **THEN** y
",
    )
    .unwrap();
    assert_eq!(
        merge(&base(), &delta).unwrap_err(),
        MergeError::AddedConflict("Alpha".into())
    );
}

#[test]
fn removed_deletes_by_header() {
    let delta = parse_delta(
        "## REMOVED Requirements

### Requirement: Beta
**Reason**: gone
",
    )
    .unwrap();
    let (merged, stats) = merge(&base(), &delta).unwrap();
    assert_eq!(stats.removed, 1);
    assert_eq!(merged.requirements.len(), 1);
    assert_eq!(merged.requirements[0].name, "Alpha");
}

#[test]
fn removed_missing_is_rejected() {
    let delta = parse_delta(
        "## REMOVED Requirements

### Requirement: Zeta
**Reason**: gone
",
    )
    .unwrap();
    assert_eq!(
        merge(&base(), &delta).unwrap_err(),
        MergeError::RemovedMissing("Zeta".into())
    );
}

#[test]
fn modified_replaces_content() {
    let delta = parse_delta(
        "## MODIFIED Requirements

### Requirement: Alpha
The system SHALL do alpha much better now.

#### Scenario: Alpha improved
- **WHEN** alpha
- **THEN** better
",
    )
    .unwrap();
    let (merged, stats) = merge(&base(), &delta).unwrap();
    assert_eq!(stats.modified, 1);
    assert!(merged.requirements[0].text.contains("much better"));
    assert_eq!(merged.requirements[0].scenarios[0].name, "Alpha improved");
}

#[test]
fn rename_then_modify_uses_new_name() {
    // Ordering guarantee: rename applies before modify, so MODIFIED matches the
    // NEW header.
    let delta = parse_delta(
        "## MODIFIED Requirements

### Requirement: Alpha Prime
The system SHALL do alpha prime.

#### Scenario: Prime
- **WHEN** a
- **THEN** b

## RENAMED Requirements

- FROM: `### Requirement: Alpha`
- TO: `### Requirement: Alpha Prime`
",
    )
    .unwrap();
    let (merged, stats) = merge(&base(), &delta).unwrap();
    assert_eq!(stats.renamed, 1);
    assert_eq!(stats.modified, 1);
    assert_eq!(merged.requirements[0].name, "Alpha Prime");
    assert!(merged.requirements[0].text.contains("alpha prime"));
}

#[test]
fn rename_source_missing_is_rejected() {
    let delta = parse_delta(
        "## RENAMED Requirements

- FROM: `### Requirement: Nonexistent`
- TO: `### Requirement: Whatever`
",
    )
    .unwrap();
    assert_eq!(
        merge(&base(), &delta).unwrap_err(),
        MergeError::RenameSourceMissing("Nonexistent".into())
    );
}

#[test]
fn rename_target_conflict_is_rejected() {
    let delta = parse_delta(
        "## RENAMED Requirements

- FROM: `### Requirement: Alpha`
- TO: `### Requirement: Beta`
",
    )
    .unwrap();
    assert_eq!(
        merge(&base(), &delta).unwrap_err(),
        MergeError::RenameTargetConflict("Beta".into())
    );
}

#[test]
fn modified_referencing_pre_rename_name_is_rejected() {
    // RENAMED applies before MODIFIED, so a MODIFIED block that still targets
    // the OLD header must fail to match — even though that header existed in
    // the base spec before the merge began.
    let delta = parse_delta(
        "## MODIFIED Requirements

### Requirement: Alpha
The system SHALL do alpha differently.

#### Scenario: x
- **WHEN** a
- **THEN** b

## RENAMED Requirements

- FROM: `### Requirement: Alpha`
- TO: `### Requirement: Alpha Prime`
",
    )
    .unwrap();
    assert_eq!(
        merge(&base(), &delta).unwrap_err(),
        MergeError::ModifiedMissing("Alpha".into())
    );
}

#[test]
fn removed_then_added_same_name_in_one_delta_succeeds() {
    // Fixed ordering (RENAMED, REMOVED, MODIFIED, ADDED) means a delta may
    // remove a requirement and add a fresh one under the same header without
    // tripping the ADDED-conflict check, regardless of section order in the
    // source document.
    let delta = parse_delta(
        "## ADDED Requirements

### Requirement: Beta
The system SHALL do an all-new beta.

#### Scenario: New beta works
- **WHEN** beta2
- **THEN** ok

## REMOVED Requirements

### Requirement: Beta
**Reason**: replaced
",
    )
    .unwrap();
    let (merged, stats) = merge(&base(), &delta).unwrap();
    assert_eq!(stats.removed, 1);
    assert_eq!(stats.added, 1);
    assert_eq!(merged.requirements.len(), 2);
    let beta = merged
        .requirements
        .iter()
        .find(|r| r.name == "Beta")
        .expect("re-added Beta must be present");
    assert!(beta.text.contains("all-new beta"));
}

#[test]
fn duplicate_header_in_base_is_rejected_before_any_mutation() {
    let dup_base = parse_spec(
        "# Widget Spec

## Requirements

### Requirement: Alpha
The system SHALL do alpha.

#### Scenario: Alpha works
- **WHEN** alpha
- **THEN** ok

### Requirement: Alpha
The system SHALL do alpha, again, with a second block sharing the header.

#### Scenario: Alpha works again
- **WHEN** x
- **THEN** y
",
    )
    .unwrap();
    // Even an empty (no-op) delta must surface the pre-existing corruption —
    // the check runs before any operation is applied.
    assert_eq!(
        merge(&dup_base, &DeltaSpec::default()).unwrap_err(),
        MergeError::DuplicateInBase("Alpha".into())
    );
}

#[test]
fn rename_to_identical_name_is_a_recorded_noop() {
    let delta = parse_delta(
        "## RENAMED Requirements

- FROM: `### Requirement: Alpha`
- TO: `### Requirement: Alpha`
",
    )
    .unwrap();
    let (merged, stats) = merge(&base(), &delta).unwrap();
    assert_eq!(
        stats.renamed, 1,
        "a self-rename still counts as an operation"
    );
    assert_eq!(merged, base(), "content must be otherwise unchanged");
}

#[test]
fn empty_base_via_project_empty_spec_accepts_added_only() {
    // The new-capability path: `project::empty_spec` seeds a title + a
    // `## Requirements` lead with zero requirements, ready to receive ADDED
    // operations during archive of a brand-new capability.
    let new_base = openspec_core::project::empty_spec("Widget Two");
    assert!(new_base.requirements.is_empty());

    let delta = parse_delta(
        "## ADDED Requirements

### Requirement: Gamma
The system SHALL do gamma.

#### Scenario: Gamma works
- **WHEN** gamma
- **THEN** ok
",
    )
    .unwrap();
    let (merged, stats) = merge(&new_base, &delta).unwrap();
    assert_eq!(stats.added, 1);
    assert_eq!(merged.requirements.len(), 1);
    assert_eq!(merged.title, "Widget Two");
    assert_eq!(merged.lead, "## Requirements");

    let rendered = render_spec(&merged);
    let reparsed = parse_spec(&rendered).unwrap();
    assert_eq!(merged, reparsed);
}

#[test]
fn empty_base_modified_is_rejected() {
    // A brand-new capability has nothing to MODIFY yet.
    let new_base = openspec_core::project::empty_spec("Widget Three");
    let delta = parse_delta(
        "## MODIFIED Requirements

### Requirement: Ghost
The system SHALL do nothing that exists yet.

#### Scenario: n/a
- **WHEN** a
- **THEN** b
",
    )
    .unwrap();
    assert_eq!(
        merge(&new_base, &delta).unwrap_err(),
        MergeError::ModifiedMissing("Ghost".into())
    );
}

#[test]
fn merged_result_reparses_cleanly() {
    let delta = parse_delta(
        "## ADDED Requirements

### Requirement: Gamma
The system SHALL do gamma.

#### Scenario: g
- **WHEN** g
- **THEN** ok
",
    )
    .unwrap();
    let (merged, _) = merge(&base(), &delta).unwrap();
    let rendered = render_spec(&merged);
    let reparsed = parse_spec(&rendered).unwrap();
    assert_eq!(merged, reparsed, "merged spec must survive render/parse");
}
