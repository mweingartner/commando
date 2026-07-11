//! Fidelity tests against real OpenSpec fixtures and a fence-torture case.

use openspec_core::{
    has_blocking, parse_delta, parse_spec, render_delta, render_spec, validate_spec,
};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Parsing then rendering then parsing yields the same model (canonical-form
/// idempotence) — the property that guarantees the merge/archive round-trip is
/// lossless for structured content.
fn assert_idempotent_spec(src: &str) {
    let once = parse_spec(src).expect("parse 1");
    let rendered = render_spec(&once);
    let twice = parse_spec(&rendered).expect("parse 2");
    assert_eq!(once, twice, "spec model changed across render round-trip");
    // Rendering is a fixed point.
    assert_eq!(rendered, render_spec(&twice), "render not stable");
}

#[test]
fn real_cli_archive_spec_round_trips() {
    let src = fixture("cli-archive.spec.md");
    let spec = parse_spec(&src).expect("parse cli-archive");
    // Sanity: known requirements are present and fence/structure discrimination held.
    let names: Vec<&str> = spec.requirements.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"Change Selection"), "names: {names:?}");
    assert!(names.contains(&"Skip Specs Option"), "names: {names:?}");
    assert!(names.contains(&"Archive Process"), "names: {names:?}");
    // Every requirement has at least one scenario (canonical rule).
    for req in &spec.requirements {
        assert!(!req.scenarios.is_empty(), "{} has no scenarios", req.name);
    }
    assert_idempotent_spec(&src);
    // The real file is valid OpenSpec (no structural errors).
    let issues = validate_spec(&spec);
    assert!(
        !has_blocking(&issues, false),
        "unexpected errors: {issues:?}"
    );
}

#[test]
fn real_conventions_spec_round_trips() {
    let src = fixture("openspec-conventions.spec.md");
    let spec = parse_spec(&src).expect("parse conventions");
    // This file embeds `### Requirement:`/`## RENAMED Requirements` examples in
    // prose and fences; a correct parser recovers the true requirement set.
    assert!(
        spec.requirements.len() >= 10,
        "expected the real requirements, got {}",
        spec.requirements.len()
    );
    // No parsed requirement name may be one of the in-fence/inline examples.
    for req in &spec.requirements {
        assert!(
            !req.name.contains("Old Name") && !req.name.contains("New Name"),
            "leaked an example header as a requirement: {:?}",
            req.name
        );
    }
    assert_idempotent_spec(&src);
}

#[test]
fn fenced_structural_markers_are_ignored() {
    let src = fixture("fenced-torture.spec.md");
    let spec = parse_spec(&src).expect("parse fenced torture");
    assert_eq!(
        spec.requirements.len(),
        1,
        "fenced fake headers were mis-parsed as requirements"
    );
    let req = &spec.requirements[0];
    assert_eq!(req.name, "Only real structure is parsed");
    assert_eq!(req.scenarios.len(), 1, "fenced fake scenario was counted");
    // The fenced example content survives verbatim in the scenario body.
    let body = &req.scenarios[0].body;
    assert!(
        body.contains("### Requirement: FAKE"),
        "body lost fence content"
    );
    assert!(
        body.contains("## ADDED Requirements"),
        "body lost fence content"
    );
    assert_idempotent_spec(&src);
}

#[test]
fn real_delta_parses_and_round_trips() {
    let src = fixture("real-delta.cli-validate.md");
    let delta = parse_delta(&src).expect("parse real delta");
    assert!(!delta.added.is_empty(), "expected ADDED requirements");
    // Idempotence for deltas.
    let rendered = render_delta(&delta);
    let twice = parse_delta(&rendered).expect("parse rendered delta");
    assert_eq!(delta, twice, "delta model changed across render round-trip");
    assert_eq!(rendered, render_delta(&twice), "delta render not stable");
}

#[test]
fn all_sections_delta_parses_every_operation() {
    let src = fixture("all-sections.delta.md");
    let delta = parse_delta(&src).expect("parse all-sections delta");
    assert_eq!(delta.added.len(), 1, "added");
    assert_eq!(delta.modified.len(), 1, "modified");
    assert_eq!(delta.removed.len(), 1, "removed");
    assert_eq!(delta.renamed.len(), 1, "renamed");
    assert_eq!(delta.renamed[0].from, "Old dashboard");
    assert_eq!(delta.renamed[0].to, "New dashboard");
    assert_eq!(delta.removed[0].name, "Legacy export");
    assert!(delta.removed[0].body.to_lowercase().contains("reason"));

    let rendered = render_delta(&delta);
    assert_eq!(parse_delta(&rendered).unwrap(), delta, "round-trip");
}
