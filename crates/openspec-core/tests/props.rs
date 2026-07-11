//! Property & metamorphic tests for the parser/renderer/merger.
//!
//! These stand in for fuzzing (which needs a nightly toolchain): proptest
//! generates thousands of structured models and inputs per run, shrinking to a
//! minimal counterexample on failure.

use openspec_core::{
    merge, parse_delta, parse_spec, render_delta, render_spec, DeltaSpec, Requirement, Scenario,
    Spec,
};
use proptest::prelude::*;

/// A requirement/scenario name: trimmed, single-line, no structural characters.
fn name_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z][A-Za-z0-9]{0,6}( [A-Za-z0-9]{1,6}){0,2}"
}

/// A single body line that cannot be mistaken for structure or a fence.
fn line_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9][A-Za-z0-9 .,*_-]{0,32}"
}

/// A non-empty prose block (used for requirement text and scenario bodies).
fn block_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(line_strategy(), 1..3).prop_map(|lines| lines.join("\n"))
}

/// Possibly-empty prose block.
fn opt_block_strategy() -> impl Strategy<Value = String> {
    prop_oneof![Just(String::new()), block_strategy()]
}

prop_compose! {
    fn scenario_strategy()(name in name_strategy(), body in opt_block_strategy()) -> Scenario {
        Scenario { name, body }
    }
}

prop_compose! {
    fn requirement_strategy()(
        name in name_strategy(),
        text in opt_block_strategy(),
        scenarios in prop::collection::vec(scenario_strategy(), 0..3),
    ) -> Requirement {
        Requirement { name, text, scenarios }
    }
}

prop_compose! {
    fn spec_strategy()(
        title in name_strategy(),
        lead in prop_oneof![Just(String::new()), Just("## Requirements".to_string())],
        requirements in prop::collection::vec(requirement_strategy(), 0..4),
        tail in prop_oneof![
            Just(String::new()),
            block_strategy().prop_map(|b| format!("## Notes\n\n{b}")),
        ],
    ) -> Spec {
        Spec { title, lead, requirements, tail }
    }
}

prop_compose! {
    fn delta_strategy()(
        added in prop::collection::vec(requirement_strategy(), 0..3),
        modified in prop::collection::vec(requirement_strategy(), 0..3),
    ) -> DeltaSpec {
        DeltaSpec { title: None, lead: String::new(), added, modified, removed: vec![], renamed: vec![] }
    }
}

/// Build a valid base spec with unique requirement names `Req0..Req{n}`.
fn indexed_spec(n: usize) -> Spec {
    let requirements = (0..n)
        .map(|i| Requirement {
            name: format!("Req{i}"),
            text: format!("The system SHALL do thing {i}."),
            scenarios: vec![Scenario {
                name: format!("Case {i}"),
                body: "- **WHEN** x\n- **THEN** y".to_string(),
            }],
        })
        .collect();
    Spec {
        title: "Indexed".to_string(),
        lead: "## Requirements".to_string(),
        requirements,
        tail: String::new(),
    }
}

proptest! {
    /// parse ∘ render ∘ parse == parse (canonical-form idempotence).
    #[test]
    fn spec_render_parse_is_idempotent(spec in spec_strategy()) {
        let rendered = render_spec(&spec);
        let parsed = parse_spec(&rendered).expect("rendered spec must parse");
        let rendered2 = render_spec(&parsed);
        prop_assert_eq!(&rendered, &rendered2, "render not a fixed point");
        prop_assert_eq!(parse_spec(&rendered2).unwrap(), parsed, "model not stable");
    }

    /// Same idempotence property for deltas.
    #[test]
    fn delta_render_parse_is_idempotent(delta in delta_strategy()) {
        let rendered = render_delta(&delta);
        let parsed = parse_delta(&rendered).expect("rendered delta must parse");
        prop_assert_eq!(render_delta(&parsed), rendered, "delta render not a fixed point");
    }

    /// The parser never panics on arbitrary bytes (robustness / fuzz surface).
    #[test]
    fn parser_never_panics(garbage in ".*") {
        let _ = parse_spec(&garbage);
        let _ = parse_delta(&garbage);
    }

    /// An empty delta is the identity merge.
    #[test]
    fn empty_delta_is_identity(n in 0usize..6) {
        let base = indexed_spec(n);
        let (merged, stats) = merge(&base, &DeltaSpec::default()).unwrap();
        prop_assert_eq!(merged, base);
        prop_assert_eq!(stats.added + stats.modified + stats.removed + stats.renamed, 0);
    }

    /// Adding `m` fresh requirements grows the set by exactly `m`.
    #[test]
    fn added_grows_by_m(n in 0usize..5, m in 0usize..4) {
        let base = indexed_spec(n);
        let added: Vec<Requirement> = (n..n + m)
            .map(|i| Requirement {
                name: format!("Req{i}"),
                text: format!("The system SHALL do {i}."),
                scenarios: vec![Scenario { name: "s".into(), body: "- **WHEN** a\n- **THEN** b".into() }],
            })
            .collect();
        let delta = DeltaSpec { added, ..DeltaSpec::default() };
        let (merged, stats) = merge(&base, &delta).unwrap();
        prop_assert_eq!(merged.requirements.len(), n + m);
        prop_assert_eq!(stats.added, m);
    }

    /// Add-then-remove returns to the original requirement-name set.
    #[test]
    fn add_then_remove_is_identity(n in 1usize..5) {
        let base = indexed_spec(n);
        let extra = Requirement {
            name: "Temp".into(),
            text: "The system SHALL temp.".into(),
            scenarios: vec![Scenario { name: "s".into(), body: "- **WHEN** a\n- **THEN** b".into() }],
        };
        let add = DeltaSpec { added: vec![extra], ..DeltaSpec::default() };
        let (with_extra, _) = merge(&base, &add).unwrap();
        let remove = DeltaSpec {
            removed: vec![openspec_core::Removed { name: "Temp".into(), body: "**Reason**: x".into() }],
            ..DeltaSpec::default()
        };
        let (back, _) = merge(&with_extra, &remove).unwrap();
        let base_names: Vec<&str> = base.requirements.iter().map(|r| r.name.as_str()).collect();
        let back_names: Vec<&str> = back.requirements.iter().map(|r| r.name.as_str()).collect();
        prop_assert_eq!(base_names, back_names);
    }

    /// Renaming A→B then B→A restores the original names.
    #[test]
    fn rename_roundtrip_restores_names(n in 1usize..5) {
        let base = indexed_spec(n);
        let fwd = DeltaSpec {
            renamed: vec![openspec_core::Rename { from: "Req0".into(), to: "RenamedZero".into() }],
            ..DeltaSpec::default()
        };
        let (mid, _) = merge(&base, &fwd).unwrap();
        prop_assert_eq!(&mid.requirements[0].name, "RenamedZero");
        let back_delta = DeltaSpec {
            renamed: vec![openspec_core::Rename { from: "RenamedZero".into(), to: "Req0".into() }],
            ..DeltaSpec::default()
        };
        let (back, _) = merge(&mid, &back_delta).unwrap();
        prop_assert_eq!(&back.requirements[0].name, "Req0");
    }

    /// Metamorphic relation: applying two *disjoint* deltas (each removes a
    /// distinct pre-existing requirement and adds a distinct fresh one) in
    /// either order must land on the same final requirement-name *set*, even
    /// though there is no reference implementation to diff against and the
    /// merge is not commutative in a stronger sense (append order differs).
    #[test]
    fn disjoint_deltas_are_order_independent_on_name_set(n in 2usize..6) {
        let base = indexed_spec(n);

        let d1 = DeltaSpec {
            removed: vec![openspec_core::Removed { name: "Req0".into(), body: "**Reason**: x".into() }],
            added: vec![Requirement {
                name: "Extra1".into(),
                text: "The system SHALL extra one.".into(),
                scenarios: vec![Scenario { name: "s1".into(), body: "- **WHEN** a\n- **THEN** b".into() }],
            }],
            ..DeltaSpec::default()
        };
        // Disjoint from d1: touches a different existing requirement (Req1,
        // not Req0) and adds a differently-named requirement (Extra2).
        let d2 = DeltaSpec {
            removed: vec![openspec_core::Removed { name: "Req1".into(), body: "**Reason**: y".into() }],
            added: vec![Requirement {
                name: "Extra2".into(),
                text: "The system SHALL extra two.".into(),
                scenarios: vec![Scenario { name: "s2".into(), body: "- **WHEN** c\n- **THEN** d".into() }],
            }],
            ..DeltaSpec::default()
        };

        let d1_then_d2 = merge(&base, &d1).and_then(|(mid, _)| merge(&mid, &d2));
        let d2_then_d1 = merge(&base, &d2).and_then(|(mid, _)| merge(&mid, &d1));
        let (a, _) = d1_then_d2.unwrap();
        let (b, _) = d2_then_d1.unwrap();

        let mut a_names: Vec<&str> = a.requirements.iter().map(|r| r.name.as_str()).collect();
        let mut b_names: Vec<&str> = b.requirements.iter().map(|r| r.name.as_str()).collect();
        a_names.sort();
        b_names.sort();
        prop_assert_eq!(a_names, b_names);
    }
}

/// The render∘parse fixed-point property, exercised against every real
/// fixture on disk rather than proptest-generated models. This is a
/// regression net: any fixture dropped into `tests/fixtures/` is
/// automatically checked, catching authored-prose shapes the generators in
/// this file can't produce (real indentation habits, real cross-references).
#[test]
fn real_fixtures_are_render_parse_fixed_points() {
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read fixtures dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".md") {
            continue; // skip spec-driven.schema.yaml — not OpenSpec markdown
        }
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        if name.contains("delta") {
            let once = parse_delta(&src).unwrap_or_else(|e| panic!("parse {name}: {e}"));
            let rendered = render_delta(&once);
            let twice =
                parse_delta(&rendered).unwrap_or_else(|e| panic!("reparse rendered {name}: {e}"));
            assert_eq!(
                once, twice,
                "{name}: delta model changed across render round-trip"
            );
            assert_eq!(
                rendered,
                render_delta(&twice),
                "{name}: delta render not a fixed point"
            );
        } else {
            let once = parse_spec(&src).unwrap_or_else(|e| panic!("parse {name}: {e}"));
            let rendered = render_spec(&once);
            let twice =
                parse_spec(&rendered).unwrap_or_else(|e| panic!("reparse rendered {name}: {e}"));
            assert_eq!(
                once, twice,
                "{name}: spec model changed across render round-trip"
            );
            assert_eq!(
                rendered,
                render_spec(&twice),
                "{name}: spec render not a fixed point"
            );
        }
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected to check at least 5 real fixtures, checked {checked}"
    );
}
