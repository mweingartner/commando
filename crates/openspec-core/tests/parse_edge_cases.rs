//! White-box edge cases for the fence-aware parser that the fidelity/props
//! suites don't exercise: empty input, missing structure, unusual fences,
//! CRLF line endings, and multiple trailing sections.

use openspec_core::{parse_delta, parse_spec, render_spec, ParseError};

#[test]
fn empty_input_spec_is_missing_title() {
    assert_eq!(parse_spec(""), Err(ParseError::MissingTitle));
}

#[test]
fn empty_input_delta_is_a_valid_empty_delta() {
    // Delta files may omit everything; an empty document is a no-op delta,
    // not an error.
    let delta = parse_delta("").expect("empty delta must parse");
    assert!(delta.title.is_none());
    assert!(delta.is_empty(), "{delta:?}");
}

#[test]
fn prose_with_no_headings_is_missing_title() {
    let src = "Just some prose.\nNo headings anywhere in this document.\n";
    assert_eq!(parse_spec(src), Err(ParseError::MissingTitle));
}

#[test]
fn title_only_no_requirements() {
    let src = "# Empty Capability\n\n## Requirements\n";
    let spec = parse_spec(src).expect("parse");
    assert_eq!(spec.title, "Empty Capability");
    assert!(spec.requirements.is_empty());
    // Idempotent even with zero requirements.
    let rendered = render_spec(&spec);
    assert_eq!(parse_spec(&rendered).unwrap(), spec);
}

#[test]
fn requirement_with_zero_scenarios_parses_cleanly() {
    let src = "# T\n\n### Requirement: Foo\nThe system SHALL do foo.\n";
    let spec = parse_spec(src).expect("parse");
    assert_eq!(spec.requirements.len(), 1);
    let req = &spec.requirements[0];
    assert_eq!(req.name, "Foo");
    assert!(req.text.contains("do foo"));
    assert!(req.scenarios.is_empty());
    // Round trip must still hold with no scenarios.
    let rendered = render_spec(&spec);
    let reparsed = parse_spec(&rendered).unwrap();
    assert_eq!(spec, reparsed);
}

#[test]
fn empty_requirement_name_is_rejected() {
    let src = "# T\n\n### Requirement: \nBody text.\n";
    assert_eq!(parse_spec(src), Err(ParseError::EmptyRequirementName));
}

#[test]
fn empty_scenario_name_is_rejected() {
    let src = "# T\n\n### Requirement: Foo\nBody.\n\n#### Scenario: \n- **WHEN** a\n- **THEN** b\n";
    assert_eq!(parse_spec(src), Err(ParseError::EmptyScenarioName));
}

#[test]
fn unclosed_fence_never_reopens_structure() {
    // A fence opened and never closed swallows everything after it as body
    // text — including lines that look exactly like requirement headers.
    // This must not panic, and must not manufacture a phantom requirement.
    let src = "# Doc\n\n```\n### Requirement: Fake\nMore fake body\n";
    let spec = parse_spec(src).expect("must not panic or error");
    assert_eq!(spec.title, "Doc");
    assert!(
        spec.requirements.is_empty(),
        "the never-closed fence must suppress structural parsing: {:?}",
        spec.requirements
    );
    assert!(spec.lead.contains("### Requirement: Fake"));
}

#[test]
fn tilde_fences_are_fence_aware_like_backtick_fences() {
    let src = "# T\n\n\
        ### Requirement: Real\n\
        Body.\n\n\
        #### Scenario: Has a tilde fence\n\
        ~~~\n\
        #### Scenario: Fake nested scenario\n\
        ## RENAMED Requirements\n\
        ~~~\n\
        - **WHEN** real\n\
        - **THEN** ok\n";
    let spec = parse_spec(src).expect("parse");
    assert_eq!(spec.requirements.len(), 1);
    let req = &spec.requirements[0];
    assert_eq!(
        req.scenarios.len(),
        1,
        "fenced fake scenario must not split the real one"
    );
    let body = &req.scenarios[0].body;
    assert!(body.contains("#### Scenario: Fake nested scenario"));
    assert!(body.contains("- **WHEN** real"));
    let rendered = render_spec(&spec);
    assert_eq!(parse_spec(&rendered).unwrap(), spec);
}

#[test]
fn mismatched_fence_chars_do_not_close_each_other() {
    // A `~~~` fence cannot be closed by a ``` line and vice versa; the
    // structural marker inside must stay swallowed until the matching fence.
    let src = "# T\n\n\
        ### Requirement: Real\n\
        Body.\n\n\
        #### Scenario: Mixed fence chars\n\
        ~~~\n\
        ```\n\
        #### Scenario: Still fake\n\
        ~~~\n\
        - **WHEN** a\n\
        - **THEN** b\n";
    let spec = parse_spec(src).expect("parse");
    assert_eq!(spec.requirements[0].scenarios.len(), 1);
}

#[test]
fn scenario_body_with_embedded_fenced_hash_heading_is_preserved_verbatim() {
    let src = "# T\n\n\
        ### Requirement: Real\n\
        Body.\n\n\
        #### Scenario: Embeds a fenced fake heading\n\
        - **WHEN** the example is shown\n\
        - **THEN** it renders:\n\n\
        ```markdown\n\
        #### Scenario: this looks structural but is not\n\
        ```\n";
    let spec = parse_spec(src).expect("parse");
    assert_eq!(spec.requirements.len(), 1);
    assert_eq!(spec.requirements[0].scenarios.len(), 1);
    let body = &spec.requirements[0].scenarios[0].body;
    assert!(body.contains("#### Scenario: this looks structural but is not"));
    let rendered = render_spec(&spec);
    let reparsed = parse_spec(&rendered).unwrap();
    assert_eq!(spec, reparsed);
}

#[test]
fn multiple_trailing_level2_sections_are_captured_as_one_tail_block() {
    let src = "# T\n\n\
        ### Requirement: Foo\n\
        Body.\n\n\
        #### Scenario: S\n\
        - **WHEN** a\n\
        - **THEN** b\n\n\
        ## Why These Decisions\n\
        Some rationale.\n\n\
        ## Future Work\n\
        Some notes.\n";
    let spec = parse_spec(src).expect("parse");
    assert_eq!(spec.requirements.len(), 1);
    assert!(spec.tail.contains("## Why These Decisions"));
    assert!(spec.tail.contains("## Future Work"));
    assert!(spec.tail.contains("Some rationale."));
    assert!(spec.tail.contains("Some notes."));
    let rendered = render_spec(&spec);
    let reparsed = parse_spec(&rendered).unwrap();
    assert_eq!(spec, reparsed, "multi-section tail must round-trip");
}

#[test]
fn windows_style_paths_in_body_text_survive_verbatim() {
    let src = "# T\n\n\
        ### Requirement: Config path\n\
        The system SHALL read config from `C:\\Users\\svc\\AppData\\config.toml`.\n\n\
        #### Scenario: Path is read\n\
        - **WHEN** the service starts on Windows\n\
        - **THEN** it reads `C:\\ProgramData\\App\\settings.ini`\n";
    let spec = parse_spec(src).expect("parse");
    let req = &spec.requirements[0];
    assert!(req.text.contains(r"C:\Users\svc\AppData\config.toml"));
    assert!(req.scenarios[0]
        .body
        .contains(r"C:\ProgramData\App\settings.ini"));
    let rendered = render_spec(&spec);
    let reparsed = parse_spec(&rendered).unwrap();
    assert_eq!(spec, reparsed);
}

#[test]
fn crlf_line_endings_do_not_panic_and_round_trip() {
    let src = "# Title\r\n\r\n\
        ### Requirement: Foo\r\n\
        Does foo.\r\n\r\n\
        #### Scenario: S\r\n\
        - **WHEN** a\r\n\
        - **THEN** b\r\n";
    let once = parse_spec(src).expect("CRLF input must parse without panicking");
    assert_eq!(once.title, "Title");
    assert_eq!(once.requirements.len(), 1);
    assert_eq!(once.requirements[0].name, "Foo");
    assert_eq!(once.requirements[0].scenarios.len(), 1);
    // Canonical-form idempotence must hold even though raw `\r` bytes may be
    // embedded in the preserved body text (the parser does not normalize line
    // endings inside verbatim regions).
    let rendered = render_spec(&once);
    let twice = parse_spec(&rendered).expect("re-parse of rendered CRLF-derived spec");
    assert_eq!(
        once, twice,
        "CRLF input model must be stable across round-trip"
    );
}

#[test]
fn indented_fence_within_three_spaces_still_recognized() {
    let src = "# T\n\n\
        ### Requirement: Foo\n\
        Body.\n\n\
        #### Scenario: Indented fence\n\
        - **WHEN** shown\n\
        - **THEN** ok:\n\n\
           ```\n\
           #### Scenario: fake, indented fence\n\
           ```\n";
    let spec = parse_spec(src).expect("parse");
    assert_eq!(spec.requirements[0].scenarios.len(), 1);
}

#[test]
fn four_space_indented_marker_is_not_a_fence() {
    // >3 leading spaces means the fence detector must not treat this as a
    // fence delimiter (CommonMark indented-code-block territory); it is
    // simply body text here since it's inside a scenario, not a real
    // structural heading either way. Must not panic.
    let src = "# T\n\n\
        ### Requirement: Foo\n\
        Body.\n\n\
        #### Scenario: S\n\
        - **WHEN** a\n\
            ```\n\
        - **THEN** b\n";
    let spec = parse_spec(src).expect("must not panic");
    assert_eq!(spec.requirements.len(), 1);
}
