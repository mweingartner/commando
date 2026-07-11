//! Non-functional passes: performance budget on the parse/render hot path,
//! and a determinism check under concurrent access.
//!
//! These are pure, allocation-heavy hot paths (no I/O, no shared mutable
//! state), so the main risks are (a) an accidentally-quadratic scan
//! reintroduced by a future refactor and (b) any latent reliance on global
//! state that would make concurrent use non-deterministic. Both are cheap
//! insurance given how central `parse`/`render` are to every other feature.

use openspec_core::{parse_spec, render_spec};
use std::sync::Arc;
use std::time::Instant;

/// Build a synthetic spec with `n` requirements, each with one scenario.
fn generate_large_spec(n: usize) -> String {
    let mut s = String::from("# Load Test Spec\n\n## Requirements\n\n");
    for i in 0..n {
        s.push_str(&format!(
            "### Requirement: Req {i}\n\
             The system SHALL do thing {i}.\n\n\
             #### Scenario: Case {i}\n\
             - **WHEN** input {i}\n\
             - **THEN** output {i}\n\n"
        ));
    }
    s
}

/// Parsing (and rendering) 5,000 requirements must stay well within budget —
/// a regression here would indicate an accidentally-quadratic boundary scan
/// (see `next_requirement_boundary` in `parse.rs`, which is only amortized
/// O(n) as long as each call advances the cursor rather than rescanning).
///
/// Baseline captured on this machine (median of 5 runs, debug build):
/// parse ~a few ms, render ~well under a ms, for 5,000 requirements — the
/// 500ms budget below leaves generous headroom for slower CI machines while
/// still catching an O(n^2) blowup (which would push a 5,000-item input from
/// single-digit ms into seconds).
#[test]
fn large_spec_parses_and_renders_within_budget() {
    let src = generate_large_spec(5_000);

    let mut parse_durations = Vec::new();
    let mut spec = None;
    for _ in 0..5 {
        let start = Instant::now();
        let parsed = parse_spec(&src).expect("parse large spec");
        parse_durations.push(start.elapsed());
        spec = Some(parsed);
    }
    let spec = spec.unwrap();
    assert_eq!(spec.requirements.len(), 5_000);

    parse_durations.sort();
    let parse_median = parse_durations[parse_durations.len() / 2];
    assert!(
        parse_median.as_millis() < 500,
        "parsing 5,000 requirements took a median of {parse_median:?} across {} runs \
         (all samples: {parse_durations:?}) — possible quadratic blowup",
        parse_durations.len(),
    );

    let mut render_durations = Vec::new();
    let mut rendered = String::new();
    for _ in 0..5 {
        let start = Instant::now();
        rendered = render_spec(&spec);
        render_durations.push(start.elapsed());
    }
    render_durations.sort();
    let render_median = render_durations[render_durations.len() / 2];
    assert!(
        render_median.as_millis() < 500,
        "rendering 5,000 requirements took a median of {render_median:?} across {} runs",
        render_durations.len(),
    );

    // Must also remain a lossless, stable round-trip at this scale.
    let reparsed = parse_spec(&rendered).expect("reparse rendered large spec");
    assert_eq!(spec, reparsed, "large spec must survive render round-trip");
}

/// The parser and renderer hold no shared mutable/global state, so parsing
/// the same input concurrently from many threads must be deterministic: every
/// thread observes an identical model. A future refactor that introduces
/// interior mutability (e.g. a shared cache) without synchronization would
/// show up here as a divergence or a panic.
#[test]
fn concurrent_parses_of_the_same_input_are_deterministic() {
    let src = Arc::new(generate_large_spec(200));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let src = Arc::clone(&src);
            std::thread::spawn(move || parse_spec(&src).expect("parse in worker thread"))
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (i, r) in results.iter().enumerate().skip(1) {
        assert_eq!(
            r, &results[0],
            "thread {i} produced a divergent parse result"
        );
    }
}
