# Test report: Harness-first README quickstart

## Actor

Tester-Sol-72

## Coverage

Functional and regression coverage checks the requested placement, both exact copy-ready
outcome prompts, Codex/Claude harness separation, model-owned command language, external
release boundary, missing-setup state, `Everyday flow` anchor, balanced code fences, and a
single bounded README diff hunk. Current help verifies that `conduct` exists without a
`--harness` option and `next` owns `--harness`.

Accessibility/nonfunctional coverage inspects semantic heading order, numbered steps,
explicit text labels, plain-text copyability, narrow-line wrapping, and no color-dependent
meaning. Performance, load, resource, concurrency, fuzz/property, and metamorphic tests are
not applicable to static Markdown with no runtime, parser, structured input, or UI state.
The governance-selected profile still exercises the complete repository verifier and typed
artifact contract on the exact Candidate.

## Results

- README content/structure/command assertions: 15 passed, 0 failed.
- document staleness: PASS across 19 current Markdown files.
- whitespace validation: PASS.
- Build profile: PASS with a typed Candidate artifact and four checks.
- Security(code) and Design Sign-off: PASS on the actual built copy.

The MPD Test gate must additionally pass the high-risk local profile with a real non-zero
test count; any red or no-op verifier blocks this report.

## Verdict

PASS
