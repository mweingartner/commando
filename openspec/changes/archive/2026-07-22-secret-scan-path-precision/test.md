# Test report

## Actor

Tester (claude-code harness). Verification + adequacy pass; the Builder wrote the
full test set (Security-code verified it), so this phase runs at scale and
assesses adequacy rather than re-writing.

## Coverage

**Functional — the precision rule:**
- `generic_rule_ignores_filesystem_paths` — the exact motivating ledger
  array-element line, a quoted `archive_path:` assignment, and an unquoted
  `SECRET_STATE=.mpd/state/…json` line → all clean.
- `generic_rule_ignores_hyphenated_dictionary_values` — dated hyphenated name +
  UUID (longest run 12) → clean (pinned accepted misses).
- `generic_rule_ignores_grouped_keys` — 4-char-grouped key
  `AAAA-1111-BBBB-2222-CCCC-3333` (all runs 4) → clean (pinned accepted miss;
  added this phase to make the `MIN_TOKEN_RUN` doc comment's "pinned" claim true).
- `generic_rule_still_flags_contiguous_digests` — `format!`-assembled 64-hex →
  flagged.
- `generic_rule_run_threshold_boundary` — exactly-16 run flags; exactly-15 does
  not (both directions).
- `generic_rule_alphabet_pins_plus_and_slash` — `+`-joined flags; `/`-joined
  (runs of 8) does not.

**Property / metamorphic (seeded, reproducible):**
- `new_gate_implies_old_gate` (monotonicity, Security-plan Condition 2) — over
  `any::<String>()`; **200,000 cases** in a stress run, pass.
- `separator_decomposed_values_are_never_generic_flagged` (Condition 4) —
  rule-specific `!= Some("generic-secret-assignment")`; **50,000 cases**, pass.
- `contiguous_alnum_tokens_are_flagged` — 50,000 cases, pass (the
  `PLACEHOLDERS`-exclusion filter added at Security review does not over-reject).
- `detection_is_invariant_to_token_position` (existing metamorphic, window-straddle
  band) — 50,000 cases, pass.

**Non-functional:** `has_contiguous_token_run` (secrets.rs:319-344) is a single
O(len) pass, no allocation, over the original slice; `scan_line_windows` caps each
window at `MAX_SCAN_LINE` (4096) so total work is O(N). `long_line_is_bounded`
(1M-char adversarial line) passes with no measurable regression; no quadratic
behavior.

**End-to-end:** `cargo run -p mpd -- check` over the live tree produces zero raw
findings under `.mpd/state/**` — the motivating false positive is gone (Security-code
C2, corroborated). (That run exits 1 on an unrelated semgrep finding elsewhere in
the repo; `semgrep` over `secrets.rs` alone is 0 findings — out of scope here.)

## Results

Command: `cargo test -p mpd` and `cargo test --workspace`.
```
(bins)       test result: ok. 486 passed; 0 failed; 1 ignored; 0 measured
(e2e)        test result: ok. 107 passed; 0 failed; 0 ignored; 0 measured
(workspace)  openspec-core: 58 + 5 + 15 + 2 + 16 + 20 + 9 + 5 passed; 0 failed
```
`cargo clippy -p mpd --tests -- -D warnings` clean; `cargo fmt --all -- --check`
clean. Reruns identical (zero flakiness across 5 invocations; proptests stable at
elevated case counts). The 1 ignored is the pre-existing by-design perf `#[ignore]`.
After the grouped-keys pin was added, the affected tests were independently
re-run green and `git diff` confirms only `crates/mpd/src/checks/secrets.rs`
changed.

## Verdict

PASS — full suite green with real non-zero counts; monotonicity proven at scale;
accepted-miss classes pinned; the doc-comment overclaim found this phase was
corrected. No product defect; the security control is tighter (fewer false
positives) with every dedicated-covered secret shape unaffected.
