## 1. Rule precision (crates/mpd/src/checks/secrets.rs)

- [ ] 1.1 Add `const MIN_TOKEN_RUN: usize = 16;` (after `PLACEHOLDERS`, before `MAX_SCAN_LINE`) with a doc comment: alphabet `[A-Za-z0-9+]`, threshold rationale (AKIA=16 / Stripe tail=16), accepted-miss classes (UUID, grouped keys, slash-bearing base64).
- [ ] 1.2 Add `is_token_char(char) -> bool` and `has_contiguous_token_run(&str) -> bool` (single O(len) pass, no allocation, letter+digit-in-run).
- [ ] 1.3 Replace `generic_secret_assignment`'s final gate (`has_alpha && has_digit`, secrets.rs:246-248) with `has_contiguous_token_run(value)`; extend the function doc comment noting the monotonicity implication (`new_flag ⇒ old_flag`).

## 2. Regression + boundary tests (same file, existing `mod tests`)

- [ ] 2.1 `generic_rule_ignores_filesystem_paths` — the ledger array-element shape, a quoted path assignment, an unquoted env-style path → `None`.
- [ ] 2.2 `generic_rule_ignores_hyphenated_dictionary_values` — dated hyphenated name and a UUID-shaped value under `api_key` → `None` (pinned accepted miss, comment references the design).
- [ ] 2.3 `generic_rule_still_flags_contiguous_digests` — `format!`-assembled 64-hex under `token` (fragments ≤13) → `Some("generic-secret-assignment")`.
- [ ] 2.4 `generic_rule_run_threshold_boundary` — exactly-16 letter+digit run flags; exactly-15 does not.
- [ ] 2.5 `generic_rule_alphabet_pins_plus_and_slash` — `+`-joined 26-char value flags; `/`-joined (runs of 8) does not.

## 3. Property tests (seeded, existing proptest regime)

- [ ] 3.1 `separator_decomposed_values_are_never_generic_flagged` — 3-8 segments of `[a-w0-9]{1,15}` joined by `{/,-,_, }`, embedded `token = "<v>"` → assert NOT `Some("generic-secret-assignment")` (rule-specific, not `== None` — a composed `sk-`/`ghp` tail may legitimately trip a curated rule; Cond 4/12).
- [ ] 3.2 `contiguous_alnum_tokens_are_flagged` — `[a-w0-9]{20,64}` with ≥1 letter and ≥1 digit, embedded `token = "<v>"` → `Some("generic-secret-assignment")`.
- [ ] 3.3 `new_gate_implies_old_gate` (monotonicity, Cond 2/11) — reimplement the OLD gate (len≥20 + non-placeholder + whole-value alpha+digit) in tests; proptest over arbitrary `String` that `has_contiguous_token_run(v) ⇒ old_gate(v)`.

## 4. Spec (openspec/specs/local-validation/spec.md — via change delta)

- [ ] 4.1 Add "Path-precise generic secret detection" requirement + the two scenarios.

## 5. Verification

- [ ] 5.1 Full suite green with a real non-zero count (`cargo test -p mpd`).
- [ ] 5.2 `first_party_source_is_scanner_clean` (secrets.rs:513) green with empty `SOURCE_HYGIENE_ALLOW` (no allow entries added).
- [ ] 5.3 Confirm the live ledger false positives (`.mpd/state/*.json` archive-path lines) are no longer flagged by the built-in scanner.
- [ ] 5.4 Empirically scan `.mpd/state/**` with the allowlist exemption IGNORED and record the finding count (Cond 3/13); if zero, file a follow-up to narrow/remove the `.mpd/state/**` entry. `.mpd/secret-allowlist.json` stays unchanged in this change (scope discipline).
