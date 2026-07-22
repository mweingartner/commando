# Security (code) review

## Actor

Security (claude-code harness, deep tier — high-risk deep_tier_bump). Code-stage
audit of the real implementation on disk.

## Findings

No Critical/High. The rule logic is correct and the monotonic-tightening claim
holds in the real code. Two Low advisories were fixed inline (A1, A2 below);
three Medium conditions (C1-C3) are closed or carried per their owners.

## Conditions verified

Verified against the real `crates/mpd/src/checks/secrets.rs`:

- **Helper correct, no silent disablement.** `is_token_char` (:299-301) =
  `is_ascii_alphanumeric() || c == '+'` (alphabet exactly `[A-Za-z0-9+]`).
  `has_contiguous_token_run` (:319-344) evaluates the just-ended run before
  reset, catches a run ending at EOF (no off-by-one), and resets run-len +
  letter-seen + digit-seen together (letter AND digit required WITHIN one run —
  the cross-run-leakage probe `abcdefghijklmnopq-2` correctly does NOT flag).
- **Monotonicity (Security-plan Condition 2) — CLOSED.** A qualifying run donates
  its letter+digit to the whole value; upstream gates unchanged ⇒ strict subset.
  `new_gate_implies_old_gate` (:935) asserts `has_contiguous_token_run(v) ⇒
  old_whole_value_gate(v)` over `any::<String>()`; the reference gate (:837) is
  faithful. Seed-persisted.
- **Rule-specific proptest (Security-plan Condition 4) — CLOSED.**
  `separator_decomposed_values_are_never_generic_flagged` (:891) asserts
  `!= Some("generic-secret-assignment")`, not `== None`; generators constrained
  (`[a-w0-9]{1,15}` segments, `/ - _ ' '` joins).
- **Existing positives still flag**: secrets.rs:378/:404 (20/27-run), the planted
  `token = "abc123…"` (24-run) at local_validation.rs (10 sites) + checks/mod.rs:371,
  and the window-truncation pin (label unchanged).
- **Scope**: only secrets.rs; `scan_line` order + nine curated rules +
  extraction + PLACEHOLDERS + windowing content-unchanged; `.mpd/secret-allowlist.json`
  and `checks/mod.rs` untouched.
- **Source hygiene**: every new fixture assembled via `format!`/`concat!`
  (fragments <16 token-alphabet chars); `first_party_source_is_scanner_clean`
  green with empty `SOURCE_HYGIENE_ALLOW`.

## Independent review

Fresh miss-hunt (novel surface): probed hex digests, `npm_`, SendGrid `SG.`,
base32 TOTP seeds, Heroku-UUID, separator-broken passphrases — every realistic
accidental-commit shape with no dedicated rule either flags or is already in the
design's accepted-miss table (UUID/grouped/passphrase). No un-documented miss.
Push-time scan confirmed: `.githooks/pre-push` → `scan_outgoing_objects`
(local_validation.rs:6738-6797) scans every outgoing blob/commit/tag fail-closed.

## Refutation

Strongest attacks: (1) cross-run letter+digit leakage → refuted (state resets
together). (2) `+`-in-alphabet creating a new positive → refuted (a `+`-only run
lacks letter/digit; any qualifying run keeps whole-value alpha+digit, so still
⊂ old). (3) an unbranded accidental-commit secret with no ≥16 run and no dedicated
rule → only the documented accepted classes (UUID/grouped/short-slash-base64/
Azure-glpat env form), all compensated by adjacent AKIA detection, branded-prefix
rules, and gitleaks. Refutation produced no new blocking finding.

## Verdict

**CONDITIONAL PASS.** Security-plan Conditions 2 and 4 are CLOSED (present and
correct on disk). Remaining conditions:

- **C1 [Medium — orchestrator] Diff confinement — CLOSED.** The read-only
  reviewer could not run `git diff`. Evidence: `git diff --name-only -- crates/`
  shows only `crates/mpd/src/checks/secrets.rs`; the curated rules / extraction /
  PLACEHOLDERS / windowing are byte-unchanged. Recorded here.
- **C2 [Medium — Builder/verification] Empirical `.mpd/state/**` scan — CLOSED.**
  The built-in scanner run over `.mpd/state/**` with the exemption ignored found
  **0 raw findings across 19 files** (Builder), corroborated by the reviewer's
  independent keyword+run sweep. Follow-up to narrow/remove the exemption filed
  (task_a098de26). Design condition 13 / tasks 5.4 closed.
- **C3 [Medium — Architect follow-up, NON-BLOCKING] CI absent.** `.github/workflows/`
  is empty (ci.yml deleted); the gitleaks compensation has no push-side machine
  backing on clones without local hooks/gitleaks. Follow-up filed
  (restore `cargo test` + gitleaks CI). Does not block this change.
- **A1 [Low] — FIXED inline.** `contiguous_alnum_tokens_are_flagged`'s
  `[a-w0-9]{20,64}` generator could compose a `PLACEHOLDERS` substring
  (`todo`/`changeme`/`redacted`/`placeholder`/`dummy`), which the rule suppresses
  → a seed-persisted spurious failure. The `prop_filter` now excludes any
  `PLACEHOLDERS` substring (referencing the same const the rule uses).
- **A2 [Low] — FIXED inline.** The `first_party_source_is_scanner_clean` doc
  comment claimed `scan_secrets` is `unwrap_or_default()` fail-open; after
  scan-secrets-fail-closed it is fail-closed. Reworded to the accurate rationale
  (the guard uses `scan_paths` for raw findings, not the report wrapper).
- **A3 [Low] — accepted.** Monotonicity proptest premise is often vacuous over
  arbitrary unicode; the analytic proof carries the weight. Not fixed.

## Re-review addendum (A1/A2 fix delta)

A1 and A2 are test-robustness (a `prop_filter` predicate) and a doc-comment
reword — the security-relevant surface (the `is_token_char`/`has_contiguous_token_run`
helpers, the `generic_secret_assignment` gate slot-in, and all nine curated rules)
is byte-identical to what was audited above. The fix stales the Build candidate,
so Build → Security (code) → Test re-run over the corrected tree; the verdict is
unchanged. No secret-shaped literal was introduced (the A1 comment names
placeholder words, none ≥16 token chars; A2 is prose).

Test-phase delta (also test/comment only, rule logic byte-identical): the Tester
found the `MIN_TOKEN_RUN` doc comment overclaimed "each accepted-miss is pinned by
a test" — the grouped-keys class had no dedicated pin, and the Azure/GitLab
classes are probabilistic (not deterministically pinnable). Closed by adding
`generic_rule_ignores_grouped_keys` (fixture `AAAA-1111-BBBB-2222-CCCC-3333`, all
runs ≤4, scanner-clean as a literal) and rewording the comment to distinguish
deterministic-pinned (UUID, grouped-keys, slash-in-token) from
probabilistic-documented (Azure/GitLab). No rule-logic change.
