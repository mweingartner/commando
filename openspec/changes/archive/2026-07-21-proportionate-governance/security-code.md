# Security (code) review

## Actor

Security

## Findings

Full-depth audit of the real diff (`git diff HEAD -- crates/mpd/`), no inline
fixes performed. No behavior- or trust-affecting path into the light lane was
found. Findings, most severe first:

- **F-1 (low, test-adequacy — deviation from design Conditions 3 and 6).**
  Design Condition 3 instructs "the existing `effective_risk_max_law` property
  test is extended to classifier v2"; `crates/mpd/src/ledger.rs:3175-3183` is
  untouched and still exercises only the abstract `RiskLevel::max` ordinal law —
  it never calls `classify_effective_risk`. Likewise Condition 6's
  classifier-level invariants (suppression iff predicate; `signal_digest`
  changes whenever the predicate outcome or suppressed set changes) are pinned
  by example tests only
  (`closure.rs` `predicate_true_never_lowers_a_requested_medium_or_high`,
  `signal_digest_changes_when_the_predicate_flips_for_the_same_underlying_signal`,
  `each_condition_5_deny_pattern_keeps_full_unsuppressed_derivation_alongside_a_doc_pattern`),
  not by a seeded property over arbitrary scope × requested-level inputs. The
  invariant itself is enforced in code at a single site
  (`closure.rs:2199`, `effective = requested.max(derived)`, verbatim v1) and
  the named High/Medium corners are example-tested, so this is not
  exploitable; the Builder disclosed the deviation in `tasks.md` 2.3. Attack
  prevented by closing it: a future refactor of the classifier's derivation
  arm regressing the max-law or the suppression-iff-predicate coupling in a
  corner the example tests do not enumerate. Remediation: a seeded classifier-
  level proptest (scope drawn from allow ∪ deny corpora × requested level)
  asserting `effective.rank() >= requested.rank()`, suppression markers
  present iff the predicate holds, and digest sensitivity. See Verdict
  condition C1.
- **F-2 (informational — Condition 12 met via its fallback arm, disclosed).**
  `cmd_gate` does perform a second `load_manifest` at selection time
  (`cli.rs:3301-3302`) rather than passing through the freshness refresh's
  snapshot. Condition 12's own escape clause applies: divergence between the
  two reads must demonstrably resolve to full profiles, and it does — see
  Refutation attack 2 and the two helper-level tests cited there. Recorded as
  a fact, not a defect.
- **F-3 (informational — Builder disclosure verified fail-safe).** The typed
  `BuildOutputV1` attachment predicates key on the canonical `gates.build`
  profile name only (`local_validation.rs:7006` and `:7331`); a selected
  `docs-build` profile therefore never attaches a build output. This fails
  safe, not silent: a typed-execute Deploy requires the contract and the Build
  record's output and refuses loudly when either is absent
  (`cli.rs:3498-3510`). The caveat and the two remediation options are
  documented in `docs/proportionate-governance.md` ("Residual surfaces").
- **F-4 (informational — Builder disclosure verified fail-safe).** Post-archive
  workflow status can never select a docs profile: the synthetic manifest is
  rebuilt from the archive closure's frozen `allowed_paths`
  (`cli.rs:1568-1585`), which always contains `SystemScope::paths()`
  (`closure.rs:1701-1711`) — including `.mpd/state/<change>.json` and the
  bare, trailing-slash-less `openspec/changes/<change>` — both of which fail
  `doc_safe_pattern`. The `unwrap_or_else(ChangeManifest::seed)` fallback
  (`cli.rs:1577`) yields empty `paths`, and `predicate(∅) = false`
  (`closure.rs:2064-2066`). Either way selection resolves to exactly today's
  High/non-High Test split; behavior is byte-identical to the replaced code.

## Conditions verified

All fourteen (design.md 1-9, security-plan.md 10-14) were checked against the
shipped code; each holds.

1. **Allowlist, fail-closed (Cond 1).** `doc_safe_pattern`
   (`closure.rs:2037-2042`) is exactly the D1 allowlist: byte-exact
   `str::starts_with` on `docs/`, `openspec/specs/`,
   `openspec/changes/{change}/` (trailing slash inside the literal, so the
   bare dir and `-evil` siblings fail), plus `root_markdown`
   (`closure.rs:2023-2025`: no `/`, literal `.md` suffix). No normalization,
   no case folding anywhere. Deny corpus of 27 patterns + overlong pattern all
   refuse (`predicate_denies_the_full_deny_corpus`,
   `an_overlong_pattern_is_not_safe` — executed, pass).
2. **Mixed scope poisons (Cond 2).** `scope_is_documentation_only` is
   `all(...)` over `paths ∪ shared_paths` (`closure.rs:2067-2074`); one bad
   pattern anywhere — including in `shared_paths` — falls through to the
   v1-identical `else` arm of the classifier with zero suppression
   (`closure.rs:2189-2196`). Verified by
   `one_deny_pattern_in_shared_paths_poisons_an_otherwise_safe_paths_list` and
   `each_condition_5_deny_pattern_keeps_full_unsuppressed_derivation_alongside_a_doc_pattern`
   (every deny pattern paired with a doc pattern still derives High with the
   raw `deployment-configured` reason present and no
   `documentation-only-scope` marker).
3. **Only synthetic signals suppressed; max-law verbatim (Cond 3).**
   `effective = requested.max(derived)` unchanged at `closure.rs:2199`.
   Suppression is reachable only when the predicate holds
   (`closure.rs:2181-2188`), and under a true predicate the suppressed set is
   structurally confined: no doc-safe pattern can begin with any
   `sensitive_roots` prefix (all are multi-segment non-doc roots;
   `security.md` ≠ `security/`), so `unknown-sensitive-path` can never
   coexist with the predicate — the suppressed set is exactly the two config
   synthetics plus keyword false-cognates on allowlist-proven doc paths, per
   D2. Requested Medium/High never lowered
   (`predicate_true_never_lowers_a_requested_medium_or_high`). Property-test
   extension deferred — F-1/C1.
4. **Floor enforced loudly (Cond 4).** `select_gate_profile` resolves the
   selected docs profile post-`includes` via `effective_checks`
   (`config.rs:582-628`, cycle-detecting, unknown-profile/-check erroring) and
   requires ≥1 `SecretScan` kind always and ≥1 `DocCheck` kind for
   Build/Test (`closure.rs:2280-2300`); violation returns an explicit
   `config-policy blocker` `Err` (`closure.rs:2291-2299`) which propagates as
   a hard command error — never a silent fallback, never a skipped scan.
   Unconfigured fields select exactly today's profiles
   (`unconfigured_docs_fields_select_exactly_todays_profiles`).
5. **Negative corpus (Cond 5).** Every named pattern — `crates/**`,
   `security/**`, `.githooks/**`, `.mpd/config.json`, `.mpd/**`, `scripts/**`,
   `Cargo.toml`, `Cargo.lock`, `.github/**`, `openspec/schemas/**`, another
   change's dir, root non-markdown, wildcard-leading — appears in both the
   predicate deny corpus and the classifier-level mixed-scope test, deriving
   full v1 High and full profiles
   (`mixed_scope_falls_back_to_full_profiles_even_when_docs_lane_is_configured`).
6. **Property tests (Cond 6).** Seeded proptest suite present and passing:
   conjunction law over non-empty operands, monotone poisoning from non-empty
   not-safe, empty-scope property, allow-corpus always safe, deny-corpus never
   safe under decoration (`closure.rs` `scope_is_documentation_only_tests`).
   Classifier-level invariants example-based only — F-1/C1.
7. **Versioning and digest binding (Cond 7).** `RISK_CLASSIFIER_VERSION = 2`
   (`closure.rs:2014`); the signal tuple binds the version, the paths, the
   reasons (which encode the relabeled `suppressed:` set), both config bits,
   and `predicate_holds` (`closure.rs:2200-2208`). Stored assessments are a
   cache: `enforce_freshness_before_effects` (`cli.rs:1961`) recomputes from
   the live manifest via `current_risk_assessment` (`cli.rs:1943-1958`) before
   any effect, so v1↔v2 transitions change `signal_digest`, stale the
   Governance dependency, and rewind — in both directions; no ledger is
   migrated in place.
8. **One selection function (Cond 8).** `select_gate_profile`
   (`closure.rs:2243`) is the only selection logic; the strict gate executor
   (`cli.rs:3303-3310`) and post-archive workflow status (`cli.rs:1578-1584`)
   both delegate to it. `docs_lane` is recomputed inside the helper from the
   supplied manifest and effective risk (`closure.rs:2250`) — no cached or
   ledger-stored boolean exists anywhere in the diff.
9. **Machinery untouched (Cond 9).** Non-Build phases feed the selected name
   into the unchanged `validate_candidate_profile` with the same
   reopen-before/reopen-after candidate revalidation and
   `validate_candidate_report_binding` exact-subject pinning
   (`cli.rs:3318-3348`); Build feeds it through
   `execute_strict_candidate_build` (`cli.rs:2864-2900`), whose only change is
   accepting the profile name instead of hard-coding `gates.build`.
   `validate_candidate_profile`/`_inner` themselves have zero changed lines.
   This repository's `.mpd/config.json` contains no `docs-*` keys (grep
   verified) — behavior here is byte-identical.
10. **Predicate trusts no caller (Cond 10 / F1).** `scope_is_documentation_only`
    first validates the `change` argument via `validate_change_name`
    (`closure.rs:2060-2062`; kebab-only `[a-z0-9-]`,
    `openspec-core/src/names.rs:12-34` — no dots, slashes, or glob
    metacharacters, so the concatenated own-dir prefix is wildcard-free by
    construction), then rejects empty `paths` (`closure.rs:2064-2066`), then
    requires `digest::validate_canonical_path` per pattern *before* the
    prefix check (`closure.rs:2067-2074`, short-circuit `&&`).
    `validate_canonical_path` (`digest.rs:205-221`) rejects empty, >4096-byte,
    absolute, backslash, NUL, control-character, and empty/`.`/`..`-segment
    patterns. `load_manifest` (`closure.rs:1638-1647`) indeed performs no
    `ChangeManifest::validate` — the predicate's self-validation is what
    closes F1, and the Condition 10 extended deny corpus
    (`docs/../crates/**`, `docs//x`, `docs/./x`, `docs\evil`, control byte,
    overlong, `docs\u{200B}/x`, `**`, `*`, bare own dir, `-evil` sibling) is
    all present and refusing.
11. **Empty scope (Cond 11 / F2).** `predicate(∅) = false` by an explicit
    early return (`closure.rs:2064-2066`), with a dedicated example test
    (including safe `shared_paths` alongside empty `paths`), a dedicated
    property test, and a classifier-level test proving the empty scope falls
    through to unsuppressed v1 derivation
    (`empty_scope_never_suppresses_even_when_no_keyword_reason_fires`). The
    conjunction/monotone laws are restated over non-empty operands exactly as
    the condition demands; the forbidden "fix" was not taken.
12. **Single snapshot / divergence fail-safe (Cond 12).** Met via the
    condition's fallback arm — see F-2 and Refutation attack 2.
13. **Medium excluded by construction (Cond 13).** `docs_lane` requires
    `effective == RiskLevel::Low` exactly (`closure.rs:2250`); the Test-High
    short-circuit precedes any docs consideration (`closure.rs:2258-2260`).
    Pinned by
    `medium_or_high_effective_risk_excludes_the_docs_lane_even_for_a_pure_doc_scope`.
14. **Residuals documented (Cond 14).** `docs/proportionate-governance.md`
    "Residual surfaces" states all four: unchanged prose/LLM-injection surface
    with the zero-differential reasoning, the directory-shaped (non-extension)
    allowlist admitting non-markdown, the kind-not-efficacy floor with the
    High-rigor `.mpd/config.json` backstop, and the classifier-bump
    availability cost — plus the F-3 build-output caveat.

Machine verification: 30 targeted unit/property tests
(`scope_is_documentation_only_tests`, `select_gate_profile_tests`,
`risk_classifier_tests`) and both new e2e tests
(`documentation_only_scope_resolves_low_on_a_deployment_configured_repo_but_mixed_scope_stays_high`,
`a_doc_only_change_widening_its_own_manifest_after_architecture_pass_stales_evidence_and_rewinds`)
executed during this review: 32 passed, 0 failed.

## Independent review

A second pass deliberately distrusted the first and re-derived the escape
question from the glob matcher outward instead of from the predicate inward:
enumerate every pattern shape the predicate can accept, then ask what each can
*match*, using only `pathmatch.rs` semantics. Because `starts_with("docs/")`
fixes the pattern's first segment to the literal `docs` (a wildcard cannot
appear before the first `/` of the prefix), `glob_match`'s segment-by-segment,
byte-exact matching (`pathmatch.rs:18-123` — no normalization, no case
folding, no dot-resolution) can only ever bind such a pattern to index paths
whose first segment is literally `docs`; identically for the two- and
three-segment `openspec/specs/` and own-change prefixes. A `root_markdown`
pattern is single-segment, and `match_segments` cannot match a one-segment
non-`**` pattern against a multi-segment path (`pathmatch.rs:69-95`), so it
reaches only root files literally ending `.md` — including the degenerate
`**.md`, which is not the `**` token (that requires the segment to be exactly
`**`) and collapses to stem wildcards. Unicode decorations inside later
segments (`docs/．．/x`) stay imprisoned under `docs/` because matching is
textual, never filesystem resolution. Conclusion of the independent pass: the
set of paths reachable by any predicate-accepted pattern is exactly
`docs/**` ∪ `openspec/specs/**` ∪ `openspec/changes/<change>/**` ∪ root
`*.md` — no accepted pattern can name a path outside the four roots, and the
independently-enforced staged-scope gate (`cli.rs`, `manifest_view`) and
pre-push profile are unchanged by this diff. The pass also independently
re-checked the two cli.rs integration sites against their surrounding control
flow (freshness ordering at `cli.rs:3100-3116`; post-archive branch guard
`ledger.archive_closure.is_some() && coherence.coherent` at `cli.rs:1547`)
rather than trusting the diff hunks' comments.

## Refutation

Strongest attacks attempted against a PASS, and why each fails:

1. **Suppress a genuine signal.** Declare `docs/auth-tokens.md` and plant real
   credentials or agent-directed prose. The keyword hit is suppressed — but
   the docs lane's floor makes the secret scan unskippable
   (`closure.rs:2291-2295`), both judgment Security reviews still run, the
   staged-scope and pre-push gates are untouched, and nothing in mpd executes
   doc-root content. Differential exposure vs. the full profile is zero:
   clippy/tests/SAST never analyzed prose either. Fails.
2. **TOCTOU the double read.** Swap the manifest between the freshness
   recompute (read A, fixes `effective_risk`, `cli.rs:3100-3116`) and the
   selection reload (read B, `cli.rs:3301`). Doc-only→widened: read B's live
   predicate fails → full profile. Widened→doc-only: `effective` is already
   High from read A → `docs_lane` false → full/high profile. Both directions
   are pinned by
   `mixed_scope_falls_back_to_full_profiles_even_when_docs_lane_is_configured`
   and
   `medium_or_high_effective_risk_excludes_the_docs_lane_even_for_a_pure_doc_scope`.
   Widening *after* read B: judgment receipts recorded under the narrow scope
   carry Scope/Governance dependency digests that no longer match the live
   manifest, so the next effectful command's freshness projection rewinds to
   Architecture (verified live by the widening e2e test) — a light-lane-
   validated candidate under a widened scope can never be consumed
   downstream. Fails.
3. **Replay a v2 Low into a v1 world (or vice versa).** The stored assessment
   is never consulted without recomputation (`cli.rs:1961-1971` before every
   effect), and the digest tuple binds the classifier version
   (`closure.rs:2201`), so any version transition stales Governance-dependent
   evidence and rewinds. Fails.
4. **Reach the lane at Medium, or via config.** `effective == Low` is exact
   (`closure.rs:2250`); a floor-less docs profile blocks loudly rather than
   falling back (attack surface shifts to editing `.mpd/config.json`, which
   is itself a sensitive-root High-rigor change — the documented, accepted
   backstop). Fails.
5. **Escape the prefix.** The full deny corpus — traversal, doubled/empty
   segments, backslash, control bytes, zero-width Unicode, case variants,
   leading wildcards, sibling and cross-change dirs, overlong patterns — is
   mechanically refused by self-validation plus byte-exact prefixes, and the
   independent review's matcher-outward derivation shows no accepted pattern
   can name a path outside the four doc roots. Fails.

The one finding the refutation produced is F-1: the corners are example-
tested, not property-swept, at the classifier level — a robustness gap in the
*test net*, not a hole in the mechanism.

## Verdict

CONDITIONAL PASS

The escape hatch is airtight in the actual code: the predicate self-validates
and fail-closes (Cond 10/11), `effective = requested.max(derived)` is
verbatim v1 (`closure.rs:2199`), one non-doc pattern anywhere restores full
unsuppressed derivation, the docs lane requires exactly-Low plus a live
predicate re-check at one shared selection site, the floor blocks loudly with
an unskippable secret scan, the sandbox machinery is byte-identical, replay is
closed by version-bound digests plus pre-effect recomputation, and this
repository's own config leaves the lane unwired. No behavior- or
trust-affecting change can reach the light lane. 32 targeted tests executed
and passed during this review.

Condition (owner: Tester, at the Test phase — additive test code only; any
change to the classifier/selection kernel itself would instead re-run
Security per design.md):

- **C1 (closes F-1).** Add a seeded classifier-level property test alongside
  `risk_classifier_tests`: for scopes drawn from the allow ∪ deny corpora and
  all requested levels, `effective.rank() >= requested.rank()`,
  `suppressed:`/`documentation-only-scope` markers appear iff
  `scope_is_documentation_only` holds, and `signal_digest` differs whenever
  the predicate outcome or suppressed set differs. Closing evidence: the
  named proptest in `crates/mpd/src/closure.rs`, executed green in the Test
  gate's suite.

Unresolved, C1 blocks deployment per protocol; it does not reopen Build.
