# Doc validation

## Actor

Architect+Designer

## Architect lens

Every cited symbol, line, and behavioral claim in `documentation.md` was
re-verified against the working tree (`git diff HEAD -- crates/mpd/`), the
tree-built `./target/debug/mpd`, and the upstream artifacts. All accuracy
checks pass:

- **Predicate self-validation (claimed at `closure.rs:2059`).** Confirmed:
  `scope_is_documentation_only` is at `crates/mpd/src/closure.rs:2059`; it
  rejects an invalid change name via `validate_change_name` (2060–2062),
  rejects empty `paths` (2063–2065, `predicate(∅) = false`), and runs
  `digest::validate_canonical_path(pattern).is_ok() && doc_safe_pattern(...)`
  (2071) — short-circuit `&&`, so canonical validation precedes any prefix
  check, exactly as documented. The "load_manifest performs none" claim is
  true: `load_manifest` (`closure.rs:1638–1647`) only deserializes, never
  calls `ChangeManifest::validate`.
- **Allowlist shape (claimed 2023–2025 / 2037–2042).** Confirmed byte-for-byte:
  `root_markdown` at 2023–2025 (`!pattern.contains('/') &&
  pattern.ends_with(".md")` — literal `.md` suffix, single segment);
  `doc_safe_pattern` at 2037–2042 with exactly the four documented shapes:
  `docs/`, `openspec/specs/`, `openspec/changes/{change}/` (trailing slash
  mandatory via the `format!` literal), or `root_markdown`. One
  non-qualifying pattern poisons the whole scope via the `.all(...)`
  conjunction at 2066–2072.
- **Classifier v2 (claimed 2090, version at 2014).** Confirmed:
  `classify_effective_risk` at 2090; `RISK_CLASSIFIER_VERSION: u32 = 2` at
  2014. Under a true predicate (2181–2190) `derived = RiskLevel::Low` and
  every collected reason — the two synthetic signals pushed at 2161–2172
  and any keyword hit on a doc path — is relabeled `suppressed:<reason>`
  (2183–2186), never dropped; the false predicate branch (2191–2197) is
  v1-identical. The Purpose section's v1 citation (`closure.rs:2088-2099`,
  "pre-existing v1 logic") checks out against `git show
  HEAD:crates/mpd/src/closure.rs` — those lines are exactly the two
  synthetic-signal pushes in the pre-change file.
- **Max law unchanged (claimed 2199).** Grep-confirmed: `let effective =
  requested.max(derived);` at `closure.rs:2199`, and the identical line
  existed at HEAD (`closure.rs:2107` pre-change) — verbatim v1, requested
  Medium/High never lowered.
- **Digest binding.** The tuple at 2200–2207 serializes
  `(RISK_CLASSIFIER_VERSION, paths, reasons, deploy-bit,
  local-validation-bit, predicate_holds)` — version, suppressed set (inside
  `reasons`), and predicate outcome are all in the preimage, as documented.
  Governance-key staleness rewinds via `stale_dependency_rewind`
  (`closure.rs:2328–2331`).
- **Selection (claimed 2243).** Confirmed: `select_gate_profile` at 2243;
  `docs_lane = effective == RiskLevel::Low && scope_is_documentation_only(...)`
  (2250) — *exactly* Low, live predicate — and the docs profile applies only
  when the corresponding `Option` field is configured
  (`docs.filter(|_| docs_lane)` at 2269, else the full profile). The floor
  blocks loudly: `Err("config-policy blocker: ... omits a required
  secret-scan check")` at 2290–2295 (all three profiles) and the
  `doc-check` requirement at 2296–2301 for Build/Test only
  (`requires_doc_check` true at 2252/2261, false for SecurityCode at
  2253–2257) — never a silent fallback. Both documented callers verified:
  the strict gate executor passes a freshly loaded live manifest
  (`cli.rs:3301–3309`) into the same `validate_candidate_profile` path
  (`cli.rs:3323`); post-archive workflow status (`cli.rs:1568–1584`)
  synthesizes its manifest from `archive_closure.allowed_paths`, which is
  built as declared scope ∪ `SystemScope::paths()` (`cli.rs:6407–6411`) and
  therefore always contains `.mpd/state/<change>.json`
  (`closure.rs:1702`, `2715`) — never doc-safe, so the predicate can never
  hold there, exactly as documented.
- **This repository's config.** `grep -n docs .mpd/config.json` → no match:
  no `docs-build`/`docs-security-code`/`docs-test` keys exist; `gates`
  carries only the five full profiles. Byte-identical behavior confirmed
  live: `./target/debug/mpd status --json` on this change reports
  `classifier_version: 2` with the raw (unsuppressed) reasons
  `deployment-configured`, `local-validation-process-hook-sandbox-policy`,
  `unknown-sensitive-path: .mpd/state/proportionate-governance.json` and
  `effective: high` — the v1-identical path for a non-doc-only scope.
- **Residual-surface claims.** `docs-build` unwired: the `BuildOutputV1`
  attachment is keyed on the canonical build profile name only
  (`local_validation.rs:7006` `profile == candidate_policy.gates.build`,
  `:7331` `profile_name == config.gates.build` — no `docs_build` arm), and
  Deploy refuses loudly without a typed build output (`cli.rs:2907–2908`
  "Build candidate profile passed without a typed BuildOutputV1";
  `cli.rs:3498–3510` "Deploy gate refused: typed execute Deploy requires
  build_output"). False-cognate: the `process` needle in the
  `process-execution` category (`closure.rs:2117`) does fire on
  `openspec/specs/process-governance/spec.md` and is relabeled
  `suppressed:` only under the doc-only predicate — the Value section's
  claim is correctly scoped by its surrounding fail-closed-conjunction
  sentence, and the Functional details state the relabel-not-drop semantics
  precisely.
- **Test/verification claims vs test.md.** "684 tests passed, 0 failed,
  1 deliberately ignored (100 MB digest-throughput benchmark)" matches
  test.md's Results verbatim. C1-closed matches: the three property names in
  documentation.md are byte-identical to test.md's and exist in the tree
  (`closure.rs:4899`, `:4966`, `:5029`, inside `mod risk_classifier_tests`
  at 4575). The `effective_risk_max_law` characterization ("abstract
  `RiskLevel::max` ordinal law, never `classify_effective_risk` itself") is
  accurate (`ledger.rs:3175`, u8 draws only). Security quotes check out
  against security-code.md: verdict CONDITIONAL PASS, sole condition C1,
  the quoted "the escape hatch is airtight in the actual code", and the
  five refutation attempts as listed. The deferred live docs-profile e2e is
  stated with the same rationale and forward recommendation as test.md.
  The documented e2e behavior ("`\"paths\": [\"docs/**\"]` at `--risk low`
  resolves `effective: low`") is pinned by the compiled-binary e2e
  (`e2e.rs:1678`, asserts requested/derived/effective all `low`,
  `classifier_version: 2`).

Nothing is overstated; the rigor-lowering feature's preconditions (opt-in
config, exactly-Low, live predicate, fail-closed floor, unwired here) are
stated at or below their actual strength. **Architect lens: accurate.**

## Designer lens

Vocabulary and operator-surface checks:

- **Established vocabulary** — scope, declared manifest scope
  (`paths ∪ shared_paths`), derived/effective risk, classifier, signal
  digest, docs profile/lane, floor, sensitive root, rewind, receipts — all
  used with their codebase meanings; no invented terms. `GateProfiles`
  fields (`docs_build`/`docs_security_code`/`docs_test`,
  `config.rs:283–288`) and `CheckKind::DocCheck` (`config.rs:253`) are
  named exactly as shipped.
- **Operator-visible behavior claims** — accurate: a docs-only `--risk low`
  change resolves Low (e2e-pinned); code-touching changes are unchanged
  (live `mpd status --json` on this very change shows the full v1-identical
  High derivation); suppression is auditable in `mpd status --json`
  (the `reasons` array is surfaced there); adoption requires editing
  `.mpd/config.json`, which classifies High under this same classifier
  (`.mpd/` is a sensitive root, `closure.rs:2140`, and never doc-safe).
- **One finding, found and FIXED during this validation.** The first pass of
  this review found the Usage recipe's check block written with snake_case
  `"timeout_secs"`/`"result_policy"`, where `CheckConfig` is
  `#[serde(rename_all = "kebab-case", deny_unknown_fields)]`
  (`config.rs:228–235`) — the documented opt-in shape would have been
  rejected at config load (loud and fail-closed, so no safety
  overstatement, but a broken recipe in the doc's sole actionable section).
  The Documenter applied the exact prescribed fix; re-read after the fix,
  documentation.md lines 176–177 now read `"timeout-secs": 60` and
  `"result-policy": "exit-zero"`, matching this repository's own
  `.mpd/config.json` usage (e.g. the `format` check: `"timeout-secs": 180,
  "result-policy": "exit-zero"`). The full fence was re-verified key by
  key against the shipped serde surface and now parses: `kind`/`program`/
  `args`/`timeout-secs`/`result-policy` are exactly `CheckConfig`'s
  kebab-case fields with no unknown fields and `timeout-secs: 60` within
  the 1..=1800 validation (`config.rs:475`); `"kind": "doc-check"` matches
  `CheckKind::DocCheck` and `"result-policy": "exit-zero"` matches
  `ResultPolicy::ExitZero` (both kebab-case enums); `profiles` entries
  match `ProfileConfig` (`{ "checks": [...] }`); all eight `gates` keys
  match kebab-case `GateProfiles` including `docs-build`/
  `docs-security-code`/`docs-test` (`config.rs:283–288`); top-level
  `local_validation` matches the repository's actual file; and the example
  profiles satisfy the documented floor. Finding closed.

## Verdict

PASS

Both lenses clean. Architect lens: every accuracy check — symbols, line
numbers, predicate self-validation ordering, allowlist shapes, v2
suppression semantics, the unchanged `effective = requested.max(derived)`
law, digest binding, selection preconditions, the loud floor, the
unwired-here guarantee, both residual-surface claims, and the 684-test/C1
evidence — verified against the tree diff and the built
`./target/debug/mpd`. Designer lens: vocabulary, config surface, and
operator-visible behavior claims all accurate; the single first-pass
finding (snake_case `timeout_secs`/`result_policy` in the Usage recipe) was
fixed by the Documenter exactly as prescribed and re-verified — the recipe
now parses against the shipped kebab-case `deny_unknown_fields` config
schema. Nothing in the document overstates the safety of the
rigor-lowering lane.
