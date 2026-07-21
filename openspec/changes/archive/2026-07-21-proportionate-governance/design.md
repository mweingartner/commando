# Design: Proportionate Governance

## Actor

Architect

## Context

This file is the canonical current-state contract. Move superseded drafts and
reviews to `history/`; do not accumulate contradictory amendments here.

Observed empirically all session: a two-file docs/chore change is escalated to
effective-high risk and forced through the full sandbox candidate validation at every
objective gate. Root cause, verified against the current tree:

- **Classification.** `classify_effective_risk` (`crates/mpd/src/closure.rs:2018-2124`)
  derives risk from two input families: (a) per-path signals — nine keyword categories
  substring-matched over the lowercased declared patterns plus a `sensitive_roots`
  prefix list (`closure.rs:2029-2087`); (b) **repo-configuration signals that ignore
  scope entirely**: `config.deploy.is_some() || local_validation.deploy_output` pushes
  `"deployment-configured"` (`closure.rs:2088-2096`) and `config.local_validation.is_some()`
  pushes `"local-validation-process-hook-sandbox-policy"` (`closure.rs:2097-2099`).
  Derivation is binary: *any* reason at all yields `derived = High`
  (`closure.rs:2102-2106`); there is no Medium tier. `effective = requested.max(derived)`
  (`closure.rs:2107`). On this repository `.mpd/config.json` always carries
  `local_validation` (with `deploy-output`), so both synthetic signals fire on every
  change and `mpd conduct <change> --risk low` still resolves effective-high.
- **Consumption.** `Ledger::effective_risk` (`crates/mpd/src/ledger.rs:941-946`) reads
  `risk_assessment.effective`, falling back to `governance.risk`. The assessment is
  recomputed from the live manifest before every effectful command
  (`current_risk_assessment`, `crates/mpd/src/cli.rs:1912-1924`, called from
  `enforce_freshness_before_effects`, `cli.rs:1929-1940`) and is a gate-evidence
  dependency (`DependencyKey::{Scope, Governance}`, `closure.rs:68-78`), so scope or
  governance drift stales downstream evidence and forces a causal rewind.
- **Profile selection.** Under strict, Build/Security(code)/Test delegate to the
  structured candidate validator with a fixed mapping (`cli.rs:3258-3264`):
  Build → `gates.build`, Security(code) → `gates.security_code`, Test →
  `gates.high_risk_test` when effective is High else `gates.test`. Post-archive
  workflow status mirrors the Test choice (`cli.rs:1557-1561`). The **only**
  risk-sensitive selection is Test's high/low split; Build always runs
  format+clippy+workspace-tests+release-build and Security(code) always runs
  policy-static+dependency-audit+gitleaks+semgrep (profiles in `.mpd/config.json`),
  each 10–40 minutes in the sandbox. High risk additionally: adds
  `phase-model-tests` + `scoped-digest-throughput` to Test, demands
  "Independent review"/"Refutation" sections in security-code.md (`cli.rs:4111-4114`),
  removes artifact page budgets (`ledger.rs:207-213`), and floors persona tuning to the
  deep tier (`cli.rs:2650`).
- **Scope declaration.** `ChangeManifest` (`closure.rs:1420-1436`) declares
  repo-relative `*`/`**` patterns (`pathmatch::glob_match`: `*` within a segment, `**`
  across segments; iterative, no backtracking blowup — `pathmatch.rs:10-18`).
  Validation fails closed (`ManifestIssue`, `closure.rs:1441-1462`): non-canonical,
  absolute, `..`, control-character, or empty patterns are rejected; empty `paths`
  blocks Architecture PASS. The system scope (`active_system_scope`,
  `closure.rs:2533`) implicitly covers the change dir, its ledger, and archive targets
  without declaration. The staged-scope commit gate (`manifest_view`,
  `cli.rs:1819-1909`) blocks any staged path outside declared+system scope.

So a documentation/process-only change is *already detectable* from its declared,
validated, fail-closed scope — the classifier just never looks.

## Goals / Non-Goals

Goals:

1. A docs/process-only change conducted at `--risk low` resolves an honest
   `derived`/`effective` on a deployment-configured repo, instead of a synthetic High.
2. Its objective gates can (opt-in via config) run a lighter — but still real,
   sandboxed, fail-closed — validation profile that always includes the secret scan
   and the doc-staleness check.
3. **Zero** rigor reduction for any change whose scope can affect behavior or trust:
   code, config, security policy, hooks, scripts, dependencies. Ambiguity of any kind
   resolves to full rigor.
4. Absent new config, behavior is byte-identical to today.

Non-Goals:

- No judgment phase is skipped or reordered; Architecture, Security(plan), Build,
  Security(code), Test, Deploy still run for every change (phase machine untouched).
- No change to attempt limits, artifact budgets, reconciliation, freshness, candidate
  capture, sandbox policy, receipts, pre-push, or archive semantics.
- No automatic scope inference — scope remains a declared, human/agent-authored fact.
- `.mpd/config.json` of this repository is **not** edited by this change (out of
  declared scope); adopting the docs profiles is a separate, high-rigor config change.

## Decisions

### D1 — Documentation-only scope predicate (allowlist, fail-closed)

New `closure::scope_is_documentation_only(manifest: &ChangeManifest, change: &str) -> bool`:

```
scope_is_documentation_only(m, change) :=
    !m.paths.is_empty()
    && every pattern p in m.paths ∪ m.shared_paths satisfies doc_safe_pattern(p, change)

doc_safe_pattern(p, change) :=
       literal_prefix(p, "docs/")
    || literal_prefix(p, "openspec/specs/")
    || literal_prefix(p, "openspec/changes/" + change + "/")   // own change dir ONLY
    || root_markdown(p)
```

- `literal_prefix(p, pre)`: the named prefix must appear in `p` **literally and
  case-sensitively** — every prefix segment is wildcard-free and matches
  byte-for-byte. `docs/**` and `docs/guide/*.md` qualify; `d*cs/**`, `**/docs/x`,
  `Docs/**` do not (a leading wildcard segment could reach any root).
- `root_markdown(p)`: exactly one segment (no `/`), ending in the **literal** `.md`,
  with wildcards (`*`/`?`) permitted only in the stem — `*.md`, `README.md`,
  `SECURITY.md` qualify; `*.m?`, `*.*`, `*` do not.
- The predicate runs only on patterns that already passed `ChangeManifest::validate`
  (canonical, relative, no `..`/NUL/control bytes), and it is a **closed allowlist**:
  anything not proven safe — `crates/**`, `security/**`, `.githooks/**`, `.mpd/**`
  (including `.mpd/config.json` and ledgers), `scripts/**`, `Cargo.*`, `.github/**`,
  `openspec/schemas/**`, *another* change's `openspec/changes/<other>/**`, any root
  non-markdown file, any unrecognized or future root — is not-safe, and one not-safe
  pattern makes the whole scope not documentation-only.

Why own-change-dir only: `openspec/changes/**` at large would let a "docs" change edit
*another* change's `manifest.json`. The existing invariants would still catch the
consequences (`DependencyKey::Scope` stales the victim's evidence and the staged-scope
gate blocks out-of-scope commits), but the tightened allowlist removes the vector
outright instead of relying on downstream recovery. The self-referential case — a
documentation-only change widening its *own* manifest — is safe by construction:
classification is recomputed from the live manifest before every effectful command
(`cli.rs:1937`) and gate evidence depends on `Scope`, so a widened manifest immediately
reclassifies and rewinds stale approvals before any further gate can run.

Why patterns rather than staged files: the classifier's contract is *declared blast
radius* (it must price what the change is allowed to touch, before anything is
staged). The staged-scope commit gate already enforces, byte-wise and case-sensitively
via `glob_match`, that nothing outside the declared patterns can land — a `Docs/evil.sh`
staged against a `docs/**` declaration is "unrelated staged content" and blocks
(`cli.rs:1891-1893`).

### D2 — Risk classifier v2: scope-conditional synthetic signals (Option 1)

`classify_effective_risk` gains the `change: &str` parameter (both call sites —
`cli.rs:1918-1923` and `closure.rs:2764` — have it in hand) and becomes:

- Predicate **false** (or `paths` empty): behavior identical to v1 — full category,
  sensitive-root, and repo-configuration signal derivation. Nothing is suppressed.
- Predicate **true**: `derived = Low`; `reasons` records
  `documentation-only-scope` first, followed by one `suppressed:<original-signal>`
  entry per signal the v1 derivation would have produced (both the two synthetic
  config signals and any keyword false-cognates such as
  `process-execution: openspec/specs/process-governance/spec.md`, which fires today
  because the *filename* contains "process"). Under a proven documentation-only scope
  every such signal is definitionally synthetic: markdown under the allowlisted roots
  cannot execute, parse untrusted input, or deploy, so no *genuinely*-derived signal
  can exist. The reasons trail keeps the suppression auditable in `mpd status` JSON.
- `effective = requested.max(derived)` verbatim (`closure.rs:2107` unchanged): a
  requested Medium/High is never lowered; owners can still raise docs changes.
- `RISK_CLASSIFIER_VERSION` bumps to 2, and the signal-digest tuple additionally binds
  the predicate outcome and the suppressed-signal list, so any flip of the predicate or
  the suppressed set changes `signal_digest` and stales dependent evidence.

Alternative considered and rejected — suppressing *only* the two config signals while
keeping keyword path signals: it leaves the docs lane unreachable for any document
whose name contains "process"/"deploy"/"auth" etc. (this repository's own
`openspec/specs/process-governance/` — the false-cognate problem), while providing no
additional safety, because keyword hits on allowlist-proven doc paths carry no more
signal than the config bits do.

### D3 — Proportionate validation profiles (Option 2, opt-in, floor-enforced)

`GateProfiles` (`config.rs:268-275`) gains three **optional** kebab-case fields:

```
docs-build: Option<String>, docs-security-code: Option<String>, docs-test: Option<String>
```

Selection (one shared helper, used by both the strict gate executor at `cli.rs:3258-3264`
and post-archive workflow status at `cli.rs:1557-1561` — never two divergent copies):

```
docs_lane := scope_is_documentation_only(live manifest, change)      // recomputed NOW
             && effective_risk == Low                                 // from current assessment
Build          → docs_lane && gates.docs_build.is_some()          ? docs-build  : build
Security(code) → docs_lane && gates.docs_security_code.is_some()  ? docs-sec.   : security-code
Test           → effective High ? high-risk-test
               : docs_lane && gates.docs_test.is_some()           ? docs-test   : test
```

Mandatory floor, enforced in code at selection time (not by config convention): resolve
the chosen docs profile's checks (including `includes` expansion); it must contain at
least one check of kind `secret-scan`, and `docs-build`/`docs-test` must additionally
contain at least one check of the new kind `doc-check` (the doc-staleness lane,
`scripts/check-doc-staleness.sh`). A docs profile missing its floor **blocks the gate
with an explicit config-policy blocker** — loud fail-closed, never a silent fallback
that would mask a misconfigured policy, and never a silent skip of the scan.

Execution is otherwise untouched: the selected profile name feeds the same
`validate_candidate_profile` candidate-sandbox path (`cli.rs:3276-3282`), same exact
subject binding, receipts, resource limits, and freshness dependencies as today. The
lighter lane is lighter *content*, not lighter *machinery*.

Adoption recipe (documented in `docs/proportionate-governance.md`; applying it to
`.mpd/config.json` is a separate change, and because `.mpd/` is a sensitive root that
config change itself classifies High — governance guards its own relaxation):

```
checks:   "doc-staleness": { kind: "doc-check", bash scripts/check-doc-staleness.sh }
profiles: "docs-build": [format, doc-staleness, gitleaks]
          "docs-test":  [format, doc-staleness, gitleaks, doc-tooling tests]
          "docs-security-code": [gitleaks, policy-static]
gates:    "docs-build" / "docs-security-code" / "docs-test"
```

### D4 — Both options, layered; why neither suffices alone

Option 1 is the prerequisite: profile selection keyed off High-effective risk while
every docs change *is* High would be incoherent (a High change on a light profile
violates "High ⇒ full rigor"). Option 1 alone, however, saves almost nothing: Build and
Security(code) profiles are risk-insensitive today, so an honest Low still pays the
full compile+clippy+suite+release per gate; only `high-risk-test`'s extra lanes drop.
Option 2 without Option 1 is unreachable (`docs_lane` requires effective Low, which the
synthetic signals forbid). Therefore: risk relaxation (D2) feeds profile selection
(D3), and the safe default for any ambiguity at either layer is full rigor.

### D5 — What deliberately does not change

Judgment phases and their artifacts, attempt limits (`cli.rs:3119`), artifact budgets,
persona tuning inputs, `pre-push` profile, hook policy, sandbox contract, candidate
capture/reopen, archive and landing-commit verification, and the `effective_risk_max_law`
property (`ledger.rs:3175-3182`, extended — not weakened — by this change).

## Risks / Trade-offs

- **[Predicate false-safe]** A pattern judged doc-safe that can reach executable
  content. → Closed allowlist with literal, case-sensitive prefixes; wildcard-leading
  patterns rejected; property tests over adversarial pattern corpora; and the staged-
  scope gate independently blocks any staged path the patterns don't cover.
- **[Self-widening scope]** A docs change edits its own manifest after gates pass. →
  Classification recomputes pre-effects (`cli.rs:1937`); `Scope` is a gate-evidence
  dependency, so widening stales evidence and rewinds; classifier v2's digest also
  binds the predicate outcome.
- **[Config misdeclaration]** An operator wires a docs profile without the secret
  scan. → Selection-time floor check blocks the gate explicitly (D3); scaffold
  defaults ship compliant profiles.
- **[Docs-as-attack-surface]** A markdown change can still socially engineer humans
  (e.g., README instructions) or plant secrets in prose. → Security(plan)/(code)
  judgment reviews still run for every change; gitleaks runs in every selectable
  profile; nothing in the docs lane is exempt from the staged-scope or pre-push secret
  gates.
- **[Behavioral drift between selection sites]** Gate executor and workflow status
  disagreeing on the profile. → Single shared selection helper (D3), tested at both
  call sites.
- **[Complexity tax]** A second lane to reason about. → The lane is opt-in, closed
  over three profile names, floor-enforced in code, and dead (identical behavior) when
  unconfigured.

## Conditions for Builder

1. **The safe-scope predicate is allowlist-based and fail-closed.** Exactly the D1
   allowlist: literal case-sensitive prefixes `docs/`, `openspec/specs/`,
   `openspec/changes/<this change>/`, plus single-segment literal-`.md` root patterns.
   An unknown, unmatched, wildcard-prefixed, or non-canonical pattern → not-safe. An
   empty `paths` → not documentation-only. Not-safe → full rigor.
2. **Mixed scope → full rigor.** One non-doc pattern anywhere in `paths ∪ shared_paths`
   poisons the whole predicate. The predicate must satisfy
   `predicate(S ∪ T) == predicate(S) && predicate(T)`.
3. **The relaxation removes only synthetic derived-High signals.** It never lowers a
   requested risk and never suppresses anything when the predicate is false;
   `effective = max(requested, derived)` is preserved verbatim, and the existing
   `effective_risk_max_law` property test is extended to classifier v2 (including:
   predicate true with requested High ⇒ effective High).
4. **The secret scan and doc-staleness checks always run** on the docs lane: any
   selected docs profile must resolve (post-`includes`) to ≥1 `secret-scan`-kind
   check, and `docs-build`/`docs-test` to ≥1 `doc-check`-kind check; a missing floor
   blocks the gate with an explicit blocker — no silent fallback, no silent skip.
   Full-profile behavior when the optional gates are unconfigured must be
   byte-identical to today.
5. **No path by which a code/security/config-scoped change gets the lighter
   treatment.** Negative tests must cover at minimum: `crates/**`, `security/**`,
   `.githooks/**`, `.mpd/config.json`, `.mpd/**`, `scripts/**`, `Cargo.toml`,
   `Cargo.lock`, `.github/**`, `openspec/schemas/**`, another change's
   `openspec/changes/<other>/**`, root non-markdown patterns, and wildcard-leading
   patterns — each must classify with full v1-equivalent derivation and select full
   profiles.
6. **The predicate has property tests** (seeded, reproducible, alongside the existing
   proptest suite): the conjunction law from Condition 2; monotone poisoning (adding
   any pattern never flips not-safe → safe); every deny-corpus pattern not-safe; every
   allow-corpus pattern safe; and classifier-level invariants — suppression occurs iff
   the predicate holds, and `signal_digest` changes whenever the predicate outcome or
   suppressed set changes.
7. **Versioning and digest binding.** `RISK_CLASSIFIER_VERSION` → 2; the signal-digest
   tuple includes the predicate outcome and suppressed signals; existing ledgers load
   unchanged (`risk_assessment` is recomputed, never migrated in place).
8. **One selection function.** The strict gate executor (`cli.rs:3258`) and workflow
   status (`cli.rs:1557`) must share the single helper; `docs_lane` is recomputed from
   the live manifest and current effective risk at gate time — never from a cached or
   ledger-stored boolean.
9. **Machinery untouched.** Docs profiles execute through the same
   `validate_candidate_profile` sandbox path with the same candidate binding, receipts,
   limits, and freshness dependencies; no new execution path, no bypass of the
   validator, and `.mpd/config.json` of this repository is not modified by this change.

## Verdict

PASS

This approves the plan, not the code. Build proceeds only after Security (plan) passes
this design. The classifier and the selection helper are governance kernel surface:
Security (code) findings there are not fixed inline — re-run Security after every fix.
