# Security (plan) review

## Actor

Security

## Threat model

This change deliberately lowers objective-gate rigor for a class of changes, so the
review target is the escape hatch itself: the documentation-only scope predicate (D1),
the classifier that consumes it (D2), and the profile selector it feeds (D3). Trust
boundaries and adversary capabilities:

- **The change manifest is attacker-authorable.** `manifest.json` patterns can be
  AI-composed or hand-edited at any time, including *between* commands (TOCTOU) and
  *after* gates have passed. The predicate's only input is these declared patterns
  (`paths ∪ shared_paths`) — it is the sole key that opens the lighter lane, so every
  byte of it is untrusted.
- **Config is semi-trusted.** `.mpd/config.json` selects the docs profiles, but it
  lives under the `.mpd/` sensitive root, so editing it is itself a High-rigor change
  (governance guards its own relaxation, per D3). This change does not edit it.
- **Prose is a live surface.** Content under the allowlisted roots is read by judgment
  personas (specs, design artifacts) and by future agents (root `AGENTS.md`,
  `README.md`), so "documentation-only" is not "inert" at the social/LLM layer.

### Attack analysis of the safe-scope predicate (verified against the tree)

1. **Prefix-escape.** No escape found. `glob_match`
   (`crates/mpd/src/pathmatch.rs:18-123`) performs **no normalization, no case
   folding, and no `.`/`..` resolution** — every non-wildcard segment matches
   byte-for-byte. Therefore a pattern with a literal, case-sensitive `docs/`,
   `openspec/specs/`, or `openspec/changes/<change>/` prefix can only ever match real
   index paths whose leading segments are literally those bytes, and Git index paths
   never contain `.`/`..` components. `docs/../crates/**` would only match a path
   containing a literal `..` segment (none exists), so it is inert — it widens nothing
   at the staged-scope gate, which independently blocks any staged path the declared
   patterns do not cover (`cli.rs:1891-1893`). Case tricks (`Docs/**` on
   case-insensitive APFS): the predicate rejects `Docs/` (case-sensitive prefix) and
   the staged-scope gate compares byte-wise, so `Docs/evil.sh` staged against `docs/**`
   is unrelated content and blocks. Unicode confusables (`docs\u{200B}/x`) fail the
   byte-for-byte prefix and go to full rigor — the fail-closed direction.
   `root_markdown` correctly excludes `*`, `*.*`, `*.m?`, and multi-segment
   `**/*.md`; a single-segment `**.md` degenerates to `*.md` semantics (safe).
   **However, the plan's stated precondition is false — see Finding F1.**
2. **Own-dir-only.** Sound. The prefix includes the trailing slash, so
   `openspec/changes/<change>-evil/**` and the bare `openspec/changes/<change>` both
   fail it; a change cannot declare another change's directory into the light lane.
   Change names are validated kebab-case `[a-z0-9-]` with no dots, slashes, or glob
   metacharacters (`crates/openspec-core/src/names.rs:12-33`), so the concatenated
   prefix is wildcard-free by construction — provided the predicate actually
   revalidates the name it is handed (Condition 10). The own change dir does contain
   `manifest.json` and the gate artifacts, but that is already true today via the
   system scope, and artifact/manifest edits stale evidence through the
   `ArchitecturePlan`/`ProducedArtifact`/`Scope` dependencies — no new surface.
3. **Runtime vs declared (TOCTOU).** Covered. The gate path calls
   `enforce_freshness_before_effects` (`cli.rs:3068`) which recomputes the assessment
   from the **live** manifest (`current_risk_assessment`, `cli.rs:1912-1924`) before
   `effective_risk` is read (`cli.rs:3084`) and before selection (`cli.rs:3258`). The
   Governance dependency digest binds the *entire* `RiskAssessment` — classifier
   version, reasons, and `signal_digest` (`closure.rs:2764-2785`) — and v2 binds the
   predicate outcome and suppressed set into `signal_digest` (D2), so a manifest
   widened after classification stales downstream evidence and rewinds. A
   double-read divergence within one command (assessment from read A, predicate from
   read B) resolves fail-safe because `docs_lane` is a conjunction — either conjunct
   going conservative forces full profiles — but the Builder should still use one
   snapshot (Condition 12).
4. **Profile floor.** Sound as designed: selection-time resolution post-`includes`,
   ≥1 `SecretScan`-kind check in every selectable docs profile, ≥1 `doc-check` for
   build/test, and a missing floor **blocks with an explicit config-policy blocker**
   (D3) — no silent fallback, no silent skip. The secret scan is additionally
   unskippable end-to-end: the pre-push profile and the commit hard gate are untouched
   (D5). Docs profiles execute through the identical
   `validate_candidate_profile` sandbox path with candidate binding and receipts
   (`cli.rs:3276-3283`). Residual: the floor validates check *kind*, not efficacy — a
   `kind: secret-scan` check pointing at `/bin/true` satisfies it. Accepted because
   wiring such a check requires editing `.mpd/config.json`, which is a sensitive-root
   High-rigor change reviewed on its own; documented per Condition 14.
5. **effective = max preserved.** Verified. `closure.rs:2107` is kept verbatim; the
   predicate is false for any scope containing `crates/**`, `.mpd/**`, `.githooks/**`,
   `scripts/**`, `Cargo.*`, etc., so those derive High exactly as v1 (one poisoned
   pattern poisons the whole scope, Condition 2); requested High/Medium is never
   lowered, and `docs_lane` additionally requires effective == Low exactly, so a
   requested-Medium docs change still runs full profiles. The spec delta's scenarios
   cover all four corners.
6. **Classifier version bump.** No replay or downgrade path. The stored
   `risk_assessment` is only a cache: every effectful command recomputes with the
   *current* binary before acting, and because the signal tuple embeds
   `RISK_CLASSIFIER_VERSION`, any v1↔v2 transition changes `signal_digest`, changes
   the Governance dependency, and stales evidence — in **both** directions (an old
   binary recomputing v1-High against v2-Low evidence rewinds; it never adopts the
   stored Low). Side effect worth stating: bumping the version stales the Governance
   dependency of every in-flight change and forces rewinds. That is the fail-safe
   direction — an availability cost, not a vulnerability (Condition 14 documents it).
7. **False-cognate fix.** Safe. Keyword suppression happens *only* when the predicate
   holds, and the predicate holds only when every pattern is doc-allowlisted — so a
   genuinely sensitive path (`crates/mpd/src/process.rs`, `scripts/deploy.sh`) can
   never have its keyword signal suppressed: its presence makes the predicate false,
   which restores v1-identical derivation for the whole scope, including keyword hits
   on the doc paths in that mixed scope.

### Findings

- **F1 (must fix — Condition 10).** D1 states "the predicate runs only on patterns
  that already passed `ChangeManifest::validate`". That premise is **false at both
  planned call sites**: `load_manifest` explicitly performs no
  `ChangeManifest::validate` (`closure.rs:1630-1646`, its own doc comment says so),
  and neither `current_risk_assessment` (`cli.rs:1918`) nor the dependency capture
  (`closure.rs:2764`) validates before classifying. Today this is non-exploitable —
  the no-normalization glob semantics make non-canonical patterns inert, as analyzed
  above — but the escape hatch's safety argument must not rest on a false premise
  that a future refactor of glob semantics or call ordering could silently void.
- **F2 (must fix — Condition 11).** Condition 2/6's algebraic laws are falsifiable
  as written at the empty boundary: with `predicate(∅) = false` (required),
  `predicate(S ∪ ∅) = predicate(S)` can be true while `predicate(S) && predicate(∅)`
  is false, and adding a safe pattern to an empty scope flips not-safe → safe,
  violating "monotone poisoning" verbatim. The dangerous resolution — making
  `predicate(∅) = true` to satisfy the law — must be explicitly forbidden.
- **F3 (accepted, document — Condition 14).** Residual surfaces that the lighter lane
  does *not* change but the operator must understand: (a) root `*.md` covers
  agent-instruction files (`AGENTS.md`, `README.md`) and `openspec/specs/**` is
  persona-prompt surface — prose/LLM-injection risk is real but has **zero
  differential exposure**, because the full profiles' objective checks (clippy,
  tests, semgrep) never analyze prose semantics either; the actual controls — both
  judgment Security reviews, gitleaks, staged-scope and pre-push gates — all still
  run in the docs lane; (b) `docs/**` and the own change dir admit non-markdown
  files (e.g. `docs/evil.sh`) — nothing in mpd's machinery executes doc-root content
  (hooks come from `.githooks/` under hook policy; check programs come from config),
  but the allowlist is directory-shaped, not extension-shaped, and that choice should
  be a documented decision, not an accident.

## Conditions for Builder

Design.md Conditions 1-9 are sound and complete as far as they go; all nine are
affirmed. The following are **additional** conditions, numbered continuously; each
names the failure it prevents and is closed by code + test evidence at Security (code):

10. **The predicate trusts no caller (closes F1).** `scope_is_documentation_only`
    MUST itself, before any prefix logic: (a) run
    `digest::validate_canonical_path` on every pattern in `paths ∪ shared_paths` and
    treat any failure as not-safe (poisoning the whole scope), and (b) run
    `openspec_core::validate_change_name` on the `change` argument and return `false`
    on failure. It must not assume `ChangeManifest::validate` ran upstream. Failure
    prevented: a future call site or glob-semantics change turning a non-canonical
    pattern (`docs/../crates/**`, `docs//x`, `docs/./x`, backslash or control-byte
    patterns) into a live escape. The Condition 5 deny-corpus MUST be extended with:
    `docs/../crates/**`, `docs//x`, `docs/./x`, `docs\evil`, a control-character
    pattern, a >MAX_PATH_BYTES pattern, `docs\u{200B}/x`, `**.md`'s neighbors `**`
    and `*`, `openspec/changes/<change>` (no trailing slash), and
    `openspec/changes/<change>-evil/**`.
11. **The algebraic laws are stated over non-empty scopes (closes F2).** Restate the
    conjunction law and monotone-poisoning property for non-empty operands, or state
    them over the per-pattern `doc_safe_pattern` (where pure conjunction genuinely
    holds) with the emptiness check hoisted. `predicate(∅) = false` MUST remain and
    MUST have its own explicit test; resolving the law violation by making the empty
    scope qualify is forbidden. Failure prevented: a property-test "fix" that widens
    the empty-scope behavior.
12. **One manifest snapshot per command.** The selection helper (Condition 8) MUST
    receive the same loaded manifest/assessment pair produced by the freshness
    refresh of the current command invocation — not perform a second
    `load_manifest`. If implementation constraints force a reload, a test MUST
    demonstrate that any divergence between the two reads resolves to full profiles.
    Failure prevented: a mid-command manifest swap causing predicate and effective
    risk to be judged against different scopes.
13. **Medium is excluded by construction.** `docs_lane` requires
    `effective == RiskLevel::Low` exactly; a test MUST pin that requested-Medium (and
    any future intermediate level) on a doc-only scope selects full profiles.
    Failure prevented: a `<= Medium` comparison quietly widening the lane.
14. **The residual surfaces are documented (closes F3).**
    `docs/proportionate-governance.md` MUST state: prose/LLM-injection surface is
    unchanged by the lane (with the reasoning above); the allowlist is
    directory-shaped and admits non-markdown under `docs/` and the own change dir;
    the profile floor validates check *kind*, not efficacy, and relies on
    `.mpd/config.json` edits being High-rigor; and a classifier version bump is
    expected to stale in-flight Governance evidence (rewind, not weaken). Failure
    prevented: an operator adopting the recipe without understanding what the floor
    does and does not guarantee.

## Verdict

CONDITIONAL PASS

The escape hatch is structurally sound: the predicate's byte-literal, case-sensitive,
normalization-free prefix semantics compose with `glob_match`'s no-normalization
matching and the independent staged-scope gate so that no pattern which passes
`doc_safe_pattern` can match a real path outside `docs/`, `openspec/specs/`, the
change's own directory, or a root `*.md` file — I probed traversal, wildcard-leading,
case, Unicode, trailing-slash, cross-change, and empty/degenerate patterns and found
no mechanical escape. TOCTOU, replay, and downgrade are closed by pre-effect
recomputation plus Governance-digest binding of the versioned assessment; the max-law
is preserved verbatim; the floor fails loudly; the sandbox machinery is untouched.

The pass is conditional because the plan's safety argument currently leans on a
premise that is false in the tree (F1: classification sees unvalidated manifests) and
states two property laws that are falsifiable at the empty boundary with a dangerous
"fix" direction (F2). Conditions 10-14 above close these; owner: Builder; closing
evidence: the named tests and code, verified at Security (code) — which, per
design.md, re-runs after every fix on this kernel surface rather than accepting
inline remediation. Unresolved, these conditions block deployment.
