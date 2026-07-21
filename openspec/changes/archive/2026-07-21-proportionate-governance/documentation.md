# Proportionate Governance

## Purpose

A two-file docs/process change was classified effective-High and forced through the
full sandboxed candidate validation at every objective gate — as many compile+clippy+
test-suite+dependency-audit+SAST cycles as the verification kernel itself pays — on any
repository that configures `deploy` or `local_validation` (every strict repository,
including this one). The cause was not the change's content but two synthetic,
scope-blind signals the classifier appends to *every* change:
`deployment-configured` and `local-validation-process-hook-sandbox-policy`
(`crates/mpd/src/closure.rs:2088-2099`, pre-existing v1 logic). Because any signal at
all makes `derived = High`, a `--risk low` docs chore still resolved effective-High.
This change makes governance scope-aware: an honestly documentation-only change can
resolve an honest Low, without weakening rigor for anything that can actually affect
behavior or trust.

## Value

A change whose declared manifest scope is provably documentation-only no longer
inherits the two synthetic derived-High signals, and — only where an operator has
opted in with configured `docs-*` profiles — its Build/Security(code)/Test gates run a
lighter, still-sandboxed, fail-closed validation lane instead of the full profile. Any
change whose scope touches code, configuration, security policy, hooks, scripts, or
dependencies is completely unaffected: one non-qualifying pattern anywhere in the
declared scope keeps full rigor. This change also fixes a keyword false-cognate: a doc
filename like `openspec/specs/process-governance/spec.md` no longer trips the
`process-execution` signal purely because its name contains "process".

## Scope

**Covers.** The classifier and gate-profile-selection layers only, keyed off the
change's own **declared** manifest scope (`paths ∪ shared_paths`):

- `closure::scope_is_documentation_only` (`closure.rs:2059`) — the fail-closed
  allowlist predicate.
- `classify_effective_risk` v2 (`closure.rs:2090`, `RISK_CLASSIFIER_VERSION = 2` at
  `closure.rs:2014`) — scope-conditional suppression of synthetic signals.
- `closure::select_gate_profile` (`closure.rs:2243`) — opt-in selection of
  `docs-build` / `docs-security-code` / `docs-test` gate profiles.

**Does not cover / explicit non-goals.**

- No judgment phase is skipped or reordered — Architecture, Security(plan), Build,
  Security(code), Test, Deploy still run for every change.
- No change to attempt limits, artifact budgets, reconciliation, freshness, candidate
  capture, sandbox policy, receipts, pre-push, or archive semantics.
- No automatic scope inference — scope stays a declared, human/agent-authored fact.
- **This repository does not configure any `docs-*` profile.** `.mpd/config.json`
  here carries no `docs-build`/`docs-security-code`/`docs-test` keys (grep-verified at
  Security (code)), so behavior on this repository is byte-identical to before this
  change: every gate here still runs the full profile. Adopting the lighter lane is a
  separate config change, and because it edits `.mpd/`, a sensitive root, that config
  change itself classifies High under this same classifier — governance guards its own
  relaxation.

## Functional details

**The predicate is an allowlist, not a denylist.** `scope_is_documentation_only`
(`closure.rs:2059`) self-validates before it reasons about safety: it rejects an
invalid change name via `validate_change_name`, rejects empty `paths`
(`predicate(∅) = false`, never weakened), and runs `digest::validate_canonical_path` on
every declared pattern before any prefix check — it never assumes an upstream
`ChangeManifest::validate()` call (`load_manifest` performs none). Only then does
`doc_safe_pattern` (`closure.rs:2037-2042`) test each pattern against four shapes: a
literal, case-sensitive, wildcard-free prefix of `docs/`, `openspec/specs/`, or this
change's own `openspec/changes/<change>/` (trailing slash mandatory — a sibling
directory or the bare change directory fails), or `root_markdown`
(`closure.rs:2023-2025`): a single-segment pattern with a literal `.md` suffix,
wildcards permitted only in the stem. One non-qualifying pattern anywhere in
`paths ∪ shared_paths` — `crates/**`, `security/**`, `.githooks/**`, `.mpd/**`
(including `.mpd/config.json`), `scripts/**`, `Cargo.toml`/`Cargo.lock`, `.github/**`,
`openspec/schemas/**`, another change's directory, a root non-markdown file, or a
wildcard-leading/non-canonical pattern — poisons the entire scope back to full,
unsuppressed v1 derivation.

**Classifier v2 semantics.** When the predicate holds, `classify_effective_risk`
(`closure.rs:2090`) sets `derived = Low` and relabels every reason the v1 derivation
would have produced — the two synthetic config signals and any keyword false-cognate
on a doc path — as `suppressed:<reason>` rather than dropping it, so the suppression
stays auditable in `mpd status --json`. `effective = requested.max(derived)`
(`closure.rs:2199`) is unchanged, verbatim v1: a requested Medium or High on a
documentation-only scope is never lowered. `RISK_CLASSIFIER_VERSION` bumped 1 → 2
(`closure.rs:2014`); the signal-digest tuple binds the predicate outcome and the
suppressed set, so any v1↔v2 transition, or any flip of the predicate or suppressed
set for the same underlying scope, changes `signal_digest` and stales the `Governance`
gate-evidence dependency, forcing a rewind rather than silently adopting a stale
classification in either direction.

**Profile selection.** `select_gate_profile` (`closure.rs:2243`) is the single shared
helper for both the strict gate executor and post-archive workflow status — they can
never diverge on which profile a phase actually runs. It selects a `docs-*` profile
only when the predicate holds against the **live** manifest at gate time, effective
risk is *exactly* Low (not `<= Medium`), and the corresponding field is configured.
Post-archive, workflow status reconstructs its manifest input from the archive
closure's frozen `allowed_paths`, which always includes the system-owned
`.mpd/state/<change>.json` ledger path — never doc-safe — so the predicate can never
hold there and post-archive status always resolves to today's High/non-High split; a
deliberate, harmless consequence of reusing the shared helper honestly, not a second
divergent path. A selected docs profile must resolve, post-`includes`, to at least one
`secret-scan`-kind check (all three profiles), and `docs-build`/`docs-test`
additionally to at least one `doc-check`-kind check (the new `CheckKind::DocCheck`);
missing this floor blocks the gate with an explicit config-policy error rather than
silently falling back to the full profile or silently skipping the scan. Execution is
otherwise untouched: the selected profile name feeds the same
`validate_candidate_profile` sandbox path, candidate binding, and receipts as the full
profile — the lane is lighter content, not lighter machinery.

**Residual surfaces (read before adopting).** Security's review named these
explicitly and required they be documented rather than silently assumed:

- **Prose is still a live surface.** Root `*.md` covers agent-instruction files
  (`AGENTS.md`, `README.md`) and `openspec/specs/**` is persona-prompt surface —
  prose/LLM-injection risk is real, but has zero *differential* exposure from this
  feature: the full profile's objective checks (clippy, tests, SAST) never analyze
  prose semantics either. Both judgment Security reviews, gitleaks, and the
  staged-scope/pre-push gates still run on every change regardless of lane.
- **The allowlist is directory-shaped, not extension-shaped.** `docs/**` and the
  change's own directory admit non-markdown files (e.g. `docs/evil.sh`). Nothing in
  mpd's machinery executes doc-root content; this is a deliberate scope decision, not
  an oversight.
- **The profile floor checks kind, not efficacy.** A `kind: secret-scan` check
  pointing at a no-op program satisfies the floor. Accepted because wiring such a
  check requires editing `.mpd/config.json`, itself a sensitive-root, High-rigor
  change reviewed on its own.
- **A classifier version bump is an availability cost, not a vulnerability.** Bumping
  `RISK_CLASSIFIER_VERSION` stales the `Governance` dependency of every in-flight
  change and forces a rewind to Architecture/Security(plan) the next time each is
  touched — the fail-safe direction.
- **`docs-build`'s build output is not wired.** The typed `BuildOutputV1` attachment
  check in `local_validation.rs` is keyed on the canonical `gates.build` profile name
  only; it is intentionally not broadened to `docs-build` in this change, since that
  attachment path is a previously-audited security invariant outside this change's
  Security review scope. A future config adopting `docs-build` will still need a
  `release-build`-kind check in that profile (or an extension of the attachment check
  in its own reviewed follow-up) for Deploy to produce a release artifact; absent
  that, Deploy refuses loudly rather than silently proceeding without one.

**Verification.** Security (code) reviewed the real diff (`git diff HEAD --
crates/mpd/`), independently re-derived the escape question matcher-outward from
`pathmatch.rs` rather than trusting the predicate's own reasoning, and ran five
refutation attempts against a PASS (signal suppression on a planted secret, TOCTOU on
the double manifest read, v1/v2 replay, reaching the lane at Medium or via
misconfiguration, and direct prefix escape) — all failed to find a path in. Its
verdict was CONDITIONAL PASS with the explicit judgment that "the escape hatch is
airtight in the actual code," conditioned only on C1: a seeded classifier-level
property test (the existing `effective_risk_max_law` in `ledger.rs` exercises only the
abstract `RiskLevel::max` ordinal law, never `classify_effective_risk` itself). The
Tester closed C1 with three new seeded proptests in
`closure.rs::risk_classifier_tests` (`classifier_max_law_holds_and_suppression_occurs_iff_the_predicate_holds`,
`signal_digest_binds_the_classifier_version_and_never_collides_with_a_v1_world`,
`same_scope_digest_diverges_when_only_the_predicate_or_suppressed_set_flips`), run
green inside the full Test-gate suite: 684 tests passed, 0 failed, 1 deliberately
ignored (a 100 MB digest-throughput benchmark unrelated to this change), plus clean
`cargo fmt`/`cargo clippy -D warnings`. One item remains honestly deferred rather than
gating this change: no e2e configures a live `docs-*` profile and drives it through
the real sandbox to assert on receipts, because that requires a full
trusted-policy-bootstrapped fixture this repository's own unwired config never
exercises; the first change that actually adopts the docs lane should add that
fixture-backed e2e as part of its own high-rigor validation.

## Usage

Adopting the lighter lane means editing this repository's `.mpd/config.json` — itself
a `.mpd/` sensitive-root change that classifies High under this same classifier, so it
gets its own full-rigor Architecture/Security review. The shape to add:

```jsonc
{
  "local_validation": {
    "checks": {
      "doc-staleness": {
        "kind": "doc-check",
        "program": "bash",
        "args": ["scripts/check-doc-staleness.sh"],
        "timeout-secs": 60,
        "result-policy": "exit-zero"
      }
    },
    "profiles": {
      "docs-build": { "checks": ["format", "doc-staleness", "gitleaks"] },
      "docs-test": { "checks": ["format", "doc-staleness", "gitleaks", "doc-tooling-tests"] },
      "docs-security-code": { "checks": ["gitleaks", "policy-static"] }
    },
    "gates": {
      "build": "build",
      "security-code": "security-code",
      "test": "test",
      "pre-push": "test",
      "high-risk-test": "high-risk-test",
      "docs-build": "docs-build",
      "docs-security-code": "docs-security-code",
      "docs-test": "docs-test"
    }
  }
}
```

With this in place, a change declaring e.g. `"paths": ["docs/**"]` at `--risk low`
resolves `effective: low` and its Build/Security(code)/Test gates select the `docs-*`
profiles automatically — recomputed from the live manifest and current effective risk
at every gate, never cached. A change whose scope includes anything else — even a
single `crates/**` pattern alongside `docs/**` — runs the full profiles exactly as it
does today. This repository has not adopted the recipe: `.mpd/config.json` here
carries no `docs-*` keys, so every gate on this repository, docs-only or not, still
runs the full profile unchanged.
