# Design: Fail-early manifest process-scope validation

## Actor
Architect (claude-code harness, deep tier).

## Context
Strict candidates materialize HEAD + DECLARED dirty overlay only (`overlay_plan`
excludes undeclared dirty paths, candidate.rs:952-980; `declared()` = glob over
`paths ∪ shared_paths`, candidate.rs:889-895). The mpd flow commits once at
closure, so an undeclared `openspec/changes/<change>/**` means `manifest.json` is
never retained → archive fails at closure.rs:539-540 (ManifestLoadError::NotFound,
Display :1628). `validate_documentation_postimage` (closure.rs:1059-1081) requires
`docs/<change>.md` to glob-match the raw manifest; docs are unconditional
(`ChangeKind::documents()` = true, ledger.rs:398-417; fold target
`Config::docs_dir()` default "docs", config.rs:902-904). The ledger is excluded
from candidates as a mutable process path regardless of declaration (candidate.rs:
905-907, 960-969) and folded via SystemScope at every commit-time check
(cli.rs:4885-4892 / closure.rs:2718-2729) — so it must NOT be declared or required.

This file is the canonical current-state contract.

## Goals / Non-Goals
Goal: surface the two required process-scope entries at the earliest correct
point with an actionable error, without changing seed contents or the
undeclared-scope forcing function. Non-Goals: no auto-seed; no ledger requirement;
no spec change; no change to reopen/manual-tier/archived-manifest flows.

## Decisions
**D1 — (b) validate at the strict Build-gate capture (primary).** New pure fn
`closure::missing_process_scope(manifest, change, docs_dir) -> Vec<String>` probes
representative concrete paths with the SAME glob-over-(paths ∪ shared_paths)
semantics the enforcement sites use (so any superset like `**` passes): 
`openspec/changes/<change>/manifest.json` AND
`openspec/changes/<change>/specs/probe/spec.md` (the nested probe matters — `*`
does not cross `/`, pathmatch.rs:10-22) → either miss reports
`openspec/changes/<change>/**`; `<docs_dir>/<change>.md` miss reports it verbatim.
Hook: cli.rs gate command Build arm (~:3311), immediately before
`execute_strict_candidate_build`, using the already-loaded `live_manifest` + `cfg`;
non-empty gaps → `gate_blocked` with the copy-pasteable entries. NOT inside
`load_ready_manifest`/`capture_candidate` (dozens of narrow-manifest unit tests;
reopen must accept pre-fix captures).

**D2 — (c) archive-error hints (backstop).** closure.rs:539-540 (NotFound only)
and :1075-1078 gain a suffix naming the entry to add. All pinning tests use
`contains(...)` so suffixes are churn-free.

**D3 — no auto-seed, no ledger.** Rationale in proposal; preserves `NoDeclaredScope`,
the seed contract test (closure.rs:4371-4388), and risk/doc-only classification.

## Risks / Trade-offs
- [Narrow-manifest test fixtures that reach `gate build` would newly refuse] →
  update them (add entries only, never weaken assertions); known: "shippable"
  e2e fixture (tests/e2e.rs:2214-2217); Sandbox default `"**"` covers the rest.
- [Pre-fix in-flight candidate (frozen digest) still hits the late error] →
  the (c) hint remediates.

## Conditions for Builder
1. Check runs ONLY in the strict Build-gate arm — never in load_ready_manifest,
   capture_candidate, or reopen.
2. Probe via glob_match over paths ∪ shared_paths (mirror `declared()`); supersets
   must pass; test `*`-vs-`/` semantics.
3. Never require/seed `.mpd/state/<change>.json`; never auto-seed any path.
4. Error messages contain the exact entry strings; keep "durable-doc path" /
   "retained manifest" substrings intact.
5. Docs probe uses `docs_dir()` (no hardcoded "docs").
6. Fixture updates add entries only; sweep the suite for narrow-manifest +
   `gate build` fixtures.

## Verdict
PASS — small, lean, strictly-surfacing (no behavior weakened); ready for Security.
