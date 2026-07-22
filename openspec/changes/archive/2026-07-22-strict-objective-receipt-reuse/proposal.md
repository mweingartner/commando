# Strict objective-receipt reuse on a byte-identical candidate

## Why
A freshness rewind wipes every gate record at phase >= the rewound phase
(ledger.rs:968-973), including a still-valid Build/Test validation receipt, and strict
mode categorically refuses `--reuse` for Build/SecurityCode/Test (cli.rs:3093-3101) —
so a rewind that leaves the compiled result unchanged still pays the full slow
Build/Test sandbox re-execution.

**Scope correction (after Security (code)):** the original motivation claimed a
PROSE-ONLY edit produces a byte-identical candidate. That is FALSE. Judgment prose is
excluded from the Source DIGEST (closure.rs:2882-2905) but is still bound into the
Candidate id via the mandatory `openspec/changes/<change>/**` process scope
(entries_digest/base_tree) — on purpose, so the secret scanner covers prose. A prose
edit therefore changes the Candidate id and correctly forces fresh execution. The
genuine, narrower payoff is the residual class of rewinds whose cause lies OUTSIDE the
Candidate (a persona/governance/risk re-derivation touching no in-scope file, a
`repair-state` rewind, or a reverted edit): those leave the Candidate byte-identical,
and today they needlessly re-execute. The common prose-edit rewind is NOT accelerated;
its mitigation is the freeze-prose-before-gating discipline codified in the docs task.

## What Changes
- Add a `hermetic-reuse` opt-in to `.mpd/config.json` so future Build/Test receipts
  bind hermetic keys (including the running coordinator's own digest).
- Narrow the strict `--reuse` refusal from `Build | SecurityCode | Test` to
  `SecurityCode` only — SecurityCode evidence is never carried forward, so every
  rewind still executes a full fresh deterministic-scan pass on the candidate.
- Allow strict `mpd gate build|test --reuse <origin>` to reuse a prior receipt ONLY
  when a strict superset of equalities holds: the freshly-captured candidate id
  equals the origin's (binds base tree + manifest + entries + policy + source, so
  ANY source/config/scope drift refuses), the selected gate PROFILE matches, the
  policy digest matches, the build output still validates on disk, and the existing
  hermetic-complete `evaluate_reuse` validity holds. Any mismatch → fresh execution
  (fail-closed). `mpd next` already surfaces the reusable receipt with an explicit
  offer.
- Docs: codify the lean operating protocol (freeze prose artifacts before gating;
  tier-match / self-author low-surface reviews; batch small same-scope changes;
  record non-blocking/comment-only findings as artifact notes, not FAIL/re-drives)
  in AGENTS.md; correct the model/risk/effort ("model prompts") guidance in
  README.md (High does NOT tighten the attempt limit — it loosens it; the real High
  cost is the deep-model bump + effort floor + heavy Test profile); document the
  strict-reuse rule; sync `.mpd/directives/protocol.md` with its shipped twin.

Not **BREAKING**. It only ADDS a reuse path under strictly more conditions than the
manual tier already requires; no automatic reuse, no freshness/rewind/schema change.

## Capabilities
### New Capabilities
None.
### Modified Capabilities
None (no local-validation spec requirement governs receipt reuse; the existing
fail-closed guarantees are preserved — this removes redundant EXECUTION, not rigor).

## Impact
- `crates/mpd/src/cli.rs` (gate reuse path), `.mpd/config.json` (hermetic-reuse
  opt-in), `crates/mpd/tests/e2e.rs` (must-not-weaken tests), docs (README/AGENTS/
  protocol + twin). No edits to freshness_projection, stale_dependency_rewind,
  invalidate_for_freshness, evidence_validity, receipt schemas, or the archive.
- Because it edits crates/**, landing needs a coordinator rebuild + reactivation.
- Deliberately EXCLUDED: a risk-classifier "Medium band" (investigated, judged
  low-value — the changes that hurt correctly stay High as verification policy;
  its intent is met by the docs' tier-match discipline).
