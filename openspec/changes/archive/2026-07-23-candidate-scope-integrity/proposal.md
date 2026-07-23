# Candidate scope integrity

## Why

Two defects in the verification kernel's Candidate scope surfaced during self-hosting.
(1) The change's own planning prose (`design.md`/`proposal.md`/`tasks.md` and the other
canonical process artifacts) is folded into the Candidate id via the mandatory
`openspec/changes/<change>/**` process scope, so every prose edit rewinds AND forces a
full Build/Test sandbox re-execution — the single largest self-hosting cost driver, and
the reason the just-landed `strict-objective-receipt-reuse` feature almost never fires.
(2) The prior change (`strict-objective-receipt-reuse`, d482a20) shipped edits to
`crates/mpd/src/closure.rs` and `crates/mpd/src/config.rs` that were not in its
manifest: the Candidate silently captured base-HEAD bytes for them, Build/Test
validated code that did not include those edits, and the drive only failed at
`mpd publish --verify` — with the uninformative message `closure commit is not
coherent:` followed by nothing, because `verify_commit_coherence` returns
`blockers: []` in exactly that arm (closure.rs:3431-3438) and
`resolve_closure_landing` silently `continue`s past out-of-scope commits
(closure.rs:3577-3579).

## What Changes

- **Prose leaves the code-validation Candidate.** The active change's eleven canonical
  process artifacts (`proposal.md`, `design.md`, `tasks.md`, `design-mock.md`,
  `design-review.md`, `security-plan.md`, `security-code.md`, `design-signoff.md`,
  `test.md`, `documentation.md`, `doc-validation.md` under
  `openspec/changes/<change>/`) are physically pruned from the Candidate projection and
  excluded from its inventory, `entries_digest`, and id. `CANDIDATE_SCHEMA` bumps
  1 → 2 so v1 and v2 ids are disjoint by construction. **BREAKING (fail-closed):** a
  retained v1 Candidate cannot be reopened by the new binary mid-drive; the remedy is
  a Build rewind/recapture, and old retained roots/records are inert.
- **Reuse now fires on prose-edit rewinds.** With prose out of the Candidate, an
  uncommitted prose-only edit leaves the Candidate byte-identical, so
  `mpd gate build|test --pass --reuse <receipt>` genuinely accelerates the common
  rewind. Security(code) still always re-executes. README / AGENTS.md /
  both protocol.md twins are updated to state the new true firing set.
- **A dedicated, fail-closed prose secret-scan lane** replaces the coverage the
  sandbox scan loses. The strict Build, Security(code), and Test gates — on BOTH the
  execute and `--reuse` paths — scan the change's prose files from the worktree
  (path-addressed, so untracked prose is covered) with the built-in scanner +
  allowlist, plus gitleaks over the change directory when installed. Any finding or
  scan error blocks the gate. The staged pre-commit scan already covers prose at
  commit; a regression test pins that.
- **Source-drift guard.** The strict Build gate (execute and reuse) and the
  Security(code)/Test gates refuse when a *tracked* file is modified/deleted/renamed
  outside `manifest scope ∪ SystemScope ∪ mutable process paths`, naming each path and
  the two remedies (declare it in `manifest.json`, or stash genuinely unrelated work).
  Untracked out-of-scope files stay user-owned (loud note, never a refusal). The
  `mpd hook pre-commit` additionally blocks a *mixed landing commit*: staged content
  that includes an `openspec/changes/archive/…` landing plus out-of-closure-scope
  paths.
- **Coherence diagnostics.** `resolve_closure_landing` records a bounded diagnostic
  naming each rejected commit's out-of-scope paths; `verify_commit_coherence` never
  again returns `coherent:false` with empty blockers — the suppressed diagnostics are
  surfaced, so `mpd publish --verify` explains WHY.
- **Prose reaches the archive through receipt-bound postimages.** Because the
  Candidate no longer carries prose, `build_candidate_closure_plan` learns the
  pre-Candidate artifact lane (DesignMock/Architecture/DesignReview/SecurityPlan
  postimages, receipt-bound like today's SecurityCode/Test/… lane), and strict
  judgment gates record the artifact's SHA-256 on the `GateRecord` so archive can
  verify judgment-artifact bytes against what actually gated.

## Capabilities

### New Capabilities
None — this hardens existing candidate/closure/secret-scan capabilities.

### Modified Capabilities
- Candidate capture and identity (candidate scope, schema v2)
- Archive closure planning and commit coherence (postimage lane, diagnostics)
- Deterministic gate checks (prose secret-scan lane, drift guard, pre-commit landing guard)

## Impact

- Code: `crates/mpd/src/candidate.rs`, `closure.rs`, `cli.rs`, `ledger.rs`,
  `checks/mod.rs`, `local_validation.rs`, `stats.rs` (the latter two carry one-line
  `GateRecord` literal additions for the new non-`Default` field — mechanical fallout,
  declared so the Candidate binds them), (+`checks/secrets.rs`, `phase.rs`, `config.rs`
  declared for re-validation/possible touch), `crates/mpd/tests/e2e.rs`.
- Docs: README.md "Exact candidate and freshness", AGENTS.md lean protocol,
  `.mpd/directives/protocol.md` + shipped twin (byte-identical),
  `docs/adoption-quickstart.md` "Known rough edges", `docs/candidate-scope-integrity.md`.
- **Intended side effect:** declaring `closure.rs` and `config.rs` in THIS manifest
  re-validates the code d482a20 shipped unvalidated — the strict Candidate now binds
  and sandbox-validates those exact bytes.
- Back-compat: pre-upgrade receipts/candidates never reuse across the schema bump
  (id mismatch → fresh execution); `GateRecord.judgment_artifact_sha256` is optional
  (absent on legacy records → verified only when present, recorded always going
  forward). No receipt schema or reuse-equality-set changes.
