# Security (code) review

## Actor

Security

## Findings

Two full-depth passes over the real diff (`git diff HEAD -- crates/mpd/`:
candidate.rs, local_validation.rs, closure.rs, cli.rs, config.rs; final shape 2754
insertions, no dependency or Cargo changes, no new egress, no new CLI verbs —
grep-verified both rounds). Round 1 found no evidence-forgery or laundering channel in
any of the three loosened guards and raised three conditions plus two notes; round 2
re-audited the Builder's closing deltas. **All findings are now CONFIRMED FIXED**;
they are retained here as the audit record:

1. **MEDIUM (Condition 18 partial) — FIXED.** Round 1: the ref-level `ParityState`
   was computed but never presented alongside the per-change verdict, and a
   contained-but-Diverged landing was indistinguishable from not-contained. Fix
   audited: `ParityObservation` gained additive, serde-defaulted
   `ref_state: Option<ParityState>` and `landing_contained: Option<bool>`
   (`closure.rs:361-393`), computed UNCONDITIONALLY before state derivation
   (`closure.rs:3541-3551` containment, `:3527` ref state — legacy and modern alike;
   the Unstable arm correctly carries `None`, `:3520-3524`). The new
   `describe_ref_level_parity` helper (`cli.rs:5699-5720`) renders both facts on one
   line and is used at all three text surfaces: `publish --verify` (`cli.rs:5823`,
   below the landing-OID line), `mpd status` remote-parity (`cli.rs:2277`), and the
   `workflow_status` remote_parity fact in BOTH the Verified and Blocked arms
   (`cli.rs:1641-1652`); `--json` carries both fields directly on the serialized
   observation. Verified against the re-audit checklist: (a) contained-but-Diverged is
   now distinguishable ("ref-level state: DIVERGED; landing commit contained in
   remote: yes") — proven end-to-end by the new divergence test; (b) exit-code policy
   is UNCHANGED — Diverged/Rewritten still wins over containment in the state
   derivation (`closure.rs:3563-3574`), and `cmd_publish` exits 0 only on
   `state == Verified` (`cli.rs:5827-5843`), so a divergence can never print VERIFIED
   or exit 0; (c) back-compat holds — both fields `#[serde(default,
   skip_serializing_if)]`, no `deny_unknown_fields` on the type, `load_parity_cache`
   still degrades via `.ok()`, and the updated round-trip test asserts a legacy cache
   deserializes with all three new fields `None`; (d) no new false-PASS path — the
   state match is semantically identical to the round-1-audited logic (the containment
   value was hoisted into `landing_contained` and reused; Verified still requires
   proven containment plus a non-Diverged/Rewritten ref; the only behavioral delta is
   that a legacy closure now also computes containment, whose `is_ancestor` failure
   propagates as an error — fail-closed). Cache consumers re-checked: rewrite
   detection and `parity_current` filter on `state`/OIDs only, unaffected by the new
   fields. Residual: the `workflow_status` STALE arm omits the descriptor — correct,
   since a stale observation's ref facts describe a superseded HEAD.
2. **LOW (untested fail-closed override) — FIXED.** New test
   `verify_remote_parity_reports_divergence_loudly_even_when_the_landing_is_contained`
   genuinely constructs the branch: the remote tip descends from the landing
   (containment provable), the local tip is reset back to the landing and diverged
   with different never-pushed work (true sibling divergence). It asserts
   `landing_contained == Some(true)`, `ref_state == Some(Diverged)`,
   `state == Diverged`, and `state != Verified`. Independently run — passes.
3. **LOW (defense-in-depth pairing) — FIXED.** `validate_candidate_report_binding`
   (`cli.rs:2934-2974`) now pins `receipt.build_output.candidate_id` to the exact
   retained Candidate whenever a typed output is present — including the anomalous
   `candidate_id: None`-on-a-candidate-receipt case (`None != Some(id)` → error).
   Strictly additive: all round-1 subject checks retained, nothing relaxed, and the
   no-output case (Security/Test profiles) is unaffected. New test covers all three
   directions (match passes, mismatch fails with the named message, absent output
   passes). Independently run — passes.
4. **NOTES — BOTH FIXED.** (a) The four post-eviction reopen tests now assert the
   specific `"does not match its compact binding"` message (Condition 21 as written).
   (b) The orphan-arm eviction no longer swallows the precondition-failure reason: it
   appends it to the original fail-closed message
   (`"candidate projection record exists without its retained root: {reason}"`,
   `candidate.rs:788-793`) — the original prefix (and thus every existing consumer
   match) is preserved, the appended reason is error text only (paths/parse errors, no
   secret-bearing content), and a new test asserts the reason surfaces. (c) Condition
   15's e2e-placement deviation stands, Builder-flagged (tasks.md 2.3): reproductions
   are module tests exercising the same production functions; the Tester should weigh
   a binary-driven rewind fixture. Not blocking.

## Conditions verified

Design Conditions 1-15, checked against the shipped code:

1. **Holds.** Both arms recover under guard: existing-root arm evicts via
   `refresh_candidate_record`, orphan arm via TOCTOU-hardened
   `remove_owned_record_path` + fresh publication. Tests: base_commit-only divergence,
   root recreation (new device/inode), orphaned record; counts/status/excluded-dirty
   classes proven attempt-variant field-by-field in
   `identity_fields_partition_matches_every_field_class` (all independently run,
   passing, both rounds).
2. **Holds.** Identity fields (`CandidateRecordIdentity`) cover schema, subject
   version/change/base_tree/all four digests/id, and the full `entries` inventory
   (path/state/mode/byte_len/sha256 — everything content-bearing); mismatch keeps the
   exact original error; a foreign-change record fails identity before any eviction
   logic (`cross_change_id_collision_never_evicts_the_others_record`, bytes on disk
   asserted unchanged).
3. **Holds.** `candidate_id_has_live_gate_binding` loads the ledger fresh, fails
   closed on unreadable/non-regular ledger; error names rewind guidance; both arms
   tested with on-disk bytes asserted unchanged.
4. **Holds.** Output lock acquired (`local_validation.rs:1545`) BEFORE the ledger
   check (`:1554`); same-path live binding still refuses; different path still errors.
5. **Holds.** `candidate_output_ledger_bound` iterates `gates.values()` only; binding
   requires typed `build_output` with matching `candidate_id`; the old `:1414` error
   string is gone from the tree (grep-verified). History-only Build PASS does not
   bind; a re-recorded live gates entry binds again (tested).
6-7. **Hold.** Landing resolution judges only the landing commit's own diff (incl.
   rename origins) against its own change's scope; interleaved commits produce no
   blockers; merges excluded by `git::single_parent` regardless of content (tested,
   including a merge whose tree carries the reviewed bytes).
8. **Holds.** Earliest-first deterministic; only diff-pure commits materialized;
   diagnostics capped (5 candidates x 8 paths).
9. **Holds.** No fetch/push/ref writes anywhere in the diff (grep-verified both
   rounds); snapshot-stability loop unchanged; missing remote object →
   AncestryUnavailable with `landing_contained: None` (tested); worktree/clean
   conjuncts dropped only from the MODERN landed binding — legacy keeps them verbatim.
10. **Holds.** Readiness reporting preserved; `ready_to_commit` tested; readiness is
    presentation — the pre-commit staged-scope gate polices the actual commit.
11. **Holds.** All three additive fields (`landed_oid`, `ref_state`,
    `landing_contained`) serde-defaulted with `skip_serializing_if`, no
    `deny_unknown_fields`; legacy-cache round-trip test updated and passing.
12. **Holds.** No unwrap/expect/panic in any new production path (re-grepped after
    the round-2 delta); slicing confined to validated hex ASCII.
13. **Holds.** Refresh: O_EXCL/O_NOFOLLOW 0o600 temp, fsync, chmod 0o400, atomic
    rename, directory fsync, post-replace verification read; race loser fails closed
    retryably (deterministic injected-race test); non-canonical target path refused.
14. **Holds.** `reopen_candidate`/`verify_record_binding` byte-identical to HEAD;
    legacy plan-less closures keep whole-range fail-closed behavior — never a silent
    pass.
15. **Holds** (placement note in Finding 4c). 27 new/updated tests across the change;
    25 run independently by this review (11 + 14 batches, all passing); Builder
    reports the full workspace suite green (427 unit + 92 e2e) with fmt/clippy clean —
    the gate re-runs the suite and the sandboxed deterministic scanners
    (gitleaks/semgrep/cargo-audit).

Security-plan Conditions 16-22:

16. **Holds.** Fresh ledger load immediately before `refresh_candidate_record`
    (residual window = the temp-file write only; no stale ledger read is ever reused).
    Both race orderings fail-closed: eviction-then-gate-record dies at the pre-CAS
    reopen (`cli.rs` reopen adjacent to `save_exact_observed`);
    gate-record-then-eviction leaves a stale compact binding that errors every later
    reopen — now asserted by MESSAGE in all four tests — with the freshness rewind
    (`invalidate_for_freshness` clears `gates` >= phase) as recovery.
17. **Holds.** Vacuity guard fails closed BEFORE any commit scan or readiness
    computation; one shared `allowed` matcher drives the guard, diff purity, and both
    entry filters. Partial-drift analysis: a dropped in-scope entry also breaks any
    touching commit's purity — drift degrades fail-closed, never to a false VERIFY.
18. **Holds (was partial — Finding 1 fixed).** Ref-level state and
    landing-containment are now first-class observation fields presented at every
    surface (text + JSON); contained-but-Diverged/Rewritten reports the louder ref
    state, exits 1, and remains distinguishable via `landing_contained`; exit-code
    policy explicit in code. The docs half (wording + exit-code policy in the change's
    documentation) belongs to the not-yet-run Documentation phase — carried as a
    handoff note, not a gate condition, since the spec delta
    (`specs/remote-parity/spec.md`) already states both requirements normatively.
19. **Holds.** `build_output` attaches only when `phase == Phase::Build`; legacy
    config capture sets `candidate_id: None` so it can never bind a candidate export;
    a passing non-Build profile asserted to attach no typed output; and the C3 pin now
    cross-checks the output's `candidate_id` against the retained Candidate at
    record-binding time.
20. **Holds.** `MAX_LANDING_CANDIDATES = 2000` bounds materializations; existing
    tree/byte caps bound each; diagnostics capped; the O(range) diff-tree walk is
    unmaterialized availability-only work.
21. **Holds.** Eviction/refresh confined to `capture_candidate_with_hook`'s two
    existing-state arms (grep-verified); stale-binding failure now asserted by the
    compact-binding message in every post-eviction test.
22. **Holds.** The refreshed record is built entirely by `build_record` from
    fresh-capture values; the hostile-record test forges every attempt-variant field
    with canonically-valid adversarial values and proves the replacement equals the
    genuine fresh capture exactly. Independently run — passes.

Deterministic checks: no secrets, no new dependencies (Cargo.toml/lock untouched), no
unsafe, no exec/network additions (grep of every added line, both rounds). Working
tree extras are the change's own state/docs plus `proptest-regressions/config.txt`
(the persisted seed for the config proptest fix — expected; commit it with the
change).

## Independent review

A second pass per round that did not trust the first pass's framing, attacking the
primitives each loosened guard leans on:

- **The matcher.** `allowed` (`closure.rs`), including its reverse-containment
  clause, is load-bearing for landing selection. Traced: a path admitted only by
  reverse containment cannot cause wrong selection (scoped equivalence then fails);
  symmetric use on purity and both filter sides makes drift fail-closed.
- **The read path under hostile bytes.** `read_candidate_record` — no-follow,
  bounded, canonical re-serialization equality, domain-separated payload digest,
  triple metadata stability — parses any pre-seeded record before eviction decisions;
  non-canonical or tampered records fail closed before identity comparison.
- **The retained-tree proof.** `verify_retained_projection` runs BEFORE the record
  comparison, double-inventories with directory-identity pinning, and compares against
  entries computed from the LIVE worktree — a hostile tree cannot influence the fresh
  capture's values.
- **The ledger authority model.** `invalidate_for_freshness` removes `gates` for
  every applicable phase >= rewind; Deploy consumes only `gates[Build]` PASS with
  typed output; `history` readers are display/stats only — "superseded-but-secretly-
  live" is not constructible.
- **The end-to-end backstop.** Even under a hypothetical typed-output/candidate
  mismatch, Deploy re-opens the artifact no-follow and rejects byte drift from the
  recorded sha before executing — and the C3 pin now refuses the mismatch at
  record-binding time as well.
- **Round-2 delta review.** Verified the C1 presentation change is computation-
  hoisting plus additive fields only — the state-derivation match is semantically
  identical to the round-1-audited logic; re-checked every parity-cache consumer for
  sensitivity to the new fields (none); confirmed `describe_ref_level_parity` is
  read-only rendering used at all three surfaces; confirmed the orphan-arm reason
  string carries no secret-bearing content; re-ran the no-new-verbs/no-egress/no-panic
  greps over the final diff.
- **Independent test execution.** 25 tests run directly by this review across both
  rounds (all new D1/D2/D3/C2/C3 tests plus regression re-runs) — all passing.

## Refutation

Strongest attacks constructed against the PASS, and why each fails:

1. **Adopt attacker bytes via a pre-seeded record/tree (D1).** A hostile tree fails
   `verify_retained_projection` before any record logic; a hostile record with forged
   identity fails the identity comparison; a hostile record with matching identity and
   forged attempt-variant state is evicted and replaced by a record built 100% from
   the fresh capture — proven by the hostile-record test asserting every forged field
   is absent from the replacement. The refresh loser's post-replace verification read
   refuses unequal winners.
2. **Launder a superseded Build artifact through re-export (D2).** A live
   `gates[Build]` binding still refuses same-path re-export under the output lock; a
   rewound binding has no live reader (Deploy reads `gates`); the deleted error path
   removed only a false-positive on output-less records; Deploy's record-time and
   execute-time sha revalidation backstops the rest, now with the C3 candidate-ID pin
   in front of it.
3. **Bind a decoy landing commit (D3).** Selection demands single-parent, fully
   in-scope diff, AND in-scope tree equivalence against the archived plan — a
   qualifying "decoy" necessarily carries the exact reviewed in-scope postimage at a
   scope-pure commit, which is precisely the claim VERIFIED makes. The
   merge-with-matching-tree fixture proves content cannot buy a merge in.
4. **Vacuous or partially-vacuous scoped comparison (D3).** Total vacuity fails
   closed before any scan (tested). Partial drift is self-defeating: an entry the
   matcher drops is an entry whose landing-commit modification breaks diff purity, so
   the genuine landing stops qualifying and resolution fails closed.
5. **Fork retaining the landing while diverging elsewhere (D3).** Round 1 produced
   the findings here; round 2 closes them: the divergence test proves a
   contained-landing-in-a-diverged-ref reports `state: Diverged` (never VERIFIED,
   exit 1) while `landing_contained: Some(true)` and `ref_state: Some(Diverged)` keep
   the two claims separately visible. The remaining refutation attempt — sneak a
   false PASS through the new presentation fields — fails because `state` derivation
   is unchanged and both new fields are output-only.
6. **Race the eviction rename against a gate-record CAS (D1/Condition 16).** Both
   orderings traced to fail-closed outcomes (pre-CAS reopen failure, or a stale
   compact binding that errors every later reopen with rewind as recovery); the
   deterministic injected-race test pins the rename-race loser's refusal, and the
   post-eviction tests now pin the exact compact-binding message.

The PASS survives refutation on every axis; the round-1 residuals (presentation,
coverage, hardening) are closed and re-verified.

## Verdict

PASS — all three round-1 conditions and both notes are genuinely closed and were
re-audited against the final diff: C1's ref-level/containment presentation is additive,
visible at every surface, back-compatible, and introduces no new verdict path (the
fail-closed Diverged/Rewritten-over-containment derivation and the exit-0-only-on-
Verified policy are unchanged); C2's new test exercises exactly the
landing-contained-plus-diverged branch and asserts the loud non-VERIFIED outcome; C3's
candidate-ID pin is strictly additive and fail-closed including the None case; the
Condition-21 message assertions and the orphan-arm reason surfacing are in place. The
three loosened guards preserve the fail-closed trust chain end to end — D1 cannot
adopt attacker bytes, D2's gates-only binding matches the real authority model with
locks and CAS covering true races, D3 proves exactly the per-change landing claim with
divergence reported loudly. 25 tests independently executed by this review (all
passing); Builder-reported suite 427 unit + 92 e2e green with clippy clean, to be
re-confirmed by the gate's sandboxed deterministic checks. Handoff notes (non-gating):
the Documentation phase must state the landing-containment wording and exit-code
policy (spec delta already normative), and the Tester should weigh a binary-driven
e2e rewind fixture (tasks.md 2.3). Code may proceed to Test.
