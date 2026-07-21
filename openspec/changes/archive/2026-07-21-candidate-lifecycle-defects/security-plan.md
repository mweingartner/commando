# Security (plan) review

## Actor

Security

## Threat model

**Trust boundary.** MPD's evidence chain is tamper-evident against cooperative-but-
fallible agents, crashed/superseded attempts, and unprivileged interference with
clone-private state. A principal with full write access to `.git/`, `.mpd/`, and the
ledger is outside the boundary (they can rewrite every artifact wholesale). This change
loosens three fail-closed guards inside that trust core; the review question for each
is whether the loosening opens a laundering or evidence-forgery channel, not merely
whether it fixes the stall.

**Surfaces touched.** (1) The content-addressed candidate cache
(`.git/mpd/{candidates,candidate-records}` — owner-only 0o700 dirs, 0o400 single-link
canonical-JSON records with a domain-separated payload digest, no-follow reads);
(2) the ledger `gates`/`history` authority split (`.mpd/state/<change>.json`);
(3) publish-time closure verification and bounded remote observation (`ls-remote`
only — no fetch, push, ref write, or credential handling). No new dependencies, no
dynamic code, no new network egress.

### D1 — stale-record eviction cannot adopt attacker bytes

- **Pre-seeded record/tree adoption is closed.** In the existing-root arm,
  `verify_retained_projection` (`candidate.rs:2050`) runs BEFORE any record
  comparison: the retained tree is doubly inventoried via no-follow bounded reads and
  must byte-equal the FRESH capture's entries — which are computed from the live
  worktree projection, never from the cached record. A pre-seeded tree with different
  bytes fails `retained candidate inventory does not match its ID`. The refreshed
  record is built entirely by `build_record` from the fresh capture's own values; no
  field of the observed (stale) record flows into the replacement. The orphan arm
  adopts nothing — it only deletes and falls through to fresh publication. There is no
  path by which eviction causes adoption of attacker-controlled content.
- **The three preconditions hold up.** Identity fields include the full `entries`
  inventory, all subject digests, the ID, and the owning `subject.change`. Cross-change
  eviction is structurally impossible: there is exactly one record file per ID
  (`<id>.json`), the record names one owner, and a foreign-change record can never have
  been adopted by the capturing change (identity comparison fails closed today and
  after D1) — so a colliding change's record always trips the same-change guard. The
  live-binding guard protects every real reopen consumer: verified that
  `reopen_candidate` is only ever invoked on captures reachable from the live `gates`
  map or the in-process pending capture (`cli.rs:2838`, `:2858`, `:3251`, `:3259`,
  `:3630`, `:6228`); history-only captures are displayed and counted, never reopened.
- **`reopen_candidate` strictness is the backstop and stays untouched** (design
  Non-Goals, Cond 14). `verify_record_binding` (`candidate.rs:374`) pins record
  sha256/device/inode to the ledger's compact binding, and the retained tree is
  re-verified against the record entries on every reopen. An evicted+recaptured record
  has a different sha256, so any stale binding fails closed loudly — content can never
  be silently swapped under a recorded gate.
- **ID preimage UNCHANGED** — `candidate_id` (`candidate.rs:2388`) still digests
  `(schema, base_tree, manifest, entries, policy, source)`. Evidence-reuse integrity
  across identical trees is preserved; no process state enters the ID.
- **Residual (named, fail-closed): eviction vs in-flight gate record.** Gate recording
  reopens the candidate (`cli.rs:3630`) before the ledger CAS (`:3633-3637`); an
  eviction rename landing between the precondition read and the CAS can leave a live
  binding whose compact sha no longer matches the record. Every outcome is fail-closed
  (next reopen errors on the sha binding) and recoverable (rewind clears `gates`,
  which then permits eviction and recapture). No forgery — but the window must be
  minimized and the fail-closed outcome tested (added Condition 16).

### D2 — gates-only binding is the correct authority

- `invalidate_for_freshness` (`ledger.rs:951`) removes `gates` entries for every
  applicable phase >= the rewind target; `history` is append-only audit by design
  (`ledger.rs:711-721`). Verified no other consumer treats `history` as output-binding
  authority: the remaining `.history` readers are display/JSON/stats
  (`cli.rs:2071`, `:2177-2192`, `:2500`, `:3140`; `stats.rs`). Deploy consumes only
  `gates[Build]` filtered to a PASS with typed `BuildOutputV1` (`cli.rs:3431-3441`).
  A record can leave `gates` only via rewind or same-phase re-record — both of which
  change the authoritative verdict Deploy reads, so "superseded-but-secretly-live" is
  not constructible.
- The typed-only predicate is sound: `build_output` is attached to gate records only
  when `phase == Build` (`cli.rs:3539-3551`); Security (code)/Test/FAIL records carry
  `candidate` only. Deleting the `:1414` "no typed Build output" error removes a
  false-binding error, not a protection. The predicate's soundness depends on Build
  remaining the only typed-output-attaching phase — pinned by added Condition 19.
- **Genuine races stay covered without the history scan.** The per-candidate output
  lock is acquired before the binding check (`local_validation.rs:1549` before
  `:1558`), and record time re-verifies the on-disk output bytes and reopens the
  candidate adjacent to the ledger CAS (`cli.rs:3626-3637`). The invariant that
  matters — the live `gates[Build].build_output` sha matches the on-disk artifact at
  record time — is enforced at CAS time, so a concurrent re-export either produces
  identical bytes (harmless) or fails the recorder's revalidation (fail-closed). Live
  binding at the same path still refuses; different path still errors (Cond 4).

### D3 — landing-commit verification (scrutinized hardest)

- **Wrong-commit selection is not a forgery channel — with one guard.** A commit can
  be selected as the landing only if it is single-parent, its parent-diff is entirely
  in-scope, AND its in-scope tree equals the archived plan's in-scope entries. Any
  commit satisfying all three genuinely carries the exact reviewed in-scope postimage
  at a scope-pure commit — selecting it (earliest-first, deterministic) still proves
  precisely the property publish asserts. A crafted "decoy" landing must contain the
  reviewed bytes to qualify, at which point it is not a decoy.
- **THE load-bearing hazard: a vacuous scoped comparison.** If pattern/path
  normalization drift ever makes `allowed(closure.allowed_paths, ·)` match ZERO plan
  entries, equivalence over the empty set is trivially true and the first in-scope-pure
  commit becomes the landing — parity would then VERIFY arbitrary content. The plan as
  written ("compare only entries whose paths match allowed_paths") does not exclude
  this. Fail closed on an empty scoped expected set, and use the SAME matcher for diff
  purity and entry filtering (added Condition 17). With that guard, scoped equivalence
  at landing location is safe.
- **Scoped vs full-tree equivalence (Architect Flag 2): safe, with an honest cession.**
  The landing commit's own diff-purity proves that commit changed nothing out of
  scope; its out-of-scope tree is its parent's, attested by whichever change/commit
  produced it (policed at creation by the pre-commit staged-scope gate, and by that
  change's own publish). Full-tree equivalence still runs where the whole tree is this
  change's responsibility — archive/commit-validation time. What IS ceded and must be
  stated, not hidden: X's `publish --verify` no longer polices non-landing commits at
  all, so an unclaimed out-of-scope commit elsewhere in the range is invisible to X's
  verify. The old whole-range check was not a usable control (it false-positived on
  every legitimate interleaving, which is how controls get bypassed), and range
  policing belongs to commit time — acceptable, but output/docs must not overclaim
  (added Condition 18).
- **"Remote contains the landing" proves exactly the per-change claim and no more.**
  A fork/rewrite retaining X's landing while diverging elsewhere yields
  VERIFIED-for-X — honestly: X's reviewed closure is in that history. Whole-repo
  integrity becomes the conjunction of every change's verify plus the ref-level
  `ParityState` (still computed; Diverged/Rewritten still classified, cache-keyed per
  change/remote/ref at `closure.rs:3244-3249`). The ref-level state must therefore be
  surfaced loudly next to any per-change VERIFIED, with an explicit exit-code policy
  for contained-landing-but-Diverged/Rewritten (added Condition 18). Ancestry proof
  keeps no-fetch semantics: `git.rs:747-766` reports missing objects as `None` →
  AncestryUnavailable, never a fetch.
- **Bounds.** A no-match scan materializes every in-scope-diff commit in the range —
  availability-only, each materialization capped, but total work is O(range); bound or
  document it (added Condition 20). Legacy plan-less closures degrade to an explicit
  fail-closed blocker (Cond 14) — no silent pass. `ParityObservation.landed_oid` is
  additive and back-compatible both directions (no `deny_unknown_fields` on the type;
  `load_parity_cache` degrades via `.ok()`), and the cache remains a hint, never
  authority.

### Architect Flag 1 — deferred "closure divergence accepted" verb

**Deferring is safe.** The default stays fail-closed: a rewritten landing or archive
base keeps failing verification with an accurate diagnosis, and this change ships no
bypass verb of any kind. For the record: if such a verb is later added, it IS a
trust-boundary weakening — it converts an integrity failure into an operator
attestation — and must receive its own full threat model as novel surface (full-depth
security phases, no inline fixes): append-only and per-closure scoped (never blanket),
carrying the named operator, reason, and digests of both the archived and observed
sides, permanently surfaced in status, and yielding a distinct state
(ACKNOWLEDGED-DIVERGED), never VERIFIED.

## Conditions for Builder

Conditions 1-15 of design.md are endorsed as sound and testable; each was checked
against the code site it cites. Additions (numbering continues from the Architect's
15; owner: Builder; closing evidence: named tests plus the Security (code) review):

16. **Eviction/gate-record race is fail-closed.** Re-load the ledger and re-check the
    live-binding precondition immediately before the record rename (minimize the
    window). A gate-record CAS racing an eviction must only ever produce fail-closed
    outcomes — a stale compact binding makes every subsequent reopen error — never
    adoption of mismatched state; the recovery path is the freshness rewind. Test the
    post-eviction stale-binding reopen failure explicitly.
17. **Scoped equivalence is non-vacuous and single-matcher.** Landing resolution SHALL
    fail closed if zero retained-plan entries match `closure.allowed_paths` (a landing
    must never be declared on an empty comparison), and the SAME path-match predicate
    SHALL drive both the parent-diff purity check and the entry filtering on both
    sides. Prevents a vacuous trivially-true equivalence binding the landing to an
    arbitrary in-scope-pure commit.
18. **Per-change VERIFIED never overclaims.** `publish --verify` output (text and
    JSON) SHALL always present the ref-level `ParityState` alongside the per-change
    verdict; when the landing is contained but the ref state is Diverged or Rewritten,
    that state SHALL be reported loudly and the exit-code policy for it SHALL be
    explicit in code and docs. All wording is "this change's landing commit is
    contained in the remote", never whole-ref parity.
19. **Build stays the only typed-output phase.** Add a test asserting no gate record
    for any phase other than Build ever carries a typed `build_output` — the D2
    binding predicate's soundness depends on it, and any future phase that attaches
    typed output silently becomes a binding.
20. **Landing scan is bounded end-to-end.** Cap the number of materialized landing
    candidates (or explicitly document the O(range) no-match worst case with the
    per-materialization tree/byte caps as the authority); nearest-miss diagnostics
    stay capped (Cond 8); no unbounded blocker output into terminal or JSON.
21. **Eviction is capture-only.** No reopen, status, publish, archive, or gate path
    may ever evict or rewrite a candidate record; refresh logic lives solely in
    `capture_candidate_with_hook`'s two existing-state arms. Assert by test that a
    stale ledger binding after eviction fails closed with the compact-binding message.
22. **The refreshed record derives 100% from the fresh capture.** No field of the
    observed (evicted) record may flow into the replacement. Test with hostile
    attempt-variant values (forged counts, device/inode, status/excluded-dirty
    digests) that the republished record equals the fresh capture's own computed
    record exactly.

## Verdict

CONDITIONAL PASS — the plan is sound and each of the three loosenings preserves the
fail-closed trust chain: D1 cannot adopt attacker bytes (fresh-capture-derived
refresh behind identity/same-change/no-live-binding guards, with strict reopen as
backstop and the ID preimage unchanged), D2's gates-only binding matches the actual
authority model (history is audit-only; lock + record-time CAS cover real races), and
D3's landing-commit semantics prove exactly the per-change claim (a qualifying commit
must carry the reviewed in-scope bytes). Closing conditions: Builder honors added
Conditions 16-22 (16, 17, 18 are the load-bearing ones — the eviction race window,
the vacuous-scoped-comparison guard, and per-change VERIFIED presentation), evidenced
by the named tests and verified at the Security (code) gate. Deferring the divergence-
acknowledgment verb is safe (default stays fail-closed); if later added it requires
its own threat model as novel trust surface.
