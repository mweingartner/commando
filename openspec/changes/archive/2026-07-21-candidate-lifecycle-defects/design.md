# Design: Candidate Lifecycle Defects

## Actor

Architect

## Context

All three defects were reproduced live while the pipeline self-hosted its first four
changes (HEAD `8c7b7c5` at planning time). Every file/line reference below was verified
against the current tree. This change is pure backend/tooling (no UI surface). Risk is
high because it touches the three mechanisms that make gate evidence trustworthy: the
content-addressed candidate cache, the Build-output binding that feeds Deploy, and the
closure/parity verification that asserts "what was reviewed is what was pushed". A wrong
fix here either weakens an anti-tamper check or re-introduces the stalls.

Current defect sites (verified):

- **D1 — candidate-ID base collision.** `candidate_id` (`crates/mpd/src/candidate.rs:2388`)
  digests `(CANDIDATE_SCHEMA, base_tree, manifest_digest, entries_digest, policy_digest,
  source_digest)`. It deliberately does NOT include `base_commit` (same tree via amend or
  identical re-commit must reuse evidence), the change's status/overlay plan, or
  out-of-scope dirty state. But `CandidateProjectionRecordV1` (`candidate.rs:161`)
  additionally freezes attempt-variant process state: `subject.base_commit`, `counts`,
  `excluded_dirty_paths`, `excluded_dirty_digest`, `declared_status_digest`,
  `root_device`/`root_inode`. `capture_candidate_with_hook` (`candidate.rs:481`), in the
  "retained root already exists" arm, requires whole-record equality
  (`candidate.rs:618-628`) and errors `existing candidate projection record does not
  match its ID` (`:624`) on any difference; the sibling arm errors `candidate projection
  record exists without its retained root` (`:655-658`) on an orphaned record. So a
  superseded attempt's leftover record — identical projected content, different process
  state (e.g. different `base_commit` after a rewind/re-commit of the same tree,
  different staged-vs-worktree overlay, different out-of-scope dirt) — permanently
  stalls every fresh capture of that content. That is the reproduced
  "stale-cache stall". The answer to "if base_commit IS in the digest, why did
  collisions happen?" is: `base_commit` is NOT in the ID preimage (only `base_tree`
  is), and neither are the other attempt-variant record fields; the ID is content
  identity while the record equality check demands process-state identity.
- **D2 — re-export-after-rewind binding conflict.**
  `export_candidate_runtime_build_output` (`crates/mpd/src/local_validation.rs:1532`)
  calls `candidate_output_ledger_bound` (`local_validation.rs:1378`), which iterates
  `ledger.history` chained with `ledger.gates.values()` (`:1396-1400`). For ANY record
  referencing the candidate ID — via `record.candidate.subject.id` or
  `record.build_output.candidate_id` — it errors `candidate ledger binding has no typed
  Build output` (`:1414`) when `build_output` is absent, or blocks with `candidate Build
  output is already bound by a durable ledger event` (`:1559`). Two consequences:
  (a) Security (code)/Test gate records legitimately carry `candidate` with no
  `build_output` (`cli.rs:3588-3589` attaches `candidate` on every candidate gate;
  `build_output` only on a passing Build), so after any rewind their retained `history`
  entries make re-export error at `:1414`; (b) a superseded Build PASS in `history`
  blocks at `:1559`. Both stall Build after a freshness rewind of an identical tree.
  The authority model already exists: `Ledger::invalidate_for_freshness`
  (`crates/mpd/src/ledger.rs:951`) removes `gates` entries for every phase >= the rewind
  target while `history` intentionally preserves the audit trail (`ledger.rs:711-721`).
  The `gates` map is therefore exactly the set of live, authoritative records.
- **D3 — publish --verify whole-range semantics.** `verify_commit_coherence`
  (`crates/mpd/src/closure.rs:2940`) (i) rev-lists `closure.base_commit..HEAD` and
  checks EVERY commit's touched paths against THIS closure's `allowed_paths`
  (`:2964-2982`) — commits that landed OTHER changes are judged against the wrong scope
  (reproduced: `commit dbacbb4/f2705b5 touches out-of-scope path ...` while running
  verify for the latest change); (ii) compares the CURRENT worktree scoped digest
  against `closure.post_archive_digest` (`:2999-3002`); and (iii) runs
  `verify_candidate_commit_equivalence` (`closure.rs:607`) against HEAD
  (`:3003-3030`), so any legitimate later edit of the same files — the reproduced
  post-archive `git filter-branch` fixture redaction — reports `content digest mismatch
  at <path>`. `verify_remote_parity_with_probe` (`closure.rs:3156`) then binds VERIFIED
  to `HEAD == coherent head && worktree scoped == postimage && included clean`
  (`:3214-3218`). `cmd_publish` (`crates/mpd/src/cli.rs:5675`) consumes coherence at
  `:5696`/`:5746`; `mpd status` consumes it at `cli.rs:1547` and `:1591`. The model
  assumed "one change lands and is verified before anything else happens", which the
  self-hosting run disproved.

## Goals / Non-Goals

Goals:

- A leftover candidate record or root from a superseded attempt never hard-stalls a
  legitimate capture; genuine content disagreement and live-bound records still fail
  closed.
- A rewound (superseded) Build binding never blocks re-export of the same candidate;
  live concurrent bindings still block.
- `publish --verify` verifies each archived change against its OWN landing commit and
  the remote's containment of it; later legitimate commits — including edits to the same
  files — are never corruption; per-commit scope checks apply only to the commit(s) that
  constitute this change's landing.
- All changes fail closed, panic-free, with additive-only schema changes.

Non-Goals:

- No global "attribute every commit in history to some archived change" audit — manual
  commits are legitimate and are policed at commit time by the pre-commit staged-scope
  gate, not retroactively by publish.
- No reconciliation verb for authorized history rewrites (filter-branch): a rewritten
  landing commit keeps failing verification, now with an accurate diagnosis. The
  acknowledgment verb is DEFERRED (see Risks).
- No change to the candidate ID preimage: the ID stays pure content identity. Widening
  it to include process state would destroy evidence reuse across identical trees (the
  point of content addressing) and does not fix stale-cache handling anyway.
- No change to `reopen_candidate` (`candidate.rs:310`) strictness: reopen is the
  authority chain for a ledger-bound capture and must keep exact-binding semantics.

## Decisions

### D1: Split identity from attempt-variant state; evict stale records under guard

`capture_candidate_with_hook`, both existing-state arms:

1. **Identity fields** (fail-closed on ANY disagreement, message unchanged): `schema`,
   `subject.version`, `subject.change`, `subject.base_tree`, `subject.manifest_digest`,
   `subject.entries_digest`, `subject.policy_digest`, `subject.source_digest`,
   `subject.id`, and `entries`. These are the ID-covered content identity (plus the
   owning change; see guard below). Note `verify_retained_projection`
   (`candidate.rs:2050`) has already proven the retained tree equals the NEW capture's
   entries before the record comparison runs, so an identity mismatch here means the
   sidecar record disagrees with content that hashes to its own ID — corruption or
   tampering, never staleness.
2. **Attempt-variant fields** (differences alone trigger recovery, not error):
   `subject.base_commit`, `counts`, `excluded_dirty_paths`, `excluded_dirty_digest`,
   `declared_status_digest`, `root_device`, `root_inode`, `payload_digest` (recomputed).
3. **Recovery preconditions** (ALL must hold, else fail closed with a message naming
   the failing precondition):
   - identity fields match (per 1);
   - `observed.subject.change` equals the capturing change (cross-change ID collisions
     — possible only with identical manifests AND identical projected trees — stay
     hard-stopped so one change can never evict a record another change's ledger may
     bind);
   - the capturing change's ledger, if present, has NO record in the authoritative
     `gates` map whose `candidate.subject.id` equals this ID (history-only/superseded
     bindings do not block). If a live gate binds the ID, error with guidance to run
     the freshness rewind instead of capturing over live evidence.
4. **Recovery mechanics** — same durability discipline as `publish_candidate_record`
   (`candidate.rs:1285`) and `save_candidate_closure_plan`:
   - *Stale record with intact root* (`:618-628` arm): write the new expected record to
     a temp file (0o600, `O_EXCL`/`O_NOFOLLOW`), fsync, atomically `rename` over the
     canonical `<id>.json`, fsync the directory, then re-read via
     `read_candidate_record` (`candidate.rs:1084`) and require equality with the
     expected record (preserving the existing read-verify-read pattern). The retained
     root is kept — it was already verified equal to the new entries.
   - *Orphaned record without root* (`:655-658` arm): under the same preconditions
     (identity check limited to what the record itself carries), delete the orphan
     record, fsync the directory, and fall through to the existing fresh-publication
     path (`:660-683`). `recover_candidate_record_publication` (`candidate.rs:1194`)
     still runs first, unchanged, to settle crashed publications.
5. **Concurrency**: two processes recovering the same ID race on the `rename`; the
   loser's post-replace verification read sees the winner's record. If the records are
   equal (the common case — both computed from the same live repo state) the loser
   proceeds; if unequal, the loser fails closed with a retryable message. No new lock
   surface; a single clean retryable error is not a hard stall.

Alternative rejected: adding an attempt nonce or process state to the ID — see
Non-Goals; it trades a recoverable cache problem for permanent evidence-reuse loss.

### D2: Bind Build output only through authoritative, typed records

`candidate_output_ledger_bound` (`local_validation.rs:1378`):

- Iterate ONLY `ledger.gates.values()` — the latest-per-phase authoritative map, which
  every rewind path (`invalidate_for_freshness`, governance rewinds) already clears for
  superseded phases. Do not iterate `history`.
- A record is a binding ONLY if `record.build_output` is `Some` AND its `candidate_id`
  equals the candidate being exported. Records that merely carry `candidate` (Security
  (code), Test, any FAIL) are not output bindings and never an error — delete the
  `:1414` "no typed Build output" error entirely.
- Keep the path-consistency error (`:1416`): a live typed binding for this candidate at
  a DIFFERENT path still fails closed.
- Keep the `:1559` refusal when a live binding exists at the same path: that is the
  genuine anti-double-bind (a live Build attestation's bytes must not be replaced by a
  racing re-export — builds are not bit-reproducible, so a re-export could silently
  invalidate the recorded sha256).
- Concurrency remains covered independently of this check: the per-candidate output
  lock is acquired before the ledger check (`local_validation.rs:1549`), and the gate
  records through a CAS with a final output revalidation (`cli.rs:3626-3637`).

Why gates-map-only is exactly right: `history` is an append-only audit trail whose
records are by definition superseded once `gates` no longer carries them
(`ledger.rs:711-721`, `:951-988`). A rewound Build event's exported file has no live
reader — Deploy reads `gates[Build].build_output` — so overwriting it on re-export is
safe, while a live `gates` binding still blocks.

### D3: Landing-commit closure verification

New concept (Ubiquitous Language): the **landing commit** of an archived change — the
commit that landed its closure. Replaces "the coherent HEAD" as the subject of
post-archive verification.

1. **Resolution** — new `closure.rs` function (replacing `verify_commit_coherence`
   semantics; the three call sites `cli.rs:5696`, `:1547`, `:1591` are rewired):

   ```
   ClosureLanding {
       landed: Option<String>,        // the landing commit OID, when found
       ready_to_commit: bool,          // pre-landing worktree readiness
       blockers: Vec<String>,          // precise, bounded diagnostics
   }
   ```

   Scan `rev_list_reverse(closure.base_commit, HEAD)` in order. A commit C is a
   *landing candidate* iff it has a single parent (merge commits are never landings,
   as today `closure.rs:2980`) and every path in `diff_tree_name_status(parent, C)`
   (including rename origins) matches `closure.allowed_paths`. For each landing
   candidate in order, run **scoped closure equivalence**: materialize C via the
   existing `verify_candidate_commit_equivalence` machinery (`closure.rs:607`) against
   the retained plan from `load_candidate_closure_plan` (`closure.rs:710`), but compare
   only entries (expected and observed) whose paths match `closure.allowed_paths`.
   The first equivalent landing candidate is THE landing commit. Scoped — not
   full-tree — comparison is what makes interleaved histories verifiable: out-of-scope
   tree content legitimately reflects whichever changes landed before/after, while
   the diff-subset check has already proven this commit touched nothing outside its
   own scope.
2. **Scope purity is per-landing-commit, not per-range.** The `base..HEAD` per-commit
   out-of-scope scan (`closure.rs:2964-2982`) is removed. Commits that are not this
   change's landing commit are simply outside this change's jurisdiction — they are
   verified by their own change's publish, or were policed at creation time by the
   pre-commit staged-scope gate (change-manifest spec, "staged scope of a pending
   awaiting-commit closure"). This is the fix for "each commit's scope is checked
   against its own change".
3. **Worktree checks become pre-landing readiness only.** When no landing commit is
   found AND the closure is awaiting commit, report readiness exactly as today
   (worktree scoped digest vs `post_archive_digest`, included-scope cleanliness,
   HEAD-descends-from-base) with next action "commit the exact archived result". When
   no landing commit is found and readiness also fails, report "no commit in
   `<base>..HEAD` matches this change's archived closure" plus bounded nearest-miss
   diagnostics: for landing candidates that failed equivalence, list up to a fixed
   small cap of differing in-scope paths (this is what turns the filter-branch
   redaction from a misleading cross-change error dump into an accurate one-line
   diagnosis). Worktree dirt is NEVER a blocker for an already-landed change.
4. **Parity** — `verify_remote_parity_with_probe` (`closure.rs:3156`): the paired
   local/remote snapshot-stability loop is unchanged (no fetching, no pushing, one
   retry then UNSTABLE). The VERIFIED binding at `:3214-3218` is replaced: a stable
   observation verifies the CHANGE when the landing commit is contained in the observed
   remote OID — `remote2 == landing`, or `remote2 == snapshot2.head` (HEAD contains the
   landing by construction), or `sanitized_is_ancestor(landing, remote2)` where the
   remote object is locally present. Remote object absent locally keeps today's
   no-fetch AncestryUnavailable behavior. The `snapshot2.scoped == post_archive_digest
   && included_clean` conjunct is dropped from the landed path (it was the 3a defect);
   HEAD-containment of the landing is re-asserted on `snapshot2.head`. The overall
   HEAD-vs-remote `ParityState` classification (ahead/behind/diverged/rewritten) is
   still computed and reported as ref-level information; `publish --verify` exits 0
   when the change's landing commit is verifiably on the remote, even if the local ref
   is ahead with later work. `ParityObservation` gains an additive
   `landed_oid: Option<String>` (serde-defaulted; old caches keep deserializing).
5. **Legacy closures** (no `candidate_id`/plan — `closure.rs:3003` guard): there is no
   per-commit tree equivalence source, so landing resolution falls back to: HEAD-based
   behavior as today when the worktree scoped digest still matches, otherwise a
   fail-closed "legacy closure cannot be landing-verified after later commits" blocker.
   All closures produced by current mpd are modern; this repo has no legacy closure
   that still needs publish. Explicitly documented degradation, never a silent pass.
6. **`mpd status`** (`cli.rs:1547`, `:1591`): "committed" display maps to
   `landed: Some(oid)` (show the landing OID, not HEAD); awaiting-commit maps to
   `ready_to_commit`/blockers. No status field changes meaning silently: landed-ness,
   parity, authorization, and install remain orthogonal fields per the remote-parity
   spec.
7. **Bounds**: resolution materializes only landing candidates (commits whose diff
   already stayed in scope) — in practice one or two commits; the existing
   `MAX_CLOSURE_TREE_ENTRIES`/byte caps (`closure.rs:373-375`) bound each
   materialization. No new configuration.

Alternative considered — record the landing OID durably at commit time (pre-commit hook
knows it): cleaner O(1) lookups, but adds a new commit-time write surface and still
requires full re-verification on read (a recorded OID is a hint, not authority). The
derivational scan needs no new durable state; a clone-private landing cache can be
added later as a pure optimization. DEFERRED.

## Risks / Trade-offs

- [Record eviction could destroy evidence another party binds] → Mitigated by the three
  preconditions (identity match, same change, no live gate binding) and by leaving
  `reopen_candidate` strict: a ledger-bound capture whose record was refreshed by a
  later attempt of the same change was already superseded (its binding left the `gates`
  map before eviction was allowed).
- [Gates-map-only binding misses a live reader] → Deploy and every downstream consumer
  read `gates`, never `history` (verified: `candidate_output_ledger_bound` was the only
  history-scanning consumer of output bindings). The output lock + record-time CAS
  still serialize true races.
- [Scoped (not full-tree) equivalence weakens the landing proof] → The landing commit's
  diff-subset check proves nothing outside scope changed in that commit; in-scope
  equivalence proves the reviewed postimage landed; out-of-scope content is the
  parent's, policed by its own changes. Full-tree equivalence remains in force where it
  was designed to run: at archive/commit-validation time.
- [Filter-branch-rewritten closures still fail verify] → Correct and intended
  (fail-closed): the archived evidence genuinely never landed as-committed. The
  diagnosis becomes accurate. An append-only operator acknowledgment verb
  ("closure divergence accepted: <reason>") is DEFERRED pending a product decision —
  flagged to the user.
- [A rewritten/garbage `closure.base_commit` (base itself rewritten)] → rev-list fails;
  keep today's fail-closed blocker with clearer wording ("archive base is no longer in
  history — history was rewritten"). Remap/acknowledgment likewise DEFERRED.
- [Concurrent captures racing the record rename] → loser fails closed with a retryable
  message after the post-replace verification read; no torn state (atomic rename +
  fsync discipline).

## Conditions for Builder

1. **Stale cache never hard-stalls a legitimate capture.** With a leftover
   `.git/mpd/candidate-records/<id>.json` (and/or retained root) from a superseded
   attempt whose identity fields match the fresh capture, `capture_candidate` succeeds
   without manual cleanup — for both the stale-record-with-root and orphaned-record
   arms. Regression tests must reproduce the original stall (record differing ONLY in
   `base_commit`, ONLY in `declared_status_digest`/`counts`, ONLY in excluded-dirty
   state, and root recreated with new device/inode).
2. **Identity disagreement stays fail-closed.** A record whose identity fields
   (schema, subject version/change/base_tree/digests/id, entries) disagree with the
   fresh capture still errors with the existing corruption message; the record is NOT
   evicted. A record owned by a different change name is never evicted.
3. **Live bindings block eviction.** If the capturing change's authoritative `gates`
   map binds this candidate ID, capture fails closed with rewind guidance; nothing on
   disk changes.
4. **Anti-double-bind still blocks live concurrent bindings.** A current `gates` record
   with typed `build_output` for the candidate blocks re-export at the same path
   (unchanged message) and errors on a different path. The output lock is still
   acquired before the ledger check.
5. **A rewound binding does not poison re-export.** After
   `invalidate_for_freshness` rewinds to Build, with superseded Build PASS and
   Security(code)/Test records (carrying `candidate`, no `build_output`) retained in
   `history`, `export_candidate_runtime_build_output` for the SAME candidate ID
   succeeds. The `:1414` error is gone; no code path errors on a candidate-referencing
   record that lacks `build_output`.
6. **publish --verify never treats a legitimate later same-file edit as corruption.**
   With change X landed at commit Cx and a later commit editing files inside X's scope,
   `mpd publish --verify` (for X) locates Cx, reports no content-mismatch/out-of-scope
   blockers, and verifies when the remote contains Cx.
7. **Each commit's scope is checked against its own change.** No commit other than the
   landing commit is ever reported out-of-scope by X's verification; a range containing
   other changes' landing commits (before or after Cx) produces no blockers for X.
   Merge commits are never landing candidates.
8. **Landing resolution is deterministic and bounded.** Earliest equivalent landing
   candidate wins; only diff-in-scope commits are materialized; existing tree-entry and
   byte caps apply; nearest-miss diagnostics are bounded (fixed cap on listed paths).
9. **Parity remains observational and no-fetch.** No push, no fetch, no ref writes; the
   snapshot-stability/UNSTABLE loop, offline handling, and remote-name refusal are
   unchanged. VERIFIED-for-the-change requires the landing commit contained in the
   stable remote OID; remote object absent locally keeps AncestryUnavailable. The
   worktree-postimage and included-clean conjuncts must not gate a landed change.
10. **Pre-landing readiness is preserved.** Before the closure commit exists, readiness
    reporting (worktree postimage match, included-scope cleanliness, "commit the exact
    archived result") behaves as today.
11. **Schema changes are additive only.** `ParityObservation.landed_oid` is optional and
    serde-defaulted; no ledger field changes shape; old caches/ledgers deserialize; new
    records written by old binaries remain readable (no `deny_unknown_fields` on
    extended types that old binaries write).
12. **No new panic paths.** No `unwrap`/`expect` on input-derived state in any touched
    code; all new errors are ordinary fail-closed `Err` returns.
13. **All changes fail-closed.** Any precondition, I/O, parse, or verification failure
    in the new paths blocks with a precise message; no silent fallbacks; record
    eviction uses O_EXCL/O_NOFOLLOW 0o600 temp + fsync + rename + directory fsync +
    post-replace verification read, and the concurrent-eviction loser errors (retryable)
    rather than proceeding on unverified state.
14. **`reopen_candidate` is untouched** (exact strictness preserved), and legacy
    (plan-less) closures degrade to an explicit fail-closed blocker, never a silent
    pass, once later commits exist.
15. **Tests land with the code** (Builder writes initial tests in the same pass): unit
    tests per decision plus e2e reproductions of all three original stalls in
    `crates/mpd/tests/e2e.rs`, and the full suite runs green with a real, non-zero
    count.

## Verdict

PASS — plan complete; Conditions 1-15 enumerated for Build and the Security gates.
