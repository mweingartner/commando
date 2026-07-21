# Candidate Lifecycle Defects

## Purpose

While the pipeline self-hosted its first four changes, three closure/candidate-lifecycle
defects were reproduced live, each of which hard-stalls a legitimate pipeline run: (D1) a
fresh candidate capture collides with a stale cached projection record from a superseded
attempt and errors `existing candidate projection record does not match its ID` instead of
recovering; (D2) after a freshness rewind of an identical tree, Build cannot re-export its
output because a superseded ledger event still "binds" it, erroring `candidate Build output
is already bound by a durable ledger event`; (D3) `mpd publish --verify` verified one
change's closure against the whole `base..HEAD` range and the current worktree, so any
legitimate later commit — including a forced post-archive fixture redaction — was reported
as corruption, and earlier commits were judged against the wrong change's scope.

## Value

The pipeline no longer stalls on a stale cache or a rewound binding, and `publish --verify`
is now meaningful across a multi-change history instead of only the single-change,
nothing-else-happened case it was built for. Each archived change verifies against its own
**landing commit** — the commit that actually landed its closure — rather than the whole
commit range, so a repository with several landed changes verifies each one correctly and
legitimate later edits to the same files are never mistaken for corruption. Security
Condition 18 (C1) additionally made `publish --verify`'s presentation honest: the ref-level
parity state (`Ahead`/`Behind`/`Diverged`/`Rewritten`/…) is now surfaced *alongside*
landing-containment on every text and JSON surface, so a landing that is genuinely on the
remote but sitting on a diverged ref is distinguishable from one that isn't — the command
can never print `VERIFIED` or exit 0 for a diverged/rewritten ref regardless of
containment. An incidental fix in the same change closed a latent seed-dependent config
proptest (`arbitrary_out_of_range_sensitive_index_is_rejected`) that had escaped the
sandbox gate because only indices past the real argv length exercised its rejection branch.

## Scope

Covers the manifest's declared paths: `crates/mpd/**`, `docs/candidate-lifecycle-defects.md`,
`openspec/changes/candidate-lifecycle-defects/**`, `openspec/specs/**`, and
`.mpd/state/candidate-lifecycle-defects.json`. No UI surface, no new dependencies; ledger
and parity-cache schema changes are additive only.

**Explicitly deferred, and why:**

- **The operator "accept-divergence" acknowledgment verb.** A history rewrite that
  destroys a landing commit (e.g. `git filter-branch` redaction) still fails verification —
  correctly, fail-closed — with an accurate per-change diagnosis rather than the old
  misleading cross-change error dump. Converting that into an operator-attested override
  is a distinct trust-boundary decision (it turns an integrity failure into an attestation)
  and is left out of this change; if ever added it needs its own full threat model as novel
  surface. Concretely, this repo's own three redacted changes stay correctly unverifiable.
- **The binary-driven e2e landing/rewind fixture.** A modern closure's runtime Build-output
  export and a true rewind-then-re-export walk exist only under the strict tier with an
  activated candidate policy and the platform sandbox entry protocol — neither can run
  hermetically inside the e2e binary's sandbox. The equivalent production functions
  (`candidate_output_ledger_bound`, the landing-resolution path) are instead driven directly
  against real git repos and real saved/loaded ledgers at module level; a reusable
  activated-policy/sandbox e2e harness is left as a future tooling item, not a gap in this
  change's correctness.

## Functional details

**D1 — identity vs. attempt-variant split (`crates/mpd/src/candidate.rs`).** The candidate
ID (`candidate_id`) is pure content identity: `(schema, base_tree, manifest_digest,
entries_digest, policy_digest, source_digest)`. The cached
`CandidateProjectionRecordV1` sidecar additionally freezes attempt-variant process state —
`base_commit`, counts, excluded-dirty inventory/digest, declared-status digest,
retained-root device/inode. `capture_candidate_with_hook` now compares these as two
classes: any disagreement in an **identity** field still fails closed with the unchanged
error and never touches the record; a disagreement confined to **attempt-variant** fields
triggers a guarded eviction and atomic republish instead. Eviction requires all three
preconditions to hold, else it fails closed naming the failing one:

1. identity fields match the fresh capture;
2. the existing record names the same owning change (a foreign change's record is never
   evicted — cross-change ID collisions stay hard-stopped);
3. the capturing change's authoritative `gates` map has no live binding on this candidate
   ID (a live-bound candidate must be rewound, not captured over).

The refreshed record is derived 100% from the fresh capture's own values — no field of the
stale, evicted record flows into the replacement — via the same durability discipline as
other candidate writes (0o600 `O_EXCL`/`O_NOFOLLOW` temp, fsync, atomic rename, directory
fsync, post-replace verification read). The orphaned-record arm (a record with no retained
root) applies the same preconditions, then deletes and falls through to fresh publication.
`reopen_candidate`'s exact-binding strictness is untouched — refresh only ever happens at
capture time.

**D2 — authoritative-only Build-output binding (`crates/mpd/src/local_validation.rs`).**
`candidate_output_ledger_bound` now considers only the ledger's authoritative `gates` map
(the latest-per-phase view a freshness rewind actually clears), not the append-only
`history` it used to scan. A binding exists only when a `gates` record carries a typed
`BuildOutputV1` naming this candidate ID — Build is the only phase that ever attaches one;
Security (code)/Test/FAIL records carry `candidate` with no `build_output` and are never a
binding and never an error. A live binding at the same path still refuses re-export
(`candidate Build output is already bound by a durable ledger event`, unchanged message); a
live binding at a different path still fails closed. The per-candidate output lock is
still acquired before the ledger check, and Build stays pinned as the only typed-output
phase by a dedicated regression test.

**D3 — landing-commit closure verification (`crates/mpd/src/closure.rs`).** Verification no
longer asserts "nothing else happened since archive"; it locates and verifies this change's
own **landing commit**: the earliest single-parent commit in `base_commit..HEAD` whose
parent diff (including rename origins) stays entirely inside the closure's scope, and whose
in-scope tree content is equivalent to the retained closure plan's expected entries. Scope
purity and content equivalence are asserted only on the landing commit — never on the whole
range — so other changes' commits before or after it, and later legitimate edits to the same
files, produce no blockers. A load-bearing guard (Condition 17) makes this safe: landing
resolution fails closed if zero retained-plan entries match the closure's scope matcher
(a vacuous, trivially-true comparison could otherwise bind the landing to arbitrary
content), and the same matcher drives diff-purity and both sides of the entry filter so
scope drift always fails closed rather than silently passing. Before a landing commit
exists, the old worktree-postimage/clean checks still apply as pre-landing readiness.
`ParityObservation` gained two additive, serde-defaulted fields — `landing_contained:
Option<bool>` and `ref_state: Option<ParityState>` — computed unconditionally so the
per-change containment verdict and the ref-level `Ahead`/`Behind`/`Diverged`/`Rewritten`/
`Unstable`/`AncestryUnavailable` classification are always both recorded, never only one.
`describe_ref_level_parity` (`cli.rs`) renders both on one line at every text surface;
`--json` carries both fields directly. The exit-code policy is unchanged: `mpd publish
--verify` exits 0 only when `state == Verified`, so a diverged or rewritten ref can never
print `VERIFIED` even when its landing commit is genuinely contained.

## Usage

`mpd publish --verify` now reports each change against its own landing commit, and shows
both the containment verdict and the ref-level parity state on separate lines:

```sh
mpd publish --verify
```

```
Remote parity: VERIFIED
  local:  <local HEAD oid>
  remote: <observed remote oid>
  this change's landing commit: <landing oid>
  ref-level state: AHEAD; landing commit contained in remote: yes
No push or deploy performed.
```

Operator-visible behavior that changed:

- A repository with several already-landed changes now verifies each one correctly —
  another change's landing commit elsewhere in the range, or a later commit editing the
  same files, is no longer reported as corruption.
- A diverged or rewritten remote ref is reported distinctly rather than buried: when the
  landing commit is contained but the ref itself has diverged, the command reports
  `ref-level state: DIVERGED; landing commit contained in remote: yes` and still exits
  non-zero — containment alone is never enough to print `VERIFIED`.
- `mpd status`'s "committed" display and its JSON `ready_to_commit`/blockers fields, and the
  `archived-closure-head-coherence` doctor finding, now key off landing-is-ancestor-of-HEAD
  rather than exact-HEAD equality, so a healthy repository with later, unrelated commits no
  longer reports spurious incoherence.
