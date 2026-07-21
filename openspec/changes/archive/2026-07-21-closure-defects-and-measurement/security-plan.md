# Security (plan) review

## Actor

Security

## Threat model

Cooperative-owner model throughout: the repository owner, the allowlist, the repo-owned
gitleaks config, and the hook installation are trusted-and-reviewable; hooks defend
against accident and against a fallible cooperating agent, not against a local principal
with full filesystem control (who can `--no-verify` today). What an adversary (hostile
tree content, hostile on-disk state, a dishonest gate actor label, or another local user
on a shared host) controls and can reach, per decision:

### D1 — pre-push path-mapped scanning (highest-risk surface)

The allowlist becomes reachable from the push path for the first time. Attacks assessed:

- **Real secret committed AT an allowlisted path.** Suppressed by design — this is the
  inherent residual of any path allowlist and already exists at the pre-commit/check
  gates (`cli.rs:3214`, `cli.rs:4653`). Mitigations hold: the allowlist is
  version-controlled reviewed trust (`allowlist.rs` doctrine), suppressions are counted
  and reported at push time (Cond 2), and `AllowEntry` supports rule/line narrowing.
  Residual accepted; broad `paths` globs widen it — prefer narrow entries.
- **Multi-binding laundering.** Verified the plan preserves "suppressed under one path
  but bound elsewhere still scans strictly": the per-commit
  `diff-tree -r -m --no-renames --root` pass observes EVERY path binding introduced
  anywhere in the outgoing range (not `rev-list`'s single first-seen name — that
  alternative is correctly rejected in D1), a multi-path blob is scanned once per
  distinct path, and suppression requires an allowlist match under EVERY mapped path
  (Cond 1, spec scenario "Same secret content at an allowlisted and a source path").
  Not first-wins. Closed by construction.
- **Coverage edges.** A blob reachable only outside any commit diff (e.g. annotated tag
  directly on a blob) stays unmapped → synthetic `git-object:<oid>` scan, no allowlist
  (fail-closed). Introduced-then-removed blobs are mapped at the introducing commit's
  `A` row. `-m` covers merges, `--root` covers root commits. Path-validation failure
  unmaps (never skips, never errors in a skippable way). Commit/tag messages never
  allowlisted. Cap overflow blocks the push, matching today's enumeration
  (`local_validation.rs:6549-6588`).
- **Availability.** One `diff-tree` per outgoing commit is bounded by the existing
  byte/object caps; overflow is a hard block, the safe direction.
- **Digest honesty (Cond 10).** The v2 constant bump invalidates stale authorizations —
  fail-closed direction.

### D3 — closure scope union

Plan entries are not a laundering channel within the model: the retained plan derives
from the gated candidate projection inside the archive transaction (no live worktree
bytes — `closure.rs` `build_candidate_closure_plan` doctrine), is stored clone-private
(0700 `.git/mpd/closure-plans/`), and the loader enforces no-follow bounded read (64
MiB), canonical round-trip, entry canonical-path/mode/digest validation, entry+byte
caps, self-consistent tree digest, and transaction-id binding
(`closure.rs:690-727`, `1217-1268`). The union only WIDENS the staged allowance to the
digest-recorded expected post-archive tree; staged secret scanning
(`scan_staged_postimages`) is unaffected, and base-to-HEAD commit coherence plus remote
parity still enforce the recorded closure content downstream. Present-but-invalid plan
blocks — correct fail-closed direction exactly where suspicion is warranted. Known
limit, honest: the plan file's self-consistency is attacker-recomputable by a local
principal with `.git` write access; that principal is outside the hook threat model.
Cross-checking the plan's `expected_tree_digest` against the transaction journal's
recorded digest would be defense-in-depth (recommended, not required).

### D6 — actor separation

The review-subject table closes the reproduced alternating-label exploit: Build=A,
SecurityCode=B, DesignSignoff=A passes adjacency today but fails subject(DesignSignoff)
= Build → A==A. Checked every documented reuse pattern against BOTH rules: Designer at
Mock/Review/Signoff, Security at both gates, Architect at Architecture+DocValidation
all pass (each gate's adjacent-upstream and subject actors are different personas).
Side effect verified by hand: two labels can no longer complete even a non-UI change
(Test is blocked by subject=Build for A and by adjacency vs SecurityCode for B), so the
minimum honest label count rises to three. The rewound-subject rule (no record → no
comparison) is safe because phase readiness independently requires the upstream gates.
Honestly scoped as cooperative provenance, not authentication — no legitimate flow
breaks.

### D5 — version guard

Failure-path-only probe confirmed as designed: a successfully-parsed ledger is returned
untouched, so no new deserialization surface on the happy path. The probe re-parses
bytes already capped at 16 MiB (`read_contained_capped`, `DEFAULT_MAX_BYTES`) as
`serde_json::Value` (bounded recursion) — no widening of hostile-ledger parsing. Two
hardening gaps become conditions below: non-numeric/absurd `format` values must degrade
to "absent", and probe-derived strings must never reach the terminal unsanitized.

### D7/D8 — stats and introduced-by

Strictly read-only claims are coherent (no writes, no git, no network, no
`.mpd/current` effects) and D7's bounded no-follow reads match the existing loader
discipline. Remaining hostile-input surface is arithmetic and rendering over
attacker-shaped ledger bytes (u64::MAX timestamps, reversed intervals, huge counts,
control characters in strings) — conditions below. `introduced_by` cannot retroactively
alter gate truth: no gate logic reads it (D8 scopes it to status/stats display), it is
write-once at begin, and validation (name + archive existence) runs before any state is
created.

### D2/D4 — panic removal and gitleaks scope

D2 keeps fail-closed: `openspec_core::build_plan` verified write-free (pure capture/
digest, `transaction.rs:657+`), so erroring after it and before `prepare` leaves the
tree untouched. One ordering gap found: `save_candidate_closure_plan` (cli.rs:6183)
sits between `build_plan` and `prepare` — the captured-error check must precede that
clone-private write too (condition below). D4's fallback direction is the louder scan:
repo-owned `.gitleaks.toml` → byte-identical invocation (gitleaks already honors a
target-dir config natively, so no trust change); temp-write failure → unexcluded scan,
never a skipped scan. Residuals: (a) shared-host temp-dir races around the ephemeral
config need exclusive-create (condition below); (b) the `/target/` regex can suppress
external-scan findings under any directory literally named `target` — compensated by
the built-in scanner (all git-tracked files) and D1's path-mapped pre-push scan, both
of which still catch a committed secret there. Accepted with compensating controls.

## Conditions for Builder

Design Conditions 1-12 were each checked against the current code and are sound and
complete as far as they go; they are incorporated by reference and remain binding. The
following are additional invariants (numbered continuing the design's list), owner:
Builder; closing evidence: verified line-by-line at Security (code), which re-runs
after every fix on the D1 surface (novel-threat-surface rule).

13. **D2 error check precedes every durable effect.** The captured closure-plan error
    MUST be checked and returned before `closure::save_candidate_closure_plan`
    (cli.rs:6183), not merely before `openspec_core::prepare` — no clone-private plan
    file may be written for a failed build. Prevents: a stale/orphaned plan under
    `.git/mpd/closure-plans/` becoming later pre-commit scope input via D3.
14. **Ephemeral gitleaks config is exclusive-create.** Create with
    `OpenOptions::create_new` (O_EXCL semantics) and 0600 permissions under an
    unpredictable pid+nonce name; ANY failure (create, write, close) falls back to the
    unexcluded scan. Prevents: a shared-host attacker pre-placing or symlinking the
    temp path to substitute a scan-weakening config.
15. **Version-probe output is typed and sanitized.** The probe MUST read `format` as an
    unsigned integer only — a string, float, negative, or otherwise non-u32 value is
    treated as absent (original serde error path), never a panic or a version claim.
    Diagnostics MUST echo only numeric format values and the ledger path; any
    probe-derived string (e.g. `change`) MUST pass the existing terminal-safety helper
    before printing. Prevents: hostile ledgers steering the error path or injecting
    terminal control sequences.
16. **Stats arithmetic never panics or wraps on hostile numerics.** All aggregation
    over disk-derived numbers (durations, attempts, epochs) MUST use
    saturating/checked arithmetic; a record with `completed < started`, u64::MAX
    epochs, or absurd counts contributes a clamped value or an `unreadable`-class
    annotation, never a panic, overflow, or negative duration. Prevents: a single
    crafted ledger DoSing or corrupting the whole report.
17. **Stats renders disk strings as data.** Every string surfaced in the human table
    (change names, failure classes, `introduced_by`, error classes) MUST go through
    the terminal-safety helper and be length-bounded; change identity MUST come from
    the validated `change` field or a `validate_change_name`-checked filename stem —
    a mismatch or invalid name is reported as an `unreadable`/`invalid` row under a
    sanitized name. `--json` relies on serde escaping only. Ledgers MUST be processed
    per-file (bounded peak memory), and symlinks/non-regular files under `.mpd/state/`
    are reported rows, never followed. Prevents: terminal escape injection and
    identity spoofing in the report.
18. **`--introduced-by` archive-dir resolution is exact.** After
    `validate_change_name`, the legacy fallback MUST match directory names by exact
    decomposition `<YYYY-MM-DD>-<name>` (date prefix validated, full remainder equals
    the name) over a bounded, non-recursive directory listing — no substring or glob
    matching. Prevents: provenance links resolving against a different change via
    name-prefix/suffix confusion.
19. **`introduced_by` stays out of gate logic.** No readiness, gate, scope, or
    verification decision may read `introduced_by`; it remains display/measurement
    data only, write-once at begin. Prevents: a measurement field quietly becoming an
    authority input.
20. **D1 mapping tests include the tag-on-blob and merge edges.** The D1 test set
    (tasks 1.4) MUST additionally cover: an annotated tag pointing directly at a
    secret blob (unmapped → synthetic strict scan blocks), and a merge commit whose
    side branch introduces the allowlisted-path binding (still enumerated and
    scanned). Prevents: the two enumeration edges most likely to silently regress the
    fail-closed unmapped path.

Recommended, non-blocking: pre-commit cross-check of the loaded closure plan's
`expected_tree_digest` against the pending transaction journal's recorded digest
(defense-in-depth against clone-private plan tampering, outside the hook threat model).

## Verdict

CONDITIONAL PASS

The plan is approved: D1 closes the allowlist push-blocker without first-wins
suppression, D3 widens scope only to the digest-bound expected tree and fails closed on
an invalid plan, D6 provably closes the alternating-label self-review exploit while
preserving every documented persona reuse, and D5/D7/D8 add no new happy-path parsing
or write surface. The pass is conditional on Conditions 13-20 above (owner: Builder;
closing evidence: Security (code) verification, re-run after every fix on the pre-push
scanning surface per the novel-threat-surface rule). Conditions 13-15 close genuine
gaps in the plan text (error-check ordering vs the clone-private plan write; temp-file
exclusive-create; probe output typing); 16-20 pin the hostile-input handling the plan
implies but does not state. No FAIL-class finding: no decision weakens an existing
gate, and every ambiguous failure direction in the plan already resolves fail-closed.
