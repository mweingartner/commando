# Design revisit: what MPD was for, and why it stopped delivering it

Date: 2026-07-24. Subject: commando / `mpd` at `2d988dc` plus this change.

This document records a full re-examination of the system against its four
original goals, the measured evidence behind the diagnosis, what was changed in
response, and — as important — what was deliberately **not** changed and why.

## The four original goals

1. Push a task through clear gates from design to architecture to build, test,
   document, **with assurance that output meets intent**.
2. The roles are adversarial, **but each role has province within their
   expertise to move forward** when convinced the output will meet intent.
3. **Optimize model engagement cost** — "just enough" model per task. Best model
   on architecture; a cheaper one on documentation.
4. Layer it on **OpenSpec so the system of record is transparent to all
   personas**.

The reported outcome was the opposite: slower to create, costlier through
cycling on errant tasks, and not meeting intent.

## What the evidence actually says

Measured over all 29 ledgers in `.mpd/state`:

| Measure | Value |
| --- | --- |
| Recorded gate attempts | 516 |
| Attempts that were repeats | 285 (55%) |
| Repeats caused by a FAIL verdict | 15 |
| Repeats caused by freshness invalidation | 242 |
| `reconcile --continue` attempt-limit bypasses | 143 |
| Recorded usage/cost measurements | 0 of 516 |
| Attempts closing within 30s of phase entry | 305 (62%) |
| Changes whose subject was mpd's own machinery | 29 of 29 |

Seven findings follow from this, in rough order of severity.

### RC1 — Judgment is bound to bytes, so authoring destroys approval

A gate's PASS is content-bound to file digests, and that file set includes
artifacts the same phase authors and later phases legitimately edit. Refining a
plan — the central act of a design→architecture pipeline — invalidated the
plan's own approval and both Security approvals. 67 of 96 freshness events
rewound all the way to Architecture, the most expensive persona in the system.

Two of these inputs were not even content. `SystemScope::archive_target` embeds
`today_utc()` and was hashed into the Scope digest, so **the wall clock was a
causal input**: a change left open across midnight UTC woke to a mismatch and a
rewind. And `docs/<change>.md`, authored at the Documentation phase, folded into
the Source digest, so writing the documentation retroactively staled the Build,
Security(code), and Test receipts recorded before it.

### RC2 — Gates check structure, never intent

The entire implementation of "assurance that output meets intent" is
markdown-heading presence, a 120-byte floor, and a string match on the Verdict
line. A persona satisfies the gate by emitting well-formed prose with the right
headings. Refusals therefore cluster on mechanical properties while substantive
intent-misses pass cleanly.

### RC3 — Authority is asymmetric: every persona can block, none can release

The state machine is a monotonic ratchet with rewind-only escape hatches.
Judgment can only ever add cost, never remove it. Goal 2 asked for province to
move forward on conviction; there was no forward-motion primitive at all. The
`Applicability.docs` axis existed in the data model, was labelled "legacy
compatibility", and was discarded by `Phase::is_active` — so an eleven-gate
sequence ran on a 37-line README change.

### RC4 — Self-hosting with no external term

Every fail-closed guard added to relieve cost was global and kernel-resident,
and fired on legitimate states its author never enumerated. Relief required a
new change; the new change touched the kernel, classified High, paid full rigor,
and created the next guard's blind spot. 17 of 29 changes were opened to repair
damage from an earlier governance change. Self-hosting a governance tool has a
property self-hosting a compiler does not: every defect it surfaces reads as a
mandate for *more* governance.

### RC5 — Goal 3 was built as an attestation problem before a single measurement

The cost goal's rigorous form — signed usage provenance and blinded Pareto
routing — was built first. The trivial form (write down which model you used)
was never built, so `usage coverage` has read `0/516` for the project's entire
life, every token budget in `.mpd/config.json` is unreachable, and `routing
apply` cannot obtain the evidence it requires.

Worse, it was inverted. `mpd` **prints** a model recommendation and nothing ever
compared it to what ran. Meanwhile the risk classifier folded two
repository-level constants into every per-change derivation, pinning changes at
High — and High is precisely the switch that escalates Security and Tester onto
the *deep* model. The owner asked for a cheap Documenter; the realized policy
put the deep tier on roughly 71% of attempts and policed 41 cheap documentation
writes with 36 dual deep-tier validation runs.

The flagship remedy for this — the documentation lane — **never fired once**.
Two independent defects cancelled it. `active_system_scope` seeds every manifest
with `openspec/changes/<change>` and a dated archive target, neither carrying a
trailing slash, and `doc_safe_pattern` required one; so the scope predicate was
poisoned by mpd's own seeds on every change. And the lane was conjoined with
`effective == Low`, so any change the operator asked to review carefully was
forced to compile and test code it had not touched.

### RC6 — Two systems of record; the authoritative one is unreadable

OpenSpec was layered underneath for transparency, but `.mpd/state` is what every
command reads and gates on: 8.8 MB across 29 changes against 132 KB of specs,
and 61% of those bytes were pretty-print indentation. Commit `70e16e1` added 37
lines to `README.md` and 17,890 lines to its ledger.

### RC7 — The gates were largely not delegated

This is upstream of RC2 and RC3, and it reframes everything else.

`started_at_epoch_secs` is stamped at phase entry, so each recorded interval is
the persona's entire work window. 305 of 495 clocked attempts closed inside 30
seconds — doc-validation 78% of the time, despite the brief rendering "spawn TWO
subagents in parallel."

The decisive correlation: **fail rate tracks duration**. `design-review` has the
highest median (53s), the lowest sub-30s share, and a 28% FAIL rate. Every gate
with a median at or below 17s has a FAIL rate at or below 7.7%; the five fastest
gates produced 2 FAILs across 233 attempts. The gate that took real time is the
gate that said no.

Architecture's 104 PASS / 0 FAIL is not primarily a lint problem. It is a
session declining to fail itself. A gate cannot check intent when the checker
and the author are the same context — and nothing in the ledger recorded which
had happened, so a self-recorded PASS and a genuinely reviewed PASS were
indistinguishable.

## What changed

### Observability first (the finding that makes the rest measurable)

`GateRecord` now carries a `DelegationRecordV1`: whether a distinct persona was
spawned, which model it ran under, and whether that matched the model `mpd next`
resolved for that exact attempt. `mpd next` offers the flags in the command it
prints; `mpd stats` reports delegation and route compliance.

Omission records `UNKNOWN`. Defaulting either way would manufacture exactly the
fiction the field exists to remove.

`mpd stats` also counted attempts as `max(record.attempt)` rather than the
number of history records. Because a rewind resets the attempt counter, this
under-reported precisely the rework the report exists to expose — 495 against a
true 516.

### The documentation lane, revived

`doc_safe_pattern` now recognizes the two forms mpd emits for itself, by **exact
string equality** — never `starts_with`, because the trailing-slash rule is the
deliberate guard against `<change>-evil` siblings, and `glob_match` is
segment-exact so neither form can reach one. The lane is now keyed on scope
alone: requested rigor raises review *depth*, and no amount of it makes
compiling untouched source informative about a prose edit. The high-risk `Test`
arm no longer short-circuits ahead of the lane either, so a prose change stops
running a 10k-path throughput workload.

This reverses the former "Condition 13". The reasoning is recorded in the test
that replaces it. What still holds the line: the predicate is a fail-closed
closed allowlist over the entire declared scope, one non-doc pattern poisons it,
manifest-scope enforcement refuses undeclared tracked edits, and every docs
profile must carry a secret scan and a doc check by kind or selection blocks.

A regression test pins the real `add-harness-first-readme-quickstart` manifest —
a README-only change that was forced through format, clippy, the full workspace
test suite, and a release build.

### The documentation axis, reconnected

`ChangeKind::documents()` returned an unconditional `true`. It now returns true
for `Feature` only, and `Phase::is_active` honors the axis. A `--fix` restores
behavior the docs already describe and a `--chore` changes no functional
behavior; neither pays a Documenter pass plus a two-persona deep-tier
validation. Measured over the ledgers, Documentation and Doc Validation recorded
80 attempts and **zero** FAIL verdicts — every repeat was upstream rework.

Deploy remains mandatory for every kind.

### The clock and the late-phase output, out of the digests

`SystemScope::stable_paths()` supplies the Scope digest; the full `paths()`
still supplies enforcement, so the archive target stays authorized scope while
midnight stops being a rewind trigger. `docs/<change>.md` is excluded from the
Source digest at that call site only — the shared artifact array is also
consumed by candidate pruning and the prose secret-scan lane, which must keep
covering it.

### Ledger encoding

Ledgers serialize compact. Nothing is dropped and `load` is unchanged; 61% of
`.mpd/state` was indentation.

### The repository could not validate anything

Independent of the above: the suite was **red on the owner's machine**. A macOS
point update (`26A5378n` → `26A5388g`) tripped an exact build-string equality
gate and re-signed `/usr/bin/ssh-keygen`, and four tests failed closed.

The certification boundary now enforces architecture and OS *product* version —
what the Seatbelt profile and extension SPI contract actually track — and folds
the **observed** build into `ready_digest`, so a receipt still names the exact
host that produced it and reuse across an OS update correctly re-executes rather
than silently carrying over. The `ssh-keygen` digest stays a hard pin, because
an external verifier is a boundary worth failing closed on; what changed is that
`mpd doctor` now names the observed digest and the exact re-review edit instead
of surfacing an opaque assertion failure.

This is the same pathology as everything else in this document: fail-closed
aimed at the owner rather than at an adversary. The owner's own in-flight fix to
`mpd policy digest` — which refused to run precisely when a broken policy needed
repairing — is another instance. That fix is preserved here, with the missing
distinction restored: an absent `local_validation` still errors, while a broken
*activated* policy no longer blocks reading the digest.

## What was deliberately not done

**Deleting the hermetic sandbox kernel was rejected.** The proposal was
attractive — 29,153 of 43,868 production LOC for a boundary `SECURITY.md` itself
says cannot resist the repository owner — but its cost premise is arithmetically
false. Build's *median* is 12 seconds. The 59-minute mean is four records
totalling 90.7% of all Build time, which are overnight authoring spans, and two
of them predate the kernel they were blamed on. The scoping is also impossible
as stated: `local_validation.rs` carries 808 sandbox/candidate references and
`ledger.rs` imports `CandidateCapture`. Deleting the immutable subject would
also remove what makes the observed-test-count check meaningful — the one
mechanism in the repository that beats self-report.

**Restoring an out-of-boundary CI gate is still worth doing** and was not done
here. `.github/workflows/ci.yml` (63 lines: fmt, clippy, workspace tests,
audit-check, gitleaks) was deleted in `dbacbb4`. It is the only gate that ever
sat outside the trust boundary. Note what its restoration would be: not a clean
revert, but reconstruction of a decision that was itself driven through eleven
phases and whose entire record was later rebased out of `HEAD` without the tool
noticing.

**Acceptance-criteria gating was sequenced after observability, not before.** If
62% of gates were not delegated, a stricter artifact schema mostly makes
self-recording more laborious rather than more adversarial. Measure first.

**Per-record `candidate` and `validation_receipt` truncation was not done.**
Together they are 62.6% of the largest ledger, but truncating them is lossy and
should be re-measured after fewer staleness events shrink the ledgers naturally.

**Goal 2 still has no forward-motion primitive.** A persona still cannot say
"I am convinced; fold the next phase into this verdict." The documentation axis
is proportionality by change *kind*, which is adjacent but not the same thing.
This remains the least-served of the four goals.

## The two things that matter most

**Do first:** run the next several changes with `--delegated`/`--self-recorded`
and `--model` populated, ideally on a repository that is not mpd. Until that
data exists, every cost claim about this pipeline — including the ones in this
document — has a denominator nobody has measured. Either answer is worth more
than another round of gate redesign: if the personas largely did not run, then
goals 1 and 2 were never actually tested.

**Stop doing:** driving mpd's own governance machinery through mpd, and
recording a gate verdict for a persona that did not run. These are one habit.
When the driver is also the reviewer, a PASS costs twelve seconds and means
nothing, and the ledger fills with green nobody can distinguish from judgment.
A skipped gate you can see is worth more than a passed gate you cannot trust.
