# Content-Addressed Release Closure

## Purpose

`mpd` could prove a gate ran, but it could not answer three release-closeout
questions: does prior gate evidence still describe the exact content being
released, which repository paths and commit make up this change, and does the
configured remote ref resolve to that same commit? This change gives each of
those three truths — evidence validity, change manifest, and remote parity —
its own explicit, non-conflatable representation, so "PASS" never quietly
comes to mean "still true," "committed," or "published."

## Value

Operators and reviewers get a trustworthy release story instead of a checkbox:
stale evidence is named and cannot be silently reused; mixed staged work can
no longer be swept into a change's closure; a `publish --verify` result means
the exact archived commit, and only that commit, is present at the configured
remote — never a guess, a push, or a local-path impostor. Automation gets the
same guarantees structurally through `--json`, with no privileged text-only
path.

## Scope

Covers `mpd status`/`next`/`gate`/`archive`/`doctor`, three new commands
(`mpd manifest`, `mpd closure recover`/`abandon`, `mpd publish [--verify]`),
and three new modules in `crates/mpd` (`digest`, `git`, `closure`) plus
`openspec_core::transaction`, the crash-safe archive-transaction executor.

It does **not** perform a push, force-push, ref creation, fetch, or deploy;
does not attest provenance, authorship, or supply-chain signing; does not
offer a graphical staging UI; and does not treat any Git-accepted network
response, branch, or remote as trusted input. Evidence reuse for Build, Test,
and Security(code) remains fresh-execution-by-default and only turns on
through an explicit, versioned, complete hermetic policy; Deploy is never
reusable, and a `CONDITIONAL PASS` receipt is never reusable regardless of
whether its original condition later closed.

## Functional details

**Evidence lifecycle.** Every executed gate PASS/CONDITIONAL/FAIL carries a
canonical SHA-256 receipt over exactly the inputs its phase-causal
`DependencyPolicy` says that phase reviewed (scope, source, governance,
config, tool/scanner identity, applicable artifacts — never an output a later
phase created). `mpd status`/`next`/`gate` report each gate's evidence as
`valid`, `stale` (naming the changed dependency class), or `absent` —
independent of reuse eligibility. `mpd gate <phase> --pass --reuse <id>`
reuses only an exact-match, unconditional-PASS, non-Deploy receipt, appending
a distinct `reused` event; it never re-executes the check and never mutates
history on refusal.

**Change manifest.** `openspec/changes/<name>/manifest.json` declares a
change's repository-relative path scope and optional publication
remote/ref. Architecture cannot pass with an empty/invalid manifest. `mpd
status`, `mpd check --staged`, and `mpd archive` compute a `ManifestView`:
`ready`, `incomplete`, or `blocked` (any staged path outside declared/system
scope) — without ever touching the Git index. Once the active change
directory has been archived, `status`/`check --staged`/`publish` resolve the
single pending closure (via `.mpd/pending-closure`) rather than reporting "no
current change."

**Journaled archive transaction.** `mpd archive --yes` composes spec merges,
documentation, and the closure-ledger postimage into one
`ArchiveTransactionPlan`. Before any repository target changes, every
postimage is staged, `sync_all`'d, and journaled with its explicit
absent/existing preimage digest and postimage digest/mode; the ignored
`.mpd/pending-closure` pointer is written only after that journal is durable.
Each target then replaces only from its exact recorded preimage to its exact
staged postimage (or is already the exact postimage); any third state stops
`manual-recovery-required` without writing. Only after every target and the
active→archive directory rename verify does state reach `AwaitingCommit`.
`mpd closure recover` is a read-only preview by default; `recover --yes`
performs completion-only roll-forward (never re-running the semantic spec
merge, never claiming rollback). `mpd closure abandon --yes` is accepted only
from `AwaitingCommit` and deletes only the owned ignored pointer/journal
metadata — never repository content, ledger history, the index, or commits. A
pending closure blocks `mpd begin` and a second `mpd archive` until it is
recovered or abandoned.

**Commit coherence.** After the operator commits the archived result with
normal Git, coherence requires HEAD to descend from the recorded base commit
with no merge, walks **every** commit `base..HEAD` (not just the endpoint
diff) unioning every add/delete/rename/copy path via `diff-tree -r
--name-status -z -M -C`, rejects any out-of-scope path anywhere in that
history (closing the "add-then-delete a secret before the endpoint" class),
and requires the final scoped digest to match the recorded post-archive
digest exactly.

**Remote parity.** `mpd publish` is a non-mutating readiness report. `mpd
publish --verify` resolves the publication target only from the manifest, then
`closure.default_remote`/`default_ref`, then the current branch's configured
upstream — a token is accepted only as an exact configured remote name, never
a path/URL/`.`/unknown token. It snapshots local HEAD/index/scoped bytes and
the remote OID (`git ls-remote`, no fetch), re-observes after classification,
and reports `verified`, `not verified`, `offline`, `ahead`, `behind`,
`diverged`, `rewritten` (previously verified history force-pushed away),
`ancestry-unavailable` (exact OIDs differ and the remote object isn't already
local — MPD never fetches to find out), `unavailable` (unborn/detached/missing
remote), or `unstable` (either snapshot moved across the one permitted retry —
no cache is written). It never pushes, force-pushes, creates refs, stages,
commits, archives, or deploys. The bounded local observation cache
(`.mpd/parity-observations.json`, a single most-recent-observation file whose
entry is consulted only when its change/remote/ref match the current target)
stores only target names, OIDs, classification, and a timestamp — no URL,
credential, or raw network output.

**Doctor.** `mpd doctor` reports the pending closure (change + stage),
whether a complete hermetic-reuse policy is configured, and the resolved
closure config (`default_remote`/`default_ref`, the bounded
`remote_timeout_secs` fallback of 15s, and the bounded `human_path_list_limit`
fallback of 50) — in both text and `--json`.

## Usage

```
mpd manifest init                          # seed manifest.json; declare paths + publish target
mpd gate architecture --pass                # requires a valid, non-empty manifest
mpd status --json | jq .evidence            # valid/stale/absent per gate, separate from reuse
mpd gate architecture --pass --reuse <id>    # explicit, append-only reuse of a valid receipt
mpd archive --yes                            # journaled transaction; ends AwaitingCommit
mpd closure recover                          # read-only preview if interrupted
mpd closure recover --yes                    # completion-only roll-forward when eligible
git add -A && git commit -m "close change"   # normal Git — MPD never commits
git push                                     # normal Git — MPD never pushes
mpd publish --verify                         # fresh, non-fetching remote-parity observation
mpd doctor --json | jq .closure              # resolved closure config + pending-closure state
```
