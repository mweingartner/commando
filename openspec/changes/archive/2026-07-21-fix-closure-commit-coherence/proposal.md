# Fix Closure Commit Coherence

## Why

The pre-commit governance gate makes the archive closure commit impossible after `mpd
archive --abandon --yes` has run: the hook's no-pending-closure branch demands the
change's *active* manifest in the Git index ("active manifest is absent or unreadable
in the index"), but a properly-archived change has deleted exactly that file. The only
escape has been to resurrect a stray `openspec/changes/<change>/manifest.json` copy and
commit it — which pollutes the tree and is precisely the "extra path" divergence that
keeps `mpd publish --verify` red. Two such strays are committed in HEAD today
(`openspec/changes/candidate-lifecycle-defects/manifest.json`,
`openspec/changes/proportionate-governance/manifest.json`).

## What Changes

- **Archived-closure fallback in the pre-commit gate.** When no closure is pending, the
  coordinated change's ledger records an `ArchiveClosure`, and the staged diff itself
  removes that change's active manifest, the hook authorizes the commit from the
  clone-private archive record — the closure's concrete recorded footprint
  (`ArchiveClosure::system_paths`) united with the retained closure plan's validated
  entry paths — instead of hard-failing on the deleted active manifest. This extends the
  active/archived authority split `manifest_view` already implements to the hook.
  Ordinary in-progress commits are byte-for-byte unchanged.
- **Actionable errors instead of the misleading dead end.** Post-abandon, a
  closure-shaped staged diff with no coordinator (or the wrong one) gets a message that
  names the archived change and the recovery step (`mpd use <change>`, then commit), and
  states the correct order for next time (commit **before** `mpd archive --abandon`).
  No message ever suggests re-creating the active manifest.
- **Stray cleanup.** The two committed stray manifests are deleted; their paths are
  declared in this change's manifest scope so the deletion commit passes the ordinary
  pre-commit gate, clearing the `publish --verify` "extra path" red for those changes.
- **Operator procedure documented.** `docs/fix-closure-commit-coherence.md` records the
  canonical flow — `mpd archive --yes` → `git commit` → `mpd archive --abandon --yes` —
  and the post-abandon recovery flow.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `change-manifest` — the "Archived closure commit" requirement gains the
  post-abandonment authorization contract: an abandoned pending closure never strands
  its closure commit, the archive record (not a resurrected active manifest) is the
  authority, and every ambiguity fails closed.

## Impact

- `crates/mpd/src/cli.rs` — `staged_precommit_governance` gains the archived-closure
  fallback branch and error guidance; `cmd_closure_abandon` messaging reiterates
  ordering.
- `crates/mpd/tests/e2e.rs` and unit tests — post-abandon closure commit, fail-closed
  cases, ordinary-commit regression.
- `openspec/changes/candidate-lifecycle-defects/manifest.json` and
  `openspec/changes/proportionate-governance/manifest.json` — deleted.
- `openspec/specs/change-manifest/spec.md` — merged delta at archive.
- No UI surface (design phases skip). Operator-facing behavior changes (a previously
  impossible commit becomes authorized; new guidance), so documentation phases run.
