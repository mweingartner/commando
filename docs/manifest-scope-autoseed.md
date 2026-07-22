# Fail-early manifest process-scope validation

## Purpose
A strict change whose `manifest.json` omitted its own process-state scope used to
pass every gate and fail only at `mpd archive`, with a cryptic error. This
surfaces the requirement at the Build gate instead, with a copy-pasteable fix.

## Value
Removes a late, confusing failure that cost real re-drives: the author is told at
Build exactly which `paths` entries to add, not after everything else has passed.

## Scope
**Covers:** the strict Build gate refuses if the manifest does not declare
`openspec/changes/<change>/**` and `docs/<change>.md`, naming both entries; the two
late archive errors gain remediation hints; `mpd manifest` guidance names the
entries.
**Does not cover / by design:** no auto-seeding (an empty seed is the forcing
function that makes an undeclared scope visible); the ledger
`.mpd/state/<change>.json` is neither required nor declared (it is folded via
SystemScope regardless).

## Functional details
- New pure `closure::missing_process_scope(manifest, change, docs_dir)` probes the
  change dir (via a nested-spec path, since `*` does not cross `/`) and the durable
  doc, using the same glob-over-(paths ∪ shared_paths) matching as the enforcement
  sites, so any superset like `**` passes. Hooked in the strict Build-gate arm
  before the candidate build; on gaps it returns a gate refusal.
- No change to the manifest seed, candidate capture, reopen, or any spec.

## Usage
- `mpd gate build` on a change whose manifest is `["crates/**"]` now refuses:
  "manifest.json does not declare the change's own process-state scope; add
  \"openspec/changes/<change>/**\", \"docs/<change>.md\" …". Add the two entries and
  re-run — Build proceeds.
- A change declaring `openspec/changes/<change>/**` + `docs/<change>.md` (the
  conventional pair) passes; the ledger path is not needed.
