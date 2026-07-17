# mpd strict — promote a change to the strict tier

## Purpose

The per-change `strict` bit — which turns on the orchestration tier's
judgment-artifact enforcement — could only be set at change *creation* (`mpd
conduct` / `begin --strict`). A change begun with plain `mpd begin` had no way to
opt in later without re-`begin`ing or hand-editing the ledger. `mpd strict
<change>` closes that gap.

## Value

A harness (or human) that began a change on the manual tier can promote it to
strict mid-flight with one command, so its remaining judgment gates and its
archive enforce that the adversarial artifacts exist and survive — no ledger
surgery, no losing the change and starting over.

## Scope

Adds one verb, `mpd strict <change>`. It is universal (works regardless of tier)
and additive: it does not change how strict gates behave once set, does not touch
any other change or file, and cannot demote (the `strict` bit is write-once).

## Functional details

`mpd strict <change>` validates the change name and confirms the change's ledger
exists (mirroring `mpd use`), then sets `strict=true` through the monotonic
`set_strict()` helper and saves the ledger. It is idempotent — promoting an
already-strict change prints "already strict" and makes no change — and it only
ever writes the change's own `.mpd/state/<change>.json`. Because `strict` is
write-once, this verb can only ever promote (false→true), never demote.

## Usage

```
mpd begin my-change                 # begun on the manual tier (strict=false)
# ...later, decide to enforce the adversarial record:
mpd strict my-change                # promote — judgment gates now enforce their artifacts
mpd strict my-change                # idempotent no-op: "already strict"
```
