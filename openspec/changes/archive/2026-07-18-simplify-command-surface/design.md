# Design: simplify the mpd command surface

Canonical current-state contract. Superseded prose → `history/`.

## Context

18 flat top-level verbs; `gate` has 17 flags. The everyday harness path is
`conduct → (next → gate)* → status → archive → publish --verify`; the rest are
author-support, one-time setup, or rare recovery. This is a pure ergonomics
refactor of the `clap` command tree + dispatch in `cli.rs` — NO new functional
behavior, and (except the deliberately-replaced 5 gate exploit flags) every
existing invocation must behave identically.

## Decisions

### D1 — Tier the help (cosmetic)
Reorder the `Command` enum into three role tiers so `--help` leads with the core
loop: **Core** (init, conduct, next, gate, status, archive, publish) · **Author &
govern** (brief, resolve, reconcile, persona, manifest, use) · **Setup & recovery**
(strict, check, doctor; `begin`/`closure` hidden). Add a grouped top-level
`after_help` naming the core loop. Enum order is clap's display order; no behavior
changes.

### D2 — Flatten `manifest`
Replace `Manifest { command: ManifestCommand }` (a one-variant group) with
`Manifest { change: Option<String> }`; delete `ManifestCommand`; dispatch calls the
same seed logic. `mpd manifest [--change N]` is byte-for-byte the old
`mpd manifest init [--change N]`.

### D3 — Fold `closure` into `archive`
Add `--recover` / `--abandon` (+ `--json`) to `Archive`. **The recover/abandon
routing MUST happen in `run()`'s dispatch arm, BEFORE `cmd_archive` — never inside
`cmd_archive`'s body (Security-plan Finding 2).** `cmd_archive`'s first substantive
check refuses when a pending closure exists ("Cannot archive — already pending; run
`mpd closure recover`…"); a pending closure is the exact (ordinary, non-crash) state
`--recover`/`--abandon` exist for, so routing them through `cmd_archive` would hit
that refusal instead of recovering. The `run()` arm:
```rust
Command::Archive { change, skip_specs, yes, recover, abandon, json } => match (recover, abandon) {
    (true, true)   => Err("--recover and --abandon are mutually exclusive".into()),
    (true, false) | (false, true) if skip_specs => Err("--recover/--abandon are mutually exclusive with --skip-specs".into()),
    (true, false)  => { let root = find_root()?; cmd_closure_recover(&root, yes, json) }
    (false, true)  => { let root = find_root()?; cmd_closure_abandon(&root, yes, json) }
    (false, false) => cmd_archive(change, skip_specs, yes),
},
```
`--json` is meaningful only on the recover/abandon branch (the normal archive path is
print-only); scope it there (Finding 4). `--change` is ignored by the closure ops
(they act on the single pending closure under `.mpd/`); reject `--change` combined
with `--recover`/`--abandon` rather than silently ignore it (Finding 3b). Keep the
`Closure` variant as a **hidden alias** (`hide = true`) so existing
`mpd closure recover|abandon` invocations still work. The `cmd_closure_*` logic and
the archive journaled-transaction path are untouched.

### D4 — Collapse the 5 gate exploit flags → `--exploit`
Replace `--attacker/--capability/--boundary/--harm/--fix` with a single
`--exploit <STRING>` parsed as exactly five `|`-delimited fields
(attacker|capability|boundary|harm|fix). **Exploitability is MANDATORY on every
Security FAIL — not merely validated-when-present (Security-plan Finding 1).**
Today's `cmd_gate` unconditionally builds `Exploitability` on a Security FAIL,
running `bounded_text("")` on any omitted field, so a Security FAIL with NO exploit
evidence is already refused. The refactor MUST preserve that: `--exploit` **absent**
on a Security FAIL errors identically to a malformed value. Implement as an
exhaustive match, NEVER `exploit.map(parse).transpose()?` (which would let `None`
sail through as `exploitability: None`):
```rust
let exploitability = match (verdict, security, exploit) {
    (Verdict::Fail, true, Some(raw)) => Some(parse_exploit(&raw)?), // split '|', require exactly 5, bounded_text each
    (Verdict::Fail, true, None)      => return Err("Security --fail requires --exploit \"attacker|capability|boundary|harm|fix\"".into()),
    (_, _, Some(_))                  => return Err("--exploit is valid only with a Security --fail".into()),
    (_, _, None)                     => None,
};
```
Each field through `bounded_text` (non-blank, trimmed, ≤500). A malformed `--exploit`
(≠5 fields, or a blank field) MUST error. A literal `|` inside a field is not
supported (documented); the fields are short structured phrases, not prose. `--reuse`
forces `Verdict::Pass`, so `--exploit --reuse` falls out of the `(_, _, Some(_))` arm
(refused) — pin it.

### D5 — `conduct` as the single start verb
Mark `Begin` `hide = true` (help-only) — it stays fully functional so the manual tier
(`mpd begin [--strict]`) is still reachable; `conduct` is unchanged and documented.

## Risks / Trade-offs
- [`--exploit` parse loosens Security-FAIL evidence] → the field-count + per-field
  `bounded_text` checks are mandatory (Cond 2); a Security-FAIL test asserts a
  malformed `--exploit` is refused.
- [Folding closure flags interact with archive modes] → explicit mutual-exclusion
  guard (Cond 3); the hidden `closure` alias preserves the old path verbatim.
- [Hidden `begin` looks removed] → `hide` is help-only; an e2e asserts `mpd begin`
  still works.

## Conditions for Builder
1. **No functional change** except D4's flag rename: every other existing invocation
   (`begin`, `manifest init` → `manifest`, `closure recover|abandon` → both the new
   `archive` flags AND the hidden `closure` alias) MUST behave identically. Pin with
   e2e: `mpd begin` still starts a manual change; `mpd manifest` seeds the same stub;
   `mpd archive --recover`/`--abandon` and the hidden `mpd closure …` both reach the
   same logic.
2. **`--exploit` preserves Security-FAIL rigor, incl. MANDATORY presence (Finding 1)**:
   exactly 5 `|`-delimited fields, each `bounded_text`-validated; **`--exploit` is
   REQUIRED on every Security FAIL — its absence errors identically to a malformed
   value** (via the exhaustive 4-arm match in D4, NOT `.map/.transpose`); rejected
   outside a Security FAIL (so `--exploit --reuse` is refused). Tests: a good
   `--exploit` records the 5 fields; a malformed one (≠5 / blank) is refused; a
   Security FAIL with NO `--exploit` is refused; `--exploit` outside a Security FAIL
   is refused. Load-bearing (revert the count/blank/absence guard → red).
3. **Closure fold-in is mode-guarded AND dispatched before the pending-closure
   early-return (Finding 2)**: the `--recover`/`--abandon` routing lives in `run()`'s
   `Command::Archive` arm, ahead of `cmd_archive`; `--recover`/`--abandon` are mutually
   exclusive with each other, with `--skip-specs`, and with `--change`; `--json` is
   scoped to the recover/abandon branch; each routes to the unchanged
   `cmd_closure_recover`/`cmd_closure_abandon`; the `Closure` alias stays hidden but
   functional. The archive journaled-transaction path is unchanged.
4. **Help tiering is cosmetic**: enum reorder + `after_help` only; no flag or behavior
   change. `mpd --help` lists the core verbs first.
5. **This change runs under strict and retains its judgment artifacts through archive.**

## Security-plan disposition (CONDITIONAL PASS)
Findings 1 (mandatory `--exploit` on Security FAIL) and 2 (recover/abandon dispatched
before `cmd_archive`'s pending-closure early-return) folded into D4/Cond 2 and
D3/Cond 3 above. Finding 3 (`--reuse`+`--exploit`, `--change`+recover/abandon) and 4
(`--json` scoped to recover/abandon) folded in. Security (code) re-verifies both HIGH
conditions against the real diff (not a Builder self-report) + runs the pending-closure
e2e.
