# Per-persona behavior tuning (with an audited interview)

## Purpose

mpd runs a fixed set of adversarial personas, but until now the only per-persona
lever was the model. Persona tuning lets a user adjust each persona's *behavior* —
review rigor, Tester depth, and project-specific instructions — while making it
structurally impossible to *silently* weaken the adversarial guarantee the tool
exists to provide.

## Value

Teams can dial an mpd persona up for a risky change (a paranoid Security review, a
fuzz-depth Tester) or add a standing project instruction to any persona, and a
harness can conduct that tuning as an interview with the user. Every strengthening
is free; the one un-rankable lever (free-text instructions, or a hand-edited base
directive) is recorded on the gate receipt rather than blocked — so a reviewer or
auditor can always see when a persona was tuned, and a tuned PASS is never
indistinguishable in the ledger from a full-rigor one.

## Scope

**Covers.** A `personas` block in `.mpd/config.json` with three knobs per persona
(keyed by persona display name, or `DocValidation` for the composite Doc-Validation
persona):
- `rigor` (`standard | deep | paranoid`) — raises reasoning effort and, for
  review personas, reviewer count.
- `depth` (`examples | property | fuzz`) — the Tester only; a strengthen-only
  test-emphasis overlay.
- `directive_append` — a non-destructive instruction appended *after* the bundled
  directive (never replacing it); the one un-rankable knob.

The resolved tuning is carried into the `mpd next` brief (effort, reviewers,
directive overlay). `mpd persona list/show/set/reset` inspect and edit it, and the
bundled doctrine documents the harness-conducted interview.

**Does NOT cover (guardrails / trust boundaries surfaced in design + security).**
- The knobs are **strengthen-only**: their lowest term is the baseline no-op and
  there is deliberately no sub-baseline term, so the menus cannot dial a persona
  weaker. At `risk=high` the adversarial set (Security, Tester, Doc-Validation) is
  floored to deep effort regardless of any custom model pin.
- The one un-rankable vector cannot be proven rigor-preserving, so it is
  **recorded, never blocked** — a `weakened` flag on the brief and a
  `persona_tuning` stamp on every gate receipt. It never converts a gate to a
  CONDITIONAL and never creates a stuck-state.
- mpd never runs the persona, so the stamp is a best-effort integrity signal, not a
  cryptographic guarantee. The strong, non-bypassable guarantees are the structural
  ones (no sub-baseline term, the high-risk floor); the retained strict-tier
  judgment artifact is the audit backstop. A manual operator who hand-edits config
  around a raw `gate --pass` gets the same total self-trust the manual tier already
  grants.
- An absent/empty `personas` block is fully inert: a baseline brief, `--json`
  envelope, and ledger file are byte-identical to a pre-feature project.

## Functional details

- **Resolution (config-only).** `resolve_tuning_governed` maps `rigor` → an ordinal
  reasoning effort (`standard`→tier baseline, `deep`→`high`, `paranoid`→`max`),
  composed as a monotonic `max` over an ordinal rank (never string order) with the
  high-risk floor; `paranoid` on a review persona adds one reviewer (clamped ≤ 4,
  never gating Doc-Validation's structural dual). `directive_append` is sanitized
  (`terminal_safe` + a length cap; oversized → dropped). A `rigor`/`depth`/
  `directive_append` value that is not the expected type degrades that one field to
  its baseline — a bad token never fails the whole config.
- **The two un-rankable weakening vectors.** A free-text `directive_append` and a
  locally-modified base directive file (`.mpd/directives/personas/<p>.md` differing
  from the bundled default) are both treated identically: `mpd next` records the
  weakening determination for the current `(phase, attempt)`, and `mpd gate` stamps
  the receipt *from that record* — so editing a directive, briefing, then restoring
  it before the gate cannot launder a weakened review into a clean stamp.
- **Recording is conditional + monotonic.** `mpd next` writes a `brief_tuning`
  record only when a non-baseline tuning is in force (untuned projects stay
  byte-identical), and merges weakest-seen: once a weakening is recorded for an
  attempt, no later re-brief can clear it until the attempt advances.
- **Reuse safety.** A narrow `DependencyKey::PersonaTuning` binds each governed
  phase's effective directive (config tuning + resolved directive text), so a
  reused receipt goes stale when *that* persona's directive changes — but not on an
  unrelated config edit.
- **Errors.** `mpd persona set` rejects an unknown persona name or enum term (so a
  typo cannot silently write inert config), warns loudly when setting the
  un-rankable `directive_append`, and writes through the symlink-guarded
  `Config::save`.

## Usage

Inspect a persona (a harness reads the `--json` form during an interview):

```
$ mpd persona show Security --json
{ "persona": "Security",
  "fields": {
    "rigor": { "current": null, "baseline": "standard",
               "range": ["standard","deep","paranoid"], "dangerous": false },
    "directive-append": { "current": null, "range": "free text …",
                          "dangerous": true } } }
```

Strengthen a persona (ordinal knobs, no warning):

```
$ mpd persona set Security rigor paranoid
Security.rigor: — → paranoid
$ mpd persona set Tester depth fuzz
Tester.depth: — → fuzz (Tester only)
```

Add a project instruction (the un-rankable knob — warned and recorded):

```
$ mpd persona set Security directive-append "Always check for IMAP cleartext."
  ⚠ Security.directive-append set — this is the ONE un-rankable knob. It is
    appended (never replaces the base directive), recorded on every gate receipt,
    and flagged `weakened`. mpd cannot prove it rigor-preserving.
```

The next brief then carries the tuning, and the gate receipt records it:

```
$ mpd next            # brief shows: effort max · 2 reviewers · ⚠ persona weakened …
$ mpd gate security-code --pass --evidence security-code.md
# → GateRecord.persona_tuning = { rigor: paranoid, had_append: true, weakened: true }
```

Clear it back to baseline:

```
$ mpd persona reset Security                 # all of Security
$ mpd persona reset Tester depth             # one field
```

**The interview (harness-conducted).** To tune personas with the user, a harness
loops the tunable personas, reads `mpd persona show <persona> --json` (current value,
range, baseline, `dangerous` flag per field), asks the user — surfacing the current
value and range, and a clear ⚠ on the `directive-append` choice — and records each
answer with `mpd persona set`. Because the validation, danger classification, and
write all live in mpd, an interview-set value and a hand-edited one are guarded
identically. The harness applies the brief's fields as emitted (it must not re-read
`config.json`), and records a gate before any further `persona set`/`reset`.
