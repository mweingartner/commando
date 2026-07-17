# Self-enforcing adversarial pipeline (two tiers)

## Purpose

mpd enforced its *objective* gates (build/test pass-count, secret scan, doc
structure, closure coherence) but treated the *adversarial-judgment* gates —
Architecture/Security reasoning, review verdicts — as a verdict plus an
unverified evidence pointer. So whether the review actually happened, and whether
its record survived, depended entirely on operator discipline. This change makes
mpd **self-enforce** the adversarial-durability process through two interface
tiers over one ledger and one gate code path.

## Value

A model harness can no longer "use mpd correctly" and still lose the review: in
the orchestration tier every judgment gate refuses without a structurally-checked,
non-stub artifact, `--evidence` must resolve to that phase's own artifact, and the
artifacts are re-checked at archive — so the adversarial record is durable in
OpenSpec, not evaporated into a chat transcript. A human driving a local model by
hand keeps the raw verbs with zero new friction. Every new requirement has a
one-command escape, so nothing becomes a dead-end, and the tool actively reduces
what a harness must hold in context.

## Scope

Two tiers selected by a durable per-change `strict` bit:

- **Manual tier** (`strict=false`, the default for `mpd begin`): the raw verbs
  (`next`/`gate`/`status`/`check`/`resolve`/`reconcile`) — full control, only the
  objective machine gates apply. Byte-identical to before.
- **Orchestration tier** (`mpd conduct` / `begin --strict`): adds the strict
  judgment-artifact gate, evidence resolution, attempt-scoped waivers, reuse-seam
  enforcement, the archive-time re-check, and (at `risk=high`) the
  Independent-review/Refutation sections and a model-tier bump.

Universal to both tiers: `mpd use`, `mpd doctor --fix`, `mpd brief`, `mpd next
--context`, `mpd status --brief`, the archive transient-path pre-flight. Out of
scope: mpd never runs the personas/models (independence/refutation is enforced
only as required structural sections); no separate findings store (reuse
Conditions + `resolve`); archived changes are never retroactively re-checked.

## Functional details

**Strict judgment gate.** For each judgment phase (Security plan/code, Design
review/sign-off, Test, Doc validation; Architecture requires design.md's
`Conditions for Builder`), a strict gate refuses unless the phase's artifact
exists and passes the same structural check the Documentation gate uses (required
`##` sections, no `<!-- -->` placeholders, minimum length). `--evidence` must
resolve — after stripping a `#anchor`, rejecting absolute/`..`, and
`assert_contained` — to exactly that phase's own artifact; omitted, it defaults to
it. Every refusal prints the escape.

**Waivers.** `mpd gate <phase> --pass --waive-artifact "reason"` records a
bounded, terminal-safe, append-only waiver scoped to the current attempt (dropped
on a Security rewind), shown WAIVED in status and the archive summary. A waiver
never bypasses an objective gate, never converts a FAIL, is rejected with
`--reuse`, requires `--pass`, and — under `--autonomous` on a Security phase —
halts for a human instead.

**Anti-evaporation.** The `--reuse` path also enforces the artifact check, and
`mpd archive` re-checks every applicable judgment artifact (honoring valid
waivers) — closing the exact hole through which a prior change archived with its
review artifacts missing. All change-dir/`.mpd` reads are containment-checked
(`assert_contained`, intermediate-symlink-safe) so a symlinked change dir can
never point a gate at an out-of-tree file.

**Recovery + context.** `mpd use <change>` restores a cleared `.mpd/current`;
`mpd doctor --fix` heals `.mpd/.gitignore` (add-only, fail-closed on a symlink)
and flags a no-pass-count test command + phase stall age; the archive pre-flight
refuses (and names `doctor --fix`) when an in-scope transient path is
un-gitignored. `mpd next --context` emits only the phase slice (persona directive,
manifest scope, the `Conditions for Builder` block, the `artifacts` to produce,
the `gate_command`);
`mpd status --brief` is compact. At `risk=high` a seeded-default Security/Tester
model is bumped to the deep tier (a custom pin is left untouched). Autonomous mode
never weakens rigor: any threat-profile change or risk downgrade halts.

## Usage

```
# A model harness drives the orchestration tier:
mpd conduct my-change --risk high        # begin + strict + prints the call-loop
loop:
  mpd next --harness claude-code --context --json   # phase slice + persona + model + artifacts + gate_command
  # spawn the persona at that model; author the phase's judgment artifact; do the work
  mpd gate <phase> --pass --evidence <artifact>     # strict checks auto-apply
mpd archive --yes                        # re-checks the judgment artifacts survived

# Escapes (never a dead-end):
mpd brief <phase>                        # scaffold a phase's judgment template
mpd gate <phase> --pass --waive-artifact "reason"   # bounded, audited waiver
mpd use <change>                         # restore a cleared current pointer
mpd doctor --fix                         # heal .mpd/.gitignore + diagnostics

# A human keeps the manual tier unchanged:
mpd begin my-change                      # strict=false; only objective gates apply
mpd gate architecture --pass --evidence design.md#conditions
```
