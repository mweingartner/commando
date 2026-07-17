# Model-Paired Development — Protocol Doctrine

This is the canonical doctrine mpd enforces. mpd installs it into every project
it initializes (`.mpd/directives/protocol.md`); edit that copy to adapt it. The
per-persona directives live alongside it in `.mpd/directives/personas/`.

## The idea

Model-Paired Development pairs a fixed sequence of **adversarial personas** —
each with a distinct lens and its own model — against every non-trivial change,
and backs the human-fallible parts with **deterministic, machine-enforced
gates**. The goal is *correct* code, not merely *working* code. mpd is the
harness-agnostic engine: it orders the phases, names the persona and model for
each, and refuses to advance on an unmet gate.

## The pipeline

```
Design Mock → Architecture → Design Review → Security (plan) → Build →
Security (code) → Design Sign-off → Test → Documentation → Deploy → Doc Validation
```

A phase is skipped only when it genuinely has no bearing on the change — never to
save time:

- **Design** phases (Mock, Review, Sign-off) run only for changes with a UI/UX
  surface (`mpd begin --ui`).
- **Documentation** phases (Documentation, Doc Validation) run only for feature
  changes that alter functional behavior; defect fixes (`--fix`) and
  non-functional chores (`--chore`) skip them.
- Everything else is mandatory. Small or docs-only changes use concise,
  proportionate artifacts; size or familiarity never bypasses a gate.

## Two ways to drive mpd

mpd exposes one code path under two tiers, selected per change by a durable
`strict` bit. A dropped call in a strict run degrades loudly, not silently — the
exact hole through which an adversarial record can otherwise evaporate.

**Humans — manual verbs.** Drive the pipeline by hand with full control: `mpd
next` for the next step, `mpd gate <phase> --pass` to record a verdict, `mpd
status` to inspect. Only the objective gates (build/test pass count, secret scan,
`documentation.md` structure, deploy, closure coherence) are enforced; judgment
artifacts are not demanded. This tier is byte-identical to the classic flow.

**Model harnesses — `mpd conduct <name>`.** `conduct` (or `begin --strict`)
begins the change, sets `strict=true`, seeds the first phase's judgment stub, and
prints the call-loop contract. The motion stays the *unchanged* `next → spawn
persona → gate` verbs — there is no forked driver:

```
mpd conduct <name> --risk high
loop:
  brief=$(mpd next --harness claude-code --context --json)  # slice + persona + model + artifact_path + gate_command
  break if brief.phase == "done"
  # spawn the persona at brief.model, fill brief.artifact_path, do the work
  mpd gate <phase> --pass --evidence <artifact_path>        # strict checks auto-apply from ledger.strict
mpd archive --yes
```

Under strict, every judgment gate demands its own non-stub artifact
(security-plan.md, security-code.md, design-review.md, design-signoff.md,
test.md, doc-validation.md), `--evidence` must resolve to *that phase's own*
artifact (not a basename alias), high-risk security-code additionally requires
`Independent review` + `Refutation` sections, and archive re-checks that every
applicable artifact survived post-gate. `strict` is write-once and survives
session death, so a resumed harness gets the same strictness.

**Both tiers share the escape verbs** — every strict requirement has a
one-command escape, so a refusal is never a dead-end:

- `mpd brief <phase>` — scaffold a phase's judgment-artifact stub to author.
- `mpd gate <phase> --pass --waive-artifact "reason"` — waive the artifact check
  with a bounded, append-only, audited reason (loud WAIVED banner; never bypasses
  an objective gate and never converts a FAIL). Waivers are attempt-scoped; a
  reconcile rewind drops them so a re-run demands the artifact again.
- `mpd use <change>` — restore `.mpd/current` after it was cleared.
- `mpd doctor --fix` — heal a missing `.mpd/.gitignore` (add-only, idempotent,
  fail-closed).

Strict is set once, at `conduct`/`begin --strict`, and is monotonic (no path sets
it back to false). There is no verb to promote an already-begun non-strict change
to strict without re-`begin`ing under `conduct` — the harness opts in once.

## Proportional governance

Every change declares a risk level (`low`, `medium`, or `high`) and a credible
threat profile. `mpd next` carries that contract into every persona brief.
Security may block only on a concrete exploit path within or into the declared
profile: attacker, prerequisite capability, crossed boundary, concrete harm,
and exact fix. Out-of-profile defense in depth is advisory.

Canonical `proposal.md`, `design.md`, and `tasks.md` describe the current
approved contract. Move superseded drafts to `history/`. Artifact page guidance
is advisory; review-attempt limits require an explicit `mpd reconcile` decision
before expansion, but reconciliation never converts or bypasses a FAIL. If the
human rejects a criterion, reconcile immediately instead of manufacturing more
review prose.

## Gates are machine-enforced, not self-reported

Every gate ends **PASS**, **CONDITIONAL PASS**, or **FAIL**. Every FAIL is
classified as product, test, infrastructure, environment, or policy. A conditional pass
records open conditions (owner + closing evidence) that block archive until
resolved (`mpd resolve`). A FAIL blocks; a material change returns to the
earliest affected phase and invalidates downstream approvals.

Prefer the machine over the persona's word:

- **Build/Test** gates re-run the configured test command and require a real,
  non-zero pass count. A clean result from an unverified runner is a red flag.
- **Security (code)** runs secret scanning (built-in floor; gitleaks/Semgrep when
  present) and refuses on any finding.
- **Documentation** structurally checks the doc (all sections, no placeholders).
- **Deploy** runs the configured deploy command and refuses on failure.
- **Archive** refuses on any non-PASS gate or open condition, and previews the
  spec + doc merge before applying.

## Content-addressed closure

Declare the change's repository scope and optional publication branch in
`manifest.json`; never guess scope from whichever files happen to be staged.
Architecture cannot pass with an empty or invalid manifest. Mixed staged work
blocks closure without MPD changing the index.

Every executed PASS receives a receipt bound to that phase's exact content and
governing inputs. Treat `valid`, `stale`, and `absent` as evidence states, not
gate verdicts. Reuse is explicit, append-only, and only from an exact valid
executed receipt. CONDITIONAL PASS is rerun fresh; Build, Test, and Security
(code) run fresh unless a complete hermetic policy is configured; Deploy always
runs fresh.

Archive is a completion-only journaled transaction: it stages and syncs exact
postimages before replacing repository targets, retains no rollback preimages,
and never claims filesystem-independent atomicity. Recover previews by default;
only `closure recover --yes` may roll forward exact preimages, and any third
state refuses before another write.

After archive, commit and push through normal Git. `mpd publish --verify` is a
fresh, non-fetching observation that requires a coherent linear closure commit
and exact configured-branch OID parity. It never stages, commits, pushes,
force-pushes, fetches, deploys, or invents a publication target.

Parsers, interpreters, serializers, codecs, and wire protocols get
property/fuzz/metamorphic tests (seeded + reproducible), not just example tests.
Performance/size claims need before+after numbers, median of several runs, same
build, command shown. **Verify your verification** — confirm the test command
actually executed tests.

## Rigor escalation — novel threat surface

When a change involves auth/credentials, network egress, file I/O on untrusted
input, dynamic code execution, sandboxing, cryptography, or a feature with no
analog already shipped: run the security phases at full depth (explicit threat
model at plan stage, deep code audit at code stage) and do **not** fix findings
inline — re-run Security (code) after every fix. Code cannot reach Test without a
passing Security (code).

## Persona models

Each persona runs under a model resolved per harness. mpd carries built-in tier
defaults — the judgment/creative planning and validation phases (Design,
Architecture, Doc Validation) get the strongest model; the execution/synthesis/
review phases (Security, Build, Test, Documentation) get the standard model — and
lets you override per persona in `.mpd/config.json` (`models`, `model_fallbacks`)
as models evolve. `mpd next --harness <h>` prints the resolved model per phase.

## Working principles (apply proportionately)

- **Speak the domain's language.** Use the user's exact terms in code, specs,
  and commits. Reconcile "false cognates" before writing code.
- **Promote implicit rules into named concepts.** A buried guard clause the user
  would describe in a sentence is a missing concept — name it.
- **Bounded contexts at every seam.** Translate at boundaries with external
  systems; don't import their types into the core.
- **Refactor toward deeper insight.** The first model is usually wrong; friction
  is a signal, not just nuisance.
- **Supple design.** Intention-revealing names; side-effect-free functions where
  possible; assertions for invariants; factor along the domain's natural seams.

DDD-grade modeling is a tax that pays back in complex domains and bankrupts
simple ones. Default to lighter approaches; reach for the heavy patterns only
when complexity demands it.
