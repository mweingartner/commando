# Project Context

Commando is the source repository for `mpd`, a local-only Model-Paired Development
meta-harness. It turns a change into an explicit, gated sequence of design,
architecture, security, implementation, test, documentation, and delivery facts,
recorded in an append-only ledger and layered over OpenSpec + Git.

## What this project is for

Four goals, in the owner's words:

1. Push a task through clear gates from design to architecture to build, test,
   document, **with assurance that output meets intent**.
2. Roles are **adversarial**, but each role has **province within their expertise
   to move forward** when convinced the output will meet intent.
3. **Optimize model engagement cost** — "just enough" model per task: the best
   model on architecture, a cheaper one on documentation.
4. Layer it on **OpenSpec so the system of record is transparent to all personas**.

Read these before proposing anything that trades one away. A change that makes the
pipeline more rigorous *and* more expensive is usually moving away from the goals,
not toward them.

## Core domain vs. supporting machinery

The **Core Domain** is the phase/persona/gate model and the evidence ledger:
`phase.rs`, `ledger.rs`, `personas.rs`, `directives.rs`, `harness.rs`, and the
`conduct`/`next`/`gate`/`status` surface. This is what makes the tool valuable and
distinctive, and it is where care belongs.

The hermetic local verification kernel — sandbox, candidate hashing, receipts, tool
pinning, offline enforcement, policy activation, closure, attestation,
publish/parity — is **supporting infrastructure**. It is roughly two-thirds of the
code. It is genuinely load-bearing (the observed-test-count check is the one
mechanism here that beats self-report), but it is not the point, and growing it
further should clear a high bar.

## Trust boundary

A cooperative repository owner. The owner can replace the executable, edit Git
state, or bypass hooks. MPD records and checks the normal path; it does not claim to
resist that owner. Actor, model, and session labels are recorded provenance, not
authenticated identity.

Design consequence: **fail-closed belongs on boundaries an adversary controls, not on
the owner.** Guards aimed at the owner have repeatedly cost the whole toolchain for
no attacker — an exact OS build-string pin that a routine macOS update tripped, and a
`policy digest` command that refused to run precisely when a broken policy needed
repairing. Prefer a recorded observation with an actionable message.

## Known state (2026-07-24)

The pipeline has been driven 29 times, all 29 on mpd's own machinery. Delegation was
never recorded, so it is not known how often the personas actually ran; 62% of
attempts closed within 30 seconds of phase entry, and fail rate tracks duration.
`mpd gate` now records `--delegated`/`--self-recorded` and `--model`. Until that data
exists, treat any claim about this pipeline's cost or quality — including claims in
its own documentation — as having an unmeasured denominator.

See `docs/design-revisit-2026-07-24.md` for the full diagnosis, the measured
evidence, and what was deliberately deferred.

## Conventions

- Rust 2021, workspace at `crates/`. `openspec-core` is the format layer; `mpd` is
  the harness. No Node dependency.
- Capability specs live in `openspec/specs/<capability>/spec.md`; a change proposes
  deltas under `openspec/changes/<change>/specs/`.
- Never `git add -A`. Never commit secrets or build artifacts.
- `.mpd/directives/**` and `crates/mpd/assets/directives/**` must stay
  byte-identical; `mpd doctor` checks parity.
