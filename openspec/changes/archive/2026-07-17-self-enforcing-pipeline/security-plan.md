# Security (plan): self-enforcing-pipeline

Governance: risk **medium**, threat profile **local-trusted-user**. Reviewed at
full depth (novel surface: dynamic gate enforcement + autonomous-mode rigor
policy + new file-writing self-heal). Two adversarial rounds.

## Threat model

The actor under `local-trusted-user` is the operator or their harness on their
own repo — so the dominant risk class is **rigor integrity** (the enforcement
silently degrading to the pre-change state), not external exploitation, plus the
usual file-I/O safety (CWE-59 symlink, CWE-22 traversal, CWE-532 info-leak) on
the new read/write sites. Trust boundaries and the invariants that must hold:

- **Enforcement bit (`strict`)** is the linchpin — if it can be cleared or a gate
  can be passed without its artifact, the whole guarantee is void. → write-once/
  monotonic (Cond 14); every judgment gate, its `--reuse` seam, and the archive
  re-check enforce the artifact (Cond 9/13/17).
- **Waivers** are the deliberate escape — they must never become either a silent
  suppressor (across a rewind) or an un-archivable dead-end, and never bypass an
  objective gate or convert a FAIL. → attempt-scoped + dropped on rewind (Cond 5),
  honored at archive (Cond 9), mutually exclusive with `--reuse` (Cond 17),
  objective gates untouched (Cond 5).
- **New file reads** (evidence, artifacts, `next --context`, `brief`, doctor) must
  be symlink-refusing, size-capped, contained, and leak no content. → `read_capped`
  + `assert_contained` everywhere (Cond 1/2); evidence validation is metadata-only.
- **New file write** (`doctor --fix`) must be add-only, path-locked to
  `.mpd/.gitignore`, and fail-closed on a symlinked/oversized target. → Cond 7.
- **Autonomous mode** must never weaken rigor unattended. → all threat-profile
  changes, risk downgrades, and Security-phase waivers halt-and-report (Cond 12);
  the reuse+waiver combination is rejected outright (Cond 17).
- **Model bump** must only ever strengthen, never invert a deliberate custom pin,
  and never surface an unsafe model id. → Cond 10.

## Findings

**Round 1 — CONDITIONAL PASS.** 4 blocking + 8 advisory. The blockers were the
change's own footgun class:
- **B1** waiver replay across a rewind silently suppresses the artifact gate →
  closed: `Waiver.attempt` + drop-on-rewind (Cond 5, test R11).
- **B2** a gate-time waiver becomes un-archivable → closed: archive honors valid
  waivers (Cond 9, R12).
- **B3** `--reuse` returns before the enforcement block, bypassing the artifact
  gate → closed: reuse path enforces the artifact (Cond 13, R13).
- **B4** autonomous threat-profile "downgrade" is undefined on an unordered enum →
  closed: refuse ALL threat-profile changes autonomously (Cond 12, R14).
- Advisories A1–A8 (evidence containment/aliasing, doctor-fix symlink fail-close,
  model-bump inversion, read-site enumeration, strict monotonicity, shared
  transient constant, escape-in-refusal) → all closed in Conditions 1/2/7/8/10/14/
  15, verified against code in round 2.

**Round 2 — re-verify: all 12 confirmed closed against code, + 1 NEW gap.** The
B3 fix opened the same seam for the B4 fix: `--waive-artifact` + `--reuse` under
`--autonomous` could skip both the autonomous halt and the artifact check (reuse
returns at cli.rs:1113 before the enforcement block). → closed: `--waive-artifact`
is mutually exclusive with `--reuse`, rejected at the top of `cmd_gate` before the
early-return (Cond 17, test R17). Minor advisories M1–M3 folded in.

## Conditions for Builder

The 17 Conditions for Builder + accepted residual risks in `design.md#conditions-for-builder`
are the normative closing evidence for this gate; each blocking finding maps to a
numbered Condition and a named risk-to-test row (R10–R17). The reuse-mutual-
exclusion (Cond 17) is verifiable at Security (code) without a further plan re-run.

## Verdict

**CONDITIONAL PASS → PASS on the revised design.** All 4 round-1 blockers, all 8
advisories, and the 1 round-2 gap are closed by the revised Conditions, verified
against the real code (not name-dropped), each with a named test. Proceed to
Build. Security (code) must confirm, on the real implementation: Cond 2 post-join
exact-equality (M2), Cond 5/9/13/17 waiver+reuse seam behavior, Cond 7 doctor-fix
fail-closed, Cond 10 no custom-pin inversion, and Cond 14 strict monotonicity.
