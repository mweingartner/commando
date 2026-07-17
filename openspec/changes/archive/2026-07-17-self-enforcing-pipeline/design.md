# Design: self-enforcing adversarial pipeline (two-tier)

Canonical current-state contract. Superseded drafts/reviews go to `history/`.

## Context

mpd is a state-machine CLI: it orders phases, names each persona + model, and
runs *deterministic* gates. It does **not** run the LLM personas — the harness
does. So "enforcement" means structural requirements + deterministic checks +
state-machine rules, never mpd spawning reviewers. Today `cmd_gate`
(cli.rs:983–1282) enforces only the objective gates; the `evidence` field is
recorded verbatim and never validated (`mpd gate security-code --pass --evidence
smoke` succeeds), and no judgment gate requires its artifact to exist. That is
the exact hole through which the CARC adversarial record evaporated.

## Goals / Non-Goals

**Goals.** Make the adversarial-judgment layer self-enforcing *for harnesses*
without adding friction for a human driving manually; keep one code path; make
every new requirement escapable; reduce (not grow) harness context load.

**Non-Goals.** No quorum/independent-N engine (mpd can't run models). No separate
`findings.json` (reuse `Condition` + `resolve`). No retroactive validation of
archived changes. No per-invocation `--strict` flag (a dropped call silently
degrades — the exact CARC footgun) and no per-project strict config (forces
friction onto hand-driven experiments in the same repo).

## Decisions

### D1 — Two tiers over one ledger, selected per-change by a durable bit

Add `Ledger.strict: bool` (`#[serde(default)] = false`) as the single source of
truth. `mpd conduct <name> [--ui --fix|--chore --risk --threat-profile]` is a
thin alias over `cmd_begin` that additionally sets `strict=true`, scaffolds the
current phase's judgment template, and prints the harness call-loop contract.
`mpd begin --strict` is the same bit-setter. Chosen per-change because a run is
the natural scope: the harness opts in *once*, it survives session death, and a
resumed harness gets the same strictness. A human never sets it and sees no
change.

### D2 — The harness loop uses the UNCHANGED verbs (no forked driver)

mpd cannot run personas, so the motion stays `mpd next → spawn persona → mpd
gate`. Strict mode enriches the *same* `mpd next --json` envelope (adds
`artifact_path` + a strict `gate_command`) and turns on the extra checks in the
*same* `cmd_gate`. No `conduct step`/`conduct gate` sub-machine — that would fork
the code path the operator forbade.

```
mpd conduct self-enforcing-pipeline --risk high
loop:
  brief = mpd next --harness claude-code --context --json   # slice + persona + model + artifact_path + gate_command
  break if brief.phase == "done"
  <spawn persona at brief.model; fill brief.artifact_path; do the work>
  mpd gate <phase> --pass --evidence <artifact_path>        # strict checks auto-apply from ledger.strict
mpd archive --yes
```

### D3 — Orchestration-only vs universal

**Orchestration-only (fires only when `ledger.strict`):** required non-stub
judgment artifact per judgment gate; `--evidence` must resolve to a real
contained file **and, for a judgment phase, to that phase's own artifact** (kills
the CARC security-code→security-plan.md aliasing); archive-time re-check that the
artifacts survive; high-risk security-code additionally requires `Independent
review` + `Refutation` sections.

**Universal (both tiers):** `mpd use`, `mpd doctor --fix`, `mpd brief <phase>`,
`mpd next --context`, `mpd status --brief`, the archive transient-path pre-flight,
the test-runner no-pass-count hint, and the risk→deep model bump.

**Objective gates (unchanged, unwaivable, for everyone):** Build/Test pass-count,
secret scan, `documentation.md` structural check, Deploy, closure coherence,
manifest-ready, `artifact_stub_issues`. With `strict=false` the new branch is
inert, so the manual tier is byte-identical to today.

### D4 — Reuse existing machinery, add one gate branch

`Phase::judgment_artifact() -> Option<(&'static str, &'static [&'static str])>`
(phase.rs) maps each judgment phase to (filename, required `##` sections).
`check_documentation` is refactored into `check_sections(text, &[&str], min_len)`
(byte-identical wrapper preserved). `cmd_gate` gains one `if ledger.strict { … }`
branch cloning the existing `requires_doc_check` branch. Findings-closure reuses
`Condition` + `mpd resolve` + `blocking_reasons()` (already archive-gating).

### D5 — Escapes on every requirement (no new stuck-state)

`mpd gate <phase> --pass --waive-artifact "reason"` records a bounded,
append-only waiver (loud WAIVED banner in status); artifacts are auto-scaffolded
by `conduct`/`begin --strict`/`mpd brief`; `--evidence` omitted in strict
defaults to the phase artifact; `mpd use` restores a cleared `.mpd/current`;
`mpd doctor --fix` heals a missing `.mpd/.gitignore`. Waivers never bypass the
objective gates and never convert a FAIL.

### D6 — Resolved open questions

- **Model-bump precedence: elevate ONLY the seeded-default case** (revised per
  Security-plan A3). `default_models()` seeds an explicit standard-tier entry for
  every persona, so a naive "fall back to deep default" bump is a dead no-op — it
  must override the *seeded* entry. But overriding a *user-customized* pin would be
  a rigor **inversion** (forcing the deep default over a deliberately-pinned strong
  custom model mpd cannot rank). So at `risk=high`, Security/Tester elevate to the
  harness **deep** model ONLY WHEN their resolved model equals the harness
  standard-tier default (the seeded case); a custom/non-standard pin is a
  deliberate operator choice, left untouched. Resolve through the existing
  `model_for` path with `is_deep` forced true so `valid_model_id` degradation is
  preserved and no unsafe id reaches a rendered `--model`. Print `risk=high → deep
  tier` when the elevation fires. Opt-out lever: lower the risk.
- **Required sections** (finalized): security-plan.md → `Threat model`,
  `Conditions for Builder`, `Verdict`; security-code.md → `Findings`,
  `Conditions verified`, `Verdict` (+ high-risk: `Independent review`,
  `Refutation`); design-review.md → `Intent check`, `Verdict`; design-signoff.md
  → `Implementation vs intent`, `Verdict`; test.md → `Coverage`, `Results`,
  `Verdict`; doc-validation.md → `Architect lens`, `Designer lens`, `Verdict`.
  Architecture keeps design.md but strict adds required `Conditions for Builder`.
- **Waivers**: surfaced (loud banner + counted in the archive summary as an audit
  signal), not hard-capped — keep it simple (but attempt-scoped and
  autonomous-restricted; see D7).

### D7 — Waiver scoping, reuse, and the strict backstops (Security-plan hardening)

- **Waivers are attempt-scoped.** `Waiver` carries `attempt: usize` (mirroring
  `Reconciliation`); a waiver applies only to the attempt it was recorded for, and
  `invalidate_from_security`'s rewind drops/marks-non-applicable waivers for the
  rewound phases — so a stale attempt-1 waiver can never silently suppress the
  artifact gate on a re-run under a changed threat profile (B1).
- **The archive re-check honors a validly-scoped waiver** for an applicable
  judgment phase (counted in the WAIVED audit summary, never blocking) — otherwise
  a legitimate gate-time waiver would be an un-archivable stuck-state, since a
  scaffolded template does not pass `check_sections` (B2).
- **The `--reuse <receipt>` path also enforces the strict artifact check.** Reuse
  returns before the `advances()` block, so in strict mode the phase's own artifact
  must still exist and pass `check_sections` on the reuse path, or the
  anti-evaporation guarantee is bypassed at gate time (B3).
- **`strict` is write-once / monotonic** — no code path sets it true→false; a test
  pins it (A6).
- **Autonomous mode never weakens rigor** (B4/A4): under `--autonomous`, a
  `--waive-artifact` on a Security phase, ANY threat-profile change (the enum is
  unordered, so all changes halt), and any risk *downgrade* are halt-and-report;
  only `--risk` upgrades and `--continue`/`--narrow` proceed with a recorded reason.

## Risks / Trade-offs

- [A strict requirement becomes a stuck-state] → every one has a one-command
  escape (D5); the dogfood run proves the escapes end-to-end.
- [The model-bump override surprises a user who pinned a model] → it only ever
  *strengthens* the tier, prints a note, and risk is the documented opt-out lever.
- [Strict branch changes manual behavior] → gated entirely on `ledger.strict`;
  a `strict=false` gate is pinned byte-identical by test.
- [Legacy ledger breakage] → all new fields `#[serde(default)]`; legacy
  round-trip test.
- [Evidence/artifact reads follow a symlink and exfil] → all reads via
  `read_capped` + `assert_contained` (symlink-refusing); evidence validation
  never reads content into output.

## Conditions for Builder

1. **ALL** new file reads MUST use `openspec_core::read_capped` +
   `assert_contained` — including evidence validation, the judgment-artifact
   check, the archive re-check, `mpd next --context` `extract_section`,
   `mpd brief` template probes, and the `doctor --fix` gitignore read. A
   symlinked/oversized target reads as `""` and fails structurally, never
   followed or read through. (A5)
2. `validate_evidence` MUST strip at the **first** `#`, require the stripped path
   non-empty, `join` it to the change dir and run `assert_contained` (which
   catches `.`/CurDir/empty-component/intermediate-symlink/escape — do NOT rely on
   ad-hoc absolute/ParentDir checks alone), confirm existence via
   `symlink_metadata` (never follow), and MUST NOT read content into any output.
   For a judgment phase the contained path MUST **equal** `change_dir/<judgment
   artifact filename>` exactly (not a basename match — a planted
   `subdir/security-code.md` must not alias); when `--evidence` is omitted in
   strict it defaults to that exact artifact. Compare the **post-`join`**
   PathBuf (`change_dir.join(evidence)` vs `change_dir.join(artifact)`) and
   reject an absolute `--evidence` before joining (`Path::join` replaces on an
   absolute argument). (A1, B-aliasing, M2)
3. The `check_sections` refactor MUST leave `check_documentation` byte-identical
   (same `REQUIRED_DOC_SECTIONS`, backtick-aware placeholder check, 120-char
   floor); pin with the existing doc tests + an equivalence test.
4. New ledger fields MUST be `#[serde(default)]`; add a legacy-ledger round-trip
   test and a test proving a `strict=false` gate is byte-identical to today.
5. `--waive-artifact` reason MUST pass `bounded_text` (non-blank, ≤500), render
   `terminal_safe`, append to append-only history, show a loud WAIVED banner, and
   MUST NOT bypass the objective gates or convert a FAIL. A `Waiver` MUST carry
   `attempt: usize` and apply ONLY to that attempt; `invalidate_from_security`
   MUST drop/mark-non-applicable waivers for rewound phases (test: waive →
   reconcile-rewind → the re-run demands the artifact again). (B1)
6. `mpd use <change>` MUST `validate_change_name` and confirm the ledger file
   exists before writing `.mpd/current`.
7. `mpd doctor --fix` MUST read the existing `.mpd/.gitignore` via `read_capped`
   and **fail-closed** (refuse + report, never write) if it is a symlink or
   oversized; re-run `assert_contained` immediately before writing (the
   double-check pattern in `Config::save`/`write_new`); be idempotent and
   add-only with a guaranteed trailing-newline boundary; write ONLY
   `.mpd/.gitignore` (never the project-root `.gitignore`, never delete/truncate).
   The test-command/stall diagnostics MUST be read-only and MUST NOT mutate
   `config.json`. (A2)
8. The archive un-gitignored-transient pre-flight MUST fail-closed on `--yes`, and
   MUST demand exactly the transient-path set that `doctor --fix` heals (ONE
   shared constant extending scaffold's `/current /tmp/ /pending-closure
   /parity-observations.json`), so `--fix` always fully clears it (prove
   dirty → refuse → `--fix` → archive succeeds). (A7)
9. The archive-time strict re-check MUST honor applicability skip rules (only
   applicable judgment phases) AND treat a **validly-scoped waiver** for such a
   phase as satisfied (shown WAIVED in the audit summary, never blocking) — else a
   legitimate gate-time waiver is an un-archivable dead-end. (B2, Cond 9)
10. The `risk=High` model bump MUST change the resolved model on a default-init
    project by overriding the **seeded standard-tier** entry, but MUST leave a
    **user-customized/non-standard pin untouched** (elevate only when the resolved
    model equals the harness standard default — never a rigor inversion). It only
    ever strengthens, preserves `valid_model_id` degradation (resolve via
    `model_for` with `is_deep` forced true), and surfaces no unsafe id; extend the
    proptest to the bumped Security/Test path. (A3)
11. All new user-controlled text in human render (waiver reasons, evidence paths,
    extracted section text) MUST pass `harness::terminal_safe`; `--context` output
    MUST additionally be length-bounded.
12. Under `--autonomous`, ANY threat-profile change (the enum is unordered → all
    halt), any `--risk` downgrade, and any `--waive-artifact` on a Security phase
    MUST halt-and-report; only `--risk` upgrades and `--continue`/`--narrow` may
    proceed, with a recorded reason. (B4, A4)
13. In strict mode the `--reuse <receipt>` path (which returns before the
    `advances()` block) MUST still enforce the judgment-artifact check — the
    phase's own artifact must exist and pass `check_sections` — or the
    anti-evaporation guarantee is bypassed at gate time; add a strict-reuse test.
    (B3)
14. `strict` MUST be write-once/monotonic: no code path sets it true→false; pin
    with a test. This is the linchpin the whole enforcement hangs on. (A6)
15. Every strict refusal (artifact gate + archive re-check) MUST print the working
    escape (`mpd brief <phase>` / `--waive-artifact "reason"`) so a refusal parsed
    from stderr is never a dead end. (A8)
16. This change MUST run under strict and retain its own design.md /
    security-plan.md / security-code.md / test.md / documentation.md /
    doc-validation.md through archive — the direct regression against the exact
    evaporation it fixes (this exercises but does not alone prove B1–B3; the named
    targeted tests are required too). (Cond 13)

17. `--waive-artifact` MUST be rejected together with `--reuse` at the TOP of
    `cmd_gate` (before the reuse early-return at cli.rs:1113), alongside the
    existing `--reuse requires --pass` validation — so the reuse seam can never
    combine with a waiver to skip the autonomous halt (Cond 12) or the artifact
    check (Cond 13). `--waive-artifact` MUST also require `--pass` and be rejected
    on any phase with no `judgment_artifact()` (audit hygiene). Add test R17:
    under `--autonomous`, `mpd gate security-code --reuse <r> --waive-artifact
    "x"` is rejected, never a silent reused PASS. (re-review new gap; M1)

### Accepted residual risks (recorded, not blocking)

- The archive re-check fires only under `ledger.strict`, so the evaporation hole
  remains open for **manual-tier** changes by design (the two-tier trade-off:
  manual tier byte-identical to today). Mitigation: harness/orchestrated runs use
  `conduct` (strict).
- There is no verb to promote an already-begun non-strict change to strict without
  re-`begin` (`conduct`/`begin --strict` refuse an existing change dir).
  Acceptable per "the harness opts in once"; documented in the AGENTS.md/protocol
  rewrite (task 4.1).
- Under the model-bump rule (Cond 10), a user who pins a *weaker-than-standard*
  custom model for Security/Tester keeps it at risk=High — mpd cannot rank models,
  so a non-standard pin is deliberately left untouched. Defensible tradeoff. (M3)
