# Design sign-off

## Actor

Designer

## Implementation vs intent

Date: 2026-07-20. Verified against `design-mock.md` (the approved operator contract)
and `design-review.md` (DR-1..DR-3 closures), by inspecting the tree-built binary
`./target/debug/mpd` (read-only commands only) and the rendering source it ships.

Surfaces inspected: `status --change local-first-verification-hardening` (human and
`--json`), `doctor`, `--help`, `validate --help`, `policy --help`, `policy activate
--help`, `gate --help`, `repair-state --help`, `next --harness claude-code --context`;
source spot-checks in `crates/mpd/src/cli.rs` (workflow/containment rendering
1590–1659, blocker table 1129–1167, containment construction 1183–1290, policy
activate output 4960–4980, refusal rendering 2711–2717 and 3124–3130),
`crates/mpd/src/harness.rs` (`terminal_safe`, 406–415), and
`crates/mpd/src/local_validation.rs` (bounded tails 7112–7122, 7282–7295).

### Checkpoints verified

1. **Separate honest facts.** The status "Workflow truth" block renders ten distinct
   facts (Worktree, Candidate, Gates/freshness, Local validation, Archive, Commit,
   Push authorization, Transfer, Remote parity, Install) plus a Containment block,
   each as outcome + typed state + optional evidence; the JSON `workflow` object
   carries the identical fields. The live output is itself the proof: Remote parity
   is `PASS VERIFIED` while Push authorization stays `BLOCKED BYPASSED` and Transfer
   `BLOCKED UNAUTHORIZED/BYPASSED` — parity does not repair missing authorization.
   Local validation names its own profile (`profile=security-code … checks=4`, a
   real non-zero count); the Build gate receipt carries only a typed `BuildOutputV1`
   and never Test-profile fields. Install distinguishes `readiness-only` from
   `installed-and-verified` in code (cli.rs 1529–1547).
2. **Readiness-only Deploy language.** `doctor` prints `deploy command: (unset —
   Deploy gate records readiness only)`; the install fact states above match the
   mock's typed detail exactly.
3. **NOT CERTIFIED renders honestly.** Containment shows `adapter=CERTIFIED
   full-profile=NOT CERTIFIED certified-claim=NOT CERTIFIED` with host, SPI/ABI,
   fixed-profile, and root-inventory digests, all three residual limitations, a
   single `blocker: sandbox.full-profile-incomplete`, and exactly one `action:`
   line — no fallback offered, matching the mock's drift/narrow-proof examples.
   Narrower proof never fills a wider row: the security-code receipt is CURRENT yet
   full-profile stays NOT CERTIFIED.
4. **Blocker codes map to actionable next steps.** All six `sandbox.*` codes exist
   with one action each, unclassified falls to `sandbox.spi-abi-drift` →
   Architecture (cli.rs 1129–1167); human and JSON carry the same single
   `blocker_code`/`blocker_action` pair.
5. **Hostile-output safety.** Untrusted state/evidence/limitation/action strings pass
   `terminal_safe` at every human render point (cli.rs 1607/1610/1643/1646/1653/1657);
   `terminal_safe` strips all control characters except `\n`/`\t` plus bidi and
   directional-isolate controls (harness.rs 408–415, OSC-8 covered by test at 682).
   The new profile-failure tails are bounded to 512 bytes via `saturating_sub(512)`,
   lossy-UTF-8 decoded, and `terminal_safe`-filtered before embedding
   (local_validation.rs 7114–7118, 7286–7290). JSON stdout is exactly one valid
   UTF-8 document with zero stderr bytes on the happy path (verified empirically).
6. **Profile-failure error presentation.** The refusal format is stable and named:
   `"<Phase> structured profile <profile> refused: check <name> <state> (exit …;
   output tail: …)"` (cli.rs 2711–2717, 3124–3130) — stable prefix, failing check
   named, no raw control bytes. Consistent with the design language.
7. **Readability.** Gate history truncates honestly ("… 37 earlier event(s) omitted
   (see `mpd status --json`)"); Evidence renders as an aligned validity/reuse table;
   the `next --context` brief bounds its manifest listing ("… 3 more").
8. **Superseded surface removed.** `--help` exposes no `policy bootstrap` or
   `first-adoption` route (the latter survives only under `#[cfg(test)]`); `gate
   --help` has no `--waive-artifact`; `validate --help` carries no pretrust ceremony
   language; `policy activate` now requires the digest-confirmed cooperative
   signature (`--confirm-policy-digest`, `--confirm-executable-digest`, `--yes`) and
   its output honestly disclaims side effects ("Activation created no validation
   receipt, gate PASS, push authorization, transfer, or remote-parity fact.").

### Findings (all non-blocking; owners named)

- **F1 — known gap, Phase 4.** The `sandbox.profile-drift` action text "run the
  printed digest-confirmed policy activation" (cli.rs:1140) and the
  `trusted-policy-missing` action "run the exact digest-confirmed `mpd policy
  activate` command" (local_validation.rs:5736) refer to a printed command that no
  code path actually prints: nothing ever emits a filled-in `mpd policy activate
  --commit … --confirm-policy-digest …` line with the reviewed digests. Until the
  printer exists, the sole remediation action is not directly executable. Owner:
  Builder (Phase-4 backlog; tracked alongside open tasks 7.2/7.3).
- **F2 — compiler-tree fact is a constant, and the human line elides its outcome.**
  `compiler_process_tree` is always constructed as outcome `NOT RUN` with the static
  state "FEASIBILITY EVIDENCE ONLY; NOT A FULL-PROFILE SUBSTITUTE" in both
  construction paths (cli.rs 1192–1195, 1281–1284), and the human renderer prints
  only the state (cli.rs 1641–1643), so the human view never shows the `NOT RUN`
  half and can never show the mock's "PASS · feasibility evidence only" once a probe
  actually runs. Direction of error is conservative — it never overclaims — but the
  mock's proof-layering display expects a distinguishable NOT RUN/PASS fact. Owner:
  Builder.
- **F3 — canary count omitted.** Human shows `canaries=PASS` (outcome only,
  cli.rs 1640–1642); the mock example shows `Canaries: PASS <required>/<required>`.
  JSON carries outcome+state but no count either. Minor honesty-of-count gap
  against acceptance criterion 6. Owner: Builder.
- **F4 — status next action hardcodes a harness.** `next_action` is the literal
  "run `mpd next --harness codex --context`" (cli.rs:1555) regardless of the
  driving harness; this session's own directives invoke `--harness claude-code`.
  The single safe next action should be harness-neutral or configured. Owner:
  Builder.
- **F5 — blocker classification by substring sniffing.** `sandbox_blocker`
  keyword-matches error prose (cli.rs 1129–1167) although the emitters already
  produce stable `sandbox.<code>:` prefixes (e.g. sandbox_macos.rs 157–165); a
  canary error whose text mentions "host" would surface the wrong sole remediation.
  Prefer parsing the stable prefix. Owner: Builder.
- **F6 — newline retention in embedded tails.** `terminal_safe` deliberately keeps
  `\n`, so a hostile check's 512-byte tail embedded in a one-line refusal can start
  fresh lines at column 0 that visually imitate status lines. No ANSI/OSC/bidi/
  cursor tricks are possible and the surrounding result is FAILED/BLOCKED (the
  verdict of record cannot flip), but replacing newlines with a visible separator
  or indenting continuation lines when embedding untrusted tails would close the
  visual-imitation residue. Owner: Builder, with Security(code) to re-assess.
- **Cosmetic:** `policy activate` prints the executable digest under `coordinator=`
  (cli.rs 4971–4976) while `--coordinator` takes a path; `coordinator-digest=`
  would remove the label/value drift. Owner: Builder.

No finding shows the surface collapsing facts, rendering a NOT CERTIFIED state
optimistically, or reintroducing a superseded ceremony. Every gap errs conservative.

## Verdict

PASS

The built human/CLI/JSON surface realizes the approved contract: facts stay
separate and honest, NOT CERTIFIED states render as blocked truths with one code
and one action, hostile bytes are filtered and bounded, and the superseded routes
are gone. Findings F1–F6 are recorded with named owners; none misrepresents state
to the operator, so none blocks Test. This is a Design Sign-off only — not a
Security, Test, documentation, release, installation, push, or parity verdict.
