# Commando Agent Instructions

Commando is the source repository for `mpd`, a local-only Model-Paired Development
meta-harness. Read `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CONTRIBUTING.md`, the
active change artifacts, and every directly affected source/test file before editing.

## Required operating loop

For every non-trivial change:

```sh
mpd conduct <change>
mpd next --harness <harness> --context
# perform only the current role and satisfy its written artifact
mpd gate <phase> --pass --by <actor> --evidence <artifact>
```

## Harness and model selection

Set `<harness>` by which agent is reading this file:

- **Claude Code** sessions use `--harness claude-code`. Deep phases (Design,
  Architecture, Doc Validation) resolve to Fable, falling back to the latest
  Opus when Fable is unavailable; every other phase resolves to Sonnet.
- **Codex** sessions use `--harness codex`. Deep phases resolve to GPT-5.6 Sol;
  every other phase resolves to Terra (this repo's `.mpd/config.json` overrides
  the Codex Documenter to the user-authorized Terra route).

`mpd next --harness <harness>` prints the resolved model for each phase; treat
that output as authoritative over any prose table, including this one. Note
that `mpd conduct` takes no `--harness` flag — harness is a rendering choice
made per `mpd next` call, not a property of the change.

**Effort/tier follows effective risk.** At effective High risk, Security and Tester
also resolve to the deep model with a raised effort floor, and Test selects the
heavier `high-risk-test` profile. High is a *depth* escalation, not an
attempt-limit tightening — High in fact loosens the attempt limit (High 3 >
Medium 2 > Low 1). A documentation-only change derives Low; every other change in
this repo derives High (its source and `.mpd/`/config files are verification
policy). Match the *requested* risk to blast radius (`mpd conduct --risk`); the
classifier can only raise it, never lower it.

## Lean operating protocol

Keep the adversarial review; cut the mechanical re-work:

- **Each lane runs once per Candidate; documentation never compiles.** Build, Security(code),
  and Test validate the SAME immutable Candidate, so the profiles are disjoint by design:
  Build owns `format`/`clippy`/`workspace-tests`, Security(code) owns the four scans, Test
  owns `release-build` (+ non-functional at high risk). A lane that already passed against
  this Candidate is covered — re-running it at a later gate is duplication, not rigor, and
  `LocalValidationConfig::validate` refuses any config that drops a lane from the drive's
  union or re-adds one twice. `pre-push` deliberately keeps the full set: it verifies the
  COMMIT, a genuinely different subject, once. The docs profiles carry no compile and no
  test lane at all — a documentation change never rebuilds.
- **Size validation to code motion.** A change confined to a bounded area gets the tests
  covering that area; it does not need a full-workspace sweep or a release build to prove
  it. Reserve the full profile for cross-cutting work — shared/config/policy/sandbox/security
  code, dependency manifests, or the toolchain. Never gate on exercising an area the change
  does not touch.
- **Full re-validation is for defects, not routine.** Re-run the whole cycle when a real bug
  surfaces or a security issue with a demonstrated path of access — not because prose was
  reworded, a comment moved, or a gate was re-recorded.
- **Editing prose after its gate still rewinds — but no longer re-executes the
  sandbox.** The change's own process prose (`design.md`/`proposal.md`/`tasks.md` and
  the judgment artifacts) is excluded from the Candidate and covered by a dedicated
  secret-scan lane, so an *uncommitted* prose edit leaves the Candidate byte-identical:
  the rewound judgment gates re-run (cheap), and Build/Test **reuse** their prior
  receipts (`mpd gate <phase> --pass --reuse <receipt>`, offered by `mpd next`) instead
  of re-executing. Freezing prose before gating is still the tidiest path (fewer
  rewinds), but a late wording fix or a closed review condition is now cheap. Reuse
  still re-executes for any in-scope source/config/spec/manifest edit, a *committed*
  prose edit (base HEAD moves), and Security(code) always. See README "Exact candidate
  and freshness".
- **Tier-match the review to blast radius.** Spawn deep-tier persona subagents for
  real threat surface or novel logic; for a genuinely low-surface change (a config
  narrow, a back-compatible rename, a docs edit) author the Security/Doc artifacts
  inline rather than spending a deep-tier pass.
- **Batch small same-scope changes** into one traversal instead of one change per fix.
- **Record non-blocking / comment-only findings as notes in the artifact**, not as
  a FAIL or an artifact edit that triggers a re-drive.
- **Keep efficiency claims coverage-aware.** Never report missing token, active-time,
  currency, or cost evidence as zero. Soft budgets warn; hard budgets and the fixed
  two-blocker/30-minute anti-stall boundary stop only a new brief. Cooperative actor,
  model, and session labels are not authenticated provenance; this repository has no
  external issuer, so authenticated provenance is `NOT DEPLOYED`.
- **Do not optimize routing from fixtures.** `benchmarks/routing-v1/` defines the blind
  suite, but only sufficient fresh actual-session evidence may support `routing apply`.
  Evaluate and review the preview first; `MISSING`/`INSUFFICIENT` preserves mappings.
- **Preserve reuse floors.** Check-level reuse requires a current exact-identity
  executed origin. Security(code), outgoing secret scanning, Commit, and pre-push stay
  fresh. The docs lane applies only to effective-Low documentation-only scope.
- **Declare the manifest completely up front** — source/spec paths plus
  `openspec/changes/<change>/**` and `docs/<change>.md`; NOT the ledger
  `.mpd/state/<change>.json` (folded via SystemScope; declaring it trips the
  `.mpd/` sensitive-path risk signal). The strict Build gate now names any missing
  entry.

## Landing

Repeat `next -> work -> gate` until Done, then archive, commit, release the closure
with `mpd archive --close --yes` (formerly `--abandon`, still accepted as an alias),
push normally through the activated local hooks, and run `mpd publish --verify`. Keep these facts separate in
every report: local worktree, exact Candidate, gates/freshness, local validation,
archive, commit coherence, push authorization, observed transfer, remote parity, and
installation.

The ordered gates are:

`Design Mock -> Architecture -> Design Review -> Security(plan) -> Build ->
Security(code) -> Design Sign-off -> Test -> Documentation -> Doc Validation -> Deploy`

Only Design phases may be N/A, with a recorded no-human-visible-impact rationale. A
FAIL blocks. A condition blocks archive until resolved. Material changes return to the
earliest affected phase and invalidate downstream approval.

## Role discipline

- Designer specifies and later inspects the real CLI/human/JSON surface, including
  missing, stale, blocked, hostile-output, bypass, readiness, and installed states.
- Architect writes the file/API/dependency plan, risks, test map, and Conditions for
  Builder. Architect does not implement.
- Security reviews plan and code separately, cites concrete file/line findings, states
  reviewed and omitted scope, and ends PASS, CONDITIONAL PASS, or FAIL.
- Builder implements only the approved bounded plan and tests each vertical slice.
- Tester reads the implementation and exercises functional, regression, integration,
  boundary/error, concurrency/resource, and seeded property/metamorphic categories.
- Documenter updates durable guidance and verifies every named path, flag, and command.

Strict judgment artifacts require one exact `## Actor` and `## Verdict`. The first
nonblank verdict line is exactly `PASS`, `CONDITIONAL PASS`, or `FAIL`; artifact Actor
must match `--by` and differ from the latest applicable upstream actor. These labels are
cooperative provenance, not authenticated identity. Commando has no artifact waiver.

## Verification and trust boundary

GitHub Actions and hosted CI are not validation authority. The authoritative profile is
local, exact-subject, offline, tool-pinned, resource-bounded, and network-denied. The
release certification boundary is macOS 27.0 build `26A5378n`, Apple silicon,
`aarch64-apple-darwin`, with the fixed Seatbelt compatibility adapter and all canaries
current. Every other host is NOT CERTIFIED.

The adapter uses deprecated custom-profile and undocumented extension SPI. Do not add
an App Sandbox, `sandbox-exec`, broad-read, unsandboxed, hosted, or Linux fallback. Do
not claim global path-metadata/literal-root-entry confidentiality or same-user process
isolation.

Authoritative checks use typed argv, exact pinned executables, private HOME/Git/XDG/temp
state, bounded stdout/stderr/logs/resources, one private runtime write root, and no
network. Roots must never come from argv, environment, or candidate policy. Any host,
ABI, profile, root, token, descriptor, inheritance, canary, timeout, truncation, leak,
race, or cleanup ambiguity is BLOCKED.

During Builder work, compile early and use focused tests. Before a gate claim, run the
full relevant local profile. Verify the verifier: report exit status and real counts;
the ignored 10k-path/100MB workload must be run explicitly and must report one test
passed. A narrower compiler process-tree probe is feasibility evidence only.

## Git and files

- Check `git status` first and treat unrelated changes as user-owned. The line is
  tracked vs untracked: a *tracked* file you modify that is part of the change MUST be
  declared in the manifest (the strict Build/Security(code)/Test gates refuse otherwise
  — that is how a change silently shipped unvalidated `.rs` files before); a genuinely
  unrelated tracked edit must be stashed; *untracked* files stay user-owned.
- Use `apply_patch` for edits. Stage explicit files only; never `git add -A`.
- Never use `--no-verify`, force push, destructive reset, or source-tree secrets.
- Do not commit `.git/mpd`, `.mpd/current`, `.mpd/tmp`, `.mpd/build-output`,
  `.mpd/local`, receipts, logs, target artifacts, or installed binaries.
- The only policy activation route is `mpd policy activate` bound to an immutable
  reviewed commit, canonical policy digest, absolute coordinator digest, and tracked
  `.githooks` wrappers. There is no legacy trust-bootstrap policy route.
- Normal Git alone performs transport. `mpd hook pre-push` only authorizes the exact
  invocation; `mpd publish --verify` separately observes parity.
- Candidate-cache inspection is read-only. Pruning requires `mpd cache prune --yes`,
  retains live and archived references, and is not a substitute for archive recovery.

## Completion evidence

For a production-ready Commando change, record at least:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --workspace --all-targets --offline --locked
cargo test --release -p mpd scoped_digest_throughput_over_10k_paths_100mb \
  --offline --locked -- --ignored --nocapture
cargo build --workspace --release --offline --locked
bash scripts/check-doc-staleness.sh
bash scripts/ci-local.sh --profile high-risk-test --commit HEAD
```

After archive and commit, rerun the exact Commit profile through the activated
coordinator, push through the normal hook, verify remote parity, and verify the typed
installed-file identity. Code changes after a successful receipt or install make that
evidence stale.
