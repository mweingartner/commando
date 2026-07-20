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
  the Codex Documenter to Luna).

`mpd next --harness <harness>` prints the resolved model for each phase; treat
that output as authoritative over any prose table, including this one. Note
that `mpd conduct` takes no `--harness` flag — harness is a rendering choice
made per `mpd next` call, not a property of the change.

Repeat `next -> work -> gate` until Done, then archive, commit, push normally through
the activated local hooks, and run `mpd publish --verify`. Keep these facts separate in
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

- Check `git status` first and treat unrelated changes as user-owned.
- Use `apply_patch` for edits. Stage explicit files only; never `git add -A`.
- Never use `--no-verify`, force push, destructive reset, or source-tree secrets.
- Do not commit `.git/mpd`, `.mpd/current`, `.mpd/tmp`, `.mpd/build-output`,
  `.mpd/local`, receipts, logs, target artifacts, or installed binaries.
- The only policy activation route is `mpd policy activate` bound to an immutable
  reviewed commit, canonical policy digest, absolute coordinator digest, and tracked
  `.githooks` wrappers. There is no legacy trust-bootstrap policy route.
- Normal Git alone performs transport. `mpd hook pre-push` only authorizes the exact
  invocation; `mpd publish --verify` separately observes parity.

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
