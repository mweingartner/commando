# mpd adoption quickstart

How to adopt mpd in another repository, based on a fresh-repo pilot run
(`mpd init` → conduct/begin → gates → archive on a scratch project with a plain
test command). It records what actually works today, including the honest
boundary between the two tiers.

## TL;DR — pick your tier

mpd has two tiers, and the choice determines how much setup you need:

| | **Manual tier** (`mpd begin`) | **Strict tier** (`mpd conduct`) |
|---|---|---|
| Setup on a fresh repo | `mpd init` + set `test` in `.mpd/config.json` | the same portable setup; `local_validation` is optional for exact-Candidate certification |
| Build/Test gate | runs your configured test command via the shell, checks a real non-zero pass count, secret-scans | uses structured exact-Candidate validation when configured; otherwise uses the same legacy test/scan checks without a Candidate or structured receipt |
| Portability | any repo, any OS | governance is portable; structured certification is currently limited to **one macOS/Apple-silicon host** via a deprecated Seatbelt path |
| Gate enforcement | machine-checked secret scan + test count; persona verdicts cooperative | additionally enforces strict artifacts, actors, freshness, risk, and task closure; sandbox/exact-Candidate enforcement requires `local_validation` |

The strict tier no longer requires a full `local_validation` migration. A fresh
repository can adopt strict governance with its existing test command, then add
structured validation later if exact-Candidate receipts and containment
certification justify the additional setup.

## Manual-tier setup (the portable path) — verified end-to-end

1. **Init** (from the repo root):
   ```sh
   mpd init
   ```
   Scaffolds `openspec/`, `.mpd/config.json`, the persona directives, and
   installs a `.git/hooks/pre-commit` gate. The default config is lightweight —
   no `local_validation`, no sandbox.

2. **Set your test command** in `.mpd/config.json`:
   ```json
   { "test": "./run-tests.sh" }
   ```
   The test command must emit a recognizable pass count (libtest / pytest /
   jest / Swift-Testing / XCTest formats are parsed). `mpd doctor` confirms it:
   `test cmd sanity: ok`. `mpd check` runs the secret scan + test standalone.

3. **Drive a change** (manual tier):
   ```sh
   mpd begin <change-name> --chore --risk low   # or --fix, or plain for a feature
   mpd manifest                                  # then edit manifest.json to declare paths
   mpd next --harness claude-code --context      # per phase: read brief, do the work
   mpd gate <phase> --pass --by <actor> --evidence <artifact>
   # repeat next → work → gate until Done
   mpd archive --yes
   git commit
   ```

## Gotchas the pilot surfaced (put these in front of any agent)

- **Declare the manifest scope before Architecture.** A change with an empty
  `manifest.json` `paths` is refused at the Architecture gate
  (`no declared scope`). Run `mpd manifest` and fill `paths` with the globs the
  change touches (e.g. `src/**`, `openspec/changes/<name>/**`).
- **Author artifacts from the seeded template, not free-form.** Each judgment
  artifact requires specific `##` sections (e.g. `design.md` needs Actor,
  Context, Goals/Non-Goals, Decisions, Risks/Trade-offs, Conditions for
  Builder; a security artifact needs Actor + Verdict with the first non-blank
  verdict line exactly `PASS`/`CONDITIONAL PASS`/`FAIL`). A hand-written file
  missing a section is refused — Commando permits no artifact waivers. Start
  from `openspec/schemas/mpd/templates/` or the seeded stub.
- **Actor separation.** A gate's `--by` actor must differ from the adjacent
  upstream actor (and, per the review-subject rule, from the actor of the phase
  being reviewed). Reuse across non-adjacent phases (Designer at mock and
  sign-off) is fine.
- **Strict governance and structured validation are separate choices.**
  `mpd conduct` accepts the configured plain-shell test command when
  `local_validation` is absent. Build/Test still require a recognizable non-zero
  pass count and Security(code) still scans secrets, but the resulting gates do
  not carry a Candidate, structured validation receipt, containment
  certification, or typed Build output. Deploy likewise uses the legacy deploy
  command or records readiness without installed-artifact identity.
- **`--chore` still ran the Documentation phases in the pilot.** Budget for
  Documentation + Doc Validation even on a chore in the manual tier (or confirm
  your config's skip behavior first).

## When to invest in the strict tier

Reach for `local_validation` when you want the machine to validate an **exact,
offline, sandboxed candidate** — i.e. you accept the single-certified-host
constraint and want gate results that don't depend on the driving agent's
honesty for the build/test step. Strict governance itself remains useful without
that policy: it adds artifact, actor, freshness, risk, and task enforcement on
top of the portable secret-scan and real-test-count floor.

## Known rough edges (tracked, not blockers)

- `mpd publish --verify` verifies each landed change against its own landing
  commit; a legitimate later edit to a change's files (or a history rewrite,
  e.g. to clear a host's secret push-protection on a test fixture) leaves that
  change fail-closed-unverifiable with an accurate diagnosis — and when a landing
  commit carries out-of-scope paths, the failure now **names them** rather than
  reporting a bare "not coherent". An operator divergence-acknowledgment verb is
  deliberately not shipped.
- A *tracked* file modified outside the change's manifest scope refuses the strict
  Build/Security(code)/Test gates (declare it or `git stash` it); untracked files
  stay user-owned. This stops a change from silently shipping source the sandbox
  never validated.
- After an mpd upgrade that bumps the candidate schema, a candidate captured by the
  older binary refuses to reopen mid-drive; the remedy is one Build rewind to
  recapture. Old retained candidate roots are inert.
- Candidate-cache and rewound-binding stalls that affected earlier self-hosting
  are fixed as of the `candidate-lifecycle-defects` change.
- Proportionate governance (scope-aware risk) is landed but **opt-in** — a repo
  must configure `docs-build`/`docs-security-code`/`docs-test` gate profiles to
  get the lighter docs lane; otherwise every strict change runs full rigor.
