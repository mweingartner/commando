# mpd adoption quickstart

How to adopt mpd in another repository, based on a fresh-repo pilot run
(`mpd init` → conduct/begin → gates → archive on a scratch project with a plain
test command). It records what actually works today, including the honest
boundary between the two tiers.

## TL;DR — pick your tier

mpd has two tiers, and the choice determines how much setup you need:

| | **Manual tier** (`mpd begin`) | **Strict tier** (`mpd conduct`) |
|---|---|---|
| Setup on a fresh repo | `mpd init` + set `test` in `.mpd/config.json` | the above **plus** a full `local_validation` policy + activated coordinator + platform sandbox |
| Build/Test gate | runs your configured test command via the shell, checks a real non-zero pass count, secret-scans | materializes an exact **candidate** and runs the whole profile inside a **certified-host sandbox** |
| Portability | any repo, any OS | currently certified on **one macOS/Apple-silicon host** via a deprecated Seatbelt path |
| Gate enforcement | machine-checked secret scan + test count; persona verdicts cooperative | additionally machine-enforced sandbox validation against the exact candidate |

**For adopting mpd on your other repos today, use the manual tier.** The strict
tier is what Commando itself runs, and its heavyweight sandbox is single-host
certified — not something a general repo can turn on without the full
`local_validation` migration.

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
- **The strict tier will refuse your plain test command.** `mpd conduct` starts
  the strict tier, whose objective Build gate reports
  `strict objective gate requires local_validation migration; legacy
  test/deploy strings are manual-only`. That is expected — the plain-shell test
  path is a manual-tier feature. Use `mpd begin` unless you are prepared to
  configure the full `local_validation` policy.
- **`--chore` still ran the Documentation phases in the pilot.** Budget for
  Documentation + Doc Validation even on a chore in the manual tier (or confirm
  your config's skip behavior first).

## When to invest in the strict tier

Reach for `mpd conduct` + `local_validation` only when you want the machine to
validate an **exact, offline, sandboxed candidate** — i.e. you accept the
single-certified-host constraint and want gate results that don't depend on the
driving agent's honesty for the build/test step. For everything else, the
manual tier gives you the same phase discipline, the secret-scan floor, and a
real test-count check, on any repo and any OS.

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
