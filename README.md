# commando — `mpd`

**Model-Paired Development as a self-contained motion, over the OpenSpec format.**

`mpd` is a single Rust binary that natively speaks the [OpenSpec](https://github.com/Fission-AI/OpenSpec)
on-disk format and layers an adversarial-gate pipeline on top. It turns the
phases of a model-paired workflow — Architecture → Security → Build → Security →
Test → Documentation → Deploy → Doc Validation — into durable, machine-checkable
state that outlives any single session, and enforces the gates deterministically
at `git commit`.

It has **no runtime dependencies**: no Node, no OpenSpec CLI. The macOS/Linux
binary links only against the system C library.

```
$ otool -L target/release/mpd
    /usr/lib/libSystem.B.dylib
```

## Why this exists

Two ideas, composed:

- **OpenSpec** keeps AI honest with a durable, machine-readable *spec* — change
  folders with ADDED/MODIFIED/REMOVED deltas and GIVEN/WHEN/THEN scenarios that
  survive session death.
- **Model-Paired Development** keeps AI honest with a sequence of *adversarial
  personas* (Architect ≠ Security ≠ Tester, each on its own model) gating each
  other, backed by deterministic tooling.

`mpd` is the connective tissue: the OpenSpec artifacts become the contract the
personas verify against, and the personas' verdicts become durable gate state
the next session (or agent, or human) can read.

## The design decision that matters

`mpd` does **not** shell out to the Node OpenSpec CLI — that would reintroduce
the dependency it exists to remove. Instead it treats the OpenSpec **on-disk
format as the integration contract** and implements a native engine
(`openspec-core`) that reads and writes the same files. Directories written by
`mpd` remain readable by the reference OpenSpec implementation and vice versa —
**format compatibility with zero runtime coupling**.

## Architecture

A Cargo workspace of two crates:

```
crates/
  openspec-core/   # the format engine — the ONLY code that knows the on-disk layout
    model          #   Spec, Requirement, Scenario, Delta{Added,Modified,Removed,Renamed}
    parse          #   fence-aware markdown → model
    render         #   model → canonical markdown (idempotent form)
    merge          #   apply deltas → spec (RENAMED→REMOVED→MODIFIED→ADDED)
    validate       #   structural + convention checks
    schema         #   schema.yaml / .openspec.yaml
    project        #   filesystem layout, discovery, status, archive
  mpd/             # the overlay + CLI
    phase          #   the pipeline state machine (pure)
    ledger         #   durable gate verdicts + evidence  (.mpd/state/<change>.json)
    checks         #   secret scan + test-count verification
    personas       #   per-phase briefs + model assignments
    harness        #   `next` adapters (generic / claude-code / codex) + model policy
    githooks       #   the pre-commit enforcement floor
    scaffold       #   init / begin
```

The boundary is an **anticorruption layer**: `mpd` talks to the format only
through `openspec-core`'s typed API, never raw markdown. If the OpenSpec format
evolves, the change is contained to one crate.

## The parser

The one non-trivial algorithm is the fence-aware parser. Real spec bodies embed
structural markers as *examples* inside code fences:

````markdown
#### Scenario: Handling requirement renames
- **THEN** use a special `## RENAMED Requirements` section
  ```markdown
  ## RENAMED Requirements
  - FROM: `### Requirement: Old Name`
  - TO: `### Requirement: New Name`
  ```
````

A naive parser miscounts those as real structure. `mpd`'s parser treats a
`#`-prefixed line as a heading only at column 0 and outside a code fence, so the
example above is preserved verbatim as body text. This is verified against the
real OpenSpec fixtures and a fence-torture case.

## Quickstart

```bash
# 1. Install (from a clone of this repo)
cargo install --path crates/mpd          # → ~/.cargo/bin/mpd  (put it on PATH)

# 2. Initialize a project (from its repo root)
cd ~/my/project
mpd init --test "cargo test"             # scaffolds openspec/, installs the commit gate
# optionally set a deploy command:
#   edit .mpd/config.json → {"test": "...", "deploy": "scripts/deploy.sh"}

# 3. Start a change and let mpd drive
mpd begin add-rate-limiter               # a feature (documented). --fix/--chore skip docs.
mpd next --harness claude-code           # prints the phase's persona, model, task, gate cmd
#   … do the work the brief describes …
mpd gate architecture --pass --evidence design.md#conditions

# 4. Walk the loop: next → work → gate, until archive-ready
mpd status                               # where am I? what's blocking archive?
mpd gate build --pass                    # re-runs `cargo test`; refuses without a real pass
# …security-code, test, documentation, deploy, doc-validation…
mpd resolve --all                        # close any CONDITIONAL-PASS conditions
mpd archive                              # dry-run preview of the spec + doc merge
mpd archive --yes                        # apply: fold specs → openspec/specs/, doc → docs/
```

The **motion** is always the same three beats — `mpd next` → do the work → `mpd
gate <phase>` — so a human, Claude Code, or Codex all drive it identically.
`mpd next` tells each what to do and which model to use.

## Commands

```
mpd init [--test <cmd>]              # scaffold openspec/ + mpd schema + install the commit gate
mpd begin <name> [--ui] [--fix|--chore]   # new change (--ui adds design phases; --fix/--chore skip docs)
mpd status [--change N] [--json]    # current phase, gate verdicts, tasks, archive readiness
mpd next [--harness ...] [--json]   # emit the next persona's brief (generic | claude-code | codex)
mpd gate <phase> --pass|--conditional|--fail [--evidence P] [--condition C]
mpd resolve <n> | --all             # close open CONDITIONAL-PASS conditions (they block archive)
mpd check [--staged]                # run the secret scan now (+ external scanners/tests unless --staged)
mpd archive [--yes] [--skip-specs]  # dry-run preview, then fold specs + docs into the record & archive
mpd doctor [--json]                 # diagnose setup (schema, hook, scanners, test/deploy cmd, allowlist)
```

`--fix` (defect) and `--chore` (refactor/tooling/perf) mark non-functional
changes: they skip the two Documentation phases. `--ui` adds the three Design
phases. Neither flag bypasses a gate — they only change *which optional phases
apply*.

## The gates are real, not self-reported

- **`mpd gate build|test --pass`** re-runs the configured test command itself and
  refuses PASS unless it exits zero **and** a non-zero pass count is observed —
  it cannot accept the caller's word.
- **`mpd gate security-code --pass`** refuses PASS on any secret finding.
- **`mpd gate documentation --pass`** refuses PASS unless `documentation.md`
  exists and covers every required section (Purpose/Value/Scope/Functional/Usage)
  with no unfilled placeholders — an empty stub can't pass.
- **`mpd gate deploy --pass`** runs the configured `deploy` command (when set)
  and refuses PASS if it exits non-zero, so deploy is a machine-enforced step
  rather than a checkbox.
- **`mpd archive`** refuses on any non-PASS gate or open condition, and previews
  what it will merge before doing it (dry-run unless `--yes`).
- The **git `pre-commit` hook** re-runs the checks independently, so enforcement
  holds even when a harness that ignores `mpd` drives the commit. Bypass one
  commit with `MPD_GATE_SKIP=1`.

External best-of-breed scanners (gitleaks, Semgrep) are used when present as
*additional* passes; a built-in scanner is the always-available floor, and the
ledger records which scanners actually backed each PASS. Degraded coverage is
reported by `mpd doctor`, never silently treated as clean.

### Secret allowlist

Real repos have intentional fixture secrets (fake API keys in tests). To
acknowledge them without weakening the gate, add `.mpd/secret-allowlist.json`:

```json
{
  "paths": ["Tests/**", "scripts/fixtures/**"],
  "allow": [
    { "path": "Sources/AI/Context.swift", "rule": "private-key-block", "line": 324 }
  ]
}
```

`paths` are repo-relative globs (`*` within a segment, `**` across segments);
`allow` entries narrow by `rule` and/or `line`. Two guarantees: suppressions are
**always counted and reported** (never silent), and a missing or malformed
allowlist suppresses **nothing** (fail-closed). The file is version-controlled
trust — committing an entry is a reviewable statement that a finding is a
verified false positive. When gitleaks is the active scanner it honors its own
`.gitleaksignore` independently.

## Trust boundaries

- **`.mpd/config.json` is executable trust.** Its `test` value is run via
  `sh -c` by the Build/Test gates and the pre-commit hook. Because `.mpd/` is
  version-controlled (it is the durable spec-of-record), **merging a change that
  edits `.mpd/config.json` is equivalent to granting arbitrary code execution**
  on the next gate run — treat it like a `Makefile` or `package.json` script in
  review.
- **The engine refuses to follow symlinks out of `openspec/`.** Reads and the
  archive merge validate that every path component stays within the tree and is
  not a symlink, so a committed symlink cannot redirect a spec write to
  `~/.ssh/authorized_keys` or read an arbitrary file.
- **Change and capability names are validated at every use**, not just at
  creation — a tampered `.mpd/current` or a `--change ../../x` flag is rejected
  before it becomes a path.
- **Network egress:** when Semgrep is installed, the security-code gate runs it
  with `--config auto`, which fetches its ruleset from Semgrep's registry over
  the network. Absent Semgrep, no egress occurs; the built-in scanner is fully
  offline.

## Phase → persona → model

The persona (role) is fixed; the **model is harness-specific**. The
judgment/creative planning and validation phases — **Design, Architecture, and
Doc Validation** — are the deep-cognition tier; the execution/synthesis/review
phases are standard. `mpd next --harness <h>` resolves the concrete model:

| Phase | Persona | Tier | Claude Code | Codex |
|---|---|---|---|---|
| **Design Mock / Review / Sign-off**¹ | Designer | **deep** | **Fable** (→ Opus if unavailable) | **Sol** |
| **Architecture** | Architect | **deep** | **Fable** (→ Opus if unavailable) | **Sol** |
| Security (plan / code) | Security | standard | Sonnet | Terra |
| Build | Builder | standard | Sonnet | Terra |
| Test | Tester | standard | Sonnet | Terra |
| Documentation² | Documenter | standard | Sonnet | Terra |
| Deploy | main session | — | — | — |
| **Doc Validation**² | Architect & Designer | **deep** | **Fable** (→ Opus if unavailable) | **Sol** |

¹ Design phases run only for `--ui` changes. ² Documentation phases run only for
feature changes (a `--fix` or `--chore` skips them). The Documenter *synthesizes*
the doc cheaply; the Architect + Designer *validate* it (both spawned) at the
deep tier. Codex tiers are GPT-5.6 Sol / Terra / Luna (deepest → lightest); Luna
is unassigned by default. The `generic` harness reports the *tier*
(`deep-cognition` / `standard`) rather than a concrete model.

## Documentation

Feature changes carry documentation through the pipeline as first-class,
gated work:

- **Documentation** (after Test) — the **Documenter** (cheap, standard tier)
  *passively synthesizes* a durable doc from everything the prior phases
  produced (proposal, design + Conditions for Builder, spec scenarios, security
  findings, tasks, test results) covering **Purpose · Value · Scope · Functional
  details · Usage**. Its gate is a **deterministic structural check** — the doc
  must exist and cover every section with no unfilled placeholders — so an empty
  stub can't pass.
- **Doc Validation** (after Deploy) — the **Architect** (functional/scope
  accuracy) and **Designer** (purpose/value/representation) *both* validate the
  doc against what shipped, at the deep tier. A FAIL sends it back to the
  Documenter to revise.

At archive, the doc folds into a project subdirectory (default `docs/<name>.md`,
configurable via `docs_dir`). Defect fixes (`--fix`) and non-functional chores
(`--chore`) skip both phases — only changes that alter functional behavior are
documented.

## Driving it from an agent harness

`mpd` is harness-agnostic. To make the motion automatic, add a short block to
the file your agent reads — `AGENTS.md` (Codex, and the emerging standard) or
`CLAUDE.md` (Claude Code) — telling it to drive changes through mpd:

> For any non-trivial change: `mpd begin`, then loop `mpd next --harness <h>` → do
> exactly what the brief says → `mpd gate <phase> --pass|--fail`, until
> `mpd archive`. Author the OpenSpec artifacts under `openspec/changes/<name>/`
> when a phase calls for them. Never bypass a FAIL gate or commit around the
> pre-commit hook.

`mpd next` then supplies each phase's persona, model, task, and gate command.
Claude Code spawns each persona as a subagent on the model mpd names; Codex
(single-agent) adopts each persona in turn, or runs a fresh `codex --model <t>`
per phase. The git pre-commit hook enforces the secret gate regardless of which
harness — or human — drives the commit, so the guarantee holds even for a
harness that ignores mpd entirely.

## Build & test

```
cargo test --workspace       # unit + fidelity + property/metamorphic + e2e
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p mpd  # the encased binary at target/release/mpd
```

## License

MIT.
