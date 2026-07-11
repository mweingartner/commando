# commando — `mpd`

**Model-Paired Development as a self-contained motion, over the OpenSpec format.**

`mpd` is a single Rust binary that natively speaks the [OpenSpec](https://github.com/Fission-AI/OpenSpec)
on-disk format and layers an adversarial-gate pipeline on top. It turns the
phases of a model-paired workflow — Architecture → Security → Build → Security →
Test → Deploy — into durable, machine-checkable state that outlives any single
session, and enforces the gates deterministically at `git commit`.

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
    harness        #   `next` adapters (generic / claude-code)
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

## Commands

```
mpd init [--test <cmd>]      # scaffold openspec/ + mpd schema + install the commit gate
mpd begin <name> [--ui]      # create a change and seed its pipeline ledger
mpd status [--json]          # current phase, gate verdicts, archive readiness
mpd next [--harness ...]     # emit the next persona's brief (generic | claude-code)
mpd gate <phase> --pass|--conditional|--fail [--evidence P] [--condition C]
mpd check [--staged]         # run secret scan (+ tests) now
mpd archive [--yes]          # dry-run preview, then fold specs into the record & archive
mpd doctor [--json]          # diagnose setup
```

## The gates are real, not self-reported

- **`mpd gate build|test --pass`** re-runs the configured test command itself and
  refuses PASS unless it exits zero **and** a non-zero pass count is observed —
  it cannot accept the caller's word.
- **`mpd gate security-code --pass`** refuses PASS on any secret finding.
- **`mpd archive`** refuses on any non-PASS gate or open condition, and previews
  what it will merge before doing it (dry-run unless `--yes`).
- The **git `pre-commit` hook** re-runs the checks independently, so enforcement
  holds even when a harness that ignores `mpd` drives the commit. Bypass one
  commit with `MPD_GATE_SKIP=1`.

External best-of-breed scanners (gitleaks, Semgrep) are used when present as
*additional* passes; a built-in scanner is the always-available floor, and the
ledger records which scanners actually backed each PASS. Degraded coverage is
reported by `mpd doctor`, never silently treated as clean.

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

| Phase | Persona | Model | Skipped when |
|---|---|---|---|
| Design Mock / Review / Sign-off | Designer | opus | no UI/UX surface |
| Architecture | Architect | opus | — |
| Security (plan / code) | Security | sonnet | — |
| Build | Builder | sonnet | — |
| Test | Tester | sonnet | — |
| Deploy | main session | — | — |

## Build & test

```
cargo test --workspace       # unit + fidelity + property/metamorphic + e2e
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p mpd  # the encased binary at target/release/mpd
```

## License

MIT.
