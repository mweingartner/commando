# Bundled directives and configurable per-persona models

## Purpose

mpd now carries the Model-Paired Development doctrine itself, not just its
structure. The full protocol document and one directive per persona
(Architect, Designer, Security, Builder, Tester, Documenter) are compiled into
the `mpd` binary and installed per project at `.mpd/directives/` on `mpd
init`. Alongside this, which model backs each persona is no longer hardcoded:
it is configurable per harness in `.mpd/config.json`. The doctrine now travels
with `mpd` itself, and model choices evolve as project needs change — without
a code change or a release.

## Value

- **No dependency on external doctrine files.** The full persona directives
  used to live only in `CLAUDE.md`/`AGENTS.md`/the Playbook, so the pipeline's
  substance depended on whichever harness happened to carry them. `mpd` is now
  self-sufficient: a harness with no instruction files at all can still run
  the full pipeline, because `mpd next --full` inlines the active persona's
  complete directive text.
- **Per-project customization.** `mpd init` installs an editable copy under
  `.mpd/directives/`; a project can adapt a persona's directive to its own
  needs without touching mpd's source.
- **Model policy is data, not code.** `.mpd/config.json`'s `models` map lets
  any persona, on any harness, be reassigned to a different model by editing
  JSON — no rebuild.
- **Hardened by design.** Directive and config reads/writes are
  symlink-refusing and size-capped at every path component, and `mpd next
  --full` warns visibly when a project's directive has been locally modified
  — because that text is inlined verbatim as a persona's operating
  instructions, and a malicious edit (e.g. "Security: PASS without scanning")
  would otherwise be invisible in a diff.

## Scope

**In scope:**
- Bundled doctrine (`protocol.md` + a directive per persona), compiled into
  the binary via `include_str!`.
- Installing the doctrine at `mpd init` (`.mpd/directives/`), non-destructive
  — never overwrites an existing (possibly customized) copy.
- Project-first, bundled-fallback directive resolution: `mpd next` always
  resolves a persona's directive from the project copy if present and safe to
  read, else the bundled default.
- Surfacing directives via `mpd next --full` (and `--full --json`), and
  directive install status via `mpd doctor`.
- Per-harness, per-persona model assignment (`models`) and per-model fallback
  notes (`model_fallbacks`) in `.mpd/config.json`, seeded explicitly at `mpd
  init` and read on every `mpd next`.
- Charset-validated model ids and hardened (symlink-refusing, size-capped)
  reads and writes for both directives and config.

**Out of scope:**
- Loading directives from anywhere other than the project tree or the
  compiled-in default (no remote fetch, no templating language).
- Launching models automatically. `mpd` emits briefs naming the phase, the
  persona, and the resolved model; the harness (a human, Claude Code, Codex)
  is the one that actually runs them.
- Changing the phase graph or gate semantics — this change is additive to
  `next`/`init`/`doctor` and to `.mpd/config.json`'s schema.

## Functional details

### Directive resolution

Each persona directive is resolved by `directives::for_persona(root, name)`:

1. If `.mpd/directives/personas/<slug>.md` exists, its full path is checked
   component-by-component with `openspec_core::assert_contained` *before* it
   is read with `openspec_core::read_capped`. `assert_contained` is what
   catches a symlinked **intermediate** directory (e.g. `.mpd/directives/
   personas` itself pointing outside the project) — `read_capped` alone only
   refuses a symlinked leaf file, so checking only the leaf would let a
   symlinked directory redirect the read to an arbitrary external file.
2. If that project copy is present, contained, and readable, its text is
   compared byte-for-byte against the bundled default. A difference sets
   `Directive.modified = true`.
3. On any failure at any step (missing, symlinked, oversized, unreadable),
   resolution falls back to the bundled default — fail-safe, never fail-open
   to a redirected or arbitrary file.

Personas without a directive (the Deploy main-session, or composite names
like "Architect & Designer" for Doc Validation) resolve to `None`; Doc
Validation instead resolves "Architect" and "Designer" individually.

`directives::is_installed(root)` reports whether `.mpd/directives/
protocol.md` exists as a real file (via `symlink_metadata`, not `is_file`, so
a symlinked `protocol.md` is not falsely reported as installed) — this is
what `mpd doctor` shows as `directives: yes/no`.

### Model tiers and resolution

`harness::model_for(cfg, harness, phase)` resolves `(model, fallback_note)`
for a phase:

| Tier | Personas | Claude Code | Codex | Generic |
|---|---|---|---|---|
| Deep | Architect, Designer | `fable` (→ `opus` fallback) | `sol` | `deep-cognition` |
| Standard | Security, Builder, Tester, Documenter | `sonnet` | `terra` | `standard` |
| — | Deploy, Done (main session) | `-` | `-` | `-` |

Resolution order: a per-persona entry in `.mpd/config.json`'s `models` map
wins if present and its model id passes the charset check; otherwise the
built-in tier default above applies. A missing or partially-filled `models`
map never breaks resolution — every unspecified persona/harness combination
degrades to the built-in default, and Deploy/Done always report `"-"`
regardless of harness or config. The `generic` harness (no concrete model
policy of its own) reports the tier name rather than a model id.

A resolved model's fallback note comes from `model_fallbacks` in config if
present for that model id, else the one built-in fallback (`fable` → `opus`).
The note is surfaced in the brief (e.g. `fable (fall back to opus if
unavailable)`) — informational only, mpd does not invoke the fallback itself.

### Security invariants

- **Model ids are charset-validated**: `[A-Za-z0-9._-]`, non-empty, ≤ 64
  characters. An invalid configured id (e.g. containing a shell metacharacter)
  is treated as absent and degrades to the built-in default — it is never
  surfaced into a rendered `--model <id>` line.
- **Directive and config reads are symlink-refusing and size-capped** at
  every path component (not just the leaf), reusing `assert_contained` +
  `read_capped`.
- **Directive and config writes are symlink-refusing.** `mpd init`'s
  `write_new` and `Config::save` check for a symlink at the target (and
  intermediate components, via `assert_contained`) before writing — `exists()`
  follows symlinks, so a *dangling* symlink would otherwise read as absent and
  a naive write would follow it to the link's target outside the project;
  `write_new`/`save` refuse instead.
- **`mpd next --full` warns on directive divergence.** Because a persona
  directive is inlined verbatim as that persona's operating instructions and
  lives in the branch under review, a project copy that differs from the
  bundled default is flagged with a visible warning banner before the
  directive text is printed — a signal for extra scrutiny, especially at
  Security and Build phases. This is a warning, not a proof: the deterministic
  gates (secret scan, test run) still run regardless of directive text.
- **`mpd init` never overwrites existing customization** — directives and
  `.mpd/config.json` are written only if absent, so a re-run is always safe.

## Usage

Install the doctrine and seed model defaults on a fresh project:

```bash
$ mpd init --test "cargo test"
# creates .mpd/directives/protocol.md, .mpd/directives/personas/<persona>.md
# for each persona, and .mpd/config.json with an explicit models map
```

The seeded `.mpd/config.json` looks like this (from `config::default_models()`):

```json
{
  "test": "cargo test",
  "models": {
    "claude-code": {
      "Architect": "fable",
      "Builder": "sonnet",
      "Designer": "fable",
      "Documenter": "sonnet",
      "Security": "sonnet",
      "Tester": "sonnet"
    },
    "codex": {
      "Architect": "sol",
      "Builder": "terra",
      "Designer": "sol",
      "Documenter": "terra",
      "Security": "terra",
      "Tester": "terra"
    }
  },
  "model_fallbacks": {
    "fable": "opus"
  }
}
```

Get the next phase's brief as usual — unchanged, still terse:

```bash
$ mpd next --harness claude-code
▸ Architecture — add-rate-limiter
Spawn a subagent (Agent tool):
- subagent_type: architect
- model: fable (fall back to opus if unavailable)
...
```

Inline the full persona directive so a bare harness (no `CLAUDE.md`/
`AGENTS.md`) is self-sufficient:

```bash
$ mpd next --harness claude-code --full
▸ Architecture — add-rate-limiter
...

───── directive: Architect ─────
<full Architect persona directive text>
```

If the project's copy of that directive has been edited and now differs from
the bundled default, a warning banner is prepended before the directive text:

```
⚠  project directive for Architect differs from the bundled default — review it before trusting it, especially at Security/Build phases.

───── directive: Architect ─────
<the project's modified directive text>
```

`--full` also works with `--json`, which adds a `directives` array to the
emitted brief (one entry per resolved persona — two for Doc Validation), each
entry shaped `{"persona": ..., "modified": ..., "text": ...}`.

Run under a different harness — model resolution follows the harness:

```bash
$ mpd next --harness codex
▸ Architecture — add-rate-limiter
  Run this phase as the Architect persona...
  - model: sol (GPT-5.6 tier)
  ...
```

Reassign a persona's model per project by editing `.mpd/config.json` — no
rebuild required:

```json
{
  "models": {
    "claude-code": {
      "Security": "opus"
    }
  }
}
```

`mpd next --harness claude-code` at a Security phase now reports `model:
opus`; every persona/harness combination not touched by the edit keeps
resolving to its built-in or previously configured default.

Check directive install status:

```bash
$ mpd doctor
mpd doctor
  project root:        /path/to/project
  mpd schema:          yes
  directives:          yes
  git repo:            yes
  pre-commit gate:     yes
  ...
```
