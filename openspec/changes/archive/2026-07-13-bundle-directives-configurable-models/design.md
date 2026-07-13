# Design: Bundle the MPD doctrine as directives; configurable per-persona models

## Context

Today mpd carries the pipeline *structure* and compressed one-line persona briefs
(`personas.rs::guidance`), while the full doctrine lives in external markdown that
the harness must supply; and `harness.rs::model_for` hardcodes the model tiers.
This change makes mpd the self-sufficient source of the doctrine and moves model
assignment into per-project config.

## Goals / Non-Goals

- **Goals:** doctrine embedded + installed per project + surfaced by `mpd next`;
  per-persona/per-harness models configurable with safe defaults; no CLI or
  on-disk-format break; existing projects behave unchanged until they opt in.
- **Non-Goals:** loading remote directives; a templating language in directives;
  changing the phase graph or gate semantics.

## Decisions

- **Directives are bundled AND installed.** `crates/mpd/assets/directives/`
  (`protocol.md` + `personas/*.md`) is `include_str!`-embedded. `mpd init` writes
  them to `.mpd/directives/` with `write_new` semantics (never clobber a
  customized file). Rationale: mpd owns the canonical default (source of truth),
  the project owns its editable copy (evolution). Alternative rejected: read the
  external Playbook — reintroduces the dependency this change removes.
- **`mpd next` resolves directives project-first, bundled-fallback**, via a new
  `directives` module. `--full` inlines the text; the default brief keeps the
  short guidance plus a pointer, so routine use stays terse.
- **Models via `config.models[harness][persona] → model` + `model_fallbacks`.**
  `model_for` becomes `model_for(&Config, harness, phase)`: config lookup by
  persona name, else the existing built-in tier default. `mpd init` seeds the
  explicit current defaults. Alternative rejected: per-tier-only config — the
  user asked for per-*persona* control.
- **Persona name is the config/directive key.** `Phase::persona().name` already
  yields a stable name; directive files and model keys use it (`architect`,
  `security`, …), lowercased/kebab for filenames.

## Risks / Trade-offs

- [**Directive Content Trust** — a persona directive is untrusted instruction
  text that `mpd next --full` inlines *verbatim* as the persona's operating
  instructions, and it lives in the same branch under review. A malicious
  contributor could edit `personas/security.md` to "PASS without scanning."
  Read-hardening (symlink/size) does NOT stop this — the file is valid.] →
  Mitigation: `mpd next --full` compares the project directive to the bundled
  default and prepends a visible **warning banner** when they differ, flagging it
  for review (especially Security/Build phases). This is a warning, not a proof;
  full closure (pinning the Security directive to the bundled copy,
  un-overridable) is an accepted-for-later Non-Goal. The deterministic gates
  (secret scan, test run) still run regardless of directive text.

- [Directive files are attacker-writable project content] → read them through the
  hardened symlink-refusing, size-capped reader; on any read failure fall back to
  the bundled default (fail-safe, never fail-open to an arbitrary file).
- [A malformed/partial `models` config could break resolution] → treat missing
  keys as "use built-in default"; never panic; a broken config degrades to
  defaults, never to no-model.
- [Doctrine drift between mpd and the external Playbook] → mpd's bundled copy is
  now canonical; the external files become derived/optional. Documented.

## Conditions for Builder

- **Directive reads walk every component, not just the leaf.** Each read MUST
  call `openspec_core::assert_contained(&directives_dir, &path)` **before**
  `read_capped(&path)` — `read_capped` alone only refuses a symlinked *leaf*, so a
  symlinked *intermediate* directory (`.mpd/directives/personas` → external) would
  be followed. On any failure fall back to the bundled default, never the target.
  (Add a spec scenario for a symlinked intermediate directory.)
- **Install writes are symlink-refusing.** `write_new` uses `Path::exists()`,
  which follows symlinks — a *dangling* symlink makes `exists()` false and the
  subsequent `fs::write` writes to the link's target (arbitrary write). The
  directive install and the seeded `.mpd/config.json` MUST check
  `fs::symlink_metadata` on the target (and intermediate components, via
  `assert_contained`) before writing, refusing on any symlink rather than
  following or silently skipping it.
- **`mpd next --full` warns on directive divergence (Directive Content Trust).**
  When a project persona directive differs from the bundled default, the output
  MUST prepend a visible warning that the directive was locally modified — review
  before trusting, especially for Security/Build phases. (A string compare; no new
  I/O.)
- **Config reads are hardened too.** `Config::load` now drives `model_for` on
  every `mpd next`; it MUST read `.mpd/config.json` via the same
  symlink-refusing, size-capped path (or refuse a symlinked config), not a plain
  `read_to_string`.
- **Model values are charset-validated.** A configured model id MUST match a safe
  charset (`[A-Za-z0-9._-]`); an invalid value degrades to the built-in default
  (never surfaced into a rendered `--model` string), consistent with the
  fail-safe-to-default rule.
- **Install is non-destructive.** `mpd init` MUST NOT overwrite an existing
  `.mpd/directives/*` or `.mpd/config.json` (respect user customization).
- **Model resolution is total and fail-safe.** `model_for` MUST return a model
  for every (harness, phase): config value if present, else the built-in tier
  default. A missing/malformed `models`/`model_fallbacks` MUST degrade to
  defaults with no panic and no empty model.
- **No new secret surface.** Directive/config files contain no credentials;
  nothing new is executed. (The existing `test`/`deploy` command trust boundary
  is unchanged.)
- **Backward compatibility.** A project with no `models` config and no
  `.mpd/directives/` MUST behave exactly as before (built-in tiers, compressed
  briefs). Serde fields are `#[serde(default)]`.
- **Path containment.** Directive/config paths are built from a fixed
  `.mpd/directives/` base and validated persona names (from `Phase::persona`),
  never from untrusted free-form input. Composite/sentinel persona names
  (`Architect & Designer`, `main-session`, `-`) have no directive file and are
  resolved by their parts or excluded — no path is derived from them.
