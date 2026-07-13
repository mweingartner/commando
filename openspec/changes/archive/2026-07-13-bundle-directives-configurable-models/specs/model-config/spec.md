## ADDED Requirements

### Requirement: Configurable per-persona models
The model that backs each persona SHALL be configurable per harness in
`.mpd/config.json` under `models`, so model assignments can evolve without a code
change.

#### Scenario: Config assigns a persona's model
- **WHEN** `.mpd/config.json` sets `models.claude-code.Architect` to `"fable"`
- **THEN** `mpd next --harness claude-code --json` at the Architecture phase SHALL
  report `"model": "fable"`

#### Scenario: Unspecified persona uses the built-in tier default
- **WHEN** a persona or harness has no entry in `models`
- **THEN** `mpd next` SHALL resolve the model from the built-in tier default
  (deep → Fable/Sol, standard → Sonnet/Terra), so an absent or partial config
  never breaks resolution

### Requirement: Model fallbacks
A resolved model MAY declare a fallback via `model_fallbacks`, surfaced as a note
so a harness knows the alternative when the primary is unavailable.

#### Scenario: Fallback note is surfaced
- **WHEN** `model_fallbacks` maps `"fable"` to `"opus"` and a phase resolves to
  `"fable"`
- **THEN** the brief SHALL note that it falls back to `opus`

### Requirement: Seed default models at init
`mpd init` SHALL seed `models` with the current explicit per-persona defaults for
the known harnesses, so the mapping is visible and editable rather than hidden in
code.

#### Scenario: Init writes an explicit models map
- **WHEN** `mpd init` creates `.mpd/config.json`
- **THEN** it SHALL contain a `models` entry for `claude-code` and `codex` with a
  model for each persona, and a `model_fallbacks` entry for `fable`
