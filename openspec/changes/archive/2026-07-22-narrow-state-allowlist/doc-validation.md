# Doc validation

## Actor
Architect (claude-code harness). Designer lens N/A — config/security change, no UI.

## Architect lens
Validated documentation.md against the shipped `.mpd/secret-allowlist.json` and the
`Allowlist::is_allowed` logic: the narrowed `{path:".mpd/state/**",
rule:"generic-secret-assignment"}` entry suppresses only the generic rule; curated
rules fire on the ledger (empirically confirmed — a planted PAT-shape caught as
github-token); archive/** unchanged; config-only, no coordinator rebuild. Accurate,
no overclaim (does not claim archive/** was narrowed or the generic residual is
gone); scanner-clean (no literal token embedded).

## Designer lens
N/A — no UI/UX surface.

## Verdict
PASS — accurate against shipped behavior.
