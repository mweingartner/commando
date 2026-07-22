# Doc validation

## Actor
Architect (claude-code harness). Designer lens N/A — CLI naming change, no UI.

## Architect lens
Validated documentation.md against the shipped cli.rs: `--close` primary + `--abandon`
alias; `mpd closure close` + `abandon` alias; message "Closed the pending closure…";
JSON key `"closed"`; `→ next` hint `mpd archive --close --yes`; behavior/internal fns
unchanged (alias-parity tests confirm). Accurate; no overclaim (correctly says the
alias still works and behavior is unchanged); scanner-clean.

## Designer lens
N/A — no UI/UX surface.

## Verdict
PASS — accurate against shipped behavior.
