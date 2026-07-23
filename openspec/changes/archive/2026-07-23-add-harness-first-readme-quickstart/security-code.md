# Security (code) review: Harness-first README quickstart

## Actor

SecurityCode-Sol-70

## Findings

None. `README.md:8-43` is static Markdown and adds no executable, configuration, policy,
dependency, credential, external URL, or network behavior. The prompts assign routine MPD
operation to the model but explicitly retain genuine product decisions and unauthorized
external releases for the user.

## Conditions verified

1. The durable change is confined to `README.md`; other changed files are declared MPD
   process records.
2. The quickstart is after the value paragraph and before the existing owner/trust boundary.
3. `conduct` has no harness flag; Codex and Claude `next` commands use exact supported
   harness values.
4. The user supplies the outcome; the model owns phase calls, gates, tests, fixes, and
   status reporting.
5. Missing installation/configuration is a reported blocker, not implied success.
6. No bypass, force push, secret, authenticated-identity claim, automatic deployment, or
   release authority was introduced.

## Independent review

Security(code) separately inspected the real README diff after the Builder gate. Current
CLI help confirms `conduct` and the `next --harness` interface; placement/content checks,
doc staleness, and Build's typed Candidate profile passed. Cooperative actor labels remain
cooperative rather than authenticated.

## Refutation

The strongest objection is that “the model drives the workflow” grants unbounded agency.
The actual prompt narrows that claim: it operates existing MPD stages inside repository
instructions, stops for genuine product decisions, and requires external-release authority
the model does not already have. A missing MPD setup is surfaced as a blocker. The
unbounded-authority interpretation is therefore not supported by the shipped wording.

## Verdict

PASS
