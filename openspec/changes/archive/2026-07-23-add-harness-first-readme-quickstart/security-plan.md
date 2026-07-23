# Security (plan) review: Harness-first README quickstart

## Actor

Security-Sol-69

## Threat model

The change is static documentation, but its copy-ready prompts influence model authority.
A prompt could accidentally authorize external deployment, hook bypass, credential use,
or silent continuation through a real product decision. The user controls the desired
outcome; the model operates only within repository instructions and existing authority.
No new parser, network, credential, execution, configuration, or policy surface is added.

## Conditions for Builder

1. Change only declared documentation/OpenSpec paths.
2. Assign routine MPD operation to the model, but retain user authority for genuine product
   decisions and external release/deployment where repository instructions do not already
   authorize it.
3. Name exact supported harness commands and do not suggest bypass flags, force push,
   credentials, automatic installation, or unauthenticated provenance.
4. If MPD is missing or the repository is not configured, tell the model to report the
   blocker and setup action rather than pretending the workflow ran.
5. Preserve the README's existing owner/trust boundary and manual flow.
6. Verify the actual diff, command help, target anchor, secret scan, and exact Candidate.

Reviewed the Design Mock, architecture, requested placement, and current README command
surface. The plan contains no blocking security gap. Security(code) must inspect the exact
prompt wording after Build.

## Verdict

PASS
