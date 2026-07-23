# Security (plan) review: Fix maturity assessment links

## Actor

Security-Terra-60

## Threat model

The only boundary is documentation integrity. A malformed or external link could mislead a
reader or send them outside the reviewed repository. No untrusted parsing, credential,
network execution, privilege, persistence, or policy surface changes.

## Conditions for Builder

1. Modify only the declared documentation/OpenSpec paths.
2. Use repository-relative targets and verify the two files plus `#assessment` heading.
3. Keep all maturity claims and archived evidence unchanged outside the link lines.
4. Add no external URL, executable behavior, credential, configuration, or policy change.

Reviewed the design, proposal, manifest, current broken targets, and intended target
locations. Security(code) will inspect the exact diff and fresh secret scan.

## Verdict

PASS
