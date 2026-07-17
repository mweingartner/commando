# Security (plan): promote-to-strict

Governance: risk **low**, threat profile **local-trusted-user**.

## Threat model

The actor is the operator/harness on their own repo. `mpd strict <change>` reads
and writes only the change's own ledger (`.mpd/state/<change>.json`), a tool-owned
tracked file, and flips one boolean from false to true. There is no untrusted
input, no network, no filesystem I/O on user content, no credential handling. The
only meaningful properties are: (1) it cannot become a rigor *downgrade*
(strict→false), and (2) it cannot be tricked into writing or creating state for a
non-existent/invalid change. Both are handled by mirroring `mpd use`'s
name-validation + ledger-existence check and by mutating strictness only through
the monotonic `set_strict()` helper. The change name reaches only
`validate_change_name` and `ledger::state_path`, both existing, hardened paths.

## Conditions for Builder

The five Conditions for Builder in `design.md#conditions-for-builder` are the
normative closing evidence — chiefly Cond 1 (validate name + confirm ledger exists
before any write), Cond 2 (mutate only via `set_strict`, never `strict=false`),
Cond 3 (idempotent no-op when already strict), and Cond 5 (touches only the
change's own ledger). Security (code) will confirm on the real implementation that
no direct `strict =` assignment and no other file write exists in the new command.

## Verdict

**PASS.** No blocking threat within (or crossing into) the declared profile; the
verb is a monotonic, single-file, validated ledger flip with no untrusted input.
The write-once invariant is already pinned by the `self-enforcing-pipeline`
monotonicity test and cannot be regressed by a command that only calls
`set_strict`.
