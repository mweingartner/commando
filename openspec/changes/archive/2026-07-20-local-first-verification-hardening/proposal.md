# Local-First Verification Hardening

## Why

Commando already preserves durable phase and publication evidence, but the inherited
implementation split validation authority across hosted automation, permissive hooks,
duplicated test commands, commit-only receipts, and state transitions that could become
stale without an automatic rewind. An earlier attempt to close those gaps expanded into
a self-hosting pretrust proof system before it compiled. That design is superseded.

This change delivers a bounded production kernel for a cooperative repository owner on
the currently certified Apple-silicon macOS host. It makes local validation and local Git
hooks authoritative for the supported workflow without claiming that hooks defeat an
owner who deliberately bypasses or replaces them.

## Outcomes

- Remove GitHub Actions as validation authority. Remote hosting remains a transfer and
  parity target only.
- Enforce the phase order `Design Mock? -> Architecture -> Design Review? ->
  Security(plan) -> Build -> Security(code) -> Design Sign-off? -> Test ->
  Documentation -> Doc Validation -> Deploy`. Only the three Design phases can be N/A,
  and only with a stored rationale.
- Derive effective risk as the maximum of the requested risk and a versioned,
  conservative classifier over declared scope and execution-bearing configuration.
- Detect stale gate inputs on every MPD observation. Read-only status reports stored and
  effective truth; mutating commands append a rewind before any other effect and stop.
- Capture one deterministic worktree candidate from base HEAD plus the declared staged,
  unstaged, untracked, deleted, and mode-change overlay. Build, Security(code), and Test
  review that same candidate without changing the user's index, refs, object database,
  or worktree.
- Keep worktree-candidate, archived commit, push authorization, transfer, remote parity,
  and installed bytes as separate subjects and separate evidence facts.
- Run typed local profiles with pinned tools, offline inputs, a cleared environment,
  mandatory current-host network denial, bounded output/time/process/filesystem use,
  and fail-closed cleanup.
- Activate tracked local hooks only through an explicit, digest-confirmed cooperative
  owner command bound to an absolute reviewed coordinator. There is no pretrust,
  first-adoption, self-hosting, or silent bootstrap path.
- Make pre-commit scan staged postimages and governance artifacts. Make pre-push validate
  policy and refs for every batch, scan all outgoing blobs and commit/tag messages, and
  bind one-use authorization to the exact remote, baseline, update rows, and object set.
- Bind Deploy to the Build candidate and its parent-observed artifact bytes. Installation
  is an atomic exact copy and never rebuilds or executes the installed candidate to
  establish identity.
- Require Documentation and Doc Validation for every change kind, verify documented
  paths/flags/commands against the built binary, and report local/archived/committed/
  pushed/parity/installed truth separately.

## Trust Boundary

The supported threat model covers accidental mistakes, stale evidence, candidate input,
unsafe path/object forms, incomplete local checks, ambient configuration, network egress,
resource exhaustion, hook drift, outgoing secret transfer, and interrupted local state
changes. Role/model/session separation is cooperative metadata rather than authenticated
identity. A repository owner can use `--no-verify`, replace local binaries, rewrite refs,
or discard clone-private evidence; MPD detects and reports those conditions when it is
invoked but does not claim to prevent an owner from controlling their machine.

The certification target for this change is the current Apple-silicon macOS host recorded
by the local policy. Other platform identities are explicitly NOT CERTIFIED until their
own empirical sandbox, tool, lifecycle, and adversarial evidence exists.

## Delivery Boundary

Implementation, gate evidence, archive closure, commit, push authorization, successful
transfer, remote parity, and installed-byte verification remain distinct. The final
authorized delivery is a normal non-force Git push after the local hook gate passes,
followed by `mpd publish --verify` and parent-observed installed-byte verification. No
GitHub workflow result is required or accepted as validation evidence.

## Supersession

Historical architecture/security sidecars from the abandoned self-hosting design were
removed from the active change. Their FAIL/retry provenance remains in the append-only
ledger. `design.md`, `design-mock.md`, `design-review.md`, `security-plan.md`, and
`tasks.md` are the only pre-Build authorities for this implementation.
