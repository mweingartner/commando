# Commando Security Model

## Scope and trust boundary

MPD protects a cooperative local workflow from accidental stale review, wrong-subject
validation, malformed Git input, secret publication, unbounded child execution, and
false delivery claims. It does not resist the repository owner, who can replace MPD,
edit Git/private state, forge local records, or use `--no-verify`. Reviewer/actor labels
are cooperative provenance unless an external harness authenticates them.

GitHub Actions and other hosted systems are outside the validation authority. Normal
Git is the only transport authority. MPD never fetches or pushes as part of gate or hook
authorization.

## Protected assets

- written intent, canonical artifacts, task/condition closure, and append-only history;
- exact Candidate path/state/mode/byte identity and closure equivalence;
- policy, coordinator, hook, tool, advisory, Cargo, sandbox, and canary identities;
- host credentials and file content outside accepted read roots;
- writes outside the one private runtime root and `/dev/null`;
- network denial, bounded resources, process-tree cleanup, and redacted logs;
- every outgoing commit, tag, message, and blob plus deletion authorization; and
- truthful separation of Candidate, gates, validation, archive, commit, push
  authorization, transfer, parity, readiness, and installation.

## Untrusted inputs

Treat paths, symlinks, modes, Git status/refs/config/hook stdin, manifests, artifacts,
task text, policy/config JSON, typed argv, environment/loader variables, inherited file
descriptors, sandbox control messages/tokens, tool output, logs, structured data,
interruptions, partial effects, races, and terminal bytes as adversarial.

Ambiguity, truncation, timeout, output/resource cap overflow, leaked descendants,
identity drift, unexpected allowance, or cleanup failure cannot produce PASS or a
reusable authorization.

## Core security invariants

1. Planning gates never masquerade as Candidate evidence. Build, Security(code), and
   Test use one immutable exact Candidate and rehash it before and after execution.
2. Freshness and effective-risk checks run under the ledger lock before a downstream
   brief or effect. Rewind retains all FAIL/CONDITIONAL history.
3. Strict judgment gates require current canonical artifacts, exact Actor/verdict
   agreement, role difference, task closure, and no waiver.
4. Authority-bearing execution accepts only reviewed typed program/argv and exact
   pinned tool/input identities. Shell strings, ambient PATH, and candidate roots have
   no authority.
5. Validation is offline, network-denied, bounded, and isolated into private HOME,
   Git, Cargo, XDG, temp, log, and process state.
6. Pre-push authorizes one exact invocation only; its audit copy is never consulted to
   authorize another push. Deletion-only input cannot bypass policy/ref checks.
7. Deploy consumes only the Build output identity, copies atomically, verifies reopened
   bytes, and never executes the candidate for identity.
8. Human and JSON rendering derive from one typed result, remain meaningful without
   color, and cannot print terminal PASS before durable state exists.
9. Usage and review attestations bind one exact brief/gate attempt. Required evidence
   is consumed atomically before objective execution, so concurrent replay cannot
   validate two attempts; cooperative labels never become authenticated provenance.
10. Budget and anti-stall limits may refuse a new brief but cannot hide status, alter a
    gate verdict, erase an attempt, or turn missing usage into zero cost.
11. Routing writes are limited to reviewed existing targets and require fresh matching
    evidence/config digests after preview. Candidate-cache deletion retains every live
    or archived reference and revalidates no-follow object identity after quarantine.

## Exact-host compatibility adapter

Production certification is limited to macOS 27.0 build `26A5378n`, Apple silicon,
`aarch64-apple-darwin`. The adapter binds the fixed profile, deprecated custom-profile
Seatbelt symbols, undocumented sandbox-extension ABI, root inventory, environment,
limits, request/authority digests, and all canaries. Any mismatch is `NOT CERTIFIED` and
BLOCKED with no fallback.

The pre-entry helper is privileged until Seatbelt entry. It must not read or execute
candidate content, accept roots from argv/environment/candidate config, retain ambient
descriptors, or leak extension text. The protocol is:

`bounded nonce request -> canonical root verification -> issue(flags=0) ->
sandbox_init -> consume -> zeroize -> canaries -> READY -> matching GO ->
close control -> typed exec`.

Mandatory canaries cover allowed dependency reads, denied secrets and ambient Git
config, allowed private writes, denied `/tmp` writes, symlink targets, sockets,
loopback/outbound/DNS, descriptor leakage, child/grandchild inheritance, direct hidden
reinvocation, post-entry non-escalation, and root identity recheck.

Accepted residual risks/nonclaims:

- global path metadata/existence and literal-root directory entries are not
  confidential under the fixed profile;
- required process authority is not isolation from other same-user processes; and
- deprecated/undocumented Apple interfaces may drift on any OS update, which blocks
  certification until a new architecture/security review and canary proof.

Linux is experimental and cannot produce this release's certified claim.

## Tools, dependencies, and secrets

`security/tool-lock.json` records exact reviewed acquisition roots/digests. Cargo uses a
clone-private cache with `--offline --locked`; cargo-audit uses the pinned clone-private
binary and immutable advisory revision/tree; Semgrep and gitleaks use reviewed package
roots/digests. Bootstrap may use the network only when explicitly run. Validation never
downloads, updates, installs, or falls back.

The built-in staged/outgoing secret scanner always runs. Gitleaks and Semgrep are
additional required lanes for the full profile. Required-file reads and scanner output
are individually and aggregately capped; truncation is failure, not clean. Allowlist
entries are narrow, explicit, reviewable, and cannot turn an unavailable scanner into a
PASS.

Never commit credentials, private keys, `.env`, `.git/mpd`, validation logs/receipts,
build output, installed binaries, Cargo caches, or target products.

## Attestation, economics, routing, and cache effects

Attestation files, issuer labels, public keys, signatures, usage counters, clocks, and
routing evidence are untrusted structured input. Parsing is bounded and strict;
unknown fields, floats, duplicate bindings, invalid identifiers, stale evidence,
unblinded/duplicate samples, mixed-currency comparisons, and arithmetic overflow fail
closed or remain explicitly unavailable. No provider credentials, private issuer keys,
prompts, raw model output, or network endpoints are representable in policy.

The only authenticated envelope is SSHSIG Ed25519 verified offline by the tool-locked
`/usr/bin/ssh-keygen -Y verify` contract and fixed `mpd-attestation-v1` namespace.
Issuer trust is configuration-bound public material. Verifier absence or digest drift
is `BLOCKED`, binding or signature failure is `INVALID`, and a consumed digest is
`REPLAYED`.

This repository has `attestation.mode = cooperative` and an empty issuer map.
Consequently authenticated model/session provenance is **NOT DEPLOYED**. Omitted
evidence is allowed, but usage/provenance coverage remains missing; fixtures and
owner-generated signatures must never be presented as independent assurance.

Routing evidence can influence spend and review depth, so `routing apply` is a policy
mutation. Evaluate first, inspect the exact preview, and use `--yes` only for sufficient
fresh blind evidence covering every required target. The writer refuses new/deleted
targets, cross-harness edits, non-routing changes, and concurrent digest drift.
`MISSING` or `INSUFFICIENT` evidence must preserve the current mapping.

Candidate-cache pruning is destructive. Inspection is the default; `--yes` is required
for effects. Enumeration is capped and rooted in owner-only clone-private directories.
Symlinks, malformed sidecars, referenced IDs, identity races, incomplete scans, and
post-quarantine mismatch block deletion. Archive cleanup remains a separate operation.

## Git authorization

Activated hooks are clone-private, owner-only, byte-bound launchers to one absolute
coordinator. Policy activation is a local owner trust mutation and requires an immutable
direct commit plus explicit policy and executable digests. Missing/drifted coordinator,
wrapper, policy, config, tool, host, ABI, profile, or canary blocks.

Pre-push validates bounded authentic four-field rows. It rejects malformed fields,
wrong-old baselines, ref drift, unsafe ref/remote names, local-path remotes, symbolic or
missing trust refs, object/enumeration caps, intermediate introduced-then-removed
secrets, and protected deletion. A non-main branch deletion requires one exact one-use
approval; replay or batch/baseline/policy/nonce mismatch fails.

The owner can still bypass Git hooks. Status reports missing/bypassed authorization
separately; later parity cannot convert it to authorized.

## Reporting vulnerabilities

Do not include secrets or exploit payloads in a public issue. Report the affected commit
and component, attacker capability, trust boundary, impact, minimal reproduction, and a
proposed containment. Security gate findings use:

```text
[SEVERITY] file:line -> exact fix
```

A Security FAIL also records the credible exploit path as
`attacker|capability|boundary|harm|fix`. Unknown or unreviewed security-sensitive scope
is treated as high risk.
