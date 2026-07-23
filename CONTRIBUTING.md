# Contributing to Commando

Commando accepts changes only through the local MPD and Git-enforced workflow. Hosted
CI is not required and is not validation authority.

## Start a change

Check the worktree and read `README.md`, `AGENTS.md`, `ARCHITECTURE.md`, `SECURITY.md`,
the current OpenSpec artifacts, and affected source/tests. Preserve unrelated changes.

```sh
git status --short
mpd conduct <change-name>
mpd next --harness codex --context
```

Follow the returned role and artifact exactly. Do not implement during Architecture.
Do not let Builder self-approve Security(code), Test, or Doc Validation when independent
review is available. Gate with an exact Actor and canonical verdict:

```sh
mpd gate <phase> --pass --by <actor> --evidence <artifact>
```

Commando has no artifact-waiver flag. A FAIL blocks. A conditional gate must name every
condition and those conditions must be resolved before archive. If the review-loop limit
is reached, use one explicit `mpd reconcile --continue <bounded reason>`; do not widen
scope to avoid the limit.

`mpd next` may report a soft budget warning or refuse to commission another brief after
a hard budget or the fixed two-blocker/30-minute anti-stall boundary. Do not delete
history or invent usage to clear it. Provider token/cost evidence is optional in the
current cooperative mode; absent evidence must remain `UNREPORTED`/`UNAVAILABLE`.
Authenticated required mode must not be enabled until an external issuer is actually
deployed and its exact public-key/tool contract is reviewed.

## Builder rules

- Keep the written task plan as the contract. Canonical tasks have stable positive IDs.
- Compile immediately after plan gates and after each vertical slice.
- Use the existing ledger, candidate materializer, local validator, sandbox, Git, and
  closure abstractions; do not build a parallel authority path.
- Use typed argv and data-only configuration. No shell-string authority, ambient PATH
  trust, candidate-controlled roots, networked validation, or weaker sandbox fallback.
- Preserve exact Candidate/Commit/authorization/parity/install subject separation.
- Add tests in the same pass for every new behavior and every fixed regression.
- Update durable docs in the same change when behavior, architecture, security, local
  verification, hooks, release, or installation changes.
- Treat `executed` and `reused` check dispositions as evidence, not interchangeable
  labels. Security(code), outgoing secret scanning, Commit, and pre-push floors remain
  fresh; a reuse source must be a current exact-identity executed result.
- Use the documentation lane only when effective risk is Low and the manifest is
  documentation-only. Do not relabel code/config/policy scope to obtain the narrow
  profile; selection will fall back to the full profile or block on an incomplete lane.

Use `apply_patch` for source edits. Stage explicit files only; never `git add -A`. Never
commit secrets, `.git/mpd`, `.mpd/current`, `.mpd/tmp`, `.mpd/build-output`, `.mpd/local`,
target products, receipts/logs, or installed binaries.

## Development checks

Focused tests are expected while building. Before a production claim, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --workspace --all-targets --offline --locked
cargo test --release -p mpd scoped_digest_throughput_over_10k_paths_100mb \
  --offline --locked -- --ignored --nocapture
cargo build --workspace --release --offline --locked
bash scripts/check-doc-staleness.sh
```

Verify real counts. The default unit suite intentionally ignores the 10k-path/100MB
workload; the explicit command must report `1 passed`, not zero tests.

For the authoritative exact-subject result, first bootstrap and activate the reviewed
local policy if needed, then run:

```sh
bash scripts/bootstrap-local-ci.sh
bash scripts/ci-local.sh --profile high-risk-test --commit HEAD
```

Bootstrap may access the network and only prepares clone-private pinned inputs.
Validation is offline. The only activation route is `mpd policy activate` for an
immutable reviewed commit, exact canonical policy digest, absolute coordinator digest,
and `.githooks`. There is no legacy trust-bootstrap route.

When model routing is under review, use only the committed blind suite and bounded
evidence schema:

```sh
mpd routing evaluate --evidence <routing-evidence.json>
mpd routing apply --evidence <routing-evidence.json>
# After reviewing the exact preview:
mpd routing apply --evidence <routing-evidence.json> --yes
```

The suite under `benchmarks/routing-v1/` is a procedure and rubric, not proof that a
route has won. If actual configured Sol/Terra sessions are missing, stale, unblinded,
undersampled, or incomparable, record `MISSING`/`INSUFFICIENT` and leave mappings
unchanged.

Use cache recovery conservatively:

```sh
mpd cache inspect
mpd cache prune       # preview only
mpd cache prune --yes # only previewed, still-unreferenced identities
```

Neither cache command replaces `mpd archive --recover` or archive cleanup. Bare
`mpd doctor` and `mpd status --json` are the read-only authorities for typed hook and
current-selection diagnosis.

## Test expectations

Map each architecture/security risk to evidence. Cover functional, regression,
integration, boundary/error, concurrency/resource, interruption/rerun, hostile output,
and platform categories. Structured parsers/codecs/protocols require seeded
property/fuzz/metamorphic coverage. Security-sensitive changes must include negative
tests for malformed input, symlink/root replacement, partial durable effects, stale
identity, cap/timeout, and cleanup failure.

Containment work must exercise exact host/profile/ABI/root/canary bindings, allowed and
denied file/network behavior, descriptor leakage, child/grandchild inheritance, direct
hidden reinvocation, post-entry non-escalation, and no fallback. Document the accepted
metadata/root-entry and same-user process nonclaims.

Hook/push work must cover authentic Git field order, malformed/mixed/deletion-only
batches, nested tags, wrong-old/replay/baseline/ref drift, intermediate secrets, object
caps, authorization audit, and proof that MPD performs no transport.

Deploy work must prove source/output/target replacement resistance, interruption-safe
rerun, byte/mode/length identity, and zero execution of the installed candidate.

## Archive and publish

When all gates and tasks are closed:

```sh
mpd archive --yes
git status --short
git add <explicit paths>
git commit -m "<imperative logical change>"
git push
mpd publish --verify
```

Do not use `--no-verify` or force push. The normal pre-push hook issues an authorization
for that invocation; Git performs transport; `mpd publish --verify` separately observes
remote parity. Report all three facts separately.

After commit, rerun the exact Commit profile because Candidate receipts do not become
Commit receipts. If typed Deploy installs the release artifact, verify the reopened
installed identity. Any subsequent code change invalidates affected gate/profile/install
evidence.
