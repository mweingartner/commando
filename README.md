# Commando / MPD

Commando is a local-only meta-harness for Model-Paired Development (MPD). It turns a
change into an explicit sequence of design, architecture, security, implementation,
test, documentation, deployment-readiness, and Git-delivery facts. GitHub Actions is
not required and is not accepted as validation evidence.

MPD is deliberately not an oracle or an independent attestation service. Its trust
boundary is a cooperative repository owner. An owner can replace the executable, edit
Git state, or bypass hooks with `--no-verify`; MPD records and checks the normal path but
does not claim to resist that owner. Actor/model/session labels are cooperative
provenance unless an external harness authenticates them.

## Everyday flow

Install the current source while developing Commando:

```sh
cargo install --path crates/mpd --force --locked
```

Start and drive a strict change:

```sh
mpd conduct my-change

# Repeat until phase=done.
mpd next --harness codex --context
# Perform exactly the named role and author its artifact when required.
mpd gate <phase> --pass --by <actor> --evidence <artifact>

mpd status
mpd archive --yes
git commit
git push
mpd publish --verify
```

`mpd status --json` is the automation interface. It emits one JSON document and keeps
these facts separate: worktree, candidate, gate freshness, local validation, archive,
commit coherence, push authorization, observed transfer, remote parity, installation,
and containment certification. Remote parity does not repair missing or bypassed push
authorization. A Build receipt does not fill the full Test-profile field.

## Ordered gates

Every strict change follows:

```text
Design Mock -> Architecture -> Design Review -> Security (plan) -> Build ->
Security (code) -> Design Sign-off -> Test -> Documentation ->
Doc Validation -> Deploy
```

Only the three Design phases may be inapplicable, and only with a stored rationale that
the change has no human-visible interaction impact. Documentation, Doc Validation, and
final Deploy/readiness are mandatory. A FAIL blocks. A CONDITIONAL PASS remains open
until every condition is resolved.

Strict judgment artifacts contain the required sections, exactly one `## Actor`, and
exactly one `## Verdict` whose first nonblank line is `PASS`, `CONDITIONAL PASS`, or
`FAIL`. The artifact Actor must exactly match `--by` and must differ from the latest
applicable upstream gate actor. Commando has no artifact-waiver flag. Older ledgers with
waiver records remain readable but cannot satisfy strict archive.

Builder tasks use an explicit contract sentence—`Every box is required and has a
stable ID.`—and canonical checkbox lines such as `- [ ] 3.1 ...`. Test and archive fail
closed while required tasks are open or a deferral is stale.

## Exact candidate and freshness

Planning gates name the planning subject and report `Candidate: NOT CAPTURED`. Build
materializes an immutable, read-only projection of base `HEAD` plus the manifest-scoped
staged/unstaged tracked postimages, declared untracked files, deletions, and modes.
Build, Security(code), and Test reopen and rehash that same Candidate before and after
execution. Candidate receipts and Commit/HEAD receipts are different subjects.

The manifest is the change boundary. Any causal input change projects the earliest
affected rewind before the next brief or effect. A *tracked* file edited outside that
boundary refuses the strict Build/Security(code)/Test gates — declare it in the
manifest or stash it — so a change can no longer silently ship a source file the
sandbox never validated; an *untracked* out-of-scope file stays user-owned (a note,
not a refusal). If a landing commit still drifts, `mpd publish --verify` names the
offending paths. `mpd repair-state --to <phase> --reason <text>` previews a legacy
repair; add `--yes` to append the rewind. It never creates a PASS or erases history.
Effective risk is the maximum of requested and derived risk; configuration cannot
lower it.

When a rewind leaves the Candidate **byte-identical**, a strict Build/Test gate may
**reuse** the prior validation receipt instead of re-executing the sandbox: `mpd gate
<phase> --pass --reuse <receipt>`, offered by `mpd next`. The Candidate binds the
change's source, config, specs, and manifest — but **not** its own process prose
(`design.md`/`proposal.md`/`tasks.md` and the judgment artifacts): those are excluded
from the Candidate id (schema v2) and instead covered by a dedicated fail-closed
secret-scan lane at every strict Build/Security(code)/Test gate. So an **uncommitted**
edit to the change's prose leaves the Candidate byte-identical and **is** reusable —
the common "fixed a wording or closed a review condition after its gate" rewind no
longer re-runs the sandbox. Anything that changes the validated bytes still
re-executes: any in-scope source/config/spec/manifest edit, a *committed* prose edit
(base `HEAD` moves), a `history/**` shuffle, and Security(code) always. Reuse is
fail-closed — it requires the same Candidate id, gate profile, policy digest,
revalidated build output, and a hermetic-complete receipt bound to the coordinator's
own executable digest; any drift re-executes. It is enabled by `.mpd/config.json`'s
`closure.hermetic_reuse`, whose `external_state: "none"` attests that no *unpinned*
external mutable state feeds validation — the ambient reads that remain (cargo config
under `$CARGO_HOME`, the SDK via `DEVELOPER_DIR`, the cargo/rustc binaries, OS beyond
os-arch) are pinned by offline+locked builds, `Cargo.lock` checksums, and
execution-time tool-digest verification against `security/tool-lock.json`.

Effective risk drives *depth*, not attempt pressure: at High, Security and Tester
resolve to the deep model with a raised effort floor and Test runs the heavier
`high-risk-test` profile; High in fact *loosens* the attempt limit relative to
Medium/Low. A documentation-only change derives Low; other changes derive High because
their source and `.mpd/` policy files are verification authority. `mpd next --harness
<h>` prints the resolved per-phase model — authoritative over any prose.

## Local validation and containment

Authoritative checks use typed program/argv data, pinned tool identities, offline Cargo
and advisory inputs, bounded logs/resources, private HOME/Git/XDG/temp state, and a
network-denying platform adapter. There is no hosted, shell-string, ambient-PATH,
unsandboxed, or broad-read fallback.

The production certification boundary for this release is intentionally narrow:

- Apple silicon, `aarch64-apple-darwin`;
- macOS 27.0 build `26A5378n`;
- the exact compiled adapter ABI and fixed `security/sandbox/validation.sb` profile;
- a canonical root inventory and current denial/inheritance/non-escalation canaries; and
- the complete high-risk local profile.

Every other host is `NOT CERTIFIED`. Linux code remains experimental and cannot produce
this release's certified claim.

The macOS adapter uses deprecated custom-profile Seatbelt entry points and undocumented
sandbox-extension SPI. It is a fail-closed exact-host compatibility mechanism, not a
supported or portable Apple API. Its certified claim is limited to accepted-root file
content reads, writes to one private runtime root plus `/dev/null`, and network denial.
It does not claim global path-metadata or literal-root-entry confidentiality, nor
same-user process isolation.

The complete high-risk profile runs formatting, warning-denied Clippy, locked/offline
workspace tests, release build, cargo-audit without updating, gitleaks, Semgrep, the
phase-model lane, and the explicit 10k-path/100MB closure workload. A narrower
`cargo -> rustc -> linker -> test binary` probe is feasibility evidence only.

## Local setup and policy activation

Clone-private inputs live under the Git common directory and are never committed.
Bootstrap is explicit and network-enabled; validation itself is offline:

```sh
bash scripts/bootstrap-local-ci.sh
```

The sole activation route binds an immutable reviewed commit, canonical policy digest,
absolute coordinator bytes, tracked wrappers, and `.githooks`:

```sh
mpd policy activate \
  --commit <full-commit-oid> \
  --confirm-policy-digest <sha256> \
  --coordinator <canonical-absolute-mpd-path> \
  --confirm-executable-digest <sha256> \
  --hooks .githooks \
  --yes
```

Activation is a clone-local owner trust decision, not independent proof. It installs
owner-only clone-private launchers and configures `core.hooksPath` to that directory.
Missing or drifted policy, coordinator, wrapper, tool, host, profile, ABI, or canary
blocks validation. There is no legacy trust-bootstrap policy route.

Useful local commands:

```sh
# Full current-commit profile through the activated coordinator.
bash scripts/ci-local.sh --profile high-risk-test --commit HEAD

# Read-only diagnostics; neither command runs validation or installs anything.
mpd doctor --scope validator-policy --enforce
mpd doctor --scope runtime-health --enforce

# Fast staged check, normally called by pre-commit.
bash scripts/ci-local.sh --staged
```

`mpd doctor --fix` only heals `.mpd/.gitignore` additively. It does not change policy,
hooks, configuration, receipts, installation, or remote state.

## Git-local enforcement and publication

The activated pre-commit hook performs bounded staged secret and artifact/task checks.
Pre-push reads Git's four-field protocol from stdin, validates every outgoing commit,
tag, message, and blob, and issues an invocation-local authorization bound to the exact
remote, baseline, update rows, object set, policy, and nonce. It never pushes, fetches,
or writes refs; normal Git owns transport.

Deletion-only pushes still run trust, policy, and ref checks. Main and tag deletion are
denied. A non-main branch deletion requires one exact one-use approval:

```sh
mpd hook approve-deletion --help
```

After Git returns, `mpd publish --verify` freshly compares the coherent closure commit
with the configured remote ref. Publication status distinguishes authorization,
transfer observation, and parity.

## Deployment and installation

Build records one candidate-bound release file. Execute Deploy copies those already
tested bytes through an exclusive temporary, syncs/atomically replaces the destination,
then reopens and checks mode, length, and SHA-256. It does not rebuild or execute the
installed candidate for identity. Readiness-only Deploy is reported separately and
does not claim installation.

## Repository verification

The direct development commands are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo test --workspace --all-targets --offline --locked
cargo test --release -p mpd scoped_digest_throughput_over_10k_paths_100mb \
  --offline --locked -- --ignored --nocapture
cargo build --workspace --release --offline --locked
bash scripts/check-doc-staleness.sh
```

The local profile is authoritative because it binds the exact subject and containment
receipt; these direct commands are useful during development but do not by themselves
create an MPD gate receipt.

## Recovery and truth labels

- `mpd next` records a required freshness rewind before returning a new brief.
- `mpd reconcile --continue <reason>` authorizes one bounded excess review attempt.
- `mpd archive --recover` completes an interrupted owned archive transaction.
- `mpd archive --abandon` removes only owned closure metadata at the allowed stage.
- `mpd use <change>` restores a cleared current-change pointer.
- `mpd status` always shows the next safe action and never treats parity, install, or a
  narrower receipt as proof of a wider state.

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and
[CONTRIBUTING.md](CONTRIBUTING.md) for design, threat-model, and contribution details.
