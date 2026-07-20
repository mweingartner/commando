# Local-First Verification Hardening

## Purpose

Commando already kept durable phase and publication evidence, but the inherited
implementation split validation authority across hosted automation (GitHub Actions),
permissive hooks, duplicated test commands, commit-only receipts, and state transitions
that could go stale without an automatic rewind. An earlier attempt to close those gaps
grew into a self-hosting pretrust proof system before it compiled; that design is
superseded (its FAIL/retry provenance stays in the append-only ledger, not the active
change).

This change delivers a bounded production kernel for a cooperative repository owner on
the currently certified Apple-silicon macOS host. It makes local validation and local Git
hooks authoritative for the supported workflow — an exact-candidate projection, a
certified exact-host sandbox, structured validation receipts, a single digest-confirmed
policy-activation trust route, and delivery facts (archive, commit, push, transfer,
parity, install) kept honest and separate from readiness claims — without pretending that
hooks defeat an owner who deliberately bypasses or replaces them. Hosted CI is not
validation authority; the owner's own machine is.

## Value

Repository owners and model harnesses get one enforceable workflow that keeps written
intent, adversarial roles, exact local validation, documentation, Git delivery, and
installed-byte proof distinct. A green narrow check (a compiler-tree probe, a hosted
badge) can no longer silently stand in for a current Candidate, a full Test profile, an
authorized push, remote parity, or a verified install. Status output says exactly what is
true — worktree dirty, candidate current, push authorization missing/bypassed, remote
parity verified — instead of collapsing those into a single "green".

## Scope

The change's manifest (`openspec/changes/local-first-verification-hardening/manifest.json`)
declares 20 path patterns (`paths`: 20, `shared_paths`: 0). `mpd status` reports
`Scope: 23 path pattern(s)` because the merged view (`manifest_view`,
`crates/mpd/src/cli.rs:1679-1697`) adds 3 code-owned `SystemScope` paths that are never
hand-declared: this change's own directory, its gate ledger
(`.mpd/state/local-first-verification-hardening.json`), and the dated archive target
`ArchivePlan` computes. 20 declared + 3 system-owned = 23 — consistent with this
document's own thesis that no one number stands in for another. The 20 declared patterns
span:

- CI and hook wiring: `.github/dependabot.yml`, `.github/workflows/ci.yml` (removed as
  validation authority), `.githooks/**`;
- MPD governance state: `.mpd/.gitignore`, `.mpd/config.json`, `.mpd/directives/**`,
  `.mpd/secret-allowlist.json`;
- durable repository documentation: `AGENTS.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`,
  `README.md`, `SECURITY.md`;
- build/toolchain identity: `Cargo.lock`, `Cargo.toml`, `rust-toolchain.toml`;
- the implementation itself: `crates/mpd/**`, `crates/openspec-core/**`;
- this change's own OpenSpec directory: `openspec/changes/local-first-verification-hardening/**`;
- operational scripts: `scripts/**`; and
- security policy assets: `security/**` (tool lock, advisory lock, sandbox profile).

**Out of scope**, explicitly:

- Hosted CI (GitHub Actions or any other hosted checker) as validation authority. Remote
  hosting remains a transfer and parity target only — `mpd publish --verify` observes OID
  parity; it never validates, gates, or deploys.
- Any host identity other than the current certified Apple-silicon macOS build
  (macOS 27.0 build `26A5378n`, `aarch64-apple-darwin`). Linux remains explicitly
  experimental and NOT CERTIFIED; no other platform identity may claim production
  certification without its own empirical sandbox, tool, lifecycle, and adversarial
  evidence.
- Resisting a malicious or adversarial repository owner. The trust boundary is
  cooperative: an owner can replace the `mpd` binary, edit policy or Git state, rewrite
  refs, or push with `--no-verify`. MPD detects and reports those conditions when it is
  invoked but does not claim to prevent an owner from controlling their own machine.
  Actor/model/session labels are recorded provenance, not authenticated identity, unless
  an external harness authenticates them.

## Functional details

**Ordered facts.** Every change proceeds through candidate capture, then gates/freshness,
then structured validation receipts, then archive, then commit coherence, then push
authorization, then observed transfer, then remote parity, then install identity — each a
separate status field. Two vocabularies apply and stay separate (design-review.md DR-2):
every operation renders one of the seven canonical **outcome states** — `PASS`, `FAIL`,
`BLOCKED`, `CONDITIONAL`, `STALE`, `IN PROGRESS`, or `NOT RUN` — identically in human and
JSON; independently, each receipt carries a **detail state** — `CURRENT`, `FAILED`,
`STALE`, `BLOCKED`, or `MISSING`, with hook authorization additionally able to show
`BYPASSED`. Individual Workflow-truth fields pair their outcome with a further typed
detail rather than a new outcome spelling — e.g. Worktree's outcome pairs with `DIRTY`,
Remote parity's `PASS` pairs with `VERIFIED`, Push authorization's `BLOCKED` pairs with
`BYPASSED`, Transfer's `BLOCKED` pairs with `UNAUTHORIZED/BYPASSED`, and an unstarted fact
(Archive, Commit, Install) shows `NOT RUN` in both columns. No field fills in for
another: remote parity can read `PASS`/`VERIFIED` while push authorization stays
`BLOCKED`/`BYPASSED`, and a Build receipt never satisfies the Test-profile field. The
mandatory phase order is Design Mock →
Architecture → Design Review → Security(plan) → Build → Security(code) → Design Sign-off
→ Test → Documentation → Doc Validation → Deploy; only the three Design phases may be N/A,
and only with a stored rationale. Freshness is checked on every MPD observation before any
effect: a stale mutating command appends one rewind event, preserves prior PASS/FAIL/
CONDITIONAL history, reopens dependent obligations, and stops before it issues a brief,
runs a check, archives, or installs. `status` performs the same projection read-only.

**Candidate.** Build captures one deterministic worktree Candidate — base `HEAD` plus the
declared staged, unstaged, untracked, deleted, and mode-change overlay for the change's
manifest scope — into an owner-only clone-private staging directory. Build,
Security(code), and Test all reopen and rehash that exact projection rather than
substituting `HEAD` or ambient MPD process state (the live ledger, `.mpd/current`,
pending-closure/parity data, and clone-private receipts/logs/caches are excluded from
candidate-visible inputs and cannot move its ID). Explicit `mpd validate --commit <oid>`
and pre-push validation are distinct Commit-subject operations and never conflated with
the Candidate.

**Environment contract.** Every authority-bearing child process runs with a cleared
environment restricted to a compiled allowlist of 24 keys
(`SANDBOX_ENV_CONTRACT_KEYS` in `crates/mpd/src/sandbox.rs`): `CARGO_HOME`,
`CARGO_INCREMENTAL`, `CARGO_NET_OFFLINE`, `CARGO_TARGET_DIR`, `CARGO_TERM_COLOR`,
`DEVELOPER_DIR`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM`,
`GIT_OPTIONAL_LOCKS`, `GIT_PAGER`, `GIT_TERMINAL_PROMPT`, `HOME`, `LANG`, `LC_ALL`,
`MPD_SANDBOXED`, `PAGER`, `PATH`, `RUSTC`, `SEMGREP_SEND_METRICS`, `SSL_CERT_FILE`, `TERM`,
`TMPDIR`, `TZ`. Five of these were added or hardened specifically during this change:
`DEVELOPER_DIR` (pinned to a literal so the host's mutable `xcode-select` selection cannot
leak in), `CARGO_INCREMENTAL` and `MPD_SANDBOXED` (allowlisted and bound to the same
compiled contract the runtime asserts against), `SSL_CERT_FILE` (paired with the
read-only `/private/etc/ssl` root), and a seeded `GIT_CONFIG_GLOBAL` identity (a fixed,
non-attributable test Git identity written into a private, compiled-only runtime
directory — never derived from candidate input or ambient `~/.gitconfig`). A dedicated
test (`command_clears_environment_and_sets_offline_contract`) asserts both directions:
every key the runtime actually sets is in the contract, and every contract key is set
(modulo documented optionals).

**Containment guards with corroborated probe.** Code that must behave differently when it
is genuinely running inside the exact-host sandbox previously trusted the ambient
`MPD_SANDBOXED` marker alone — a marker that could leak from a hostile shell profile or
harness environment and silently convert in-sandbox-only tests into vacuous passes.
Hardening replaced every one of the seven (now eight, after Test added a regression)
guard sites with a corroborated predicate, `nested_in_validation_sandbox()`, requiring
**both** the marker **and** an independently observed denied read of
`/private/etc/hosts` (world-readable outside the sandbox, denied inside it). The legacy
`sh -c` gate runner additionally strips any ambient `MPD_SANDBOXED` before spawning, so
an accidental leak cannot reach the guard at all.

**Diagnosability.** A profile-check failure renders as a stable, named string —
`"<Phase> structured profile <profile> refused: check <name> <state> (exit …; output
tail: …)"` — naming the failing check and a bounded (512-byte), lossy-UTF-8,
`terminal_safe`-filtered tail of its output. This is console-only: it is emitted to
stderr via `eprintln!` and is never written to the ledger, a gate record, a receipt, or
`.mpd/state`. `terminal_safe` strips C0/C1/ESC/DEL control bytes and the full Unicode
bidi embedding/override (U+202A–U+202E) and isolate (U+2066–U+2069) ranges before any
untrusted string reaches a human or JSON render point, while preserving `\n`/`\t`.

**Compiled ceilings.** The sandbox adapter accepts at most 48 approved read roots
(`MAX_ROOTS` / `MAX_APPROVED_READ_ROOTS = 48` in `sandbox_macos.rs`/`sandbox.rs`) — sized
to the reviewed tool inventory (candidate, coordinator, Rust/Homebrew toolchain, Command
Line Tools/SDK, required system and `/dev` paths) — plus exactly one private read-write
root for HOME/XDG/temp/build/output/test state and literal `/dev/null` for writes outside
it. Roots are sorted, capped, canonical, role-checked, symlink-safe, and bound by
path/type/device/inode plus applicable digests; exceeding the cap or drifting from the
expected identity is `BLOCKED`, never a broadened allowance.

**Known open items** — tracked for follow-up, none reopening a security exposure or
blocking this change's PASS verdicts:

- Design Sign-off finding **F1**: the `sandbox.profile-drift` action text reads "run the
  printed digest-confirmed policy activation" (`cli.rs:1140`), and — separately — the
  `trusted-policy-missing` blocker reads "run the exact digest-confirmed `mpd policy
  activate` command; validation will not execute candidate policy"
  (`local_validation.rs:5736`). Neither is quite the other's wording, and neither is
  directly executable yet: no code path currently prints a filled-in `mpd policy
  activate --commit … --confirm-policy-digest …` line with the reviewed digests. Owner:
  Builder. Task 7.2 (broader adversarial/property suites) is complete with evidence; the
  remaining open item is task 7.3 (the full exact-host closure-commit rehearsal, below).
- Security(code) residual **R3**: the corroborated in-sandbox guard skips (see above) are
  counted invisibly among a receipt's passing test count rather than disclosed at the
  receipt/log level. The skips are containment-proven and their `eprintln` lands in the
  digest-bound lane log; this note is the documented-rationale evidence Test accepted in
  lieu of a receipt-surfacing change. Owner: Builder, Phase-4 backlog.
- Builder task **7.3** (run the exact full local candidate and closure-commit profiles
  against a disposable README-only clone — cooperative activation, dirty candidate, stale
  rewind, gates, closure, archive/commit validation, a real non-force push to a bare
  remote, parity, and installed-byte verification) is deferred and closes post-publish; it
  is not required for this change's Test/Security(code)/Design Sign-off PASS verdicts, but
  it remains open before any claim that the full local profile has been rehearsed
  end-to-end on a clean clone.

## Usage

Bootstrap the network-enabled, clone-private toolchain once (validation and hooks never
invoke this script themselves):

```sh
bash scripts/bootstrap-local-ci.sh
```

Activate local Git hooks through the sole ordinary route — an explicit, digest-confirmed,
cooperative-owner command bound to an absolute reviewed coordinator (there is no
bootstrap, first-adoption, or pretrust fallback):

```sh
mpd policy activate --commit <oid> --confirm-policy-digest <sha256> \
  --coordinator <absolute-mpd> --confirm-executable-digest <sha256> \
  --hooks .githooks --yes
```

Drive a strict change with the harness loop — read the brief, perform exactly the named
role, record the verdict, repeat until `phase=done`:

```sh
mpd conduct my-change
mpd next --harness codex --context
mpd gate <phase> --pass --by <actor> --evidence <artifact>
```

Run the exact local validation profile explicitly against a commit (distinct from the
Candidate gates Build/Security(code)/Test bind to):

```sh
mpd validate --commit HEAD --profile high-risk-test
bash scripts/ci-local.sh --profile high-risk-test --commit HEAD
```

Read status. `mpd status` (or `mpd status --json`) renders the ten separated workflow
facts plus containment. `NOT RUN` means the fact has no evidence yet (e.g. Archive before
`mpd archive --yes`); `BLOCKED` with a typed detail (e.g. `BYPASSED`) means MPD observed
the condition and refused rather than guessing — `Push authorization BLOCKED BYPASSED`
means no current hook authorization exists (commit/push likely happened with
`--no-verify` or without activation), and remote parity being `VERIFIED` at the same time
does not repair or imply that authorization. `NOT CERTIFIED` on the containment block
means the adapter or full local profile has not proven every required lane/canary on the
exact certified host; each `sandbox.*` blocker code carries exactly one safe action (for
example `sandbox.host-drift` → rerun on the certified host, `sandbox.canary-failed` →
return to Security(code)) and there is no fallback path:

```sh
mpd status
mpd status --json
```

Close delivery only after every gate and task is satisfied:

```sh
mpd archive --yes
git commit
git push
mpd publish --verify
```

Recover from a stale or interrupted state rather than forcing forward:

```sh
mpd repair-state --to <earlier-phase> --reason "<text>" --yes   # append-only rewind preview/apply
mpd reconcile --continue "<reason>"                              # record a bounded human decision past an excess review attempt
mpd task defer <id> --owner <actor> --reason "<text>" --evidence <artifact>  # evidence-backed task deferral
```

Read-only diagnostics that never validate, install, or deploy; `runtime-health` re-hashes
the declared installed artifact read-only to compare its recorded identity (size, mode,
SHA-256) against the Build output, but never executes it:

```sh
mpd doctor --scope validator-policy --enforce
mpd doctor --scope runtime-health --enforce
```
