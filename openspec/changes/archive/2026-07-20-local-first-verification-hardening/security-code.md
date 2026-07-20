# Security (code) review

## Actor

Security

## Findings

First-pass audit produced three findings (SC-1 MEDIUM, SC-2 LOW, SC-3 LOW). The Builder
remediated all three; each fix was re-verified against the real code on disk, and the
Build gate re-validated the fixed candidate (`45eddcbffc7b8eed…`, receipt
`2a1b5aa50862e6c1…`, attempt 3, full sandboxed profile green: format, clippy,
workspace-tests 578, release-build). Findings are recorded with their original exploit
and their verified resolution.

### SC-1 — MPD_SANDBOXED containment guard was an uncorroborated skip switch — RESOLVED

**[MEDIUM → closed]** Original defect: `crates/mpd/src/sandbox.rs` set `MPD_SANDBOXED=1`
in the contained child env, and seven tests (5 supervisor tests in `sandbox.rs`, 1 in
`local_validation.rs`, 1 in `tests/e2e.rs`) early-returned whenever the variable was
merely *present* ambiently. The legacy gate runner (`checks/tests_runner.rs`) spawned
`sh -c` with no env scrubbing, so any ambient marker (hostile export, shell-profile
accident, harness leakage) silently converted all seven tests into vacuous passes in the
only runs that exercise them — an early return counts as a pass in libtest, with no skip
signal. SECURITY.md names environment variables adversarial; this guard trusted one
without corroboration.

Verified fix (both halves confirmed on disk):

- `crates/mpd/src/checks/tests_runner.rs:39` — the `sh -c` spawn now carries
  `.env_remove("MPD_SANDBOXED")` with an explanatory comment (:37-38), so the legacy
  gate's child suite can never inherit an ambient marker.
- All seven guards now route through a corroborated predicate
  `nested_in_validation_sandbox()` requiring **both** the marker **and** an observed
  denied read (`std::fs::read("/private/etc/hosts").is_err()`): defined at
  `sandbox.rs:1481-1483`, `local_validation.rs:9911-9912`, `e2e.rs:158-159`; call sites
  `sandbox.rs:1487,1508,1537,1554,1593`, `local_validation.rs:9917`, `e2e.rs:165` —
  exactly the seven original sites, no stragglers (repo-wide grep). In an uncontained run
  `/private/etc/hosts` is world-readable (root:wheel 644, verified on the certified
  host), so the probe returns `Ok`, the guard is false, and the tests run regardless of
  the marker. The evasion channel is closed.

Failure-direction check: if a future granted read root ever made `/private/etc/hosts`
readable *inside* the sandbox, the guard would go false in-sandbox, the nested tests
would attempt to run, fail loudly (cannot nest), and the contained lane would FAIL —
fail-closed, not silent. (The in-run denied-read canary at `sandbox_macos.rs:422` — the
`run_canaries` denied-read probe — would independently BLOCK the same drift first.)

Residuals, LOW, carried to the Test phase (see Verdict): (a) the contained
workspace-tests count (578) still includes the seven corroborated skips as passes with
no receipt-level disclosure — now a truthfulness nuance only, since the skip is
containment-proven and the eprintln lands in the digest-bound log; (b) no dedicated
regression test yet pins the marker-set-but-uncontained behavior (the AND-shape makes it
structural, but a test would keep it that way); (c) the probe accepts any read error —
matching only permission-denied would keep a root-mutilated or deleted
`/private/etc/hosts` (root-only actions) from corroborating. None of these reopens the
exposure.

### SC-2 — terminal_safe passed Unicode bidi controls into the stderr-tail surface — RESOLVED

**[LOW → closed]** Original defect: `harness.rs` filtered `char::is_control` (C0, C1,
DEL) but Unicode bidirectional/isolate controls survived into the new 512-byte
candidate-influenced stderr tail (`local_validation.rs:7265-7273`), permitting visual
reordering of the console error line; SP-11 required bidi escaping.

Verified fix: `crates/mpd/src/harness.rs:413` adds
`.filter(|c| !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))` — the
embedding/override range (LRE/RLE/PDF/LRO/RLO) and the isolate range (LRI/RLI/FSI/PDI),
the complete set of terminal-relevant directional controls. Exposure was console-only
and non-persisted throughout. Residual, LOW: the existing unit test
(`terminal_rendering_strips_control_sequences`, `harness.rs:680-686`) still covers only
OSC/BEL/newline — no bidi payload assertion yet; carried to the Test phase.

### SC-3 — no automated equality check between actual child env and the compiled contract — RESOLVED

**[LOW → closed, closing evidence present]** Original defect: the runtime check compared
two static lists; nothing asserted the adapter's *actual* child environment against the
contract, so drift would be silent.

Verified fix, all three parts on disk: single source of truth
`SANDBOX_ENV_CONTRACT_KEYS` (`sandbox.rs:41-65`, 23 keys, ASCII-sorted, duplicate-free,
doc comment naming its three consumers); `compiled_environment_keys` now derives from it
(`local_validation.rs:7626`); and `command_clears_environment_and_sets_offline_contract`
asserts **both inclusions** (`sandbox.rs:1387-1410`) — every set key must be in the
contract, and every contract key must be set, modulo the documented optionals
(`CARGO_HOME`/`CARGO_TARGET_DIR` when no cargo paths are passed, `DEVELOPER_DIR` off
macOS). The fresh attempt-3 Build receipt's 23 `environment_keys` remain identical to
`.mpd/config.json`'s allowlist (re-verified). Fully closed.

The seven original Build-gate fixes remain clean as audited in the first pass:

1. **Full-platform `cargo fetch --locked`** (`scripts/bootstrap-local-ci.sh:168-172`):
   supply-chain delta is bounded — every fetched crate is checksum-pinned by the
   reviewed, committed `Cargo.lock` (no build scripts run at fetch time), the cache is
   the clone-private `CARGO_HOME` under `.git/mpd` (mode 700), and the fetch runs only in
   the explicit network-enabled bootstrap, never in validation.
2. **Preflight stderr tail** (`local_validation.rs:7261-7274`): `stderr` is `Vec<u8>`
   (`sandbox.rs`), so the tail slice is byte slicing — **no UTF-8-boundary panic path**;
   `from_utf8_lossy` absorbs an invalid start. Propagation traced end to end:
   `run_cargo_cache_preflight` → `?` → `validate_candidate_profile` → `?` at
   `cli.rs:3103` → `cli::run` `eprintln!("error: {msg}")` (`cli.rs:806-808`). **Console
   stderr only** — never written to ledger, gate record, receipt, or `.mpd/state`
   (`gate_blocked` at `cli.rs:3617-3620` is also eprintln-only; the preflight error path
   aborts before any receipt/log publication). Candidate-controlled bytes can appear but
   are bounded to 512 bytes and control-stripped; sandbox containment keeps host-secret
   content out of the child's stderr in the first place.
3. **`/private/etc/ssl` read root** (`sandbox.rs` macOS roots): read-only — it enters
   `read_roots`, all issued with the `APP_SANDBOX_READ` class; only the runtime root gets
   read-write, and the read/read-write overlap check holds. Contents verified on the
   certified host: root-owned public TLS material only (`cert.pem`, `openssl.cnf`,
   `x509v3.cnf`, empty `certs/`). The denied-read canary `/private/etc/hosts`
   (`sandbox_macos.rs:37`) is outside every granted root and is re-proven *at runtime in
   every run* (`run_canaries`, plus the post-entry non-escalation re-check), so a future
   root that covered it would fail closed as an unexpected-allowance BLOCK.
4. **`DEVELOPER_DIR` pinning**: all three sites are compile-time string literals —
   `sandbox.rs` (child env), `local_validation.rs:120` (`canonical_git_run`),
   `git.rs:237` (test-only sanitized runner). Never derived from argv, environment, or
   candidate policy. The host's `xcode-select` verifiably points at Xcode-beta —
   precisely the mutable state the pin excludes. Toolchain residual: CLT `cc`/`ld`
   content is not digest-pinned, but CLT is a root-owned system root whose
   path/device/inode identity is bound into `run_root_inventory_digests` — consistent
   with the accepted host-trust boundary that already covers `/usr/bin`.
5. **Seeded git identity**: written to `home.join("gitconfig")` where `home` is always an
   `OwnedRuntimeDir` child constructed by compiled code — never candidate-derived; on
   macOS the runtime-root containment invariant additionally binds home/tmp/target under
   one private root. Fixed non-attributable identity satisfies Condition 17; the
   env-contract test asserts the exact seeded bytes.
6. **`CARGO_INCREMENTAL`/`MPD_SANDBOXED` allowlisting**: config allowlist byte-identical
   to the compiled contract (now via `SANDBOX_ENV_CONTRACT_KEYS`), 23 entries, sorted and
   duplicate-free enforced by `validate_environment_allowlist` (`config.rs:840-862`);
   `sandbox_receipt_inputs` fails closed on any mismatch. Both shipped Build receipts
   record the full contract.
7. **Containment guards**: exactly the declared seven sites; now corroborated (SC-1).

## Conditions verified

Design.md Conditions for Builder (1–17), checked against shipped code where observable
by this review:

- **1 (bounded kernel, no pretrust/bootstrap route)** — HOLDS: `FirstAdoption` is
  `#[cfg(test)]`-gated (`cli.rs:722-723`); no transition helper, custom receiver, or
  hosted authority in the release surface.
- **3 (one exact candidate, never HEAD)** — HOLDS: Build captures and double-rehashes the
  projection (`execute_strict_candidate_build`, `cli.rs:2695-2720`); Security(code)/Test
  reopen the retained Build candidate with identical bindings
  (`retained_candidate_for_objective_gate`, `cli.rs:2740-2779`), rehash before/after
  execution (`cli.rs:3108-3120`), receipt subject bound back to the same candidate
  (`validate_candidate_report_binding`, `cli.rs:3137`).
- **7/13/14 (adapter protocol)** — HOLD: roots assembled only from compiled code plus
  policy inventory, never argv/env; one bounded nonce-bound canonical JSON control
  request with re-serialization canonicality check and `argv[0]` forced equal to the
  approved probe path (`sandbox_macos.rs:277-347`); `flags=0` issue
  (`sandbox_macos.rs:595`), zero `PREFIXMATCH` occurrences; tokens zeroized on every
  path; READY/GO digests bind request+profile+host; control fd replaced with `/dev/null`
  before `limited_exec`, which closes all descriptors >2 (`sandbox.rs`).
- **10 (exact host)** — HOLDS: `verify_certified_host` checks arch + SystemVersion
  product/build with no-follow, size-capped reads (`sandbox_macos.rs:108-131`).
- **15 (receipt binding)** — HOLDS, verified against both shipped Build receipts
  (attempt 2 `d6d53f06…` and post-fix attempt 3 `2a1b5aa5…` in
  `.mpd/state/local-first-verification-hardening.json`): adapter/profile/ABI/canary
  digests, certified host label, 23 environment keys, residual limitations, per-run
  request/authority/root-inventory/canary digests (preflight + 4 lanes, all passed).
- **16 (residual limitations explicit)** — HOLDS: `residual_limitations()`
  (`sandbox_macos.rs:193-200`) carried verbatim into the receipt.
- **17 (private Git/HOME/temp state, no ambient repair)** — HOLDS: runtime-seeded fixed
  identity, private HOME/TMPDIR per run, `HOME=/nonexistent` +
  `GIT_CONFIG_GLOBAL=/dev/null` in canonical git plumbing
  (`local_validation.rs:112-128`).
- **8 (deletion authorization)** and hook wrappers — HOLD at sweep depth: pre-push stdin
  capped at 1 MiB and parsed before trust lookup (`cli.rs:4783-4793`); deletion approval
  `--yes`-gated one-use mutation (`cli.rs:4821-4847`); activation staged journal with
  byte revalidation and exclusive (`create_new`) publications
  (`local_validation.rs:5205-5246, 2579-2618`); legacy PATH-resolved pre-commit hook
  (`githooks.rs:49-62`) fail-closed on a missing binary and explicitly superseded by
  activation-installed absolute-coordinator wrappers.
- Candidate surface — HOLDS at sweep depth: declared symlinks/special files fail closed
  (`candidate.rs:966-989`), no-follow metadata throughout, single-recovery hard-link
  publication with `nlink` checks (`candidate.rs:1190-1260`), `.mpd` process state
  excluded (confirmed in the receipt's `excluded_dirty_sample`).
- **2, 4, 5, 6, 9, 11, 12** (process conditions, freshness/risk internals, status
  separation, Deploy copy path) — not re-audited in depth; pre-existing surface outside
  this change's fixes, covered by the existing suite and plan-stage review; no
  contradicting evidence observed.

Machine-verified lanes: gitleaks, Semgrep, cargo-audit, and the static policy check are
the configured `security-code` profile (`.mpd/config.json`) and execute
deterministically in-sandbox against pinned tool-lock digests when this gate runs; they
are gate machinery, not re-run by this reviewer.

## Independent review

The first pass was independently re-audited from external evidence inward: empirical
host inspection (`/private/etc/ssl` contents; `xcode-select -p` → Xcode-beta; CLT
root-owned; `/private/etc/hosts` mode 644 root:wheel — the fact that grounds the new
probe's uncontained behavior); the *shipped* Build gate records rather than code intent,
diffing receipt `environment_keys` against both the compiled contract and
`.mpd/config.json` (identical, before and after the fix); repo-wide greps for
`MPD_SANDBOXED`, `nested_in_validation_sandbox`, `DEVELOPER_DIR`, and `PREFIXMATCH`
independent of the briefed enumeration (7 guard call sites, 3 helper definitions, 3
pins, 0 PREFIXMATCH — counts match the claims); and a top-down trace of the preflight
error string from `cli::run`'s sink instead of bottom-up from the format site. The
remediation pass was verified the same way: each fix read at its exact site on disk, the
fresh attempt-3 receipt pulled from `.mpd/state` and checked for
candidate/profile/outcome/contract integrity, and the absence of the two
closing-evidence tests (SC-1 regression, SC-2 bidi payload) established by grep before
being carried as residuals rather than assumed delivered.

## Refutation

Deliberate attempts to break the PASS, strongest first — including the new probe:

1. **"Defeat the corroborating probe in an uncontained run."** Making
   `fs::read("/private/etc/hosts")` fail outside the sandbox requires mutating a
   root-owned 644 file (chmod/removal — root-only on macOS) *and* independently setting
   the ambient marker: two deliberate privileged acts. An actor with root inside the
   cooperative-owner boundary can already replace MPD, the tests, or the ledger outright
   — the probe grants no authority they lack. A third-party outer sandbox that denies
   hosts reads plus a leaked marker would also skip, but in such an environment the
   guarded tests genuinely cannot run the validation sandbox, so the skip approximates
   the intended semantics rather than hiding real coverage. Accepted residual, noted in
   SC-1 (with the permission-denied-only tightening suggestion); not a blocker. The
   accident/leakage channel that motivated SC-1 — ambient marker alone — is structurally
   closed by the AND, and the legacy runner additionally scrubs the marker.
2. **"Invert the probe: make the guard fail *inside* the sandbox."** If a granted root
   ever covered `/private/etc/hosts`, the guard would go false in-sandbox and the nested
   tests would run and fail loudly — and the run's own denied-read canary
   (`sandbox_macos.rs:422, 506`) would BLOCK the same drift first. Fail-closed in both
   directions; attack fails.
3. **"The gitconfig seed is a pre-containment arbitrary write."** The write precedes the
   macOS runtime-root check, but `home` derives exclusively from compiled
   `OwnedRuntimeDir` construction (prefix-validated, fixed `/private/tmp` boundary) — no
   candidate, argv, or env input reaches it. Residual ordering wart only.
4. **"The stderr tail can panic or smuggle terminal control."** Byte-slicing `Vec<u8>`
   cannot panic on a UTF-8 boundary; `from_utf8_lossy` plus the now-extended
   `terminal_safe` strip C0/C1/ESC/DEL *and* the bidi embedding/override/isolate ranges.
   The string never reaches durable state. Attack fails.
5. **"Full-platform fetch widens the supply chain."** Every additional crate was already
   named and checksum-pinned in the reviewed `Cargo.lock`; fetch runs no build scripts,
   writes only the clone-private cache, and only in the explicit bootstrap. The delta is
   cache bytes, not authority; attack fails.
6. **"MPD_SANDBOXED as an injection channel into the sandbox."** Fixed literal set after
   `env_clear`; candidate code cannot influence it; it is inside the 23-key bound
   contract. Attack fails.
7. **"CLT pinning creates a toolchain the receipts don't see."** CLT content is not
   digest-bound, but its identity is inside the bound root inventory, it is root-owned,
   and the accepted trust boundary already includes unpinned `/usr/bin` system binaries.
   Consistent with SP-4/SP-8 accepted residuals; not a finding.
8. **"Replay the preflight error as evidence."** It aborts before any receipt exists and
   never reaches durable state. Attack fails.

The refutation produced no candidate-capability escalation, containment breach, receipt
forgery, or persisted-channel injection. The one finding it originally produced (SC-1)
is now verified closed at the structural level, and the strongest attack against the
remediation (probe defeat, item 1) requires root-level host mutation already inside the
accepted cooperative-owner authority.

## Verdict

PASS

All three findings are remediated and verified against the code on disk, and the Build
gate re-validated the fixed candidate under the full sandboxed profile (candidate
`45eddcbffc7b8eed…`, receipt `2a1b5aa50862e6c1…`, attempt 3: format, clippy,
workspace-tests 578, release-build — all passed; environment contract and canary
bindings intact). The SC-1 evasion channel is closed by construction (marker scrubbed in
the legacy runner; skipping requires the marker AND observed containment, and the guard
fails loud in both drift directions), SC-2's filter is correct and complete for the
terminal-relevant directional controls, and SC-3 is closed with its equality test as
closing evidence.

Three LOW test-adequacy/truthfulness residuals are handed to the Test phase (owner:
Tester; unresolved Test conditions still block deployment):

- **R1** — regression test pinning that ambient `MPD_SANDBOXED=1` in an uncontained run
  does not skip the seven guarded tests (evidence: a test exercising the guard's
  uncontained branch, or the predicate factored to be unit-testable).
- **R2** — `terminal_safe` unit test with U+202E/U+2066 payloads (evidence: assertion
  beside `terminal_rendering_strips_control_sequences`).
- **R3** — disclose the seven corroborated in-sandbox skips rather than counting them
  invisibly among receipt passes, or record a documented rationale (evidence: receipt/
  log surfacing or a short note in the change docs).

None of the residuals reopens a security exposure. A material change to the sandbox,
guards, or environment contract returns here for a fresh Security(code) pass.
