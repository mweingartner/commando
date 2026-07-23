# Test report

## Actor
Tester (claude-code harness). Functional, property, and boundary verification of the candidate-scope exclusion, the prose secret-scan lane, the drift/landing guards, coherence diagnostics, and the postimage/digest lane; non-functional surface assessed and scoped.

## Coverage

**Functional + boundary (the security-critical behaviors, all with load-bearing assertions verified by Security(code)):**
- **Prose exclusion (D1-D3):** `change_process_artifact_paths` pins the exact 11 names + sibling non-membership + byte-identical `source_digest` (closure.rs:9166); `prune_change_process_artifacts` refuses a symlink and a directory at an artifact path (candidate.rs:5043); `inventory_directory` fails closed on a physically present artifact (candidate.rs:5078); `CANDIDATE_SCHEMA==2` + reopen refusal names the Build-rewind remedy (candidate.rs:5115).
- **Property test (prose-invariance):** arbitrary prose bytes, uncommitted → identical Candidate id; a single declared code-byte flip → different id (candidate.rs:5011) — the core invariant that makes prose-edit reuse safe.
- **Prose secret-scan lane (D4, C1-C4):** secret in `design.md` blocked at Build execute (e2e.rs:2353) and Build+Test `--reuse` (cli.rs:10686, both phases); in-tree `.gitleaks.toml`/`.gitleaksignore` refused even finding-free (cli.rs:9448); subdirectory-config evasion killed (checks/mod.rs:520); requiredness matrix (cli.rs:9610); stat/encoding fail-closed incl. non-UTF-8 + symlink (checks/mod.rs:952/998); byte-threaded scan never re-reads disk (checks/mod.rs:1025); positive end-to-end detection (checks/mod.rs:1042); symlinked repo-root gitleaks config refused with fallback (checks/mod.rs:491).
- **Source-drift + landing guards (D5/D5b, C7):** d482a20-shape tracked out-of-scope edit refused at Build (e2e.rs:2284); `.mpd/state/<change>.json` never trips; untracked never refuses (closure.rs:9213/9267); mixed-landing commit blocked / pure passes / both rename sides / malformed-name + unreadable-ledger fail closed (cli.rs:9711/9749/9846); undeclared policy path refused, declared passes (cli.rs:9800).
- **Postimage lane + digest (D6, C5):** archive digest loop pins `design.md` only — all-clean passes, mutated `design.md` fails, mutated `proposal.md` does NOT trip (cli.rs:9511); mismatch never downgraded, legacy-absent accepted (cli.rs:9435); multi-file Architecture plan admission (closure.rs:4438).
- **Coherence (D7):** arm-sweep pins `coherent:false ⟹ blockers non-empty` except the genuine awaiting-first-commit arm (closure.rs:7525); `publish --verify` names out-of-scope paths.
- **Schema boundary (C8):** v1 origin under the v2 binary never reuses, both Build and Test (cli.rs:10954).
- **Commit floor (C10):** secret in `design.md` (pre-Build) and `test.md` (post-Build) each caught by `scan_staged_postimages` via `mpd hook pre-commit` (e2e.rs:1265).
- **Reuse synergy (D8):** uncommitted prose edit → byte-identical Candidate → Build/Test `--reuse` fires; committed prose edit re-executes (proven via the id-invariance property + the reuse tests).

**Parser/serializer surface:** the prose scanner (`scan_validated_bytes` → `secrets::scan_text`/`suspicious_filename`) reuses the existing secret-scanner primitives, which already carry property/fuzz coverage; the prose lane adds the invariance property + fail-closed boundary tests above. The `judgment_artifact_sha256` ledger field is an additive `Option` (serde default) — legacy records round-trip, verified in the digest tests.

**Non-functional:** N/A with rationale — the candidate-scope prune is a bounded file-set operation; the prose lane reads at most 11 artifacts capped at 16 MiB each (176 MiB < the 256 MiB aggregate cap, so it can never scan more than the sandbox would); no new network, concurrency, or accessibility surface; the drift guard is bounded status enumeration. One Low advisory (non-blocking) carried from Security(code): `scan_change_prose`'s single read is unbounded with the cap enforced post-read — detection unaffected, a `take(cap+1)` bound is a future memory-hardening nicety.

## Results
- `cargo test --workspace --all-targets --offline --locked` = **550 passed / 0 failed / 1 ignored** (mpd unit; ignored = pre-existing 10k-path perf benchmark) + **114 passed / 0 failed** (mpd e2e, includes the new candidate-scope e2e's, named in output) + **58 + 5 + 15 + 2 + 16 + 20 + 9 + 5 passed** (openspec-core). Zero failures. ~30 net-new tests over the pre-change baseline.
- `cargo clippy --workspace --all-targets --offline --locked -- -D warnings` = clean; `cargo fmt --all -- --check` = clean.
- The authoritative Build and high-risk Test gate profiles re-execute this suite in the hermetic, exact-Candidate sandbox; both recorded PASS with real non-zero counts.
- One production defect surfaced during the pipeline (the D6 archive digest miscomparison, Finding 1) and was fixed with a dedicated regression test (cli.rs:9511) before this report.

## Verdict
PASS. Every D1-D9 behavior and each of the ten Security conditions has a non-vacuous, load-bearing assertion (including the prose-invariance property and the d482a20-shape regression); the full suite is green with real counts and re-verified by the sandbox gates; non-functional surface is genuinely bounded/N/A.
