# Test report: Quality-adjusted cost and time maturity

## Actor

Tester-Terra-41

## Coverage

Functional and regression coverage spans config/ledger compatibility, attestation
known-answer and hostile parsing, economics coverage/overflow/clock behavior, atomic replay
and continuation CAS, shared human/JSON output, exact receipt/reuse identity, docs profile
selection, routing writer scope, hook/current/doctrine recovery, and candidate-cache races.
Property/metamorphic tests cover bounded arbitrary attestation/routing input and identity
invariants; concurrency tests cover CAS/cache races. The explicit nonfunctional workload
covers 10,000 paths and 100 MB.

Certified macOS 27.0 build 26A5378n acceptance passed all three docs profiles. A
byte-identical prose re-drive reused format (1,455 ms source duration) and doctrine
(905 ms), while gitleaks and release-build ran freshly and produced a new artifact.

## Results

- fmt and warning-denied workspace/all-target Clippy: PASS.
- full workspace/all-target tests: 853 passed, 0 failed, 1 ignored.
- explicit ignored workload: 1 passed, 0 failed; 10,000 paths / 100,000,000 bytes,
  scoped digest 469.429 ms and 203.2 MB/s for this single run.
- locked/offline workspace release build: PASS.
- doc-staleness: PASS across 19 current Markdown files.
- hidden doctrine check and `git diff --check`: PASS.

Acceptance and final pipeline revalidation found five real defects (volatile adapter
identity, missing/reusable docs Build artifact, a stale Design Mock rewind loop, and
single-stream-only failure diagnostics, plus an invalid nested external-verifier test
assumption); all were fixed and regression-tested or protected by the established
containment guard. Provider billing and longitudinal model-quality variance remain omitted
for lack of trustworthy evidence and are reported as maturity gaps.

## Verdict

PASS
