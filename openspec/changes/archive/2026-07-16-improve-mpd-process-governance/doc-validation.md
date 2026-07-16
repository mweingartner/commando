# Documentation validation

## Architect lens — technical and scope accuracy

**Verdict: PASS**

Validated `documentation.md` against the implemented CLI, ledger/config models,
harness rendering, delta specifications, end-to-end tests, and live help/status
output.

### Claims verified

- `mpd begin` accepts `--risk` and `--threat-profile`; explicit CLI values take
  precedence over optional project governance defaults. Non-UI/UI inference is
  low/medium and the default threat profile is `local-trusted-user`.
- Legacy ledgers receive the documented medium/local-trusted-user serde defaults
  without rewriting prior history.
- FAIL requires one closed-enum `--class`; Security FAIL additionally requires
  all five bounded exploitability fields. Invalid combinations are rejected
  before deterministic checks or ledger persistence.
- Risk attempt limits are one/two/three. Reconciliation is phase- and
  attempt-bound, consumed once, and cannot convert or erase a FAIL.
- Risk and threat-profile reconciliation preserve history, remove latest
  Security-plan-and-downstream approvals, and rewind to Security plan while
  retaining Design and Architecture records.
- Artifact guidance uses capped, symlink-refusing reads of the three canonical
  artifacts, approximately 500 words per page, with low/medium limits of two
  and eight and no high-risk page limit. Warnings do not change verdicts.
- Human and JSON governance output, attempt metadata, failure classifications,
  timestamp behavior, and terminal control filtering are implemented and
  covered by tests.
- Every documented command and flag matches current `--help` output and the E2E
  command forms.
- The scope section accurately distinguishes existing controls from this v1 and
  accurately defers evidence reuse, commit manifests, publication/remote parity,
  and tamper-proof provenance. The README makes the same bounded claims.

### Evidence inspected

- `crates/mpd/src/{cli,ledger,config,harness,scaffold}.rs`
- `crates/mpd/tests/e2e.rs`
- `openspec/changes/improve-mpd-process-governance/specs/**/spec.md`
- live `mpd --help`, `begin --help`, `gate --help`, `reconcile --help`, and
  `status --change improve-mpd-process-governance`

No documentation correction is required from the Architect lens.
