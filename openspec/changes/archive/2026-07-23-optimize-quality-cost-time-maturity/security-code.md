# Security (code) review: Quality-adjusted cost and time maturity

## Actor

SecurityCode-Terra-39

## Findings

None remaining.

Five blocking defects were found by certified-host acceptance and final pipeline
revalidation, then fixed before this review:

- [HIGH — CLOSED] `local_validation.rs` derived adapter identity from `Debug`, which
  included each materialization path and prevented real exact-check reuse. Identity now
  binds adapter kind and no-follow reviewed bytes; path-independence and byte-drift tests
  pin the boundary.
- [HIGH — CLOSED] the docs Build neither exported its release artifact nor prevented reuse
  of release-build. It now retains release-build, exports the typed Candidate-bound
  artifact, and keeps release-build and secret scans fresh. The certified re-drive reused
  only formatting/doctrine and freshly executed gitleaks/release-build.
- [HIGH — CLOSED] stale Design Mock scope/governance evidence rewound only Architecture,
  leaving the stale Design Mock receipt in a non-advancing loop. The dependency rewind now
  returns to Design Mock itself, with a regression test and a real main-ledger re-drive
  confirming that `next` advances to the correct phase.
- [HIGH — CLOSED] structured-profile failure output selected stderr whenever it was
  non-empty, erasing Rust's stdout failure names and assertions behind Cargo hints. The
  diagnostic now retains terminal-safe tails from both streams within the same 512-byte
  child-output budget, with a regression test.
- [HIGH — CLOSED] the SSHSIG known-answer test tried to invoke the external verifier from
  inside the already-entered objective sandbox, where production verification never runs,
  and failed the exact Build profile. It now uses the established marker-plus-denied-read
  containment guard; the ambient known-answer and exact tool-lock tests remain mandatory.

## Conditions verified

1. Attestation and routing parsers are strict, bounded, terminal-safe, and reject unknown,
   malformed, replayed, cross-bound, stale, mixed-currency, or scope-expanding input.
2. SSHSIG verification resolves only the reviewed `/usr/bin/ssh-keygen` identity, uses
   fixed namespace/key binding and private capped inputs, and records no private key.
3. Replay and continuation mutations use exact ledger CAS/locks and preserve full history.
4. Missing usage remains distinct from zero; currencies stay separate; budgets and
   anti-stall block only new work and preserve status/evidence access.
5. Reuse requires complete current Candidate/profile/policy/tool/platform/adapter identity,
   flattens to executed origins, and excludes security, artifact, Commit, and push floors.
6. Docs selection requires effective-Low documentation-only scope, fail-closed floors, and
   a fresh typed Build artifact for Deploy.
7. Routing writes are preview-first, allowlisted, locked, reread, digest-checked, and atomic;
   insufficient evidence leaves routing unchanged.
8. Hook/current/doctrine/cache recovery is typed and read-only or preview-first; deletion
   retains live/archive references and revalidates no-follow quarantine identity.
9. Cooperative provenance remains NOT DEPLOYED because no external issuer is configured.

## Independent review

Independent Terra passes separately audited evidence, reporting/recovery/cache behavior,
and routing/cache CLI acceptance. Certified sandbox acceptance exercised immutable-policy
activation, all three docs profiles, typed artifact export, and a prose-only Candidate
re-drive. The combined full suite passed 853 tests with one ignored workload run separately.

## Refutation

The strongest refutation was to test the efficiency controls outside unit fixtures. A real
activated Candidate initially disproved PASS twice: volatile adapter paths prevented reuse,
then reusable release-build eliminated the artifact. Final main-ledger revalidation also
exposed the stale Design Mock rewind loop, and the contained Build exposed unusable
single-stream failure diagnostics. The diagnostic then identified an invalid nested
external-verifier test assumption. All five defects now have regressions or an established
containment guard; the
repeated Candidate reused only format/doctrine while fresh security/artifact checks
executed, and the main ledger rewound to Design Mock. No unresolved quality-floor bypass
remains in declared scope.

## Verdict

PASS
