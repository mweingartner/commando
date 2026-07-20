# Test report

## Actor

Tester

## Coverage

Proportionate testing for a docs-only change (`CLAUDE.md` new, `AGENTS.md`
modified — no code shipped). Three passes, all against the fresh debug binary
(`target/debug/mpd`, built 2026-07-20 from HEAD `bd7f92c`):

1. **Functional — every command the two files instruct exists and parses.**
   - `./target/debug/mpd conduct --help` → exit 0. Options are exactly
     `--ui`, `--fix`, `--chore`, `--risk`, `--threat-profile`; **no
     `--harness`** — the corrected loop example (`mpd conduct <change>` bare,
     AGENTS.md:12) matches the real CLI (C2).
   - `./target/debug/mpd next --harness claude-code --context` → exit 0.
     Prints `Persona: Tester (model: fable (fall back to opus if unavailable))`
     and `risk=high → deep tier`.
   - `./target/debug/mpd next --harness codex --context` → exit 0. Prints
     `Persona: Tester (model: sol)`, same `risk=high → deep tier` line.
   - `./target/debug/mpd next --harness generic --context` → exit 0. Prints
     `Persona: Tester (model: deep-cognition)` — the harness-neutral tier name.
   - `./target/debug/mpd next --harness bogus --context` → **exit 0, accepted,
     not rejected.** An unknown harness resolves exactly like `generic`
     (`model: deep-cognition`). Recorded honestly: the test plan expected a
     rejection; the real behavior is a deliberate wildcard —
     `builtin_default`'s `_` arm (crates/mpd/src/harness.rs:332–338), pinned by
     unit test `builtin_default_covers_every_harness_and_tier`
     (harness.rs:711–723, asserting `"some-future-harness"` →
     `deep-cognition`/`standard`). Neither doc claims unknown values are
     rejected, and C3 bounds only the values *named in prose* (all of which are
     `claude-code`/`codex`), so this is designed behavior, not a defect.
   - **Deep- vs standard-tier model claims vs live output.** This change's
     ledger derives `risk=high` (requested low, `deployment-configured`), so
     its Test phase is live evidence of the deep tier: claude-code →
     `fable (fall back to opus if unavailable)`, codex → `sol` — exactly the
     deep-tier strings AGENTS.md:22–27 claims, opus-fallback wording included.
     The flat "every other phase resolves to Sonnet/Terra" prose is a
     default-risk statement; on this high-risk change the live output diverges
     (Tester bumped to the deep tier) precisely as the AGENTS.md:29–30
     authority clause anticipates ("treat that output as authoritative over
     any prose table, including this one"). The bump is code-enforced
     (`governed_model_for`, harness.rs:137–171) and pinned by
     `high_risk_bumps_seeded_security_and_tester_to_the_deep_tier`
     (harness.rs:736). The codex Tester config pin `terra` equals the builtin
     standard default, so the bump applies to it (observed `sol`), matching
     the seeded-pin semantics that test asserts.
   - Luna override: `.mpd/config.json` `models.codex.Documenter = "luna"`
     confirmed on disk, matching the AGENTS.md:26–27 parenthetical.
   - Every other command the two files name parses: `mpd gate --help`,
     `mpd publish --help` (contains `--verify`), `mpd policy activate --help`,
     `mpd hook pre-push --help`, `mpd archive --help`, `mpd next --help` — all
     exit 0.

2. **Content–code coherence** — the resolver unit suite that pins the doc's
   model table ran green (see Results): `builtin_defaults_when_config_is_empty`,
   `builtin_default_covers_every_harness_and_tier`,
   `builtin_fallback_is_fable_only`, `fable_fallback_note_names_opus`,
   `high_risk_bumps_seeded_security_and_tester_to_the_deep_tier`, plus 15 more
   `harness::` tests (20 total).

3. **Regression** — full workspace suite, offline and locked.

**Honest omissions.** No fuzz/property/metamorphic tests were added: this
change ships prose only and touches no parser, serializer, codec, or protocol;
the existing seeded property suites (`props.rs`, 9 tests) ran green as
regression instead of inventing a fuzz target for markdown. No
performance/load/accessibility measurements apply to two markdown files
(CLAUDE.md is 9 lines by design, C1). The ignored release-mode
`scoped_digest_throughput_over_10k_paths_100mb` workload was not run — it is
production-readiness evidence for code changes and no digest code changed
here. A live standard-tier print (`sonnet`/`terra`) was not producible: the
only in-flight change is this one (risk-high, bumped), and conducting a
throwaway low-risk change is outside this phase's write scope — the
standard-tier mapping is covered by the resolver unit tests above.

## Results

```
$ cargo test -p mpd --bin mpd --offline --locked harness:: 2>&1 | tail -1
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 340 filtered out; finished in 0.04s

$ cargo test --workspace --offline --locked 2>&1 | grep "test result"
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 359 filtered out; finished in 0.41s
test result: ok. 359 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 27.59s   (mpd unit)
test result: ok. 91 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 24.86s    (mpd e2e)
test result: ok. 58 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.56s     (openspec_core lib)
test result: ok. 5 passed;  0 failed  (fidelity)
test result: ok. 15 passed; 0 failed  (merge_tests)
test result: ok. 2 passed;  0 failed  (nonfunctional)
test result: ok. 16 passed; 0 failed  (parse_edge_cases)
test result: ok. 20 passed; 0 failed  (project_tests)
test result: ok. 9 passed;  0 failed  (props)
test result: ok. 5 passed;  0 failed  (security_tests)
test result: ok. 0 passed;  0 failed  (openspec_core doc-tests)
```

**Total: 580 passed, 0 failed, 1 ignored** (the ignored test is the
explicit-only 10k-path/100MB throughput workload). Verified the verification:
the `1 passed; 359 filtered out` line is not a second suite — it is the inner
output of a verify-the-verifier test that re-invokes the mpd test binary with
a single-test filter (`canonical_git_ignores_ambient_repository_identity_...`
region of `local_validation::tests`); the authoritative mpd unit line is
`359 passed; 0 failed; 1 ignored`. All counts are real and non-zero; every
runner reported an exit-0 `ok`.

No bug was found, so no regression test was added; the pre-existing
`builtin_default_covers_every_harness_and_tier` and
`high_risk_bumps_seeded_security_and_tester_to_the_deep_tier` already pin the
two behaviors this phase surfaced (permissive unknown-harness wildcard;
risk-high deep-tier bump).

## Verdict

PASS

Every command the two docs instruct exists and parses with the documented
shape (`conduct` takes no `--harness`; `next` accepts
`claude-code`/`codex`/`generic`); live `mpd next` output matches the doc's
deep-tier model claims verbatim on both harnesses, and the one prose/live
divergence (risk-high bump of a standard phase) is exactly the case the doc's
own authority clause subordinates prose to. Resolver suite 20/20 green; full
workspace suite 580 passed, 0 failed, 1 ignored (explicit-only workload).
