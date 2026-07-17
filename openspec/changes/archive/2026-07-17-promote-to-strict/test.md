# Test: promote-to-strict

## Coverage

One e2e test, `strict_verb_promotes_an_existing_change_and_turns_enforcement_on`
(crates/mpd/tests/e2e.rs), covers the whole verb and every risk-to-test row:

- **R1** — a change begun non-strict has `strict=false`; after `mpd strict later`
  the ledger has `strict=true` and enforcement is on: with the manifest made ready
  (so the refusal is the artifact check, not the manifest check), a strict
  Architecture gate REFUSES the seeded stub `design.md` (still full of `<!-- -->`
  placeholders) and names the `design.md` artifact — a change that a non-strict
  gate would accept.
- **R2** — a second `mpd strict later` is an idempotent no-op that succeeds and
  prints "already strict".
- **R3** — `mpd strict nope` on an unknown change errors and creates no ledger.
- **R4** — the command only ever calls `set_strict()` (never `strict=false`);
  write-once is already pinned by the self-enforcing-pipeline monotonicity test.

The test was **proven load-bearing**: neutering `ledger.set_strict()` in
`cmd_strict` turns it RED at "mpd strict must set ledger.strict = true", then it
was restored.

Non-functional: none applicable — a single-file ledger flip with no perf, load,
or concurrency surface.

## Results

- `cargo test --workspace` = **402 passed / 0 failed / 1 ignored** (+1 over the
  b0cc5ed baseline; the ignored one is the pre-existing perf benchmark).
- `cargo clippy --workspace --all-targets -- -D warnings` = clean.
- `cargo fmt --all --check` = clean.
- No production defect surfaced.

## Verdict

**PASS.** The verb's promotion, idempotency, unknown-change error, and the
enforcement-turns-on behavior each have a non-vacuous assertion in one green,
load-bearing e2e test; full suite green and independently re-verified.
