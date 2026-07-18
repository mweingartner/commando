# Design: sharpen the harness guidance

Canonical current-state contract.

## Context

The brief (`mpd next --context --json`) already resolves `model`/`effort`/`reviewers`
per phase (tier table + high-risk floor + project config + persona tuning). A harness
that hand-picks a model or under-sets risk defeats that. The README prompt is fixed;
this mirrors it into the compiled doctrine + adds a conduct-time nudge.

## Decisions

### D1 — protocol.md Harness contract (A)
Add to the existing "Harness contract" block: (1) the brief's `model` is resolved for
you — spawn each persona on the brief's `model` at its `effort` with that many
`reviewers`; do NOT substitute your own; (2) for novel/risky surface start at
`--risk high` (floors Security/Tester to the deep model + max effort). Text only; the
directive ships in the binary.

### D2 — conduct risk nudge (B)
In `cmd_conduct`, AFTER `cmd_begin` + the call-loop contract, load the change's ledger
and, if `governance.risk.rank() < High`, print one tip. Forward-looking wording only:
novel/risky surface warrants `--risk high` (floors Security/Tester to deep model + max
effort). It MUST NOT prescribe `mpd reconcile --risk high` — that verb jumps a
pre-Security change to `security-plan`, skipping Architecture (out-of-scope bug, filed
as a follow-up). The tip is absent at `--risk high`.

## Risks / Trade-offs
- [Noise] → the tip prints only at `conduct` (once per change), never per `next`; and
  only below high risk. Acceptable.
- [Misleading fix advice] → deliberately omits the buggy `reconcile` remedy (D2).

## Conditions for Builder
1. A is text-only in `protocol.md`; no code/behavior change. The two additions are the
   `model`-is-resolved rule and the novel-surface→`--risk high` rule, consistent with
   the README prompt.
2. B prints the tip iff the conducted change's resolved risk is below `High`
   (`RiskLevel::rank`), from the loaded ledger — NOT from the raw `--risk` arg (which
   is `None` on a defaulted change). The tip MUST NOT recommend `mpd reconcile`.
3. No change to gate behavior, resolution, artifacts, or any other command. e2e:
   `conduct` below high prints the tip; `conduct --risk high` does not. Load-bearing.
4. Runs under strict; retains its judgment artifacts through archive.
