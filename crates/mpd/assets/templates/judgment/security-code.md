# Security (code) review

## Actor

<!-- Exact cooperative actor label passed to `mpd gate`; not authenticated. -->

## Findings

<!-- Concrete defects found in the real code on disk, most severe first. Each
gives file:line, the exploit, and the fix. "None" only after an actual audit. -->

## Conditions verified

<!-- Each Condition for Builder from the plan, checked against the shipped code:
how it was verified and whether it holds. -->

## Independent review

<!-- High-risk only: an independent re-audit that does not trust the first pass —
who/what looked again, from a fresh angle, and what it examined. -->

## Refutation

<!-- High-risk only: the deliberate attempt to refute the PASS — the strongest
attack tried against the change and why it fails (or the finding it produced). -->

## Verdict

<!-- PASS / CONDITIONAL PASS / FAIL, with the reason. A material change returns
to the earliest affected phase. Code cannot reach Test without a PASS here. -->
