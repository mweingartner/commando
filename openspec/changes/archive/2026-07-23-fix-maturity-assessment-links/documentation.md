# Fix maturity assessment links

## Purpose

Correct two archive-relative links that became invalid when copied into the root `docs/`
directory.

## Value

Readers can navigate from the maturity correction record to the canonical assessment and
the follow-up's archived test evidence without leaving the repository or self-linking.

## Scope

Only `docs/complete-maturity-assessment.md` link text changes. Scores, evidence, runtime,
configuration, policy, dependencies, installed artifacts, and the archive-relative copy
remain unchanged.

## Functional details

The canonical link now resolves in the same directory to
`optimize-quality-cost-time-maturity.md#assessment`. The evidence link moves one directory
up to `openspec/changes/archive/2026-07-23-complete-maturity-assessment/test.md`. Tests
assert both tracked targets and the heading exist from the root document's context.

## Usage

Open `docs/complete-maturity-assessment.md` and follow either corrected link. No command or
mutation is required.
