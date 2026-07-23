# Design: Fix maturity assessment links

## Actor

Architect-Terra-59

## Context

`docs/complete-maturity-assessment.md` inherited `../../../docs/...` links that are valid
inside the archived change directory but invalid after export to `docs/`.

## Goals / Non-Goals

Correct both root-document targets and verify the files/heading. Do not change scores,
evidence, runtime behavior, configuration, policy, or the correctly relative archived copy.

## Decisions

Use a same-directory link to the canonical assessment's `#assessment` heading and a
one-level-up link to the archived test report. Do not use repository-root URLs because
GitHub would resolve them at the host root rather than the repository root.

## Risks / Trade-offs

[Export context differs from archive context] -> change only the root document and assert
both targets plus the heading exist. [Assessment drift] -> limit the durable diff to link
text.

## Verdict

PASS

## Conditions for Builder

1. Only declared documentation and OpenSpec paths may change.
2. Both root-document links must resolve to tracked repository files; the heading exists.
3. Maturity scores, negative evidence states, commit/receipt facts, and archive evidence
   remain byte-unchanged outside the link lines.
4. No URL, credential, executable command, runtime, configuration, or policy surface is
   added.
