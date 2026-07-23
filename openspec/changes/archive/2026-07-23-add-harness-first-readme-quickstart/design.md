# Design: Add a harness-first README quickstart

## Actor

Architect-Sol-67

## Context

The existing opening accurately explains MPD's value, but the next visible content is a
trust-boundary discussion followed by an operator-driven command loop. That ordering makes
the normal model-driven path appear more manual than it is.

## Goals / Non-Goals

Goals: put the easiest adoption path first; make the user responsible for the desired
outcome and the model responsible for MPD operation; distinguish Codex and Claude Code
harness values; preserve honest decision and release boundaries.

Non-goals: change CLI behavior, install MPD automatically, replace the advanced manual
flow, imply authenticated model identity, or grant deployment/release authorization.

## Decisions

1. Insert one `## Use MPD with ChatGPT or Claude Code` section after the first paragraph.
   This satisfies the requested information hierarchy without rewriting the opening value.
2. Lead with two numbered steps and two copy-ready prompts. The only user-edited field is
   `[describe the outcome you want]`.
3. Each prompt assigns `conduct`, `next`, gate completion, testing, and status reporting to
   the model. The exact `next` command carries `--harness codex` or
   `--harness claude-code`; `conduct` correctly carries no harness flag.
4. Tell the model to stop only for genuine product decisions or external-release authority.
   This preserves the deployment boundary while avoiding routine command handoffs.
5. Retain the existing `Everyday flow` as setup/manual reference and link to it from the
   quickstart prerequisite instead of duplicating installation instructions.

## Risks / Trade-offs

- Readers may assume ChatGPT means the consumer chat website -> label it ChatGPT/Codex and
  describe opening the repository in a coding harness.
- A prompt may over-authorize release -> require explicit external-release authorization.
- Too much workflow detail defeats the quickstart -> keep commands inside copy-ready model
  prompts and limit the explanation to what the model owns.
- Static Markdown has no runtime error state -> state the installed/configured prerequisite
  and instruct the model to report a missing-tool blocker rather than pretending success.

## Verdict

PASS

## Conditions for Builder

1. Modify only the declared README and change-documentation paths.
2. Place the quickstart after the opening value paragraph and before the trust boundary.
3. Use exact current commands: `mpd conduct`, `mpd next --harness codex --context`, and
   `mpd next --harness claude-code --context`; never attach `--harness` to `conduct`.
4. Make the model operate MPD and make the user's primary input the desired outcome.
5. Preserve setup, trust-boundary, gate, deployment-authority, and manual-flow truth.
6. Add no executable behavior, URL, credential, policy, configuration, or dependency.
7. Verify heading placement, prompt content, anchors, command help, doc staleness, and the
   exact Candidate through every applicable gate before archive, commit, push, and parity.
