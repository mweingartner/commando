# Design review: Harness-first README quickstart

## Actor

Designer-Sol-68

## Review

The architecture preserves the mock's information hierarchy, two-step entry, separate
copy-ready harness prompts, model/user responsibility split, setup prerequisite, and
release-authority boundary. It correctly keeps `--harness` on `next`, not `conduct`.

The plan does not degrade the simple path into a manual terminal tutorial: command details
stay inside the prompt the user gives the model, and the existing `Everyday flow` remains
the advanced reference. Semantic headings, numbered steps, short text, and fenced prompts
remain readable on narrow screens and through assistive technology. Static Markdown has no
loading/partial UI; missing setup is represented as a plain-language blocker.

## Intent check

PASS. The plan directly serves the requested outcome: users state what they want while
ChatGPT/Codex or Claude Code calls and gates the MPD stages. No acceptance criterion from
the Design Mock was removed or weakened.

## Verdict

PASS
