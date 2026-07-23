# Design mock

## Actor

Designer-Sol-66

## Purpose and boundary

Place a compact `Use MPD with ChatGPT or Claude Code` section immediately after the
opening value paragraph and before the trust-boundary detail. Its first sentence tells
the reader the division of responsibility: **you describe the outcome; the model drives
MPD**.

The section has three layers, in this order:

1. A two-step start: open the MPD-enabled repository in the chosen model harness, then
   paste one outcome-oriented prompt.
2. Separate copy-ready prompts for ChatGPT/Codex and Claude Code. Each names the exact
   `mpd next --harness ... --context` command and instructs the model to start, drive,
   gate, test, and report the workflow without asking the user to operate MPD commands.
3. A short `What the model does` explanation that keeps implementation mechanics out of
   the user's task while setting the expectation that genuine product decisions and
   external-release approval may still require the user.

The default state assumes MPD is already installed and configured in the repository and
links down to `Everyday flow` for setup. The missing-tool/unconfigured state tells the
model to report the blocker and setup action; it must not imply that merely pasting a
prompt installs or authorizes MPD. Loading, partial, and offline visuals are not applicable
to static Markdown; failure language remains plain text and does not rely on color.

Accessibility and adaptive behavior: semantic Markdown headings, numbered steps, short
paragraphs, fenced prompt blocks that wrap on narrow screens, explicit harness labels,
and no table for the primary instructions. The instructions must remain understandable
when copied as plain text or read by a screen reader.

Acceptance criteria:

- The new section is visible before trust-boundary and manual-command detail.
- A reader can begin by changing only `[describe the outcome you want]`.
- ChatGPT uses `--harness codex`; Claude Code uses `--harness claude-code`.
- The model, not the user, is assigned `conduct`, `next`, `gate`, testing, and status work.
- The copy does not promise automatic installation, authenticated actors, deployment, or
  release authority.
- Existing advanced `Everyday flow`, trust, and ordered-gate documentation remains intact.

## Verdict

PASS
