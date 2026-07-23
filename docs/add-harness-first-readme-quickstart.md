# Harness-first README quickstart

## Purpose

Put the simplest MPD adoption path at the top of the README: the user describes the desired
outcome while ChatGPT/Codex or Claude Code operates the MPD stages.

## Value

New users can start with one copy-ready prompt instead of learning the command loop first.
They stay focused on outcomes, risks, and decisions while the model handles process work.

## Scope

The README adds an outcome-first section with separate Codex and Claude Code prompts, a
setup pointer, and explicit model/user responsibility boundaries. It changes no CLI,
configuration, policy, dependency, authentication, deployment, or release authority. The
existing trust explanation and manual `Everyday flow` remain intact.

## Functional details

Each prompt tells the model to start with `mpd conduct`, follow every current brief using
the correct harness-specific `mpd next --harness ... --context`, complete and gate every
applicable phase, test the real result, and report outcome-focused updates. The model stops
for genuine product decisions or external-release authority it lacks. Missing installation
or repository configuration is reported with an exact setup action rather than hidden.

## Usage

Open the repository in ChatGPT/Codex or Claude Code, copy the matching prompt from the top
of `README.md`, replace `[describe the outcome you want]`, and send it. The user does not
need to run routine MPD commands.
