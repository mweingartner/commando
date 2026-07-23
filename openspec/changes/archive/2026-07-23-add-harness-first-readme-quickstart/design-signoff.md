# Design sign-off: Harness-first README quickstart

## Actor

Designer-Sol-71

## Implementation vs intent

Inspected the actual README surface at lines 1-80, including heading order, narrow-line
wrapping, fenced prompt boundaries, numbered steps, anchor target, and the transition into
the existing trust and `Everyday flow` sections.

The built copy leads with the intended responsibility split, requires only one placeholder
edit, gives each harness a distinct copy-ready prompt, and assigns every routine stage to
the model. The missing-setup and external-release boundaries remain visible. Semantic
Markdown structure works without color, pointer interaction, or layout-dependent meaning;
the prompts remain readable and copyable as plain text. Existing advanced guidance is
unchanged and still follows the quickstart.

All Design Mock acceptance criteria are satisfied. No unseen runtime or interactive state
exists for this static documentation surface.

## Verdict

PASS
